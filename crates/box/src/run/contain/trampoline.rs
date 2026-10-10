//! Launching `strands-box-contain-trampoline`, the trampoline that applies containment and execs
//! the workload.

use std::ffi::OsString;
use std::fs::File;
#[cfg(any(target_os = "macos", test))]
use std::io::Write as _;
#[cfg(unix)]
use std::io::{Read as _, Seek as _};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd as _};
#[cfg(any(target_os = "macos", test))]
use std::os::unix::ffi::OsStrExt as _;
// macOS stages the trampoline as a private mode-0700 copy, and the tests below set modes on every
// unix — hence `any(macos, test)`.
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
#[cfg(any(target_os = "macos", test))]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use tokio::process::Command;

use crate::error::{BoxError, SetupStage, TrampolineError};

/// The identity marker every `strands-box-contain-trampoline` image carries.
const EXECUTABLE_MARKER: &[u8] =
    b"STRANDS_BOX_CONTAIN_EXECUTABLE_IDENTITY_8E313B0F21A04D3BA52C4E87D493E6C2";

/// The trampoline's filename, which must sit beside the box executable.
const HELPER_NAME: &str = "strands-box-contain-trampoline";

/// What the box must hold until the child is reaped.
pub(crate) struct Trampoline {
    setup_status: SetupStatusPipe,
}

impl Trampoline {
    /// Build a trampoline whose setup status is already complete.
    #[cfg(all(test, unix))]
    pub(crate) fn testing_complete() -> Result<Self, BoxError> {
        let [reader, writer] =
            close_on_exec_pipe().map_err(|source| TrampolineError::StatusPipe { source })?;
        drop(writer);
        Ok(Self {
            setup_status: SetupStatusPipe {
                reader,
                writer: None,
            },
        })
    }

    /// Close the box's copy of the status pipe's write end.
    pub(crate) fn close_setup_writer(&mut self) {
        #[cfg(unix)]
        {
            self.setup_status.writer.take();
        }
    }

    /// The stage containment failed at, or `None` when it never failed.
    pub(crate) fn setup_failure(&mut self) -> Result<Option<SetupStage>, BoxError> {
        Ok(self.setup_status.read_failure()?)
    }
}

/// One validated directory and the reported path for a cached trampoline image.
#[cfg(target_os = "macos")]
pub(crate) struct ImageCache {
    path: PathBuf,
    directory: File,
}

#[cfg(not(target_os = "macos"))]
pub(crate) struct ImageCache;

impl ImageCache {
    pub(crate) fn new(path: PathBuf, directory: File) -> Self {
        #[cfg(target_os = "macos")]
        {
            Self { path, directory }
        }
        #[cfg(not(target_os = "macos"))]
        {
            drop(path);
            drop(directory);
            Self
        }
    }
}

/// Opens the cache for a validated trampoline image of a given digest.
pub(crate) type ImageName<'a> = &'a dyn Fn(&str) -> Result<ImageCache, BoxError>;

/// Everything the trampoline needs to launch one workload.
pub(crate) struct Launch<'a> {
    /// The serialized containment config, and the digest of the exact bytes written.
    pub(crate) config_path: &'a Path,
    pub(crate) config_file: &'a File,
    pub(crate) config_sha256: &'a str,
    /// The workload's environment as an opened file, inert until containment succeeds.
    pub(crate) target_environment_file: &'a File,
    /// The one executable the boundary permits, and its arguments.
    pub(crate) executable: &'a Path,
    pub(crate) arguments: &'a [String],
    /// The spelling the program reads as `argv[0]`, when it is not the executable's own.
    pub(crate) argument_zero: Option<&'a Path>,
    /// The workload's working directory — the box's own home.
    pub(crate) working_directory: &'a Path,
    /// Where a validated copy of the trampoline may be cached. Only macOS calls it,
    /// and only because `/dev/fd` exec is `ENOTSUP` there; Linux execs the opened
    /// descriptor directly and never asks for a name.
    pub(crate) image_name: ImageName<'a>,
    /// Linux only: the trampoline creates the workload's egress listener inside its
    /// new network namespace and sends the descriptor back over this socket. macOS
    /// has no namespace to cross, so it passes `None` and no argument is added.
    #[cfg(target_os = "linux")]
    pub(crate) relay_control: Option<&'a std::os::unix::net::UnixStream>,
}

/// Build the command that runs the workload under containment.
pub(crate) fn command(launch: Launch<'_>) -> Result<(Command, Trampoline), BoxError> {
    let helper = locate()?;
    let mut command = identity_bound_command(&helper, launch.image_name)?;
    let setup_status = SetupStatusPipe::attach(&mut command)?;
    attach_descriptor(&mut command, launch.config_file, "--config-fd")?;
    attach_descriptor(
        &mut command,
        launch.target_environment_file,
        "--target-env-fd",
    )?;
    #[cfg(target_os = "linux")]
    if let Some(control) = launch.relay_control {
        attach_relay_control(&mut command, control)?;
    }
    command
        .args(workload_argv(&launch))
        .env_clear()
        .current_dir(launch.working_directory);
    Ok((command, Trampoline { setup_status }))
}

/// The trampoline's own arguments, in order, after the descriptors are attached.
///
/// Separate from [`command`] so the argument list is assertable without a validated helper on disk.
fn workload_argv(launch: &Launch<'_>) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![
        "--config".into(),
        launch.config_path.into(),
        "--config-sha256".into(),
        launch.config_sha256.into(),
    ];
    if let Some(spelled) = launch.argument_zero {
        argv.push("--argv0".into());
        argv.push(spelled.into());
    }
    argv.push("--".into());
    argv.push(launch.executable.into());
    argv.extend(launch.arguments.iter().map(OsString::from));
    argv
}

/// Pass the relay control socket to the trampoline by descriptor number.
#[cfg(target_os = "linux")]
fn attach_relay_control(
    command: &mut Command,
    control: &std::os::unix::net::UnixStream,
) -> Result<(), BoxError> {
    attach_descriptor(command, control, "--relay-control-fd")
}

fn attach_descriptor(
    command: &mut Command,
    opened: &impl AsRawFd,
    flag: &str,
) -> Result<(), BoxError> {
    let descriptor = opened.as_raw_fd();
    command.arg(flag).arg(descriptor.to_string());
    // SAFETY: the closure only clears FD_CLOEXEC on the child's copy of an
    // already-open descriptor, and allocates nothing.
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(descriptor, libc::F_GETFD);
            if flags == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

/// Find `strands-box-contain-trampoline` beside the box's own executable, and nowhere else.
fn locate() -> Result<PathBuf, BoxError> {
    let current = std::env::current_exe().map_err(|source| TrampolineError::Missing {
        path: PathBuf::from(HELPER_NAME),
        source,
    })?;
    let helper = current
        .parent()
        .map(|directory| directory.join(HELPER_NAME))
        .ok_or_else(|| TrampolineError::NotExecutable {
            path: current.clone(),
        })?;
    validate_installed(&helper)?;
    Ok(helper)
}

/// Refuse an installed path that is not a plain executable file.
fn validate_installed(candidate: &Path) -> Result<(), TrampolineError> {
    if !candidate.is_absolute() {
        return Err(TrampolineError::NotExecutable {
            path: candidate.to_path_buf(),
        });
    }
    let metadata =
        std::fs::symlink_metadata(candidate).map_err(|source| TrampolineError::Missing {
            path: candidate.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(TrampolineError::NotExecutable {
            path: candidate.to_path_buf(),
        });
    }
    #[cfg(unix)]
    if metadata.mode() & 0o111 == 0 {
        return Err(TrampolineError::NotExecutable {
            path: candidate.to_path_buf(),
        });
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Identity-bound exec: validate what is open, run what was validated.

#[cfg(target_os = "linux")]
fn identity_bound_command(path: &Path, _image_name: ImageName<'_>) -> Result<Command, BoxError> {
    let (executable, mut identity_reader) = open_without_following(path)?;
    validate_opened(path, &executable, &mut identity_reader)?;
    // A fresh descriptor for the same open file, above stdio so `Command`'s own
    // stdio setup cannot claim it.
    let for_exec = duplicate_above_stdio(path, &executable)?;
    let descriptor = for_exec.as_raw_fd();
    let mut command = Command::new(format!("/proc/self/fd/{descriptor}"));
    // SAFETY: the closure only retains an already-open descriptor until exec.
    unsafe {
        command.pre_exec(move || {
            let _keep_open = &for_exec;
            Ok(())
        });
    }
    Ok(command)
}

#[cfg(target_os = "linux")]
fn duplicate_above_stdio(path: &Path, executable: &File) -> Result<File, BoxError> {
    // SAFETY: fcntl creates a fresh owned descriptor for the same open file.
    let descriptor = unsafe {
        libc::fcntl(
            executable.as_raw_fd(),
            libc::F_DUPFD_CLOEXEC,
            libc::STDERR_FILENO + 1,
        )
    };
    if descriptor == -1 {
        return Err(TrampolineError::Open {
            path: path.to_path_buf(),
            reason: std::io::Error::last_os_error().to_string(),
        }
        .into());
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a fresh descriptor owned here.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

/// macOS cannot exec `/dev/fd/<n>` (`ENOTSUP`), so the validated bytes are copied
/// into a private image and only that image is executed.
#[cfg(target_os = "macos")]
fn identity_bound_command(path: &Path, image_name: ImageName<'_>) -> Result<Command, BoxError> {
    let (executable, mut identity_reader) = open_without_following(path)?;
    validate_opened(path, &executable, &mut identity_reader)?;
    let materialize = |reason: String| TrampolineError::Materialize {
        path: path.to_path_buf(),
        reason,
    };

    identity_reader
        .rewind()
        .map_err(|error| materialize(error.to_string()))?;
    let digest = digest_of(&mut identity_reader).map_err(|error| materialize(error.to_string()))?;
    let image = image_name(&digest)?;
    let image_name = image
        .path
        .file_name()
        .ok_or_else(|| materialize("image path has no filename".to_string()))?
        .to_os_string();

    // The cached image, if it is still the bytes its name claims. Checked rather than assumed:
    if !cached_image_is_valid(&image.directory, &image_name, &image.path, &digest) {
        identity_reader
            .rewind()
            .map_err(|error| materialize(error.to_string()))?;
        let source_len = executable
            .metadata()
            .map_err(|error| materialize(error.to_string()))?
            .len();
        write_image(
            &image.directory,
            &image_name,
            &image.path,
            &mut identity_reader,
            source_len,
        )?;
    }

    Ok(command_in_directory(image.directory, &image_name))
}

/// Write the validated bytes to `image_path`, atomically and executable.
#[cfg(any(target_os = "macos", test))]
fn write_image(
    directory: &File,
    image_name: &std::ffi::OsStr,
    image_path: &Path,
    source: &mut File,
    expected_len: u64,
) -> Result<(), TrampolineError> {
    let materialize = |reason: String| TrampolineError::Materialize {
        path: image_path.to_path_buf(),
        reason,
    };
    let staging_name = format!(".staged.{}.bin", std::process::id());

    // Removed first rather than reused: `create_new` is what refuses a pre-existing symlink at the
    // staging name, so unlink plus a fresh create gets both idempotency and that refusal.
    let _ = unlink_at(directory, std::ffi::OsStr::new(&staging_name));
    let mut image = open_at(
        directory,
        std::ffi::OsStr::new(&staging_name),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o700,
    )
    .map_err(|error| materialize(error.to_string()))?;
    let copied =
        std::io::copy(source, &mut image).map_err(|error| materialize(error.to_string()))?;
    if copied != expected_len {
        let _ = unlink_at(directory, std::ffi::OsStr::new(&staging_name));
        return Err(materialize(format!(
            "copied {copied} of {expected_len} bytes"
        )));
    }
    image
        .flush()
        .and_then(|()| image.sync_all())
        .map_err(|error| materialize(error.to_string()))?;
    image
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(|error| materialize(error.to_string()))?;
    drop(image);
    rename_at(directory, std::ffi::OsStr::new(&staging_name), image_name).map_err(|error| {
        let _ = unlink_at(directory, std::ffi::OsStr::new(&staging_name));
        materialize(error.to_string())
    })?;
    Ok(())
}

/// Whether the file at `image_path` really is the trampoline `digest` names.
#[cfg(any(target_os = "macos", test))]
fn cached_image_is_valid(
    directory: &File,
    image_name: &std::ffi::OsStr,
    image_path: &Path,
    digest: &str,
) -> bool {
    let Ok(image) = open_at(
        directory,
        image_name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    ) else {
        return false;
    };
    let Ok(mut reader) = image.try_clone() else {
        return false;
    };
    if validate_opened(image_path, &image, &mut reader).is_err() {
        return false;
    }
    if reader.rewind().is_err() {
        return false;
    }
    digest_of(&mut reader).is_ok_and(|actual| actual == digest)
}

/// The SHA-256 of everything `reader` yields from its current position.
#[cfg(any(target_os = "macos", test))]
fn digest_of(reader: &mut File) -> std::io::Result<String> {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>());
        }
        hasher.update(&buffer[..read]);
    }
}

#[cfg(any(target_os = "macos", test))]
fn command_in_directory(directory: File, image_name: &std::ffi::OsStr) -> Command {
    let mut command = Command::new(Path::new(".").join(image_name));
    // SAFETY: the closure changes only the child working directory to the retained cache.
    unsafe {
        command.pre_exec(move || {
            if libc::fchdir(directory.as_raw_fd()) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            let _keep_open = &directory;
            Ok(())
        });
    }
    command
}

#[cfg(any(target_os = "macos", test))]
fn open_at(
    directory: &File,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<File> {
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cache filename contains NUL",
        )
    })?;
    // SAFETY: name is a valid C string and openat returns one owned descriptor.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags,
            mode as libc::c_uint,
        )
    };
    if descriptor == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a fresh descriptor owned here.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(any(target_os = "macos", test))]
fn unlink_at(directory: &File, name: &std::ffi::OsStr) -> std::io::Result<()> {
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cache filename contains NUL",
        )
    })?;
    // SAFETY: name is a valid C string and unlinkat uses the retained directory descriptor.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn rename_at(
    directory: &File,
    from: &std::ffi::OsStr,
    to: &std::ffi::OsStr,
) -> std::io::Result<()> {
    let from = std::ffi::CString::new(from.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cache filename contains NUL",
        )
    })?;
    let to = std::ffi::CString::new(to.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cache filename contains NUL",
        )
    })?;
    // SAFETY: both names are valid C strings and renameat uses one retained directory.
    if unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
        )
    } == -1
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn identity_bound_command(_path: &Path, _image_name: ImageName<'_>) -> Result<Command, BoxError> {
    Err(TrampolineError::UnsupportedPlatform {
        os: std::env::consts::OS,
    }
    .into())
}

/// Open `path` for reading without following a final symlink.
#[cfg(unix)]
fn open_without_following(path: &Path) -> Result<(File, File), TrampolineError> {
    let open = |reason: String| TrampolineError::Open {
        path: path.to_path_buf(),
        reason,
    };
    let executable = crate::record::layout::open_without_following(path)
        .map_err(|error| open(error.to_string()))?;
    let reader = executable
        .try_clone()
        .map_err(|error| open(error.to_string()))?;
    Ok((executable, reader))
}

/// Check the opened file, not the path it came from.
#[cfg(unix)]
fn validate_opened(
    path: &Path,
    executable: &File,
    reader: &mut File,
) -> Result<(), TrampolineError> {
    let invalid = |reason: String| TrampolineError::Invalid {
        path: path.to_path_buf(),
        reason,
    };
    let metadata = executable
        .metadata()
        .map_err(|error| invalid(error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(invalid("opened identity is not a regular file".to_string()));
    }
    if metadata.mode() & 0o111 == 0 {
        return Err(invalid("opened regular file is not executable".to_string()));
    }
    validate_native_format(path, reader)?;
    if !reader_contains_marker(reader, EXECUTABLE_MARKER)
        .map_err(|error| invalid(error.to_string()))?
    {
        return Err(invalid(
            "required executable identity marker is absent".to_string(),
        ));
    }
    Ok(())
}

/// Refuse anything that is not a native executable image — a marker-bearing
/// script, for instance, which the kernel would run through an interpreter.
#[cfg(unix)]
fn validate_native_format(path: &Path, reader: &mut File) -> Result<(), TrampolineError> {
    let invalid = |reason: String| TrampolineError::Invalid {
        path: path.to_path_buf(),
        reason,
    };
    reader
        .rewind()
        .map_err(|error| invalid(error.to_string()))?;
    let mut magic = [0_u8; 4];
    reader
        .read_exact(&mut magic)
        .map_err(|error| invalid(error.to_string()))?;
    if !is_native_magic(magic) {
        return Err(invalid(format!(
            "expected a native {} executable file",
            std::env::consts::OS
        )));
    }
    reader.rewind().map_err(|error| invalid(error.to_string()))
}

#[cfg(target_os = "linux")]
fn is_native_magic(magic: [u8; 4]) -> bool {
    magic == *b"\x7fELF"
}

#[cfg(target_os = "macos")]
fn is_native_magic(magic: [u8; 4]) -> bool {
    matches!(
        magic,
        [0xfe, 0xed, 0xfa, 0xce]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xca, 0xfe, 0xba, 0xbf]
            | [0xbf, 0xba, 0xfe, 0xca]
    )
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn is_native_magic(_magic: [u8; 4]) -> bool {
    false
}

/// Whether `marker` appears anywhere in `reader`.
#[cfg(unix)]
fn reader_contains_marker(reader: &mut File, marker: &[u8]) -> std::io::Result<bool> {
    let mut buffer = [0_u8; 64 * 1024];
    let mut overlap = Vec::with_capacity(marker.len().saturating_sub(1));
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(false);
        }
        overlap.extend_from_slice(&buffer[..read]);
        if overlap.windows(marker.len()).any(|window| window == marker) {
            return Ok(true);
        }
        let keep = marker.len().saturating_sub(1).min(overlap.len());
        let overlap_len = overlap.len();
        overlap.copy_within(overlap_len - keep.., 0);
        overlap.truncate(keep);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// The setup-status pipe: one byte, so a setup failure is not a workload exit.

#[cfg(unix)]
/// The status byte the reaper writes once containment is up and the workload is about to run — the
/// explicit "reached exec" signal for a long-lived leaf whose pipe never EOFs during setup. Must
/// stay distinct from every `SetupStage` failure byte (`1..=5`). Mirrored by the trampoline's writer.
const SETUP_SUCCESS_BYTE: u8 = 0;

struct SetupStatusPipe {
    reader: File,
    writer: Option<File>,
}

#[cfg(not(unix))]
struct SetupStatusPipe;

impl SetupStatusPipe {
    #[cfg(unix)]
    fn attach(command: &mut Command) -> Result<Self, TrampolineError> {
        let [reader, writer] =
            close_on_exec_pipe().map_err(|source| TrampolineError::StatusPipe { source })?;
        let writer_descriptor = writer.as_raw_fd();
        command
            .arg("--setup-status-fd")
            .arg(writer_descriptor.to_string());
        // SAFETY: the closure only changes FD_CLOEXEC on the child copy of an
        // already-open descriptor. The parent retains CLOEXEC on both ends.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(writer_descriptor, libc::F_GETFD);
                if flags == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(writer_descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(Self {
            reader,
            writer: Some(writer),
        })
    }

    #[cfg(not(unix))]
    fn attach(_command: &mut Command) -> Result<Self, TrampolineError> {
        Err(TrampolineError::UnsupportedPlatform {
            os: std::env::consts::OS,
        })
    }

    #[cfg(unix)]
    fn read_failure(&mut self) -> Result<Option<SetupStage>, TrampolineError> {
        // Read exactly one status byte, not to EOF. A long-lived leaf (a contained streaming MCP
        // server) keeps a writer copy open in the reaper for its whole life, so the pipe never EOFs
        // during setup — waiting for EOF would hang. So the reaper writes an explicit success byte
        // (`0`) once containment is up; a failure writes its stage byte (`1..=5`); and a bare EOF
        // (no byte, writer closed at a successful `exec`) still means success, as macOS and the
        // buffered path have always signalled it.
        let mut byte = [0u8; 1];
        let read = std::io::Read::read(&mut self.reader, &mut byte)
            .map_err(|source| TrampolineError::StatusRead { source })?;
        match (read, byte[0]) {
            // EOF with nothing written, or the explicit success marker: containment reached exec.
            (0, _) | (_, SETUP_SUCCESS_BYTE) => Ok(None),
            (_, stage) => SetupStage::decode(stage).map(Some),
        }
    }

    #[cfg(not(unix))]
    fn read_failure(&mut self) -> Result<Option<SetupStage>, TrampolineError> {
        Err(TrampolineError::UnsupportedPlatform {
            os: std::env::consts::OS,
        })
    }
}

#[cfg(target_os = "linux")]
fn close_on_exec_pipe() -> std::io::Result<[File; 2]> {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors points to storage for the two descriptors pipe2 writes.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two fresh descriptors, each transferred to one File.
    Ok(unsafe {
        [
            File::from_raw_fd(descriptors[0]),
            File::from_raw_fd(descriptors[1]),
        ]
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn close_on_exec_pipe() -> std::io::Result<[File; 2]> {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors points to storage for the two descriptors pipe writes.
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    for descriptor in descriptors {
        // SAFETY: descriptor was returned by pipe and remains owned here.
        if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
            let error = std::io::Error::last_os_error();
            // SAFETY: close each fresh descriptor exactly once on this error path.
            unsafe {
                libc::close(descriptors[0]);
                libc::close(descriptors[1]);
            }
            return Err(error);
        }
    }
    // SAFETY: both descriptors are fresh and transferred to one File each.
    Ok(unsafe {
        [
            File::from_raw_fd(descriptors[0]),
            File::from_raw_fd(descriptors[1]),
        ]
    })
}

/// Whether `path` names the trampoline the box would run, for tests.
#[cfg(test)]
fn accepts(path: &Path) -> Result<(), TrampolineError> {
    validate_installed(path)?;
    let (executable, mut reader) = open_without_following(path)?;
    validate_opened(path, &executable, &mut reader)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Launch` whose only interesting field is `argument_zero`.
    fn launch<'a>(
        config: &'a Path,
        file: &'a File,
        program: &'a Path,
        arguments: &'a [String],
        argument_zero: Option<&'a Path>,
        image_name: ImageName<'a>,
    ) -> Launch<'a> {
        Launch {
            config_path: config,
            config_file: file,
            config_sha256: "0".repeat(64).leak(),
            target_environment_file: file,
            executable: program,
            arguments,
            argument_zero,
            working_directory: Path::new("/"),
            image_name,
            #[cfg(target_os = "linux")]
            relay_control: None,
        }
    }

    /// **No environment text on the trampoline's argv.** Linux keeps the launcher's argv readable
    /// for the box's life, and a shared `/proc` shows it to other leaves and other boxes.
    #[test]
    fn the_trampoline_argv_carries_no_environment() {
        let file = File::open("/dev/null").expect("a descriptor");
        let argv: Vec<String> = workload_argv(&launch(
            Path::new("/tmp/containment.json"),
            &file,
            Path::new("/bin/true"),
            &[],
            None,
            &|_| unreachable!("argv tests never cache an image"),
        ))
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();

        assert!(
            !argv
                .iter()
                .any(|argument| argument.starts_with("--target-env")),
            "the environment travels as a descriptor attached by `command`, not in argv: {argv:?}"
        );
        assert!(
            !argv.iter().any(|argument| argument.contains('{')),
            "{argv:?}"
        );
    }

    /// **The spelling reaches the trampoline as `--argv0`, and only when there is one**, so the hop
    /// between the boundary and the contained `exec` cannot be dropped without a failing test. The
    /// executable stays the last argument before the workload's own, whichever way it goes.
    #[test]
    fn the_spelling_is_passed_as_argument_zero_and_omitted_when_absent() {
        let file = File::open("/dev/null").expect("a descriptor");
        let config = Path::new("/tmp/containment.json");
        let program = Path::new("/usr/bin/python3.9");
        let arguments = vec!["-c".to_string(), "pass".to_string()];
        let name: ImageName<'_> = &|_| unreachable!("the argument list needs no image");

        let spelled = Path::new("/ws/.venv/bin/python");
        let with = workload_argv(&launch(
            config,
            &file,
            program,
            &arguments,
            Some(spelled),
            name,
        ));
        let position = with
            .iter()
            .position(|argument| argument == "--argv0")
            .expect("the flag is present");
        assert_eq!(with[position + 1], spelled.as_os_str());
        assert!(
            position < with.iter().position(|a| a == "--").expect("the separator"),
            "the flag precedes the separator, so it is the trampoline's own and not the workload's"
        );

        let without = workload_argv(&launch(config, &file, program, &arguments, None, name));
        assert!(
            !without.iter().any(|argument| argument == "--argv0"),
            "no spelling means no flag, so the program keeps its own name"
        );
        // The two differ by exactly the flag and its value.
        assert_eq!(with.len(), without.len() + 2);
    }

    /// A file at `path` with `contents` and mode `0700`.
    fn write_executable(path: &Path, contents: &[u8]) {
        std::fs::write(path, contents).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// The magic bytes a native executable starts with on this platform.
    fn native_magic() -> &'static [u8] {
        #[cfg(target_os = "linux")]
        {
            b"\x7fELF"
        }
        #[cfg(target_os = "macos")]
        {
            &[0xcf, 0xfa, 0xed, 0xfe]
        }
    }

    /// A byte image that passes every check: native magic plus the marker.
    fn valid_image() -> Vec<u8> {
        let mut image = native_magic().to_vec();
        image.extend_from_slice(&[0_u8; 128]);
        image.extend_from_slice(EXECUTABLE_MARKER);
        image
    }

    #[test]
    fn a_valid_image_is_accepted() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(HELPER_NAME);
        write_executable(&path, &valid_image());

        accepts(&path).expect("a native image carrying the marker is accepted");
    }

    /// A marker-bearing script is refused: the kernel would run it through an
    /// interpreter, so it is not the native image the box validated for.
    #[test]
    fn a_marker_bearing_script_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(HELPER_NAME);
        let mut script = b"#!/bin/sh\n".to_vec();
        script.extend_from_slice(EXECUTABLE_MARKER);
        write_executable(&path, &script);

        let error = accepts(&path).expect_err("a script must be refused");
        assert!(error.to_string().contains("native"), "{error}");
    }

    /// A native image without the marker is refused.
    #[test]
    fn an_image_without_the_marker_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(HELPER_NAME);
        let mut image = native_magic().to_vec();
        image.extend_from_slice(&[0_u8; 4096]);
        write_executable(&path, &image);

        let error = accepts(&path).expect_err("a missing marker must be refused");
        assert!(error.to_string().contains("marker is absent"), "{error}");
    }

    /// A marker straddling the read buffer boundary is still found.
    #[test]
    fn a_marker_across_a_chunk_boundary_is_found() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(HELPER_NAME);
        let mut image = native_magic().to_vec();
        // Land the marker so it begins a few bytes before the 64 KiB boundary.
        let pad = 64 * 1024 - image.len() - 8;
        image.extend_from_slice(&vec![0_u8; pad]);
        image.extend_from_slice(EXECUTABLE_MARKER);
        write_executable(&path, &image);

        accepts(&path).expect("a marker crossing the chunk boundary must be found");
    }

    /// A symlink is refused rather than followed.
    #[test]
    fn a_symlink_is_refused_without_following_it() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real-image");
        write_executable(&real, &valid_image());
        let link = directory.path().join(HELPER_NAME);
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let error = accepts(&link).expect_err("a symlink must be refused");
        assert!(
            error.to_string().contains("not an executable regular file"),
            "{error}"
        );

        // The open layer refuses it independently of the path check.
        let error = open_without_following(&link)
            .expect_err("O_NOFOLLOW must refuse a final symlink")
            .to_string();
        assert!(error.contains("cannot securely open"), "{error}");
    }

    #[test]
    fn a_non_executable_file_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(HELPER_NAME);
        std::fs::write(&path, valid_image()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let error = accepts(&path).expect_err("a non-executable file must be refused");
        assert!(
            error.to_string().contains("not an executable regular file"),
            "{error}"
        );
    }

    #[test]
    fn a_directory_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(HELPER_NAME);
        std::fs::create_dir(&path).unwrap();

        let error = accepts(&path).expect_err("a directory must be refused");
        assert!(
            error.to_string().contains("not an executable regular file"),
            "{error}"
        );
    }

    #[test]
    fn a_missing_helper_names_the_install_expectation() {
        let directory = tempfile::tempdir().unwrap();

        let error = accepts(&directory.path().join(HELPER_NAME))
            .expect_err("an absent helper must be refused");
        assert!(
            error.to_string().contains("must be installed next to"),
            "{error}"
        );
    }

    /// A relative path is refused: the trampoline is located by install position,
    /// so a relative spelling could be reinterpreted by a cwd change.
    #[test]
    fn a_relative_path_is_refused() {
        let error = validate_installed(Path::new("strands-box-contain-trampoline"))
            .expect_err("a relative helper path must be refused");
        assert!(
            error.to_string().contains("not an executable regular file"),
            "{error}"
        );
    }

    /// Bytes are read from the opened identity, so replacing the pathname after
    /// the open cannot change what was validated.
    #[test]
    fn validation_reads_the_opened_identity_not_the_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(HELPER_NAME);
        write_executable(&path, &valid_image());

        let (executable, mut reader) = open_without_following(&path).unwrap();
        // Replace the file at the same pathname with something invalid.
        std::fs::remove_file(&path).unwrap();
        write_executable(&path, b"#!/bin/sh\nnot the validated image\n");

        validate_opened(&path, &executable, &mut reader)
            .expect("validation must read the opened identity, not the replaced path");
    }

    #[test]
    fn cache_materialization_uses_the_opened_directory_after_a_path_swap() {
        let parent = tempfile::tempdir().expect("cache parent");
        let cache = parent.path().join("cache");
        let moved = parent.path().join("moved-cache");
        std::fs::create_dir(&cache).expect("cache directory");
        let opened = File::open(&cache).expect("cache descriptor");
        std::fs::rename(&cache, &moved).expect("move cache directory");
        std::fs::create_dir(&cache).expect("replacement cache directory");

        let source_path = parent.path().join("source");
        std::fs::write(&source_path, valid_image()).expect("source image");
        let mut source = File::open(&source_path).expect("source descriptor");
        let source_len = source.metadata().expect("source metadata").len();
        let digest = digest_of(&mut source).expect("source digest");
        source.rewind().expect("source rewind");
        let image_name = std::ffi::OsStr::new("image");
        write_image(
            &opened,
            image_name,
            &cache.join(image_name),
            &mut source,
            source_len,
        )
        .expect("materialization succeeds");

        assert!(cached_image_is_valid(
            &opened,
            image_name,
            &cache.join(image_name),
            &digest
        ));
        assert!(!cache.join(image_name).exists());
        assert_eq!(
            std::fs::read(moved.join(image_name)).expect("opened cache receives image"),
            valid_image()
        );
    }

    #[tokio::test]
    async fn cached_image_exec_uses_the_opened_directory_after_a_path_swap() {
        let parent = tempfile::tempdir().expect("cache parent");
        let cache = parent.path().join("cache");
        let moved = parent.path().join("moved-cache");
        let image_name = std::ffi::OsStr::new("image");
        std::fs::create_dir(&cache).expect("cache directory");
        std::fs::copy("/usr/bin/true", cache.join(image_name)).expect("approved image");
        std::fs::set_permissions(
            cache.join(image_name),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("approved image mode");
        let opened = File::open(&cache).expect("cache descriptor");
        std::fs::rename(&cache, &moved).expect("move cache directory");
        std::fs::create_dir(&cache).expect("replacement cache directory");
        std::fs::copy("/usr/bin/false", cache.join(image_name)).expect("replacement image");
        std::fs::set_permissions(
            cache.join(image_name),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("replacement image mode");

        let mut command = command_in_directory(opened, image_name);
        command.current_dir(&cache);
        let status = command.status().await.expect("cached image runs");

        assert!(status.success(), "the opened cache must select the image");
    }

    // ── The setup-status pipe ──────────────────────────────────────────────────

    /// Silence means the workload ran: whatever status came back is authentically
    /// the workload's.
    #[test]
    fn no_status_byte_means_the_workload_ran() {
        let mut command = Command::new("/bin/true");
        let mut pipe = SetupStatusPipe::attach(&mut command).unwrap();

        pipe.writer.take();

        assert_eq!(pipe.read_failure().unwrap(), None);
    }

    /// One byte means containment failed at that stage, and the box reports the
    /// stage rather than the child's exit status.
    #[test]
    fn one_status_byte_reports_its_stage() {
        use std::io::Write as _;

        let mut command = Command::new("/bin/true");
        let mut pipe = SetupStatusPipe::attach(&mut command).unwrap();

        pipe.writer.as_mut().unwrap().write_all(&[3]).unwrap();
        pipe.writer.take();

        assert_eq!(pipe.read_failure().unwrap(), Some(SetupStage::Apply));
    }

    #[test]
    fn read_failure_reads_exactly_one_status_byte() {
        use std::io::Write as _;

        let mut command = Command::new("/bin/true");
        let mut pipe = SetupStatusPipe::attach(&mut command).unwrap();

        // The reaper writes one stage byte; a trailing byte must neither change the reported
        // stage nor make the read block, because `read_failure` consumes one byte and stops.
        pipe.writer.as_mut().unwrap().write_all(&[1, 2]).unwrap();
        pipe.writer.take();

        assert_eq!(pipe.read_failure().unwrap(), Some(SetupStage::ConfigRead));
    }

    /// The pipe passes the child a descriptor above stdio, so `Command`'s own
    /// stdin/stdout/stderr wiring cannot collide with it.
    #[test]
    fn the_status_descriptor_is_above_stdio() {
        let mut command = Command::new("/bin/true");
        let pipe = SetupStatusPipe::attach(&mut command).unwrap();

        assert!(
            pipe.writer.as_ref().unwrap().as_raw_fd() > libc::STDERR_FILENO,
            "the status descriptor must not collide with stdio"
        );
        assert!(pipe.reader.as_raw_fd() > libc::STDERR_FILENO);
    }

    /// Both ends are close-on-exec in the parent, so an unrelated spawn cannot
    /// leak the pipe and hold it open forever.
    #[test]
    fn both_pipe_ends_are_close_on_exec_in_the_parent() {
        let mut command = Command::new("/bin/true");
        let pipe = SetupStatusPipe::attach(&mut command).unwrap();

        for descriptor in [
            pipe.reader.as_raw_fd(),
            pipe.writer.as_ref().unwrap().as_raw_fd(),
        ] {
            // SAFETY: fcntl(F_GETFD) only reads flags on an open descriptor.
            let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
            assert!(flags != -1);
            assert!(
                flags & libc::FD_CLOEXEC != 0,
                "descriptor {descriptor} must be close-on-exec in the parent"
            );
        }
    }

    /// Two trampolines in one process get distinct descriptors, so their status
    /// channels cannot be confused.
    #[test]
    fn concurrent_trampolines_reserve_distinct_descriptors() {
        let mut first_command = Command::new("/bin/true");
        let first = SetupStatusPipe::attach(&mut first_command).unwrap();
        let mut second_command = Command::new("/bin/true");
        let second = SetupStatusPipe::attach(&mut second_command).unwrap();

        assert_ne!(
            first.writer.as_ref().unwrap().as_raw_fd(),
            second.writer.as_ref().unwrap().as_raw_fd()
        );
    }
}
