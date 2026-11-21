//! One disposable compiler executable, with original authority verified by its live owner.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
#[cfg(test)]
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{CompilationInput, CompilationOutput};
use crate::error::BoxError;
#[cfg(test)]
use crate::error::SuperviseError;
use crate::run::commands::snapshot as commands;
#[cfg(test)]
use crate::run::hosted::storage::Cancellation;
use crate::run::installation::snapshot as installation;

const VERSION: u32 = 1;
const FRAME_LIMIT: usize = 16 * 1024 * 1024;
const MAX_TREES: usize = 4096;
const MAX_DESCRIPTORS: usize = 2 * 4096 + 6;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(10);
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const EXIT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
    kind: u32,
}

impl ObjectIdentity {
    fn capture(file: &File) -> Result<Self, BoxError> {
        let metadata = file.metadata().map_err(io_error)?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            kind: metadata.mode() & libc::S_IFMT,
        })
    }

    fn verify(&self, file: &File) -> Result<(), BoxError> {
        let now = Self::capture(file)?;
        if (self.device, self.inode, self.kind) != (now.device, now.inode, now.kind) {
            return Err(failure(
                "compiler received a descriptor with the wrong source identity or type",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tree {
    path: PathBuf,
}

/// CompilationInput stays encoded until the captured filesystem view has been installed.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u32,
    input: String,
    namespace: ObjectIdentity,
    trees: Vec<Tree>,
    commands: commands::Manifest,
    installation: installation::Manifest,
}

impl Request {
    fn validate(&self) -> Result<usize, BoxError> {
        self.commands.validate()?;
        self.installation.validate()?;
        let count = 1
            + self.trees.len()
            + self.commands.descriptor_count()
            + self.installation.descriptor_count();
        if self.version != VERSION || self.trees.len() > MAX_TREES || count > MAX_DESCRIPTORS {
            return Err(failure(
                "unsupported compiler request version or descriptor count",
            ));
        }
        let mut names = BTreeSet::new();
        for tree in &self.trees {
            commands::validate_path(&tree.path)?;
            if tree.path == Path::new("/") || !names.insert(tree.path.clone()) {
                return Err(failure(
                    "compiler roots must name distinct, non-root directories",
                ));
            }
        }
        for left in &names {
            for right in &names {
                if left != right && left.starts_with(right) {
                    return Err(failure("compiler source roots must not overlap"));
                }
            }
        }
        Ok(count)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Authority {
    Commands,
    Installation,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum WorkerMessage {
    Verify {
        authority: Authority,
        descriptor: u32,
        digest: [u8; 32],
    },
    Complete {
        output: Box<CompilationOutput>,
    },
    Failed {
        message: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum OwnerReply {
    Verified {},
    Refused { message: String },
}

#[cfg(test)]
struct CancellationRegistration<'a> {
    cancel: &'a Cancellation,
    registration: u64,
}

#[cfg(test)]
impl Drop for CancellationRegistration<'_> {
    fn drop(&mut self) {
        self.cancel.untrack(self.registration);
    }
}

#[cfg(test)]
struct ChildGuard(Option<Child>);

#[cfg(test)]
impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn finish(&mut self) -> Result<(), BoxError> {
        let deadline = Instant::now() + EXIT_TIMEOUT;
        let child = self
            .0
            .as_mut()
            .expect("child remains owned until successful exit");
        loop {
            if let Some(status) = child.try_wait().map_err(io_error)? {
                self.0.take();
                if !status.success() {
                    return Err(failure(format!(
                        "storage compiler exited unsuccessfully: {status}"
                    )));
                }
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(failure(
                    "storage compiler did not exit after returning its result",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(test)]
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct RemoteOwner {
    authority: Authority,
    control: Arc<Mutex<UnixStream>>,
}

impl commands::OwnerVerifier for RemoteOwner {
    fn verify(&self, descriptor: u32, digest: [u8; 32]) -> Result<(), BoxError> {
        let control = self
            .control
            .lock()
            .map_err(|_| failure("compiler verification channel lock failed"))?;
        send_json(
            &control,
            &WorkerMessage::Verify {
                authority: self.authority,
                descriptor,
                digest,
            },
        )?;
        match receive_json::<OwnerReply>(&control)? {
            OwnerReply::Verified {} => Ok(()),
            OwnerReply::Refused { message } => Err(failure(format!(
                "original authority verification failed: {message}"
            ))),
        }
    }
}

/// Called only by the dedicated executable, before creating any runtime or worker thread.
pub(crate) fn main() -> ExitCode {
    match worker() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("strands-box-storage-compiler: {error}");
            ExitCode::FAILURE
        }
    }
}

fn worker() -> Result<(), BoxError> {
    if std::fs::read_dir("/proc/self/task")
        .map_err(io_error)?
        .count()
        != 1
    {
        return Err(failure(
            "storage compiler entry requires a fresh single-threaded executable",
        ));
    }
    let mut arguments = std::env::args_os().skip(1);
    let mode = arguments.next();
    let source_helper = mode.as_deref() == Some(std::ffi::OsStr::new("--source-control-fd"));
    if !source_helper && mode.as_deref() != Some(std::ffi::OsStr::new("--control-fd")) {
        return Err(failure(
            "this private executable requires its inherited controller channel",
        ));
    }
    let descriptor: RawFd = arguments
        .next()
        .and_then(|value| value.to_str().and_then(|value| value.parse().ok()))
        .filter(|descriptor| *descriptor >= 3)
        .ok_or_else(|| failure("invalid compiler controller descriptor"))?;
    if arguments.next().is_some() {
        return Err(failure("unexpected private compiler arguments"));
    }
    validate_channel(descriptor)?;
    // SAFETY: the dedicated executable accepts sole ownership of its validated inherited socket.
    let control = unsafe { UnixStream::from_raw_fd(descriptor) };
    // SAFETY: prevent this private channel from escaping a future accidental exec.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    close_other_descriptors(descriptor)?;
    // SAFETY: getppid has no preconditions and this executable does not create a PID namespace.
    let parent = unsafe { libc::getppid() };
    arm_parent_death(parent)?;
    control
        .set_read_timeout(Some(TRANSFER_TIMEOUT))
        .map_err(io_error)?;
    control
        .set_write_timeout(Some(TRANSFER_TIMEOUT))
        .map_err(io_error)?;
    if source_helper {
        return containment::storage::sources::serve(&control)
            .map_err(|error| failure(error.to_string()));
    }
    refuse_process_memory_access()?;
    let result = compile_request(&control, parent);
    match result {
        Ok(output) => send_json(
            &control,
            &WorkerMessage::Complete {
                output: Box::new(output),
            },
        )
        .map_err(BoxError::from),
        Err(error) => {
            let _ = send_json(
                &control,
                &WorkerMessage::Failed {
                    message: error.to_string(),
                },
            );
            Err(error)
        }
    }
}

fn compile_request(
    control: &UnixStream,
    parent: libc::pid_t,
) -> Result<CompilationOutput, BoxError> {
    let request: Request = receive_json(control)?;
    let count = request.validate()?;
    let mut descriptors = (0..count)
        .map(|_| {
            containment::storage::receive_fd(control)
                .map(File::from)
                .map_err(BoxError::from)
        })
        .collect::<Result<Vec<_>, BoxError>>()?
        .into_iter();
    let namespace = descriptors
        .next()
        .expect("request count always includes user namespace");
    request.namespace.verify(&namespace)?;
    let trees = descriptors
        .by_ref()
        .take(request.trees.len())
        .collect::<Vec<_>>();
    for (tree, descriptor) in request.trees.iter().zip(&trees) {
        let identity = ObjectIdentity::capture(descriptor)?;
        if identity.kind != libc::S_IFDIR {
            return Err(failure(format!(
                "captured source {} is not a directory",
                tree.path.display()
            )));
        }
        // SAFETY: inspect the received descriptor without reopening a source pathname.
        let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 || flags & libc::O_PATH == 0 {
            return Err(failure(
                "compiler source descriptor is not a captured path handle",
            ));
        }
    }
    let command_files = descriptors
        .by_ref()
        .take(request.commands.descriptor_count())
        .collect::<Vec<_>>();
    let installation_files = descriptors.collect::<Vec<_>>();
    let roots = request
        .trees
        .iter()
        .zip(&trees)
        .map(|(tree, file)| (tree.path.as_path(), file.as_raw_fd()))
        .collect::<Vec<_>>();
    containment::storage::enter_compiler_view(namespace.as_raw_fd(), &roots)?;
    arm_parent_death(parent)?;
    refuse_process_memory_access()?;
    let input: CompilationInput = serde_json::from_str(&request.input).map_err(json_error)?;
    if input.admitted
        != request
            .trees
            .iter()
            .map(|tree| tree.path.clone())
            .collect::<Vec<_>>()
    {
        return Err(failure(
            "compilation inputs do not match installed captured roots",
        ));
    }
    for root in &input.admitted {
        if !input.roots.contains(root) {
            return Err(failure("captured source is not a declared storage root"));
        }
    }
    let shared = Arc::new(Mutex::new(control.try_clone().map_err(io_error)?));
    control
        .set_read_timeout(Some(CALLBACK_TIMEOUT))
        .map_err(io_error)?;
    let commands = Arc::new(request.commands.import(
        command_files,
        Arc::new(RemoteOwner {
            authority: Authority::Commands,
            control: Arc::clone(&shared),
        }),
    )?);
    let installation = Arc::new(request.installation.import(
        installation_files,
        Arc::new(RemoteOwner {
            authority: Authority::Installation,
            control: shared,
        }),
    )?);
    if installation.storage_compiler().is_none() {
        return Err(failure(
            "compiler request omitted its originally pinned compiler role",
        ));
    }
    super::compile(input, &commands, &installation)
}

fn refuse_process_memory_access() -> Result<(), BoxError> {
    // SAFETY: disabling dumpability prevents same-UID sandbox processes from tracing this trusted worker.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn arm_parent_death(parent: libc::pid_t) -> Result<(), BoxError> {
    // SAFETY: this is the disposable worker; killing it when its sole owner exits cannot affect Box.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: recheck closes the race between reading the parent and arming its death signal.
    if unsafe { libc::getppid() } != parent {
        return Err(failure("compiler controller exited during setup"));
    }
    Ok(())
}

fn validate_channel(descriptor: RawFd) -> Result<(), BoxError> {
    let mut kind = 0_i32;
    let mut kind_length = std::mem::size_of_val(&kind) as libc::socklen_t;
    // SAFETY: getsockopt writes only the provided sized output buffer.
    if unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut i32).cast(),
            &mut kind_length,
        )
    } != 0
        || kind != libc::SOCK_STREAM
    {
        return Err(failure(
            "compiler controller descriptor is not a stream socket",
        ));
    }
    // SAFETY: zeroed ucred is a valid output buffer filled by getsockopt.
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
    // SAFETY: SO_PEERCRED returns the Unix socket peer's process and credentials into this buffer.
    let accepted = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        ) == 0
            && credentials.pid == libc::getppid()
            && credentials.uid == libc::geteuid()
    };
    if !accepted {
        return Err(failure(
            "compiler channel is not owned by its original parent process",
        ));
    }
    Ok(())
}

fn close_other_descriptors(kept: RawFd) -> Result<(), BoxError> {
    let mut descriptors = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd").map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        if let Some(descriptor) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<RawFd>().ok())
            && descriptor > 2
            && descriptor != kept
        {
            descriptors.push(descriptor);
        }
        if descriptors.len() > 65536 {
            return Err(failure("compiler inherited too many descriptors"));
        }
    }
    for descriptor in descriptors {
        // SAFETY: this fresh single-threaded executable retains only standard streams and its channel.
        // The directory iterator has already closed its own descriptor; closing that stale number is harmless.
        unsafe { libc::close(descriptor) };
    }
    Ok(())
}

fn send_json(control: &UnixStream, value: &impl Serialize) -> Result<(), TransportError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| TransportError::Invalid(json_error(error)))?;
    if bytes.len() > FRAME_LIMIT {
        return Err(TransportError::Invalid(failure(
            "compiler frame exceeds its private transport limit",
        )));
    }
    let mut control = control;
    control
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .map_err(TransportError::Io)?;
    control.write_all(&bytes).map_err(TransportError::Io)
}

fn receive_json<T: DeserializeOwned>(control: &UnixStream) -> Result<T, TransportError> {
    let mut control = control;
    let mut length = [0_u8; 4];
    control
        .read_exact(&mut length)
        .map_err(TransportError::Io)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > FRAME_LIMIT {
        return Err(TransportError::Invalid(failure(
            "compiler frame exceeds its private transport limit",
        )));
    }
    let mut bytes = vec![0; length];
    control.read_exact(&mut bytes).map_err(TransportError::Io)?;
    serde_json::from_slice(&bytes).map_err(|error| TransportError::Invalid(json_error(error)))
}

#[cfg(test)]
fn send_fd(control: &UnixStream, file: &File) -> Result<(), TransportError> {
    let byte = *b"F";
    let mut vector = libc::iovec {
        iov_base: byte.as_ptr().cast_mut().cast(),
        iov_len: 1,
    };
    let mut ancillary = [0_u64; 4];
    // SAFETY: optional message fields are null; the live buffers are installed below.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&ancillary);
    // SAFETY: aligned ancillary buffer has room for one descriptor; all buffers survive sendmsg.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize;
        std::ptr::write(
            libc::CMSG_DATA(header).cast::<libc::c_int>(),
            file.as_raw_fd(),
        );
        message.msg_controllen = (*header).cmsg_len;
        loop {
            let sent = libc::sendmsg(control.as_raw_fd(), &message, libc::MSG_NOSIGNAL);
            if sent == 1 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if sent < 0 && error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(if sent < 0 {
                TransportError::Io(error)
            } else {
                TransportError::Invalid(failure("compiler descriptor frame was incomplete"))
            });
        }
    }
}

#[derive(Debug)]
enum TransportError {
    Io(std::io::Error),
    Invalid(BoxError),
}

impl From<TransportError> for BoxError {
    fn from(error: TransportError) -> Self {
        match error {
            TransportError::Io(error) => io_error(error),
            TransportError::Invalid(error) => error,
        }
    }
}

#[cfg(test)]
fn owner_error(error: TransportError, cancel: &Cancellation) -> BoxError {
    if let TransportError::Io(ref source) = error
        && cancel.is_cancelled()
        && matches!(
            source.kind(),
            std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::NotConnected
        )
    {
        return cancelled();
    }
    error.into()
}

#[cfg(test)]
fn cancelled() -> BoxError {
    SuperviseError::StorageCancelled.into()
}
fn json_error(error: serde_json::Error) -> BoxError {
    failure(format!("invalid private compiler frame: {error}"))
}
fn io_error(error: std::io::Error) -> BoxError {
    failure(format!("private compiler transport: {error}"))
}
fn failure(message: impl Into<String>) -> BoxError {
    commands::invalid(message)
}

#[cfg(test)]
mod tests;
