//! `strands-box-contain-trampoline` — the process-agnostic containment trampoline
//! (docs/design/decisions.md#one-trampoline-spawns-every-contained-process).
//!
//! ```text
//! strands-box-contain-trampoline --config <containment-config.json> [--config-fd <fd>] \
//!   --config-sha256 <digest> --target-env-json <json> [--argv0 <spelling>] \
//!   [--setup-status-fd <fd>] [--relay-control-fd <fd>] -- <interp> [args...]
//! ```

use std::process::ExitCode;

// The parsed-args layer is pure and platform-independent, so it lives outside any
// `cfg` gate and is unit-tested on every target.
mod args;
use args::Args;

#[cfg(any(unix, test))]
type TargetEnvironment = std::collections::BTreeMap<String, String>;

/// Stable binary identity used by the composition layer's executable check.
#[used]
static EXECUTABLE_IDENTITY_MARKER: [u8; 72] =
    *b"STRANDS_BOX_CONTAIN_EXECUTABLE_IDENTITY_8E313B0F21A04D3BA52C4E87D493E6C2";

/// Usage text, shared by `--help` and parse errors.
const USAGE: &str = "usage: strands-box-contain-trampoline --config <containment-config.json> \
     [--config-fd <fd>] \
     --config-sha256 <64-lowercase-hex> --target-env-json <json-object> \
     [--argv0 <spelling>] [--setup-status-fd <fd>] [--relay-control-fd <fd>] \
     -- <command> [args...]\n\
     \n\
     Verifies and applies <containment-config.json>, then installs only the target\n\
     environment from <json-object> and exec-replaces itself with <command>.\n\
     Production apply supports macOS Seatbelt and, on Linux, the namespace\n\
     launcher; other platforms are refused fail-closed.\n\
     Everything after `--` is the command, verbatim.";

fn main() -> ExitCode {
    std::hint::black_box(&EXECUTABLE_IDENTITY_MARKER);

    let raw: Vec<String> = std::env::args().skip(1).collect();
    let args = match Args::parse(raw.iter().cloned()) {
        Ok(a) => a,
        Err(args::ParseError::HelpRequested) => {
            println!("{USAGE}");
            return ExitCode::from(2);
        }
        Err(args::ParseError::Invalid(msg)) => {
            eprintln!("strands-box-contain-trampoline: {msg}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    run(&args)
}

// --------------------------------------------------------------------------- Containment — unix
// only (both Seatbelt and the namespace launcher are unix).

#[cfg(not(unix))]
fn run(_args: &Args) -> ExitCode {
    eprintln!(
        "strands-box-contain-trampoline: unsupported platform — containment is macOS (Seatbelt) / \
         Linux (namespaces) only"
    );
    ExitCode::from(2)
}

#[cfg(unix)]
fn run(args: &Args) -> ExitCode {
    let setup_status = match SetupStatus::arm(args.setup_status_fd) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("strands-box-contain-trampoline: cannot arm setup status channel: {error}");
            return ExitCode::from(2);
        }
    };
    // Both the status pipe and the relay control socket must survive: the first reports a setup
    // failure, and the second is how the workload's egress listener gets back to the box.
    let preserved: Vec<libc::c_int> = [args.setup_status_fd, args.relay_control_fd, args.config_fd]
        .into_iter()
        .flatten()
        .collect();
    if let Err(error) = close_inherited_descriptors(&preserved) {
        return setup_status.fail(
            SetupStage::ConfigRead,
            2,
            format_args!("cannot close inherited descriptors: {error}"),
        );
    }
    // Phase 1: contain THIS process while single-threaded, before any `exec`.
    if let Err(code) = apply_containment(args, &setup_status) {
        return code;
    }
    // Phase 2: hand off — `exec` replaces this (now-contained) image with the
    // command, which is therefore born contained. On success this never returns.
    exec_command(args, &setup_status)
}

/// Close every inherited descriptor except the standard streams and `preserve`.
///
/// **Enumerate, then close.** A bounded loop to `getdtablesize()` issued one `close(2)` per number,
/// and the soft `RLIMIT_NOFILE` on a developer host is 1048576 — so every launch made a million
/// syscalls to close a handful of descriptors. The per-process descriptor directory names exactly what
/// is open, which is the same shape the namespace launcher's own drop uses.
///
/// The list is collected before anything is closed, because the directory handle is itself a
/// descriptor and appears in its own listing.
#[cfg(unix)]
fn close_inherited_descriptors(preserve: &[libc::c_int]) -> std::io::Result<()> {
    match open_descriptors() {
        Some(open) => {
            for descriptor in open {
                if descriptor <= libc::STDERR_FILENO || preserve.contains(&descriptor) {
                    continue;
                }
                close_ignoring_ebadf(descriptor)?;
            }
            Ok(())
        }
        // The directory is unreadable, so fall back to the bounded sweep rather than leaving a
        // descriptor open. Correct, and slow only where the fast path is unavailable.
        None => {
            let maximum = unsafe { libc::getdtablesize() };
            if maximum < 0 {
                return Err(std::io::Error::last_os_error());
            }
            for descriptor in (libc::STDERR_FILENO + 1)..maximum {
                if preserve.contains(&descriptor) {
                    continue;
                }
                close_ignoring_ebadf(descriptor)?;
            }
            Ok(())
        }
    }
}

/// Every descriptor this process holds, or `None` when the directory cannot be read.
///
/// `/dev/fd` on macOS and `/proc/self/fd` on Linux name the same thing.
#[cfg(unix)]
fn open_descriptors() -> Option<Vec<libc::c_int>> {
    let directory = if cfg!(target_os = "macos") {
        "/dev/fd"
    } else {
        "/proc/self/fd"
    };
    let entries = std::fs::read_dir(directory).ok()?;
    Some(
        entries
            .flatten()
            .filter_map(|entry| entry.file_name().to_str()?.parse::<libc::c_int>().ok())
            .collect(),
    )
}

/// Close one descriptor, treating `EBADF` as the desired state.
#[cfg(unix)]
fn close_ignoring_ebadf(descriptor: libc::c_int) -> std::io::Result<()> {
    // SAFETY: close only receives a descriptor number.
    if unsafe { libc::close(descriptor) } == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EBADF) {
            return Err(error);
        }
    }
    Ok(())
}

/// Reconstruct the request from serialized config and run one-step `apply`,
/// containing the calling process. Backend detection and selection are private.
#[cfg(unix)]
fn apply_containment(args: &Args, setup_status: &SetupStatus) -> Result<(), ExitCode> {
    use containment::{Containment, ContainmentConfig, ContainmentError};
    use sha2::{Digest as _, Sha256};

    let config_bytes = read_config(args).map_err(|error| {
        let path = args.config.display();
        let reason = match error {
            ConfigFileError::Read(error) => format!("cannot read config file {path}: {error}"),
        };
        setup_status.fail(SetupStage::ConfigRead, 2, reason)
    })?;

    // Bind the request to the exact bytes the supervisor authorized.
    let actual_digest = Sha256::digest(&config_bytes);
    if actual_digest.as_slice() != args.config_sha256 {
        return Err(setup_status.fail(
            SetupStage::ConfigValidation,
            2,
            format_args!("config digest mismatch for {}", args.config.display()),
        ));
    }

    // Reconstruct the complete config the caller serialized. Loading
    // revalidates path drift and unsafe platform-rule smuggling.
    let config_json = std::str::from_utf8(&config_bytes).map_err(|error| {
        setup_status.fail(
            SetupStage::ConfigValidation,
            2,
            format_args!("config is not valid UTF-8: {error}"),
        )
    })?;
    let config = ContainmentConfig::from_json(config_json).map_err(|error| {
        setup_status.fail(
            SetupStage::ConfigValidation,
            2,
            format_args!("cannot load config: {error}"),
        )
    })?;
    disclose_warnings(&config, &mut std::io::stderr());

    // Detection, backend selection, refusal, and apply are one unskippable operation.
    let egress_handoff = args.relay_control_fd.map(|descriptor| {
        // SAFETY: the descriptor was inherited across `exec` from the supervisor, which un-set
        // FD_CLOEXEC on exactly this number, and nothing else in this process owns it.
        std::mem::ManuallyDrop::new(unsafe {
            <std::os::unix::net::UnixStream as std::os::fd::FromRawFd>::from_raw_fd(descriptor)
        })
    });

    // An unsupported platform is a setup error (2); anything else means apply ran and refused, which
    // is incomplete containment (3).
    // Pass the setup-status writer so the Linux reaper can signal "reached exec" with one byte: a
    // long-lived leaf (a streaming MCP server) never lets the pipe EOF during its life, so the
    // supervisor cannot rely on EOF alone to know containment came up.
    Containment::apply(&config, egress_handoff.as_deref(), args.setup_status_fd).map_err(
        |error| match error {
            error @ ContainmentError::PlatformUnsupported { .. } => {
                setup_status.fail(SetupStage::Apply, 2, error)
            }
            error => setup_status.fail(SetupStage::Apply, 3, format_args!("apply failed: {error}")),
        },
    )?;
    // Enforcement is kernel-side and survives `exec`.
    Ok(())
}

/// Write each warning the configuration carries to `sink`, one line each, before it applies.
#[cfg(any(unix, test))]
fn disclose_warnings(config: &containment::ContainmentConfig, sink: &mut impl std::io::Write) {
    for warning in config.warnings() {
        // A disclosure that cannot be written must not stop the apply: stderr may be closed.
        let _ = writeln!(sink, "strands-box-contain-trampoline: warning: {warning}");
    }
}

#[cfg(unix)]
fn read_config(args: &Args) -> Result<Vec<u8>, ConfigFileError> {
    let Some(descriptor) = args.config_fd else {
        return std::fs::read(&args.config).map_err(ConfigFileError::Read);
    };
    use std::io::Read as _;
    use std::os::fd::FromRawFd as _;
    // SAFETY: the supervisor transferred ownership of this inherited descriptor.
    let mut file = unsafe { std::fs::File::from_raw_fd(descriptor) };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(ConfigFileError::Read)?;
    Ok(bytes)
}

#[cfg(any(unix, test))]
#[derive(Debug)]
enum ConfigFileError {
    Read(std::io::Error),
}

// Backend selection + platform gating live inside Containment::apply().

/// `exec`-replace this (now-contained) process with the command.
#[cfg(unix)]
fn exec_command(args: &Args, setup_status: &SetupStatus) -> ExitCode {
    use std::os::unix::process::CommandExt as _;

    // This metadata remains an inert argv string until after containment has
    // succeeded. The target receives only this explicit environment.
    let target_env = match decode_target_environment(&args.target_env_json) {
        Ok(target_env) => target_env,
        Err(error) => {
            return setup_status.fail(
                SetupStage::TargetEnvironment,
                4,
                format_args!("cannot load target environment: {error}"),
            );
        }
    };

    // The working directory, restored **after** apply and before exec.
    if let Some(directory) = target_env.get("PWD")
        && let Err(error) = std::env::set_current_dir(directory)
    {
        return setup_status.fail(
            SetupStage::Exec,
            4,
            format_args!("cannot enter the working directory {directory:?}: {error}"),
        );
    }

    let program = &args.command[0];
    let mut command = std::process::Command::new(program);
    if let Some(argv0) = &args.argv0 {
        command.arg0(argv0);
    }
    let err = command
        .args(&args.command[1..])
        .env_clear()
        .envs(target_env)
        .exec();
    // Only reached when exec failed, so the target never ran.
    setup_status.fail(
        SetupStage::Exec,
        4,
        format_args!("exec {program:?} failed: {err}"),
    )
}

/// Stable one-byte setup-failure protocol shared with the supervisor.
#[cfg(unix)]
#[repr(u8)]
#[derive(Clone, Copy)]
enum SetupStage {
    ConfigRead = 1,
    ConfigValidation = 2,
    Apply = 3,
    TargetEnvironment = 4,
    Exec = 5,
}

/// The inherited setup-status writer. It is close-on-exec before containment is
/// applied, so a successful target exec is observed by the parent as EOF.
#[cfg(unix)]
struct SetupStatus {
    descriptor: Option<libc::c_int>,
}

#[cfg(unix)]
impl SetupStatus {
    fn arm(descriptor: Option<libc::c_int>) -> std::io::Result<Self> {
        let Some(descriptor) = descriptor else {
            return Ok(Self { descriptor: None });
        };
        // SAFETY: fcntl only inspects and updates the inherited descriptor.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags == -1 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the descriptor was validated above.
        if unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            descriptor: Some(descriptor),
        })
    }

    /// Report a stage, name the failure on stderr, and answer the exit code for it.
    ///
    /// One helper, because the three steps were repeated at seven sites and a missed `report` is a
    /// boundary failure the supervisor reads as a workload exit.
    fn fail(&self, stage: SetupStage, code: u8, message: impl std::fmt::Display) -> ExitCode {
        self.report(stage);
        eprintln!("strands-box-contain-trampoline: {message}");
        ExitCode::from(code)
    }

    fn report(&self, stage: SetupStage) {
        let Some(descriptor) = self.descriptor else {
            return;
        };
        let byte = stage as u8;
        loop {
            // SAFETY: byte points to one readable byte and descriptor is the inherited status
            // writer.
            let written =
                unsafe { libc::write(descriptor, (&byte as *const u8).cast::<libc::c_void>(), 1) };
            if written == 1 {
                return;
            }
            if written == -1
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            return;
        }
    }
}

#[cfg(any(unix, test))]
fn decode_target_environment(json: &str) -> Result<TargetEnvironment, String> {
    let environment: TargetEnvironment =
        serde_json::from_str(json).map_err(|error| error.to_string())?;

    for (name, value) in &environment {
        if name.is_empty() {
            return Err("environment variable name is empty".to_owned());
        }
        if name.contains('=') {
            return Err(format!("environment variable name {name:?} contains '='"));
        }
        if name.contains('\0') {
            return Err(format!("environment variable name {name:?} contains NUL"));
        }
        if value.contains('\0') {
            return Err(format!(
                "environment variable {name:?} contains a NUL value"
            ));
        }
    }

    Ok(environment)
}

#[cfg(all(test, unix))]
mod descriptor_tests {
    use super::{close_inherited_descriptors, open_descriptors};

    /// **The fast path must actually enumerate.** An empty list closes nothing, and nothing else in
    /// the trampoline would notice: the workload would inherit every descriptor the box held open,
    /// against a stated premise. This is why the enumeration is asserted rather than assumed.
    #[test]
    fn the_descriptor_directory_names_what_is_open() {
        let open =
            open_descriptors().expect("this platform has a per-process descriptor directory");
        assert!(
            open.contains(&libc::STDERR_FILENO),
            "stderr is open, so it must appear: {open:?}"
        );
    }

    /// An inherited descriptor is closed, and a preserved one survives.
    ///
    /// **Run in a forked child**, because the function closes every descriptor this process holds —
    /// including the test harness's own. Called in-process it made a sibling test fail by closing
    /// stderr underneath it, which is also why the trampoline only ever calls it in a fresh process.
    /// Post-fork code here is syscall-only: no allocation, no panic, and `_exit` never `exit`.
    #[test]
    fn an_inherited_descriptor_is_closed_unless_preserved() {
        let mut ends = [0 as libc::c_int; 2];
        // SAFETY: `pipe` writes two descriptors into a two-element array.
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0, "create a pipe");
        let [read_end, write_end] = ends;

        // SAFETY: the child below runs syscalls only and never returns.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork");
        if child == 0 {
            let closed = close_inherited_descriptors(&[write_end]).is_ok();
            // SAFETY: `fcntl(F_GETFD)` only inspects a descriptor number.
            let read_gone = unsafe { libc::fcntl(read_end, libc::F_GETFD) } == -1;
            let write_kept = unsafe { libc::fcntl(write_end, libc::F_GETFD) } != -1;
            let code =
                i32::from(!closed) | (i32::from(!read_gone) << 1) | (i32::from(!write_kept) << 2);
            // SAFETY: `_exit` performs no cleanup, which is what a forked child must do.
            unsafe { libc::_exit(code) };
        }

        let mut status = 0;
        // SAFETY: waiting on the child this test created.
        assert!(
            unsafe { libc::waitpid(child, &mut status, 0) } == child,
            "waitpid"
        );
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        assert_eq!(
            code, 0,
            "bit 0 = closing failed, bit 1 = an unpreserved descriptor survived, \
             bit 2 = the preserved descriptor was closed"
        );

        // SAFETY: closing the two descriptors this process still owns.
        unsafe {
            libc::close(read_end);
            libc::close(write_end);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::fd::IntoRawFd as _;

    use super::{Args, decode_target_environment, disclose_warnings, read_config};

    /// The one warning the floors carry reaches stderr before apply, and a disjoint pair says nothing.
    #[test]
    fn a_write_plus_exec_pair_is_disclosed_before_apply_and_a_disjoint_pair_is_not() {
        use containment::{ContainmentConfig, Operation, Scope};

        let directory = tempfile::tempdir().expect("a directory");
        let root = directory
            .path()
            .canonicalize()
            .expect("a canonical directory");
        let workspace = root.join("workspace");
        std::fs::create_dir(&workspace).expect("a write root");
        let built = workspace.join("built");
        std::fs::write(&built, "built").expect("a program inside it");
        let beside = root.join("agent");
        std::fs::write(&beside, "agent").expect("a program beside it");

        let pair = ContainmentConfig::new()
            .allow(&built, Operation::Exec, Scope::File)
            .expect("the exec grant")
            .allow(&workspace, Operation::Write, Scope::Root)
            .expect("the write root that reaches it");
        let mut disclosed = Vec::new();
        disclose_warnings(&pair, &mut disclosed);
        let text = String::from_utf8(disclosed).expect("UTF-8");
        assert_eq!(text.lines().count(), 1, "one pair, one line: {text}");
        assert!(
            text.starts_with("strands-box-contain-trampoline: warning: ")
                && text.contains("both writable and executable")
                && text.contains(&built.display().to_string()),
            "the line names the tool, the pair, and the path: {text}"
        );

        let disjoint = ContainmentConfig::new()
            .allow(&beside, Operation::Exec, Scope::File)
            .expect("the exec grant")
            .allow(&workspace, Operation::Write, Scope::Root)
            .expect("a write root beside it");
        let mut silent = Vec::new();
        disclose_warnings(&disjoint, &mut silent);
        assert!(silent.is_empty(), "a disjoint pair discloses nothing");
    }

    #[test]
    fn config_load_returns_exact_bytes_and_keeps_the_caller_owned_file() {
        let dir = tempfile::tempdir().expect("config directory");
        let path = dir.path().join("containment-config.json");
        let expected = b"\x00exact config bytes\xff";
        std::fs::write(&path, expected).expect("write config");
        let args = Args {
            config: path.clone(),
            config_fd: None,
            config_sha256: [0; 32],
            target_env_json: "{}".to_string(),
            setup_status_fd: None,
            relay_control_fd: None,
            command: vec!["true".to_string()],
            argv0: None,
        };

        assert_eq!(read_config(&args).expect("path config reads"), expected);
        assert_eq!(std::fs::read(path).expect("config remains"), expected);
    }

    #[test]
    fn inherited_config_read_uses_the_opened_file_after_a_path_swap() {
        let directory = tempfile::tempdir().expect("config directory");
        let path = directory.path().join("containment.json");
        std::fs::write(&path, b"opened").expect("opened config");
        let descriptor = std::fs::File::open(&path)
            .expect("config descriptor")
            .into_raw_fd();
        std::fs::remove_file(&path).expect("remove opened name");
        std::fs::write(&path, b"replacement").expect("replacement config");
        let args = Args {
            config: path.clone(),
            config_fd: Some(descriptor),
            config_sha256: [0; 32],
            target_env_json: "{}".to_string(),
            setup_status_fd: None,
            relay_control_fd: None,
            command: vec!["true".to_string()],
            argv0: None,
        };

        assert_eq!(read_config(&args).expect("descriptor reads"), b"opened");
        assert_eq!(
            std::fs::read(path).expect("replacement remains"),
            b"replacement"
        );
    }

    #[test]
    fn target_environment_decode_preserves_exact_entries() {
        let json = r#"{"EMPTY":"","EQUALS":"left=right","UNICODE":"Grüße"}"#;
        let expected = BTreeMap::from([
            ("EMPTY".to_owned(), String::new()),
            ("EQUALS".to_owned(), "left=right".to_owned()),
            ("UNICODE".to_owned(), "Grüße".to_owned()),
        ]);

        assert_eq!(
            decode_target_environment(json).expect("valid target environment"),
            expected
        );
    }

    #[test]
    fn target_environment_decode_rejects_empty_name() {
        let error = decode_target_environment(r#"{"":"value"}"#).expect_err("invalid name");

        assert!(error.contains("name is empty"));
    }

    #[test]
    fn target_environment_decode_rejects_equals_in_name() {
        let error =
            decode_target_environment(r#"{"INVALID=NAME":"value"}"#).expect_err("invalid name");

        assert!(error.contains("name \"INVALID=NAME\" contains '='"));
    }

    #[test]
    fn target_environment_decode_rejects_nul_in_name() {
        let error = decode_target_environment(r#"{"INVALID\u0000NAME":"value"}"#)
            .expect_err("invalid name");

        assert!(error.contains("name \"INVALID\\0NAME\" contains NUL"));
    }

    #[test]
    fn target_environment_decode_rejects_nul_in_value() {
        let error = decode_target_environment(r#"{"NAME":"invalid\u0000value"}"#)
            .expect_err("invalid value");

        assert!(error.contains("variable \"NAME\" contains a NUL value"));
    }

    #[test]
    fn target_environment_decode_rejects_malformed_json() {
        assert!(decode_target_environment(r#"{"NAME":"value""#).is_err());
    }
}
