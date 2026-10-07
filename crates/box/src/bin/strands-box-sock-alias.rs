//! The socket alias: what the contained workload execs when it believes it is running
//! `zsh` or `python3`.

// Included by path rather than through a `lib.rs` façade, because the crate is `[[bin]]`-only by
// choice and a library surface is a separate decision with its own stability obligations.
#[path = "../run/broker/protocol.rs"]
mod shell_protocol;

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use shell_protocol::{
    BOUNDARY_FAILURE_STATUS, Body, Frame, Interpreter, MAX_FRAME_BYTES, PROTOCOL_VERSION, Stream,
    decode_payload, encode_payload, read_frame, write_frame,
};
use tokio::net::UnixStream;

/// The exit status for any failure of this process itself.
const SHELL_FAILURE_EXIT: u8 = BOUNDARY_FAILURE_STATUS as u8;

/// The shim name, which lives only in the box's private tree.
const ALIAS_IMAGE_NAME: &str = "strands-box-sock-alias";

/// The socket's path relative to the alias's grandparent directory. The routing lists come from the
/// module this binary already includes, so there is one definition rather than a copy per consumer.
use shell_protocol::{BROKER_SOCKET_RELATIVE, PYTHON_ALIAS_NAMES, SHELL_ALIAS_NAMES};

/// The largest positional script the alias will forward as command text.
const MAX_SCRIPT_BYTES: usize = MAX_FRAME_BYTES / 16;

/// Bound on one framed read or write against the daemon's Shell socket.
const SERVE_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on waiting for the daemon's Shell to answer.
const SERVE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(35);

/// One forwarded submission: which interpreter, and the program text for it.
#[derive(Debug)]
struct Mode {
    socket: PathBuf,
    interpreter: Interpreter,
    source: String,
}

fn main() -> ExitCode {
    if let Err(error) = close_inherited_descriptors() {
        eprintln!("strands-box-sock-alias: close inherited descriptors: {error}");
        return ExitCode::from(SHELL_FAILURE_EXIT);
    }
    // Current-thread: this image hosts no Shell, so a multi-threaded runtime would spawn worker
    // threads for a process whose whole job is one round trip.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("strands-box-sock-alias: create async runtime: {error}");
            return ExitCode::from(SHELL_FAILURE_EXIT);
        }
    };
    match runtime.block_on(run()) {
        Ok(status) => ExitCode::from(shell_status(status)),
        Err(error) => {
            eprintln!("strands-box-sock-alias: {error}");
            ExitCode::from(SHELL_FAILURE_EXIT)
        }
    }
}

/// Close every descriptor above stdio before doing anything else.
#[cfg(unix)]
fn close_inherited_descriptors() -> io::Result<()> {
    let maximum = unsafe { libc::getdtablesize() };
    if maximum < 0 {
        return Err(io::Error::last_os_error());
    }
    for descriptor in (libc::STDERR_FILENO + 1)..maximum {
        // SAFETY: close only receives a descriptor number. EBADF means the
        // descriptor was already closed, which is the desired state.
        if unsafe { libc::close(descriptor) } == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EBADF) {
                return Err(error);
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn close_inherited_descriptors() -> io::Result<()> {
    Ok(())
}

async fn run() -> io::Result<i32> {
    let Mode {
        socket,
        interpreter,
        source,
    } = parse_mode(
        std::env::current_exe()?,
        std::env::args_os().skip(1).collect(),
    )?;
    forward(&socket, interpreter, source).await
}

/// Parse the alias invocation, refusing this image's own name.
fn parse_mode(executable: PathBuf, arguments: Vec<OsString>) -> io::Result<Mode> {
    let name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid_input("executable name is not valid UTF-8"))?;
    if name == ALIAS_IMAGE_NAME {
        return Err(invalid_input(format!(
            "{ALIAS_IMAGE_NAME} is not an alias name; the trusted strands-box run process serves broker requests"
        )));
    }
    parse_alias(&executable, name, arguments)
}

/// Parse the alias invocation, deriving the socket from this image's own path.
fn parse_alias(executable: &Path, name: &str, arguments: Vec<OsString>) -> io::Result<Mode> {
    if PYTHON_ALIAS_NAMES.contains(&name) {
        return parse_script_alias(executable, arguments);
    }
    // A name that is neither a shell nor a Python alias is an MCP server name. The box places one
    // alias per declared server and no others, and `PATH` holds only this box's `bin/`, so the only
    if !SHELL_ALIAS_NAMES.contains(&name) {
        return Ok(Mode {
            socket: socket_beside(
                executable
                    .parent()
                    .and_then(Path::parent)
                    .ok_or_else(|| invalid_input("MCP alias is not inside a bin directory"))?,
                &BROKER_SOCKET_RELATIVE,
            ),
            interpreter: Interpreter::Mcp {
                server: name.to_string(),
            },
            // An MCP server takes no program text: it is a stream, and the client's own frames are
            // the traffic. `forward` sends no `Call` for this interpreter.
            source: String::new(),
        });
    }
    let usage = "Shell alias accepts only -c COMMAND, -lc COMMAND, -c -l COMMAND, or SCRIPT";
    // `-c` and `-l` are accepted as *separate* arguments, because Claude Code invokes a shell as
    // `execFile(shell, ["-c", "-l", command])`, hardcoded with no environment override, and a real
    let arguments = match <[OsString; 3]>::try_from(arguments) {
        Ok([first, second, command]) => {
            let flags = [&first, &second];
            if !flags.iter().all(|flag| *flag == "-c" || *flag == "-l")
                || !flags.iter().any(|flag| *flag == "-c")
            {
                return Err(invalid_input(usage));
            }
            return shell_mode(executable, command);
        }
        Err(arguments) => arguments,
    };
    let command = match <[OsString; 2]>::try_from(arguments) {
        Ok([flag, command]) => {
            if flag != "-c" && flag != "-lc" {
                return Err(invalid_input(usage));
            }
            command
                .into_string()
                .map_err(|_| invalid_input("Shell command is not valid UTF-8"))?
        }
        // Exactly one argument, and it must not look like a flag: `zsh -i` is an interactive shell
        // this cannot serve, and reading a file named `-i` would be a confusing way to say so.
        Err(arguments) => {
            let [script] =
                <[OsString; 1]>::try_from(arguments).map_err(|_| invalid_input(usage))?;
            let script = PathBuf::from(script);
            if script.to_string_lossy().starts_with('-') {
                return Err(invalid_input(usage));
            }
            read_script(&script)?
        }
    };
    shell_mode(executable, OsString::from(command))
}

/// One shell submission, with the socket derived from this image's own path.
fn shell_mode(executable: &Path, command: OsString) -> io::Result<Mode> {
    let command = command
        .into_string()
        .map_err(|_| invalid_input("Shell command is not valid UTF-8"))?;
    let workload_root = executable
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| invalid_input("Shell alias is not inside a bin directory"))?;
    Ok(Mode {
        socket: socket_beside(workload_root, &BROKER_SOCKET_RELATIVE),
        interpreter: Interpreter::Shell,
        source: command,
    })
}

/// Parse a `python3`/`python` invocation into one script submission.
fn parse_script_alias(executable: &Path, arguments: Vec<OsString>) -> io::Result<Mode> {
    let usage = "Python alias accepts only -c SOURCE or SCRIPT";
    // No origin label crosses the wire: the broker labels a traceback itself, because a label the
    // workload chooses is not something the daemon should echo into its own diagnostics.
    let source = match <[OsString; 2]>::try_from(arguments) {
        Ok([flag, source]) => {
            if flag != "-c" {
                return Err(invalid_input(usage));
            }
            source
                .into_string()
                .map_err(|_| invalid_input("Python source is not valid UTF-8"))?
        }
        Err(arguments) => {
            let [script] =
                <[OsString; 1]>::try_from(arguments).map_err(|_| invalid_input(usage))?;
            let script = PathBuf::from(script);
            // A leading `-` is a flag this alias does not implement, and reading a file named `-i`
            // would be a confusing way to say so.
            if script.to_string_lossy().starts_with('-') {
                return Err(invalid_input(usage));
            }
            read_script(&script)?
        }
    };
    let workload_root = executable
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| invalid_input("Python alias is not inside a bin directory"))?;
    Ok(Mode {
        socket: socket_beside(workload_root, &BROKER_SOCKET_RELATIVE),
        interpreter: Interpreter::Python,
        source,
    })
}

/// Pump one MCP server's traffic: stdin to the box, the box's output to stdout.
async fn stream_mcp(mut stream: UnixStream, interpreter: Interpreter) -> io::Result<i32> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    write_frame(
        &mut stream,
        &Frame {
            version: PROTOCOL_VERSION,
            program: ALIAS_PROGRAM,
            body: Body::Open { mode: interpreter },
        },
    )
    .await?;

    let (mut readable, mut writable) = stream.into_split();

    // stdin -> the box. Its own task, because the two directions are independent: a client may send
    // a request while a previous answer is still arriving.
    let inbound = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buffer = [0_u8; 8192];
        loop {
            let read = match stdin.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            let frame = Frame {
                version: PROTOCOL_VERSION,
                program: ALIAS_PROGRAM,
                body: Body::Input {
                    data: encode_payload(&buffer[..read]),
                },
            };
            if write_frame(&mut writable, &frame).await.is_err() {
                return;
            }
        }
        let _ = write_frame(
            &mut writable,
            &Frame {
                version: PROTOCOL_VERSION,
                program: ALIAS_PROGRAM,
                body: Body::InputEof,
            },
        )
        .await;
    });

    // The box -> stdout.
    let mut stdout = tokio::io::stdout();
    let mut status = 0;
    loop {
        let frame = match read_frame::<Frame, _>(&mut readable).await {
            Ok(Some(frame)) => frame,
            // The box closed the connection, which is how a session ends.
            Ok(None) | Err(_) => break,
        };
        match frame.body {
            Body::Output { data, .. } => {
                let bytes = decode_payload(&data)?;
                stdout.write_all(&bytes).await?;
                stdout.flush().await?;
            }
            // A refusal is a failure exit and is terminal. Printing the reason and looping left
            // `status` at 0, so a refused MCP server closed the connection and the alias exited
            Body::Denied { reason, .. } => {
                eprintln!("strands-box: {reason}");
                return Ok(i32::from(SHELL_FAILURE_EXIT));
            }
            Body::Exit { status: reported } => {
                status = reported;
                break;
            }
            _ => {}
        }
    }
    inbound.abort();
    Ok(status)
}

/// Derive a socket path from the alias's grandparent, never from an argument.
fn socket_beside(workload_root: &Path, relative: &[&str; 2]) -> PathBuf {
    relative
        .iter()
        .fold(workload_root.to_path_buf(), |path, part| path.join(part))
}

/// Read a positional script into the command text the shim will judge and run.
fn read_script(script: &Path) -> io::Result<String> {
    let text = std::fs::read_to_string(script).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("read Shell script {}: {error}", script.display()),
        )
    })?;
    if text.len() > MAX_SCRIPT_BYTES {
        return Err(invalid_input(format!(
            "Shell script {} is {} bytes; maximum is {MAX_SCRIPT_BYTES}",
            script.display(),
            text.len()
        )));
    }
    Ok(text)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Alias: forward one command, relay one result, never fall back.

/// The one Program an alias opens.
const ALIAS_PROGRAM: u32 = 1;

/// Submit one Call to one Program and reproduce its result locally.
async fn forward(socket: &Path, interpreter: Interpreter, source: String) -> io::Result<i32> {
    let mut stream = tokio::time::timeout(SERVE_IO_TIMEOUT, UnixStream::connect(socket))
        .await
        .map_err(|_| timed_out("connect to the box broker"))?
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("connect to the box broker {}: {error}", socket.display()),
            )
        })?;

    // An MCP server is a stream, not a submission: it gets `Open` and then this alias pumps stdin
    // frames for as long as the client speaks.
    if let Interpreter::Mcp { .. } = &interpreter {
        return stream_mcp(stream, interpreter).await;
    }

    // `InputEof` immediately after the Call, because this alias forwards no input: a harness
    // invoking `zsh -c` gives the command nothing on stdin, and without the EOF the Program's stdin
    for body in [
        Body::Open { mode: interpreter },
        Body::Call {
            source,
            correlation: Box::new(call_correlation()),
        },
        Body::InputEof,
    ] {
        tokio::time::timeout(
            SERVE_IO_TIMEOUT,
            write_frame(
                &mut stream,
                &Frame {
                    version: PROTOCOL_VERSION,
                    program: ALIAS_PROGRAM,
                    body,
                },
            ),
        )
        .await
        .map_err(|_| timed_out("write a transport frame"))??;
    }

    // Relayed as it arrives rather than accumulated, so a long-running command is observable
    // while it runs.
    loop {
        let frame =
            tokio::time::timeout(SERVE_RESPONSE_TIMEOUT, read_frame::<Frame, _>(&mut stream))
                .await
                .map_err(|_| timed_out("read a transport frame"))??
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "the box broker closed")
                })?;
        match frame.body {
            Body::Output {
                stream: which,
                data,
            } => {
                use std::io::Write as _;
                let bytes = decode_payload(&data)?;
                // Flushed per chunk, not at exit.
                match which {
                    Stream::Stdout => {
                        let mut out = std::io::stdout();
                        out.write_all(&bytes)?;
                        out.flush()?;
                    }
                    Stream::Stderr => {
                        let mut err = std::io::stderr();
                        err.write_all(&bytes)?;
                        err.flush()?;
                    }
                }
            }
            Body::Exit { status } => return Ok(status),
            // A transport refusal, including a version mismatch. Terminal, and reported as the
            // boundary's own failure rather than as something the program did.
            Body::Denied { reason, .. } => {
                eprintln!("strands-box: {reason}");
                return Ok(i32::from(SHELL_FAILURE_EXIT));
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("the box broker sent a client frame: {other:?}"),
                ));
            }
        }
    }
}

/// One Call's correlation, read from `TRACEPARENT` and `TRACESTATE` and from no other variable.
fn call_correlation() -> telemetry::Correlation {
    let value = |name: &str| std::env::var(name).ok();
    telemetry::Correlation::from_headers(
        value("TRACEPARENT").as_deref(),
        value("TRACESTATE").as_deref(),
    )
}

/// Narrow a Shell status to a process exit code.
fn shell_status(status: i32) -> u8 {
    u8::try_from(status).unwrap_or(SHELL_FAILURE_EXIT)
}

/// A refusal an operator reads, for input this alias will not forward.
fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn timed_out(operation: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("{operation} timed out"))
}

#[cfg(test)]
mod tests {
    // REMOVED: `the_python_alias_names_match_the_layouts`.

    use super::*;

    /// **The alias names no harness, and it reads no vendor variable.** `TRACEPARENT` and
    /// `TRACESTATE` are the only two names this image knows, because every harness spells those the
    /// same way.
    #[test]
    fn the_alias_reads_the_standard_trace_headers_and_names_no_harness() {
        let source = include_str!("strands-box-sock-alias.rs");
        let body = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(body, _)| body);
        for harness in ["CODEX_", "CLAUDE_", "STRANDS_AGENT"] {
            assert!(
                !body.contains(harness),
                "the alias must name no harness, but it names {harness}"
            );
        }
        // The alias declares no conversation variable of its own, so no environment name selects one.
        assert!(
            !body.contains("CONVERSATION"),
            "the alias must not read a declared conversation variable"
        );
        for header in ["TRACEPARENT", "TRACESTATE"] {
            assert!(
                body.contains(header),
                "the alias must read the standard header {header}"
            );
        }
    }

    /// The alias derives its socket from its own path, under both login and
    /// non-login spellings. `public/bin/zsh` → `public/run/box.sock`.
    #[test]
    fn the_alias_derives_its_socket_from_its_own_path() {
        for flag in ["-c", "-lc"] {
            let mode = parse_mode(
                PathBuf::from("/private/scaffold/public/bin/zsh"),
                vec![OsString::from(flag), OsString::from("printf ok")],
            )
            .unwrap();
            let Mode {
                socket,
                source: command,
                ..
            } = mode;
            assert_eq!(
                socket,
                PathBuf::from("/private/scaffold/public/run/box.sock")
            );
            assert_eq!(command, "printf ok");
        }
    }

    /// A positional script becomes the command text, not a path the shim would open.
    #[test]
    fn a_positional_script_is_forwarded_as_its_contents() {
        let script = std::env::temp_dir().join(format!("shim-script-{}.sh", std::process::id()));
        std::fs::write(&script, "printf ok\n").unwrap();

        let mode = parse_mode(
            PathBuf::from("/private/scaffold/public/bin/zsh"),
            vec![script.clone().into_os_string()],
        )
        .expect("a bare script is a valid alias invocation");

        let Mode {
            socket,
            source: command,
            ..
        } = mode;
        assert_eq!(
            command, "printf ok\n",
            "the shim must receive the script's text, not its path"
        );
        assert_eq!(
            socket,
            PathBuf::from("/private/scaffold/public/run/box.sock"),
            "the socket is still derived from the image, never from the argument"
        );
        let _ = std::fs::remove_file(&script);
    }

    /// An absent script is refused here, with the script named.
    #[test]
    fn an_unreadable_script_is_refused_before_any_request_is_sent() {
        let error = parse_mode(
            PathBuf::from("/private/scaffold/public/bin/zsh"),
            vec![OsString::from("/nonexistent/attacker.sh")],
        )
        .expect_err("a script that cannot be read must not become an empty command");

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(
            error.to_string().contains("/nonexistent/attacker.sh"),
            "the refusal must name the script: {error}"
        );
    }

    /// A script larger than the frame budget is refused by size, not by frame error.
    #[test]
    fn an_oversized_script_is_refused_by_size() {
        let script = std::env::temp_dir().join(format!("shim-big-{}.sh", std::process::id()));
        std::fs::write(&script, "x".repeat(MAX_SCRIPT_BYTES + 1)).unwrap();

        let error = parse_mode(
            PathBuf::from("/private/scaffold/public/bin/zsh"),
            vec![script.clone().into_os_string()],
        )
        .expect_err("an oversized script must be refused");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("maximum"),
            "the refusal must state the limit: {error}"
        );
        let _ = std::fs::remove_file(&script);
    }

    /// `-c` and `-l` split across two arguments is the same submission as `-lc`. This is the
    /// spelling Claude Code uses. Either order, because a shell accepts either.
    #[test]
    fn the_alias_accepts_c_and_l_as_separate_flags() {
        for flags in [["-c", "-l"], ["-l", "-c"]] {
            let mode = parse_mode(
                PathBuf::from("/private/scaffold/public/bin/zsh"),
                vec![
                    OsString::from(flags[0]),
                    OsString::from(flags[1]),
                    OsString::from("printf ok"),
                ],
            )
            .expect("the split-flag form is a shell submission");
            assert_eq!(
                mode.socket,
                PathBuf::from("/private/scaffold/public/run/box.sock"),
                "the socket must still come from the image's own path"
            );
            assert_eq!(mode.source, "printf ok");
            assert!(matches!(mode.interpreter, Interpreter::Shell));
        }
    }

    /// Three arguments are accepted only when the first two are both flags, so the split-flag form
    /// never becomes a third argument slot. Without the `any(-c)` condition, `-l -l COMMAND` would
    /// run a command no `-c` asked for.
    #[test]
    fn a_three_argument_form_that_is_not_two_flags_is_refused() {
        for arguments in [
            vec!["-c", "printf ok", "/tmp/attacker.sock"],
            vec!["-l", "printf ok", "/tmp/attacker.sock"],
            vec!["-c", "-i", "printf ok"],
            vec!["-l", "-l", "printf ok"],
            vec!["-c", "--serve", "printf ok"],
        ] {
            let error = parse_mode(
                PathBuf::from("/private/scaffold/public/bin/zsh"),
                arguments.iter().map(OsString::from).collect(),
            )
            .expect_err("only two recognized flags may precede the command");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(
                error.to_string().contains("accepts only"),
                "the refusal must state what is accepted: {error}"
            );
        }
    }

    /// A flag-shaped lone argument is refused rather than read as a filename.
    #[test]
    fn a_lone_flag_is_not_treated_as_a_script() {
        for flag in ["-i", "-s", "--login", "-"] {
            let error = parse_mode(
                PathBuf::from("/private/scaffold/public/bin/zsh"),
                vec![OsString::from(flag)],
            )
            .expect_err("{flag} must be refused rather than opened as a file");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(
                error.to_string().contains("accepts only"),
                "the refusal must state what is accepted: {error}"
            );
        }
    }

    /// The alias cannot be talked into serve mode.
    #[test]
    fn the_alias_cannot_become_a_shim() {
        let error = parse_mode(
            PathBuf::from("/private/scaffold/public/bin/zsh"),
            vec![
                OsString::from("--serve"),
                OsString::from("/tmp/attacker.sock"),
                OsString::from("/tmp/workspace"),
            ],
        )
        .expect_err("the alias name must never select serve mode");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    /// The alias accepts no socket argument at any position, so the workload
    /// cannot aim its requests at a serving shim it controls.
    #[test]
    fn the_alias_accepts_no_socket_argument() {
        for arguments in [
            vec!["-c", "printf ok", "/tmp/attacker.sock"],
            vec!["--socket", "/tmp/attacker.sock", "-c", "printf ok"],
            vec!["-c"],
            vec![],
        ] {
            let error = parse_mode(
                PathBuf::from("/private/scaffold/public/bin/zsh"),
                arguments.iter().map(OsString::from).collect(),
            )
            .expect_err("only -c/-lc COMMAND is accepted");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    /// A shell name routes to the Shell, and a name outside all three lists is an MCP server.
    #[test]
    fn a_shell_name_routes_to_the_shell_and_any_other_name_is_an_mcp_server() {
        for name in ["bash", "zsh", "sh"] {
            let mode = parse_mode(
                PathBuf::from(format!("/private/run/public/bin/{name}")),
                vec![OsString::from("-c"), OsString::from("printf ok")],
            )
            .unwrap_or_else(|error| panic!("{name} must be accepted as the alias: {error}"));
            let Mode {
                socket,
                source: command,
                ..
            } = mode;
            assert_eq!(socket, PathBuf::from("/private/run/public/run/box.sock"));
            assert_eq!(command, "printf ok");
        }

        // A name in neither list is an MCP server, named for the alias the box placed. It takes no
        // program text: the client's own frames are the traffic.
        for name in ["issues-mcp", "aws-mcp", "fish"] {
            let mode = parse_mode(
                PathBuf::from(format!("/private/run/public/bin/{name}")),
                Vec::new(),
            )
            .unwrap_or_else(|error| panic!("{name} must select an MCP server: {error}"));
            assert_eq!(
                mode.interpreter,
                Interpreter::Mcp {
                    server: name.to_string()
                },
                "a name outside the shell and Python lists selects an MCP server"
            );
            assert_eq!(
                mode.socket,
                PathBuf::from("/private/run/public/run/box.sock"),
                "the socket is still derived from the image's own path"
            );
            assert!(
                mode.source.is_empty(),
                "an MCP server takes no program text"
            );
        }
    }

    /// This image cannot be made to serve, by name or by flag.
    #[test]
    fn the_shim_name_is_refused_rather_than_served() {
        let error = parse_mode(
            PathBuf::from("/opt/strands/strands-box-sock-alias"),
            ["--serve", "/run/box.sock", "/workspace"]
                .iter()
                .map(OsString::from)
                .collect(),
        )
        .expect_err("the shim's own name is not an alias name");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("the trusted strands-box run process serves broker requests"),
            "the refusal must say where the brokers actually live: {error}"
        );
    }

    /// `--serve` and `--policy` are not arguments this image understands.
    #[test]
    fn serving_flags_are_treated_as_a_script_not_a_role() {
        let mode = parse_mode(
            PathBuf::from("/private/scaffold/public/bin/zsh"),
            ["--serve", "/private/scaffold/public/run/box.sock"]
                .iter()
                .map(OsString::from)
                .collect(),
        );
        // `Mode` has no serving variant, so no flag can select one. What this test *can* check is
        // that `--serve` is ordinary argument text and the socket is still derived.
        match mode {
            Ok(Mode {
                socket,
                interpreter: Interpreter::Shell,
                ..
            }) => assert!(
                socket.ends_with("run/box.sock"),
                "the socket must be derived from the image's own path, never from an \
                 argument: {socket:?}"
            ),
            Ok(Mode {
                socket,
                interpreter: Interpreter::Python,
                ..
            }) => {
                panic!("a shell name must not route to the script boundary: {socket:?}")
            }
            Ok(Mode {
                socket,
                interpreter: Interpreter::Mcp { server },
                ..
            }) => {
                panic!("a shell name must not route to an MCP server {server:?}: {socket:?}")
            }
            Err(_) => {}
        }
    }

    // ── Fail-closed exit status ───────────────────────────────────────────────

    /// A status outside `u8` fails closed rather than wrapping, so a truncated value is never
    /// reported as success.
    #[test]
    fn an_out_of_range_shell_status_fails_closed() {
        assert_eq!(shell_status(-1), SHELL_FAILURE_EXIT);
        assert_eq!(shell_status(256), SHELL_FAILURE_EXIT);
        // 0 must survive: a real success has to stay distinguishable.
        assert_eq!(shell_status(0), 0);
        assert_eq!(shell_status(126), 126);
    }
}
