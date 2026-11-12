//! The socket alias: what the contained workload execs when it believes it is running
//! `zsh` or `python3`. Each sends its command and the caller's working directory to the Shell.

// Included by path rather than through a `lib.rs` façade, because the crate is `[[bin]]`-only by
// choice and a library surface is a separate decision with its own stability obligations.
#[path = "../run/broker/protocol.rs"]
mod shell_protocol;

#[path = "alias/fallback.rs"]
mod fallback;

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use shell_protocol::{
    BOUNDARY_FAILURE_STATUS, Body, Command, Frame, Interpreter, MAX_FRAME_BYTES, PROTOCOL_VERSION,
    Stream, decode_payload, encode_payload, read_frame, write_frame,
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

const MCP_OPEN_TIMEOUT: Duration = Duration::from_secs(60);

enum Outcome {
    Status(i32),
    Fallback {
        program: String,
        arguments: Vec<String>,
    },
}

/// One forwarded submission: which interpreter, and the command for it.
#[derive(Debug)]
struct Mode {
    socket: PathBuf,
    interpreter: Interpreter,
    /// What the Shell runs. `None` for an MCP server, whose client's own frames are the traffic.
    command: Option<Command>,
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
    let outcome = runtime.block_on(run());
    drop(runtime);
    match outcome {
        Ok(Outcome::Status(status)) => ExitCode::from(shell_status(status)),
        Ok(Outcome::Fallback { program, arguments }) => {
            match fallback::execute(&program, &arguments) {
                Ok(status) => ExitCode::from(status),
                Err(error) => {
                    eprintln!("strands-box-sock-alias: {error}");
                    ExitCode::from(SHELL_FAILURE_EXIT)
                }
            }
        }
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

async fn run() -> io::Result<Outcome> {
    let Mode {
        socket,
        interpreter,
        command,
    } = parse_mode(
        std::env::current_exe()?,
        std::env::args_os().skip(1).collect(),
    )?;
    let Some(command) = command else {
        // An MCP server is a stream, not a submission: it gets `Open` and then this alias pumps
        // stdin frames for as long as the client speaks.
        return stream_mcp(connect(&socket).await?, interpreter).await;
    };
    let directory = working_directory(
        identity(Path::new(".")),
        std::env::var_os("PWD").map(PathBuf::from),
        std::env::current_dir(),
    )?;
    forward(connect(&socket).await?, command, directory).await
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
        return python_mode(executable, name, arguments);
    }
    // Any other name is an MCP server's program.
    if !SHELL_ALIAS_NAMES.contains(&name) {
        let arguments = arguments
            .into_iter()
            .enumerate()
            .map(|(index, argument)| {
                argument.into_string().map_err(|_| {
                    invalid_input(format!(
                        "MCP server argument {} is not valid UTF-8",
                        index + 1
                    ))
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
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
                arguments,
            },
            command: None,
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
        command: Some(Command::Text(command)),
    })
}

/// One `python3`/`python` invocation, sent to the Shell as its name and its arguments unchanged.
///
/// The Shell's own `python3` reads the options and the script, and refuses a form it can't run, so
/// this alias parses no option and reads no file.
fn python_mode(executable: &Path, name: &str, arguments: Vec<OsString>) -> io::Result<Mode> {
    let arguments = arguments
        .into_iter()
        .enumerate()
        .map(|(index, argument)| {
            argument.into_string().map_err(|_| {
                invalid_input(format!("Python argument {} is not valid UTF-8", index + 1))
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let workload_root = executable
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| invalid_input("Python alias is not inside a bin directory"))?;
    Ok(Mode {
        socket: socket_beside(workload_root, &BROKER_SOCKET_RELATIVE),
        interpreter: Interpreter::Shell,
        command: Some(Command::Words {
            name: name.to_string(),
            arguments,
        }),
    })
}

/// The `(device, inode)` that names `path`'s directory.
fn identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;

    std::fs::metadata(path)
        .ok()
        .map(|metadata| (metadata.dev(), metadata.ino()))
}

/// The caller's working directory, from the first source that names it.
///
/// `PWD` counts only when it is absolute and names the same directory as `.`, because a harness that
/// starts a child in another directory often leaves `PWD` unchanged. Then `getcwd`. On macOS a
/// process that may only enter its directory can't read that directory's path, so `getcwd` can fail;
/// then the alias refuses, because running the command in another directory is a silent wrong
/// answer.
fn working_directory(
    here: Option<(u64, u64)>,
    pwd: Option<PathBuf>,
    getcwd: io::Result<PathBuf>,
) -> io::Result<String> {
    let directory = match pwd {
        Some(pwd) if pwd.is_absolute() && here.is_some() && identity(&pwd) == here => pwd,
        _ => match getcwd {
            Ok(directory) if directory.is_absolute() => directory,
            Ok(directory) => {
                return Err(invalid_input(format!(
                    "the working directory {} is not an absolute path; set PWD to it",
                    directory.display()
                )));
            }
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("read the working directory: {error}; set PWD to it"),
                ));
            }
        },
    };
    directory
        .into_os_string()
        .into_string()
        .map_err(|_| invalid_input("the working directory is not valid UTF-8"))
}

/// Pump one MCP server's traffic: stdin to the box, the box's output to stdout.
async fn stream_mcp(mut stream: UnixStream, interpreter: Interpreter) -> io::Result<Outcome> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    write_frame(
        &mut stream,
        &Frame {
            version: PROTOCOL_VERSION,
            program: ALIAS_PROGRAM,
            body: Body::Open {
                mode: interpreter.clone(),
            },
        },
    )
    .await?;

    match mcp_response(&mut stream).await?.body {
        Body::McpReady => {}
        Body::McpUnmatched => {
            let Interpreter::Mcp { server, arguments } = interpreter else {
                return Err(invalid_input(
                    "ordinary fallback requires an MCP invocation",
                ));
            };
            return Ok(Outcome::Fallback {
                program: server,
                arguments,
            });
        }
        Body::Denied { reason, .. } => {
            eprintln!("strands-box: {reason}");
            return Ok(Outcome::Status(i32::from(SHELL_FAILURE_EXIT)));
        }
        other => {
            return Err(invalid_input(format!(
                "unexpected MCP routing response: {other:?}"
            )));
        }
    }

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

    let outcome = async {
        let mut stdout = tokio::io::stdout();
        loop {
            let frame = match read_frame::<Frame, _>(&mut readable).await {
                Ok(Some(frame)) => frame,
                Ok(None) | Err(_) => return Ok(Outcome::Status(0)),
            };
            validate_mcp_frame(&frame)?;
            match frame.body {
                Body::Output { data, .. } => {
                    let bytes = decode_payload(&data)?;
                    stdout.write_all(&bytes).await?;
                    stdout.flush().await?;
                }
                Body::Denied { reason, .. } => {
                    eprintln!("strands-box: {reason}");
                    return Ok(Outcome::Status(i32::from(SHELL_FAILURE_EXIT)));
                }
                Body::Exit { status } => return Ok(Outcome::Status(status)),
                _ => {}
            }
        }
    }
    .await;
    inbound.abort();
    outcome
}

async fn mcp_response(stream: &mut UnixStream) -> io::Result<Frame> {
    let frame = tokio::time::timeout(MCP_OPEN_TIMEOUT, read_frame::<Frame, _>(stream))
        .await
        .map_err(|_| timed_out("read the MCP routing response"))??
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the box broker closed before routing",
            )
        })?;
    validate_mcp_frame(&frame)?;
    Ok(frame)
}

fn validate_mcp_frame(frame: &Frame) -> io::Result<()> {
    if frame.version != PROTOCOL_VERSION || frame.program != ALIAS_PROGRAM {
        return Err(invalid_input(
            "the MCP routing response has an incompatible version or program",
        ));
    }
    Ok(())
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
// Alias: forward one command and relay its result.

/// The one Program an alias opens.
const ALIAS_PROGRAM: u32 = 1;

/// Connect to the box's broker.
async fn connect(socket: &Path) -> io::Result<UnixStream> {
    tokio::time::timeout(SERVE_IO_TIMEOUT, UnixStream::connect(socket))
        .await
        .map_err(|_| timed_out("connect to the box broker"))?
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("connect to the box broker {}: {error}", socket.display()),
            )
        })
}

/// The frames that submit `command` to one Shell Program, started in `directory`.
///
/// `InputEof` immediately after the run, because this alias forwards no input: a harness invoking
/// `zsh -c` gives the command nothing on stdin, and without the EOF the Program's stdin stays open.
fn submission(command: Command, directory: String) -> [Body; 3] {
    [
        Body::Open {
            mode: Interpreter::Shell,
        },
        Body::Run {
            command,
            directory,
            correlation: Box::new(call_correlation()),
        },
        Body::InputEof,
    ]
}

/// Submit one command to one Program and reproduce its result locally.
async fn forward(
    mut stream: UnixStream,
    command: Command,
    directory: String,
) -> io::Result<Outcome> {
    for body in submission(command, directory) {
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
    // while it runs. No alias timeout: the broker owns the configured Shell deadline.
    loop {
        let frame = read_frame::<Frame, _>(&mut stream)
            .await?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "the box broker closed"))?;
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
            Body::Exit { status } => return Ok(Outcome::Status(status)),
            // A transport refusal, including a version mismatch. Terminal, and reported as the
            // boundary's own failure rather than as something the program did.
            Body::Denied { reason, .. } => {
                eprintln!("strands-box: {reason}");
                return Ok(Outcome::Status(i32::from(SHELL_FAILURE_EXIT)));
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

    /// Shell command text, as a shell alias sends it.
    fn text(command: &str) -> Command {
        Command::Text(command.to_string())
    }

    #[tokio::test(start_paused = true)]
    async fn an_mcp_route_that_never_answers_times_out() {
        let (mut alias, _broker) = UnixStream::pair().unwrap();
        let error = tokio::time::timeout(
            MCP_OPEN_TIMEOUT + std::time::Duration::from_secs(1),
            mcp_response(&mut alias),
        )
        .await
        .expect("the MCP response wait must finish before the outer deadline")
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

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
                socket, command, ..
            } = mode;
            assert_eq!(
                socket,
                PathBuf::from("/private/scaffold/public/run/box.sock")
            );
            assert_eq!(command, Some(text("printf ok")));
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
            socket, command, ..
        } = mode;
        assert_eq!(
            command,
            Some(text("printf ok\n")),
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
            assert_eq!(mode.command, Some(text("printf ok")));
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
                socket, command, ..
            } = mode;
            assert_eq!(socket, PathBuf::from("/private/run/public/run/box.sock"));
            assert_eq!(command, Some(text("printf ok")));
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
                    server: name.to_string(),
                    arguments: Vec::new(),
                },
                "a name outside the shell and Python lists selects an MCP server"
            );
            assert_eq!(
                mode.socket,
                PathBuf::from("/private/run/public/run/box.sock"),
                "the socket is still derived from the image's own path"
            );
            assert!(
                mode.command.is_none(),
                "an MCP server takes no program text"
            );
        }
    }

    /// An MCP alias forwards its arguments in order and unchanged.
    #[test]
    fn an_mcp_alias_forwards_its_arguments_unchanged() {
        let arguments = [
            "-y",
            "@playwright/mcp",
            "--serve",
            "/tmp/attacker.sock",
            "",
            "a b",
        ];
        let mode = parse_mode(
            PathBuf::from("/private/run/public/bin/npx"),
            arguments.iter().map(OsString::from).collect(),
        )
        .expect("an MCP alias accepts any UTF-8 arguments");
        assert_eq!(
            mode.interpreter,
            Interpreter::Mcp {
                server: "npx".to_string(),
                arguments: arguments.iter().map(ToString::to_string).collect(),
            }
        );
        assert_eq!(
            mode.socket,
            PathBuf::from("/private/run/public/run/box.sock"),
            "an argument never chooses the socket"
        );
    }

    /// An MCP alias refuses a non-UTF-8 argument.
    #[cfg(unix)]
    #[test]
    fn an_mcp_alias_refuses_a_non_utf8_argument() {
        use std::os::unix::ffi::OsStringExt as _;
        let error = parse_mode(
            PathBuf::from("/private/run/public/bin/npx"),
            vec![
                OsString::from("-y"),
                OsString::from_vec(vec![0x66, 0xff, 0x6f]),
            ],
        )
        .expect_err("a non-UTF-8 argument must be refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("MCP server argument 2 is not valid UTF-8"),
            "the refusal must name the argument: {error}"
        );
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
                interpreter: Interpreter::Mcp { server, .. },
                ..
            }) => {
                panic!("a shell name must not route to an MCP server {server:?}: {socket:?}")
            }
            Err(_) => {}
        }
    }

    // ── Python aliases ────────────────────────────────────────────────────────

    /// A Python alias sends its own name and every argument unchanged, as a list, to the Shell. It
    /// parses no option and reads no file, so text a shell would expand stays literal here.
    #[test]
    fn a_python_alias_forwards_its_name_and_arguments_unchanged() {
        let cases: &[&[&str]] = &[
            &[],
            &["-"],
            &["-m", "pytest"],
            &["-c", "print(1)"],
            &["--version"],
            &["script.py", "--flag", "value"],
            &["-c", "import os; print('$(rm x)')", "`rm x`"],
            &["-c", "print(1)\nprint(2)\n"],
            &["it's", "\"double\"", "a b", ""],
            &["/nonexistent/attacker.py"],
        ];
        for name in PYTHON_ALIAS_NAMES {
            for arguments in cases {
                let mode = parse_mode(
                    PathBuf::from(format!("/private/scaffold/public/bin/{name}")),
                    arguments.iter().map(OsString::from).collect(),
                )
                .unwrap_or_else(|error| panic!("{name} {arguments:?} must be forwarded: {error}"));
                assert_eq!(
                    mode.interpreter,
                    Interpreter::Shell,
                    "a Python alias reaches the Shell"
                );
                assert_eq!(
                    mode.command,
                    Some(Command::Words {
                        name: name.to_string(),
                        arguments: arguments.iter().map(ToString::to_string).collect(),
                    }),
                    "{name} must forward {arguments:?} unchanged"
                );
                assert_eq!(
                    mode.socket,
                    PathBuf::from("/private/scaffold/public/run/box.sock"),
                    "an argument never chooses the socket"
                );
            }
        }
    }

    /// A Python alias refuses a non-UTF-8 argument, which the wire can't carry unchanged.
    #[test]
    fn a_python_alias_refuses_a_non_utf8_argument() {
        use std::os::unix::ffi::OsStringExt as _;
        let error = parse_mode(
            PathBuf::from("/private/run/public/bin/python3"),
            vec![
                OsString::from("-c"),
                OsString::from_vec(vec![0x66, 0xff, 0x6f]),
            ],
        )
        .expect_err("a non-UTF-8 argument must be refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("Python argument 2 is not valid UTF-8"),
            "the refusal must name the argument: {error}"
        );
    }

    // ── The caller's working directory ────────────────────────────────────────

    /// A directory with a `sub` folder, both canonical.
    fn directory_with_sub() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().expect("a directory");
        let top = root.path().canonicalize().expect("a canonical directory");
        let sub = top.join("sub");
        std::fs::create_dir(&sub).expect("a sub folder");
        (root, top, sub)
    }

    fn unreadable() -> io::Result<PathBuf> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }

    /// `PWD` counts only when it names `.`, so a stale `PWD` gives way to `getcwd`.
    #[test]
    fn the_working_directory_comes_from_pwd_only_when_pwd_names_it() {
        let (_root, top, sub) = directory_with_sub();
        let here = identity(&sub);
        let sub_text = sub.display().to_string();

        assert_eq!(
            working_directory(here, Some(sub.clone()), unreadable()).unwrap(),
            sub_text,
            "a PWD that names . is used even when getcwd fails"
        );
        assert_eq!(
            working_directory(here, Some(top.clone()), Ok(sub.clone())).unwrap(),
            sub_text,
            "a stale PWD gives way to getcwd"
        );
        assert_eq!(
            working_directory(here, Some(PathBuf::from("sub")), Ok(sub.clone())).unwrap(),
            sub_text,
            "a relative PWD doesn't count"
        );
        assert_eq!(
            working_directory(None, Some(sub.clone()), Ok(top.clone())).unwrap(),
            top.display().to_string(),
            "with no identity for ., PWD can't be checked and getcwd wins"
        );
    }

    /// With no usable source, the alias refuses rather than letting the command run elsewhere.
    #[test]
    fn an_unknown_working_directory_is_refused() {
        let (_root, top, sub) = directory_with_sub();
        for (here, pwd) in [
            (identity(&sub), Some(top.clone())),
            (identity(&sub), None),
            (None, Some(sub.clone())),
        ] {
            let error = working_directory(here, pwd, unreadable())
                .expect_err("an unknown working directory must be refused");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(
                error.to_string().contains("set PWD"),
                "the refusal must say how to fix it: {error}"
            );
        }
        let error = working_directory(None, None, Ok(PathBuf::from("relative")))
            .expect_err("a relative working directory must be refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    /// Every submission opens a Shell Program and sends the caller's directory with the command.
    #[test]
    fn every_submission_sends_the_callers_directory() {
        for command in [
            text("printf ok"),
            Command::Words {
                name: "python3".to_string(),
                arguments: vec!["x.py".to_string()],
            },
        ] {
            let [open, run, eof] = submission(command.clone(), "/work/sub".to_string());
            assert!(
                matches!(
                    open,
                    Body::Open {
                        mode: Interpreter::Shell
                    }
                ),
                "every alias opens a Shell Program: {open:?}"
            );
            match run {
                Body::Run {
                    command: sent,
                    directory,
                    ..
                } => {
                    assert_eq!(sent, command);
                    assert_eq!(directory, "/work/sub", "the caller's directory is sent");
                }
                other => panic!("expected a run, got {other:?}"),
            }
            assert!(matches!(eof, Body::InputEof), "{eof:?}");
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
