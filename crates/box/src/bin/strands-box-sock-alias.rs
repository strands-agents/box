//! The socket alias: what the contained workload execs when it believes it is running
//! `zsh` or `python3`.

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
use shell_protocol::{
    BROKER_SOCKET_RELATIVE, PYTHON_ALIAS_NAMES, REPLACED_PYTHON_FILE, SHELL_ALIAS_NAMES,
};

/// The largest positional script the alias will forward as command text.
const MAX_SCRIPT_BYTES: usize = MAX_FRAME_BYTES / 16;

/// The largest replaced-Python list the alias reads. Box writes at most two short names.
const MAX_REPLACED_LIST_BYTES: usize = 256;

/// Bound on one framed read or write against the daemon's Shell socket.
const SERVE_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on waiting for the daemon's direct Python interpreter to answer.
const PYTHON_RESPONSE_TIMEOUT: Duration = Duration::from_secs(35);

const MCP_OPEN_TIMEOUT: Duration = Duration::from_secs(60);

enum Outcome {
    Status(i32),
    Fallback {
        program: String,
        arguments: Vec<String>,
    },
}

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
        if is_replaced(executable, name)? {
            let directory = std::env::current_dir().map_err(|error| {
                io::Error::new(error.kind(), format!("read the working directory: {error}"))
            })?;
            let command = replaced_command(&directory, name, arguments)?;
            return shell_mode(executable, OsString::from(command));
        }
        return parse_script_alias(executable, arguments);
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

/// Whether a `[tool.<name>]` replaces the Python name `name`, from the list Box writes beside the
/// aliases.
///
/// Box writes the list and lets the agent read it only while a tool replaces a Python name, so a
/// list that is absent or that this sandbox refuses means none is, and the alias runs Monty.
fn is_replaced(executable: &Path, name: &str) -> io::Result<bool> {
    use std::io::Read as _;

    let Some(bin) = executable.parent() else {
        return Ok(false);
    };
    let list = bin.join(REPLACED_PYTHON_FILE);
    let file = match std::fs::File::open(&list) {
        Ok(file) => file,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(false);
        }
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!("read {}: {error}", list.display()),
            ));
        }
    };
    let mut text = String::new();
    file.take(MAX_REPLACED_LIST_BYTES as u64 + 1)
        .read_to_string(&mut text)
        .map_err(|error| {
            io::Error::new(error.kind(), format!("read {}: {error}", list.display()))
        })?;
    if text.len() > MAX_REPLACED_LIST_BYTES {
        return Err(invalid_input(format!(
            "{} is over {MAX_REPLACED_LIST_BYTES} bytes",
            list.display()
        )));
    }
    Ok(text.lines().any(|line| line == name))
}

/// The Shell command that runs `name` with `arguments` in `directory`, the caller's own working
/// directory, each word single-quoted.
///
/// The Shell starts every command in the workspace, so the command enters `directory` first, and a
/// relative path names what it named for the caller. A directory the Shell can't enter fails the
/// command there rather than running it elsewhere.
fn replaced_command(directory: &Path, name: &str, arguments: Vec<OsString>) -> io::Result<String> {
    let quoted = |word: &str| format!("'{}'", word.replace('\'', "'\\''"));
    let directory = directory
        .to_str()
        .ok_or_else(|| invalid_input("the working directory is not valid UTF-8"))?;
    let mut command = format!("cd {} && {name}", quoted(directory));
    for (index, argument) in arguments.into_iter().enumerate() {
        let argument = argument.into_string().map_err(|_| {
            invalid_input(format!("Python argument {} is not valid UTF-8", index + 1))
        })?;
        command.push(' ');
        command.push_str(&quoted(&argument));
    }
    if command.len() > MAX_SCRIPT_BYTES {
        return Err(invalid_input(format!(
            "the Python command is {} bytes; maximum is {MAX_SCRIPT_BYTES}",
            command.len()
        )));
    }
    Ok(command)
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

/// Submit one Call to one Program and reproduce its result locally.
async fn forward(socket: &Path, interpreter: Interpreter, source: String) -> io::Result<Outcome> {
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
    let python = matches!(interpreter, Interpreter::Python);

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
        let response = read_frame::<Frame, _>(&mut stream);
        let frame = if python {
            tokio::time::timeout(PYTHON_RESPONSE_TIMEOUT, response)
                .await
                .map_err(|_| timed_out("read a transport frame"))?
        } else {
            // The broker owns the configured Shell deadline.
            response.await
        }?
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
                mode.source.is_empty(),
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

    // ── Python names a tool replaces ─────────────────────────────────────────

    /// A box root whose `bin/` holds a replaced-Python list with `contents`, when given.
    fn replaced_box(contents: Option<&str>) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().expect("a box root");
        let bin = root.path().join("public/bin");
        std::fs::create_dir_all(&bin).expect("a bin directory");
        if let Some(contents) = contents {
            std::fs::write(bin.join(REPLACED_PYTHON_FILE), contents).expect("the list");
        }
        (root, bin)
    }

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    /// **A listed Python name sends every argument to the Shell as one command**, each argument one
    /// single-quoted word, so the Shell runs the tool that replaces the name.
    #[test]
    fn a_replaced_python_name_routes_its_arguments_to_the_shell() {
        let (_root, bin) = replaced_box(Some("python\npython3\n"));
        let here = std::env::current_dir().expect("the test's working directory");
        let enter = format!("cd '{}' && ", here.display());
        for (name, given, command) in [
            (
                "python3",
                vec!["-m", "venv", ".venv"],
                "python3 '-m' 'venv' '.venv'",
            ),
            (
                "python",
                vec!["-I", "-c", "print('a b')"],
                "python '-I' '-c' 'print('\\''a b'\\'')'",
            ),
            ("python3", vec![], "python3"),
        ] {
            let mode =
                parse_mode(bin.join(name), arguments(&given)).expect("a replaced name parses");
            assert_eq!(mode.interpreter, Interpreter::Shell, "{name} {given:?}");
            assert_eq!(mode.source, format!("{enter}{command}"));
            assert_eq!(mode.socket, bin.parent().unwrap().join("run/box.sock"));
        }
    }

    /// **The command enters the caller's own directory first**, quoted like every argument, so a
    /// relative path names what it named for the caller.
    #[test]
    fn a_replaced_command_enters_the_callers_directory_first() {
        let command = replaced_command(
            Path::new("/work/it's here"),
            "python3",
            arguments(&["setup.py", "build"]),
        )
        .expect("the command builds");

        assert_eq!(
            command,
            "cd '/work/it'\\''s here' && python3 'setup.py' 'build'"
        );
    }

    /// **A name the list leaves out, or a box with no list, keeps Monty**, so `-m` is still the
    /// alias's own usage error there.
    #[test]
    fn an_unlisted_python_name_keeps_the_script_boundary() {
        for (contents, name) in [
            (Some("python\n"), "python3"),
            (None, "python3"),
            (Some(""), "python"),
        ] {
            let (_root, bin) = replaced_box(contents);

            let error = parse_mode(bin.join(name), arguments(&["-m", "venv"]))
                .expect_err("Monty refuses -m");
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidInput,
                "{contents:?} {name}"
            );

            let mode = parse_mode(bin.join(name), arguments(&["-c", "print(1)"]))
                .expect("-c still reaches Monty");
            assert_eq!(mode.interpreter, Interpreter::Python);
            assert_eq!(mode.source, "print(1)");
        }
    }

    /// **A list over the size bound is refused** rather than read in part.
    #[test]
    fn an_oversized_replaced_python_list_is_refused() {
        let (_root, bin) = replaced_box(Some(&"python3\n".repeat(64)));

        let error = parse_mode(bin.join("python3"), arguments(&["-c", "pass"]))
            .expect_err("an oversized list is refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
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
