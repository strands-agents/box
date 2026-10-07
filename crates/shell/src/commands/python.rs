use crate::prelude::*;

const HELP: &str = "Usage: python [-c SOURCE | SCRIPT]
Run a Python script through this box's interpreter.

This box's Python is Monty, a Python subset — not CPython. Two forms are supported:
  python -c SOURCE     run SOURCE
  python SCRIPT        run the script file SCRIPT

-c and a script file are mutually exclusive, and nothing may follow the chosen
one. Unlike a normal shell, this box forwards no arguments to the script, so a
trailing token is refused rather than passed as argv: `python -c SOURCE --version`
exits with an error here, where a normal shell would run SOURCE and print `1`.
Put --version or --help before any program.

Not supported: an interactive REPL, reading a script from stdin (a pipe or a
heredoc), and `python -`. See the box's docs for the subset.";

/// A Monty-identifying version line.
///
/// Deliberately **not** a CPython version string: capability detection must not be
/// misled into expecting full CPython. `python`/`python3` in this Shell are always
/// Monty, never a host interpreter.
const VERSION: &str = "Monty (Strands-Box Python subset)";

/// `python` — forward a script to the box's interpreter (Monty).
#[command("python")]
async fn cmd_python(os: &Mediated, args: &[String]) -> CommandResult {
    run_python_command(os, args).await
}

/// `python3` — the same command under the other alias name.
#[command("python3")]
async fn cmd_python3(os: &Mediated, args: &[String]) -> CommandResult {
    run_python_command(os, args).await
}

/// The shared implementation behind both `python` and `python3`.
///
/// Accepts exactly one of `-c SOURCE` or a single script file, plus `--version` and
/// `--help`. It does **not** read stdin: a no-`-c`, no-file invocation — a REPL, a
/// pipe, or a heredoc — refuses loudly rather than silently dropping stdin.
async fn run_python_command(os: &Mediated, args: &[String]) -> CommandResult {
    let mut source: Option<String> = None;
    let mut file: Option<String> = None;

    let mut parser = lexopt::Parser::from_args(args);
    while let Some(arg) = parser.next()? {
        // Nothing may follow the chosen program — a `-c SOURCE` or a script file. This box's
        // `python` forwards no arguments to a script, so a later token is either a second program
        // or a trailing flag (`--version`, `-c`, `-h`). Refuse it loudly, so a trailing flag never
        // hijacks the run — printing the version and skipping the source, or swapping one program
        // for another. `-c` and a file are therefore mutually exclusive, not `-c`-wins.
        if source.is_some() || file.is_some() {
            let mut w = io::stderr()?;
            let message = match arg {
                Value(_) if file.is_some() => "python: only one script file may be given",
                _ => "python: no arguments are accepted after the script or -c source",
            };
            wprintln!(w, "{}", message)?;
            return Ok(2);
        }
        match arg {
            Short('c') => source = Some(parser.value()?.string()?),
            Short('V') | Long("version") => {
                let mut w = io::stdout()?;
                wprintln!(w, "{}", VERSION)?;
                return Ok(0);
            }
            Short('h') | Long("help") => {
                let mut w = io::stdout()?;
                wprintln!(w, "{}", HELP)?;
                return Ok(0);
            }
            Value(val) => file = Some(val.string()?),
            _ => return Err(arg.unexpected().into()),
        }
    }

    // Resolve the source. `-c` and a file are mutually exclusive (the loop refuses the second),
    // so at most one of these is set.
    let script = if let Some(src) = source {
        src
    } else if let Some(path) = file {
        // `python -` is stdin-as-source, which this box does not support.
        if path == "-" {
            let mut w = io::stderr()?;
            wprintln!(
                w,
                "python: reading a script from stdin is not supported; use `-c SOURCE` or a script file"
            )?;
            return Ok(2);
        }
        // Read the file through the mediated kernel, so the read is a governed `fs:read`
        // that reaches bind mounts — unlike the direct alias, which reads with the
        // workload's own syscall and cannot reach a bind. A denied read stops here and
        // forwards nothing.
        let fd = io::open(os, &path, OpenFlags::read()).await?;
        let mut reader = io::take_reader(fd)?;
        let max_output = io::with_process(|p| p.max_output);
        crate::os::read_to_string_limited(&mut reader, max_output).await?
    } else {
        // No `-c` and no file. A REPL, a pipe, or a heredoc lands here. This command
        // does not read stdin, so a heredoc's body would otherwise be silently dropped;
        // refuse loudly instead.
        let mut w = io::stderr()?;
        wprintln!(
            w,
            "python: no script given; this box's Python runs only `-c SOURCE` or a script file (no REPL, pipe, or heredoc)"
        )?;
        return Ok(2);
    };

    // Forward to the interpreter the box installed. `Unsupported` means no hook is wired
    // — report it rather than hang or pretend.
    let outcome = match os.run_script(script).await {
        Ok(outcome) => outcome,
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            let mut w = io::stderr()?;
            wprintln!(w, "python: no interpreter is available in this Shell")?;
            return Ok(127);
        }
        Err(e) => {
            let mut w = io::stderr()?;
            wprintln!(w, "python: {}", e)?;
            return Ok(1);
        }
    };

    if !outcome.stdout.is_empty() {
        let mut out = io::stdout()?;
        out.write_all(outcome.stdout.as_bytes()).await?;
    }
    if !outcome.stderr.is_empty() {
        let mut err = io::stderr()?;
        err.write_all(outcome.stderr.as_bytes()).await?;
    }
    Ok(outcome.status)
}
