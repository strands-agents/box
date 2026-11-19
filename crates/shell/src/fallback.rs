//! A command the Shell does not implement: `python` runs in Monty, and anything else runs as a
//! host program in its own boundary, each after its own decision.

use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use strands_shell::os::{CommandContext, CommandFallback, OpenFlags};
use tokio::io::AsyncWriteExt as _;

use crate::effect::{EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit};
use crate::kernel::ShellKernel;
use crate::program::{HostPrograms, HostSpawn, HostSpawner};

/// The status of a command a decision refused.
const DENIED_STATUS: i32 = 126;

/// The status of a decision that faulted, or of an outcome that could not be recorded.
const FAULT_STATUS: i32 = 125;

/// What one Python source printed and returned.
pub struct ScriptOutcome {
    /// The script's exit status.
    pub status: i32,
    /// What the script wrote to stdout.
    pub stdout: String,
    /// What the script wrote to stderr.
    pub stderr: String,
}

/// The future a [`ScriptRunner`] returns.
pub type ScriptFuture = Pin<Box<dyn Future<Output = ScriptOutcome> + Send>>;

/// Runs one Python source.
pub type ScriptRunner = Arc<dyn Fn(String) -> ScriptFuture + Send + Sync>;

/// How the commands the Shell does not implement run.
#[derive(Clone, Default)]
pub(crate) struct Commands {
    pub(crate) programs: HostPrograms,
    pub(crate) spawner: Option<HostSpawner>,
    pub(crate) script: Option<ScriptRunner>,
    /// The most script text `python SCRIPT` reads.
    pub(crate) max_script: usize,
}

const PYTHON_HELP: &str = "Usage: python [-c SOURCE | SCRIPT]
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

/// Deliberately not a CPython version, so capability detection expects Monty.
const PYTHON_VERSION: &str = "Monty (Strands-Box Python subset)";

/// Whether CPython, given `args`, reads its program from stdin: no `-c`, no `-m`, no script file,
/// or a script of `-`. `--version` and `--help` and their short forms print and exit, so they
/// read nothing. `-W` and `-X` take a value, attached or as the next word, as does
/// `--check-hash-based-pycs`.
fn reads_program_from_stdin(args: &[String]) -> bool {
    let mut words = args.iter();
    while let Some(word) = words.next() {
        let word = word.as_str();
        if word == "-" {
            return true;
        }
        if word == "--" {
            return words.next().is_none_or(|script| script == "-");
        }
        if !word.starts_with('-') {
            return false;
        }
        if word.starts_with("--") {
            match word {
                "--version" | "--help" | "--help-env" | "--help-xoptions" | "--help-all" => {
                    return false;
                }
                "--check-hash-based-pycs" => {
                    words.next();
                }
                _ => {}
            }
            continue;
        }
        let flags = &word[1..];
        for (at, flag) in flags.char_indices() {
            match flag {
                'c' | 'm' | 'V' | 'h' | '?' => return false,
                'W' | 'X' => {
                    if at + 1 == flags.len() {
                        words.next();
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    true
}

/// What Monty's refusals add, so an agent that wanted real Python can tell its operator how.
pub const REAL_PYTHON_HINT: &str = "To run real Python, the operator sets monty = false in box.toml, \
     declares a [tool] whose command file is named python3, grants it read on the venv and \
     Python's install, and permits shell:spawn on its file (see the monty key in Box's config docs).";

/// The program and its arguments as one line, for `context.input.command`.
fn command_line(program: &str, args: &[String]) -> String {
    let mut line = String::with_capacity(program.len() + args.len() * 8);
    line.push_str(program);
    for arg in args {
        line.push(' ');
        line.push_str(arg);
    }
    line
}

/// Decide one command the Shell runs itself. Every argument counts as expanded, so a record
/// redacts it.
pub(super) async fn admit_run(
    interceptor: &dyn EffectInterceptor,
    program: &str,
    args: &[String],
    cwd: &str,
) -> io::Result<Box<dyn EffectPermit>> {
    let literal = vec![false; args.len()];
    interceptor
        .intercept(&EffectAttempt::ShellRun {
            command: &command_line(program, args),
            program,
            args,
            literal: &literal,
            cwd,
        })
        .await
}

/// The status and the line a refused decision reports.
fn refusal(error: &io::Error) -> (i32, String) {
    let (status, label) = if error.kind() == io::ErrorKind::PermissionDenied {
        (DENIED_STATUS, "effect denied")
    } else {
        (FAULT_STATUS, "effect interception failed")
    };
    (status, format!("strands-shell: {label}: {error}\n"))
}

/// The diagnostic for a bare name that no tool and no file on the box's search path answers to.
fn not_found(program: &str) -> String {
    format!(
        "strands-shell: {program}: command not found\n\
         strands-shell: {program}: no tool in this box has this name, and no file of this name is \
         on the PATH that `box run` started with. A PATH set inside the box does not change where \
         the box looks\n"
    )
}

async fn write_stderr(context: &mut CommandContext, text: &str) {
    if let (_, _, Some(stderr)) = context.stdio() {
        let _ = stderr.write_all(text.as_bytes()).await;
    }
}

async fn write_stdout(context: &mut CommandContext, bytes: &[u8]) -> io::Result<()> {
    match context.stdio() {
        (_, Some(stdout), _) => stdout.write_all(bytes).await,
        _ => Ok(()),
    }
}

/// `status`, or 1 with a diagnostic when output was lost for any reason but a closed reader.
async fn written_status(
    context: &mut CommandContext,
    label: &str,
    written: io::Result<()>,
    status: i32,
) -> i32 {
    match written {
        Ok(()) => status,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => status,
        Err(error) => {
            write_stderr(context, &format!("{label}: {error}\n")).await;
            1
        }
    }
}

/// Record a command's status, or report the status of an outcome that could not be recorded.
async fn finish(context: &mut CommandContext, permit: Box<dyn EffectPermit>, status: i32) -> i32 {
    let recorded = permit
        .record_outcome(EffectOutcome::ShellCommand {
            reported_status: status,
        })
        .await;
    match recorded {
        Ok(()) => status,
        Err(error) => {
            let line = format!(
                "strands-shell: command completed with status {status}, but effect outcome \
                 recording failed: {error}\n"
            );
            write_stderr(context, &line).await;
            FAULT_STATUS
        }
    }
}

/// A permit marked indeterminate if its command is cancelled before it records.
struct Unsettled(Option<Box<dyn EffectPermit>>);

impl Unsettled {
    fn spawn_working_directory(&self) -> Option<&Path> {
        self.0.as_ref()?.spawn_working_directory()
    }

    async fn finish(mut self, context: &mut CommandContext, status: i32) -> i32 {
        match self.0.take() {
            Some(permit) => finish(context, permit, status).await,
            None => status,
        }
    }
}

impl Drop for Unsettled {
    fn drop(&mut self) {
        if let Some(permit) = self.0.take() {
            permit.mark_indeterminate();
        }
    }
}

/// A decided command the Shell does not implement, waiting for its stage to start.
pub(crate) enum Decided {
    /// `python` or `python3`, decided as `shell:exec`.
    Python(Box<dyn EffectPermit>),
    /// A name no host program answers to, decided as `shell:exec`.
    NotFound(Box<dyn EffectPermit>),
    /// A host program, decided as `shell:spawn`.
    Spawn {
        permit: Box<dyn EffectPermit>,
        program: crate::program::HostProgram,
    },
}

impl Decided {
    /// Record that the command never ran.
    pub(crate) fn drop_unrun(self) {
        match self {
            Decided::Python(permit) | Decided::NotFound(permit) | Decided::Spawn { permit, .. } => {
                permit.mark_indeterminate()
            }
        }
    }
}

impl ShellKernel {
    /// Decide one command the Shell does not implement, as the stage that runs it will.
    pub(crate) async fn decide(
        &self,
        program: &str,
        args: &[String],
        cwd: &std::path::Path,
    ) -> io::Result<Decided> {
        let cwd_text = cwd.to_string_lossy();
        if matches!(program, "python" | "python3") && self.commands.script.is_some() {
            return admit_run(self.interceptor.as_ref(), program, args, &cwd_text)
                .await
                .map(Decided::Python);
        }
        let Some(resolved) = crate::program::host_program(&self.commands.programs, program, cwd)
        else {
            return admit_run(self.interceptor.as_ref(), program, args, &cwd_text)
                .await
                .map(Decided::NotFound);
        };
        let literal = vec![false; args.len()];
        let permit = self
            .interceptor
            .intercept(&EffectAttempt::ShellSpawn {
                command: &command_line(program, args),
                program,
                program_path: &resolved.path,
                args,
                literal: &literal,
                cwd: &cwd_text,
            })
            .await?;
        Ok(Decided::Spawn {
            permit,
            program: resolved,
        })
    }
}

#[async_trait::async_trait]
impl CommandFallback for ShellKernel {
    /// `python` and `python3` name Monty ahead of `PATH`
    /// (docs/design/decisions.md#a-bare-python-name-always-means-monty).
    fn serves(&self, name: &str) -> bool {
        matches!(name, "python" | "python3") && self.commands.script.is_some()
    }

    async fn run(&self, context: &mut CommandContext) -> io::Result<Option<i32>> {
        let program = context.program().to_string();
        let args = context.args().to_vec();
        let decided = match self.take_decided(&program, &args, context.cwd()) {
            Some(decided) => decided,
            None => match self.decide(&program, &args, context.cwd()).await {
                Ok(decided) => decided,
                Err(error) => {
                    let (status, line) = refusal(&error);
                    write_stderr(context, &line).await;
                    return Ok(Some(status));
                }
            },
        };
        let (permit, resolved) = match decided {
            Decided::Python(permit) => {
                let held = Unsettled(Some(permit));
                let status = self.run_python(context, &args).await;
                return Ok(Some(held.finish(context, status).await));
            }
            Decided::NotFound(permit) => {
                let status = finish(context, permit, 127).await;
                if status == 127 {
                    write_stderr(context, &not_found(&program)).await;
                }
                return Ok(Some(status));
            }
            Decided::Spawn { permit, program } => (Unsettled(Some(permit)), program),
        };
        // With Monty off, `python3` and `python` are host programs, and a host program receives no
        // input. CPython would read an empty program from stdin and exit 0 having run nothing, so
        // a heredoc or a pipe would look like success. Refuse that form the way Monty does.
        if self.commands.script.is_none()
            && matches!(program.as_str(), "python" | "python3")
            && reads_program_from_stdin(&args)
        {
            let message = format!(
                "{program}: reading a program from stdin is not supported: a program the Shell \
                 starts receives no input yet; use -c SOURCE or a script file\n"
            );
            write_stderr(context, &message).await;
            return Ok(Some(permit.finish(context, 2).await));
        }
        let working_directory = match permit.spawn_working_directory() {
            Some(directory) if !directory.is_absolute() => {
                write_stderr(
                    context,
                    "strands-shell: effect interception failed: the admitted spawn working \
                     directory must be absolute\n",
                )
                .await;
                return Ok(Some(permit.finish(context, FAULT_STATUS).await));
            }
            Some(directory) => directory.to_path_buf(),
            None => context.cwd().to_path_buf(),
        };
        if !resolved.bound {
            permit.finish(context, 127).await;
            return Ok(None);
        }
        let spawn = HostSpawn {
            program: resolved.path.into(),
            invoked: resolved.spelling.into(),
            args,
            cwd: working_directory,
        };
        let spawned = match &self.commands.spawner {
            Some(spawner) => spawner(spawn).await,
            None => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "host-binary execution requires a contained spawner; none is installed",
            )),
        };
        let status = match spawned {
            Ok(outcome) => {
                let written = write_stdout(context, &outcome.stdout).await;
                if let (_, _, Some(stderr)) = context.stdio() {
                    let _ = stderr.write_all(&outcome.stderr).await;
                }
                written_status(
                    context,
                    &format!("strands-shell: {program}"),
                    written,
                    outcome.status,
                )
                .await
            }
            Err(error) => {
                write_stderr(context, &format!("strands-shell: {program}: {error}\n")).await;
                DENIED_STATUS
            }
        };
        Ok(Some(permit.finish(context, status).await))
    }
}

impl ShellKernel {
    /// `python -c SOURCE` or `python SCRIPT`, which reads no stdin.
    async fn run_python(&self, context: &mut CommandContext, args: &[String]) -> i32 {
        let mut source: Option<String> = None;
        let mut file: Option<String> = None;
        let mut words = args.iter();
        let mut positional = false;
        while let Some(word) = words.next() {
            if source.is_some() || file.is_some() {
                let message = if file.is_some() && (positional || !word.starts_with('-')) {
                    "python: only one script file may be given\n"
                } else {
                    "python: no arguments are accepted after the script or -c source\n"
                };
                write_stderr(context, message).await;
                return 2;
            }
            if positional || !word.starts_with('-') || word == "-" {
                file = Some(word.clone());
                continue;
            }
            match word.as_str() {
                "--" => positional = true,
                "-V" | "--version" => {
                    let written =
                        write_stdout(context, format!("{PYTHON_VERSION}\n").as_bytes()).await;
                    return written_status(context, "python", written, 0).await;
                }
                "-h" | "--help" => {
                    let written =
                        write_stdout(context, format!("{PYTHON_HELP}\n").as_bytes()).await;
                    return written_status(context, "python", written, 0).await;
                }
                "-c" => match words.next() {
                    Some(text) => source = Some(text.clone()),
                    None => {
                        write_stderr(context, "python: missing argument for option '-c'\n").await;
                        return 1;
                    }
                },
                attached if attached.starts_with("-c") => source = Some(attached[2..].to_string()),
                // `python3 -m pytest` or `-m venv` is the usual first try at real Python.
                module if module.starts_with("-m") => {
                    let message = format!(
                        "{}: -m is not supported by Monty, Box's built-in Python subset. \
                         {REAL_PYTHON_HINT}\n",
                        context.program()
                    );
                    write_stderr(context, &message).await;
                    return 1;
                }
                other => {
                    write_stderr(context, &format!("python: invalid option '{other}'\n")).await;
                    return 1;
                }
            }
        }
        let script = if let Some(source) = source {
            source
        } else if let Some(path) = file {
            if path == "-" {
                write_stderr(
                    context,
                    &format!(
                        "python: reading a script from stdin is not supported; use `-c SOURCE` or \
                         a script file. {REAL_PYTHON_HINT}\n"
                    ),
                )
                .await;
                return 2;
            }
            match self.read_script(context.cwd(), &path).await {
                Ok(script) => script,
                Err(error) => {
                    write_stderr(context, &format!("python: {error}\n")).await;
                    return 1;
                }
            }
        } else {
            write_stderr(
                context,
                &format!(
                    "python: no script given; this box's Python runs only `-c SOURCE` or a script \
                     file (no REPL, pipe, or heredoc). {REAL_PYTHON_HINT}\n"
                ),
            )
            .await;
            return 2;
        };
        let Some(runner) = &self.commands.script else {
            return 127;
        };
        let outcome = runner(script).await;
        let written = write_stdout(context, outcome.stdout.as_bytes()).await;
        if !outcome.stderr.is_empty() {
            write_stderr(context, &outcome.stderr).await;
        }
        written_status(context, "python", written, outcome.status).await
    }

    /// Read a script file through this kernel, so the read is its own `fs:read` decision.
    async fn read_script(&self, cwd: &Path, path: &str) -> io::Result<String> {
        use strands_shell::os::Kernel as _;
        let mut process = self.new_process();
        process.cwd = cwd.to_path_buf();
        let fd = self.open(&mut process, path, OpenFlags::read()).await?;
        let mut reader = process.take_reader(fd)?;
        strands_shell::os::read_to_string_limited(&mut reader, self.commands.max_script).await
    }
}

#[cfg(test)]
mod tests {
    use super::reads_program_from_stdin;

    fn reads(args: &[&str]) -> bool {
        reads_program_from_stdin(
            &args
                .iter()
                .map(|arg| (*arg).to_string())
                .collect::<Vec<_>>(),
        )
    }

    /// The forms CPython reads its program from stdin for, and the ones it doesn't.
    #[test]
    fn a_program_from_stdin_is_told_from_one_named_on_the_command_line() {
        for args in [
            &[][..],
            &["-"],
            &["-u"],
            &["-i"],
            &["-I", "-"],
            &["--", "-"],
            &["--"],
            &["-W", "ignore"],
            &["-Wignore"],
            &["-X", "utf8"],
        ] {
            assert!(reads(args), "{args:?} reads its program from stdin");
        }
        for args in [
            &["-c", "print(1)"][..],
            &["-cprint(1)"],
            &["-uc", "print(1)"],
            &["-m", "pytest"],
            &["--version"],
            &["-V"],
            &["--help"],
            &["-h"],
            &["script.py"],
            &["-u", "script.py", "-"],
            &["-W", "ignore", "script.py"],
            &["--", "script.py"],
        ] {
            assert!(!reads(args), "{args:?} names its program");
        }
    }
}
