//! `ShellBuilder::script_interpreter` + the `python`/`python3` command.
//!
//! A fake hook stands in for the box's Monty: it records the source it was handed and
//! returns a canned outcome, so these tests prove the wiring — resolution, the governed
//! file read, the refusals, and `--version` — without a real interpreter.

use std::sync::{Arc, Mutex};

use strands_shell::Shell;

fn rt() -> (tokio::runtime::Runtime, tokio::task::LocalSet) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    (runtime, tokio::task::LocalSet::new())
}

/// A fake interpreter hook. Records each source it receives and echoes it back as stdout,
/// so a test can assert both what the command forwarded and what it surfaced.
fn recording_hook() -> (
    strands_shell::os::ScriptInterpreter,
    Arc<Mutex<Vec<String>>>,
) {
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let captured = Arc::clone(&seen);
    let hook: strands_shell::os::ScriptInterpreter = Arc::new(move |source: String| {
        let captured = Arc::clone(&captured);
        Box::pin(async move {
            captured.lock().unwrap().push(source.clone());
            Ok::<_, std::io::Error>(strands_shell::os::ScriptOutcome {
                status: 0,
                stdout: format!("RAN:{source}"),
                stderr: String::new(),
            })
        })
    });
    (hook, seen)
}

/// `python -c SOURCE` forwards the exact source to the hook and surfaces its outcome.
#[test]
fn python_dash_c_forwards_the_source_to_the_hook() {
    let (hook, seen) = recording_hook();
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder()
            .script_interpreter(hook)
            .build()
            .expect("a Shell with a script interpreter builds");
        let out = shell.run("python -c \"print(1)\"").await;
        assert_eq!(out.status, 0, "stderr: {}", out.stderr);
        assert_eq!(out.stdout, "RAN:print(1)");
    }));
    assert_eq!(seen.lock().unwrap().as_slice(), ["print(1)"]);
}

/// `python3` reaches the same command as `python`.
#[test]
fn python3_alias_reaches_the_same_command() {
    let (hook, seen) = recording_hook();
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().script_interpreter(hook).build().unwrap();
        let out = shell.run("python3 -c \"x=1\"").await;
        assert_eq!(out.status, 0, "stderr: {}", out.stderr);
    }));
    assert_eq!(seen.lock().unwrap().as_slice(), ["x=1"]);
}

/// A file argument is read through the Shell (a governed read) and its contents forwarded.
#[test]
fn python_reads_a_script_file_and_forwards_its_contents() {
    let (hook, seen) = recording_hook();
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().script_interpreter(hook).build().unwrap();
        // Create the script through the Shell itself, then run it. `/home/lash` is the
        // default VFS's writable home; `/` is root-owned and denies the write.
        let wrote = shell.run("printf PAYLOAD > /home/lash/a.py").await;
        assert_eq!(wrote.status, 0, "seeding the script file: {}", wrote.stderr);
        let out = shell.run("python /home/lash/a.py").await;
        assert_eq!(out.status, 0, "stderr: {}", out.stderr);
    }));
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "one script was forwarded");
    assert!(
        seen[0].contains("PAYLOAD"),
        "the file's contents reached the hook, got: {:?}",
        seen[0]
    );
}

/// A no-argument `python` refuses loudly and never calls the hook (no REPL, no stdin).
#[test]
fn bare_python_refuses_and_does_not_call_the_hook() {
    let (hook, seen) = recording_hook();
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().script_interpreter(hook).build().unwrap();
        let out = shell.run("python").await;
        assert_ne!(out.status, 0, "a no-argument python must refuse");
        assert!(
            out.stderr.contains("no script given"),
            "the refusal names the reason, got: {}",
            out.stderr
        );
    }));
    assert!(
        seen.lock().unwrap().is_empty(),
        "a refused python must not reach the interpreter"
    );
}

/// Without a hook installed, `python` refuses rather than pretends — `run_script` is
/// `Unsupported`, so the command reports no interpreter is available.
#[test]
fn python_without_a_hook_reports_no_interpreter() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().build().unwrap();
        let out = shell.run("python -c \"print(1)\"").await;
        assert_eq!(
            out.status, 127,
            "with no interpreter the command is 127, got stderr: {}",
            out.stderr
        );
    }));
}

/// `python --version` identifies Monty and never reports a CPython version.
#[test]
fn python_version_identifies_monty() {
    let (hook, _seen) = recording_hook();
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().script_interpreter(hook).build().unwrap();
        let out = shell.run("python --version").await;
        assert_eq!(out.status, 0, "stderr: {}", out.stderr);
        assert!(
            out.stdout.starts_with("Monty"),
            "version must identify Monty, got: {}",
            out.stdout
        );
        // Pin the negative half: it must NEVER read as a CPython version, so
        // capability detection cannot mistake Monty's subset for full CPython.
        let lower = out.stdout.to_ascii_lowercase();
        assert!(
            !lower.contains("python 3") && !lower.contains("cpython"),
            "version must not read as a CPython version, got: {}",
            out.stdout
        );
    }));
}

/// `python --help` prints usage and exits 0, without calling the interpreter.
#[test]
fn python_help_prints_usage_and_does_not_call_the_hook() {
    let (hook, seen) = recording_hook();
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().script_interpreter(hook).build().unwrap();
        let out = shell.run("python --help").await;
        assert_eq!(out.status, 0, "stderr: {}", out.stderr);
        assert!(
            out.stdout.contains("Usage: python"),
            "help must print usage, got: {}",
            out.stdout
        );
    }));
    assert!(
        seen.lock().unwrap().is_empty(),
        "--help must not reach the interpreter"
    );
}

/// Two file arguments refuse loudly (exit 2) and never call the hook.
#[test]
fn python_two_file_args_refuse() {
    let (hook, seen) = recording_hook();
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().script_interpreter(hook).build().unwrap();
        let out = shell.run("python a.py b.py").await;
        assert_eq!(out.status, 2, "two files must be a usage error");
        assert!(
            out.stderr.contains("only one script file"),
            "the refusal must name the reason, got: {}",
            out.stderr
        );
    }));
    assert!(
        seen.lock().unwrap().is_empty(),
        "a refused invocation must not reach the interpreter"
    );
}

/// `python -` (stdin-as-source) is refused, not read from stdin.
#[test]
fn python_dash_stdin_source_refuses() {
    let (hook, seen) = recording_hook();
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().script_interpreter(hook).build().unwrap();
        let out = shell.run("python -").await;
        assert_eq!(out.status, 2, "python - must refuse");
        assert!(
            out.stderr.contains("stdin is not supported"),
            "the refusal must name stdin, got: {}",
            out.stderr
        );
    }));
    assert!(
        seen.lock().unwrap().is_empty(),
        "python - must not reach the interpreter"
    );
}

/// A pipe into a no-argument `python` refuses (stdin is not a script) and never runs.
#[test]
fn python_pipe_without_args_refuses() {
    let (hook, seen) = recording_hook();
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().script_interpreter(hook).build().unwrap();
        // A pipe puts data on stdin, but the command reads no stdin: it must refuse the
        // no-`-c`, no-file shape rather than silently drop the piped content.
        let out = shell.run("echo \"print(1)\" | python").await;
        assert_ne!(out.status, 0, "a piped no-arg python must refuse");
        assert!(
            out.stderr.contains("no script given"),
            "the refusal must name the reason, got: {}",
            out.stderr
        );
    }));
    assert!(
        seen.lock().unwrap().is_empty(),
        "a refused python must not reach the interpreter"
    );
}

/// `-c SOURCE` and a file are mutually exclusive: a file after `-c` refuses, and the source
/// does not silently win. (Monty forwards no argv, so a dropped file would be a silent no-op.)
#[test]
fn python_a_file_after_dash_c_source_refuses() {
    let (hook, seen) = recording_hook();
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().script_interpreter(hook).build().unwrap();
        let out = shell.run("python -c \"print(42)\" ignored.py").await;
        assert_eq!(
            out.status, 2,
            "a file after -c must refuse, not silently win"
        );
        assert!(
            out.stderr.contains("no arguments are accepted after"),
            "the refusal must name the reason, got: {}",
            out.stderr
        );
    }));
    assert!(
        seen.lock().unwrap().is_empty(),
        "a refused invocation must not reach the interpreter"
    );
}

/// A flag after `-c SOURCE` refuses, and never prints the version while dropping the source.
///
/// The `-c` counterpart of `python_flag_after_the_script_file_refuses`: guards the hijack
/// `python -c "print(1)" --version` would otherwise cause.
#[test]
fn python_flag_after_dash_c_source_refuses() {
    let (hook, seen) = recording_hook();
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().script_interpreter(hook).build().unwrap();
        let out = shell.run("python -c \"print(1)\" --version").await;
        assert_eq!(out.status, 2, "a flag after -c source must refuse");
        assert!(
            out.stderr.contains("no arguments are accepted after"),
            "the refusal must name the reason, got: {}",
            out.stderr
        );
        assert!(
            !out.stdout.contains("Monty"),
            "the version must not print when it follows -c source, got: {}",
            out.stdout
        );
    }));
    assert!(
        seen.lock().unwrap().is_empty(),
        "the -c source must not run when a flag follows it"
    );
}

/// A second `-c` refuses rather than overwriting the first source.
#[test]
fn python_second_dash_c_refuses() {
    let (hook, seen) = recording_hook();
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().script_interpreter(hook).build().unwrap();
        let out = shell.run("python -c \"print(1)\" -c \"print(2)\"").await;
        assert_eq!(out.status, 2, "a second -c must refuse");
        assert!(
            out.stderr.contains("no arguments are accepted after"),
            "the refusal must name the reason, got: {}",
            out.stderr
        );
    }));
    assert!(
        seen.lock().unwrap().is_empty(),
        "neither -c source must run when a second -c follows"
    );
}

/// The hook's stdout, stderr, and status are all surfaced by the command.
#[test]
fn python_surfaces_the_hook_status_and_streams() {
    // A hook that returns a nonzero status and writes both streams.
    let hook: strands_shell::os::ScriptInterpreter = Arc::new(move |_source: String| {
        Box::pin(async move {
            Ok::<_, std::io::Error>(strands_shell::os::ScriptOutcome {
                status: 3,
                stdout: "OUT".to_string(),
                stderr: "ERR".to_string(),
            })
        })
    });
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().script_interpreter(hook).build().unwrap();
        let out = shell.run("python -c \"x\"").await;
        assert_eq!(out.status, 3, "the hook's status must pass through");
        assert!(out.stdout.contains("OUT"), "stdout: {}", out.stdout);
        assert!(out.stderr.contains("ERR"), "stderr: {}", out.stderr);
    }));
}

/// A flag after the script file refuses, and never prints the version or runs the script.
///
/// Guards the hijack `python script.py --version` would otherwise cause: the flag is parsed
/// anywhere, so it prints the version and exits `0` without running the file.
#[test]
fn python_flag_after_the_script_file_refuses() {
    let (hook, seen) = recording_hook();
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().script_interpreter(hook).build().unwrap();
        let out = shell.run("python script.py --version").await;
        assert_eq!(out.status, 2, "a flag after the script file must refuse");
        assert!(
            out.stderr.contains("no arguments are accepted after"),
            "the refusal must name the reason, got: {}",
            out.stderr
        );
        assert!(
            !out.stdout.contains("Monty"),
            "the version must not print when it follows the script file, got: {}",
            out.stdout
        );
    }));
    assert!(
        seen.lock().unwrap().is_empty(),
        "a refused invocation must not reach the interpreter"
    );
}

/// `-c` after a script file refuses rather than silently swapping the file for the `-c` source.
#[test]
fn python_dash_c_after_a_file_refuses_rather_than_hijacking() {
    let (hook, seen) = recording_hook();
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().script_interpreter(hook).build().unwrap();
        let out = shell.run("python script.py -c \"print(1)\"").await;
        assert_eq!(out.status, 2, "a -c after the script file must refuse");
        assert!(
            out.stderr.contains("no arguments are accepted after"),
            "the refusal must name the reason, got: {}",
            out.stderr
        );
    }));
    assert!(
        seen.lock().unwrap().is_empty(),
        "the -c source must not run when it follows the script file"
    );
}

/// A hook error other than `Unsupported` surfaces as exit 1 with a `python:` prefix.
#[test]
fn python_hook_error_reports_exit_one() {
    let hook: strands_shell::os::ScriptInterpreter = Arc::new(move |_source: String| {
        Box::pin(async move {
            Err::<strands_shell::os::ScriptOutcome, _>(std::io::Error::other("monty exploded"))
        })
    });
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder().script_interpreter(hook).build().unwrap();
        let out = shell.run("python -c \"x\"").await;
        assert_eq!(out.status, 1, "a hook error (not Unsupported) is exit 1");
        assert!(
            out.stderr.contains("python:") && out.stderr.contains("monty exploded"),
            "the error must be surfaced with a python: prefix, got: {}",
            out.stderr
        );
    }));
}
