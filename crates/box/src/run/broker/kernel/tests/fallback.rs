//! A command the Shell does not implement reaches the box's kernel, and each one meets its own
//! decision before it runs.

use std::sync::Arc;

use strands_shell::Shell;

use box_shell::{ScriptOutcome, ScriptRunner, ShellKernel};

use super::{adapter, backend, limited, policy, run};

const SPAWN_AND_EXEC: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"shell:spawn", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
"#;

fn shell_with(source: &str, python: Option<ScriptRunner>) -> Shell {
    let kernel = ShellKernel::over(backend(&[]), adapter(policy(source)));
    limited(match python {
        Some(runner) => kernel.python(1024 * 1024, runner),
        None => kernel,
    })
}

/// A runner that reports the source it was handed.
fn echoing() -> ScriptRunner {
    Arc::new(|source| {
        Box::pin(async move {
            ScriptOutcome {
                status: 3,
                stdout: format!("ran {source}\n"),
                stderr: String::new(),
            }
        })
    })
}

#[test]
fn a_host_binary_is_refused_when_no_spawner_is_installed() {
    let output = run(async { shell_with(SPAWN_AND_EXEC, None).run("hostname").await });
    assert_eq!(output.status, 126, "{}", output.stderr);
    assert!(
        output.stderr.contains("requires a contained spawner"),
        "{}",
        output.stderr
    );
}

#[test]
fn a_denied_host_binary_reports_effect_denied_and_never_runs() {
    let output = run(async {
        shell_with(
            r#"permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);"#,
            None,
        )
        .run("hostname")
        .await
    });
    assert_eq!(output.status, 126, "{}", output.stderr);
    assert!(output.stderr.contains("effect denied"), "{}", output.stderr);
}

#[test]
fn a_command_found_nowhere_keeps_status_127() {
    let output = run(async {
        shell_with(SPAWN_AND_EXEC, None)
            .run("no-such-program-anywhere")
            .await
    });
    assert_eq!(output.status, 127, "{}", output.stderr);
    assert!(
        output
            .stderr
            .contains("no-such-program-anywhere: command not found"),
        "{}",
        output.stderr
    );
    assert!(
        output
            .stderr
            .contains("no file of this name is on the PATH that `box run` started with"),
        "the refusal says where the box looks for a bare name: {}",
        output.stderr
    );
    assert_eq!(
        output.stderr.matches("command not found").count(),
        1,
        "the Shell adds no second diagnostic: {}",
        output.stderr
    );
}

#[test]
fn a_missing_path_spelling_keeps_the_plain_status_127() {
    let output = run(async {
        shell_with(SPAWN_AND_EXEC, None)
            .run("/no-such-directory-anywhere/app")
            .await
    });
    assert_eq!(output.status, 127, "{}", output.stderr);
    assert!(
        output.stderr.contains("app: command not found"),
        "{}",
        output.stderr
    );
    assert!(
        !output.stderr.contains("PATH that `box run` started with"),
        "a spelling with a separator is not looked up on a PATH: {}",
        output.stderr
    );
}

#[test]
fn python_runs_in_the_script_runner_after_its_own_decision() {
    let (permitted, refused) = run(async {
        let permitted = shell_with(SPAWN_AND_EXEC, Some(echoing()))
            .run("python3 -c 'print(1)'")
            .await;
        let refused = shell_with(
            r#"permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
               when { context.input.program != "python3" };"#,
            Some(echoing()),
        )
        .run("python3 -c 'print(1)'")
        .await;
        (permitted, refused)
    });
    assert_eq!(permitted.status, 3, "{}", permitted.stderr);
    assert_eq!(permitted.stdout, "ran print(1)\n");
    assert_eq!(refused.status, 126, "{}", refused.stderr);
    assert!(refused.stdout.is_empty(), "{}", refused.stdout);
}

#[test]
fn python_refuses_an_invocation_it_cannot_run() {
    let output = run(async {
        let mut shell = shell_with(SPAWN_AND_EXEC, Some(echoing()));
        let repl = shell.run("python").await;
        let two = shell.run("python a.py b.py").await;
        let version = shell.run("python --version").await;
        (repl, two, version)
    });
    let (repl, two, version) = output;
    assert_eq!(repl.status, 2);
    assert!(repl.stderr.contains("no REPL"), "{}", repl.stderr);
    assert_eq!(two.status, 2);
    assert!(
        two.stderr.contains("only one script file"),
        "{}",
        two.stderr
    );
    assert_eq!(version.stdout, "Monty (Strands-Box Python subset)\n");
}

/// A Call settles each fallback stage it decided and never ran, so history sees it as
/// indeterminate before the next Call.
#[test]
fn a_call_settles_a_fallback_stage_that_never_ran() {
    let source = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when { context.input.program != "printf" && context.input.program != "blocked" };
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when { context.input.program == "printf" }
when temporal {
    formerly within 60s
    Box::Action::"shell:exec"::response{ input.program: "no-such-tool", output.status: -1 }
};
"#;
    let (refused, gated) = run(async {
        let kernel = Arc::new(ShellKernel::over(backend(&[]), adapter(policy(source))));
        let shell = Shell::with_kernel(Arc::clone(&kernel) as Arc<dyn strands_shell::os::Kernel>);
        let hosted = crate::run::broker::shell::HostedShell { shell, kernel };
        let (mut program, _output, _control) = crate::run::broker::program::Program::adopt(
            hosted,
            None,
            crate::record::config::limits::DEFAULT_SHELL_MAX_STDIN,
        )
        .expect("a program");
        let refused = program.call("no-such-tool | blocked").await.status;
        let gated = program.call("printf gated").await.status;
        (refused, gated)
    });
    assert_eq!(refused, 126);
    assert_eq!(gated, 0, "the unrun stage was recorded as indeterminate");
}

#[test]
fn a_piped_loop_is_decided_on_its_own_commands() {
    let output = run(async {
        shell_with(
            r#"permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
               when { ["printf", "read", "echo"].contains(context.input.program) };"#,
            None,
        )
        .run("printf 'x\\n' | while read x; do echo \"$x\"; done")
        .await
    });
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert_eq!(output.stdout, "x\n");
}

/// **Without a Monty runner, a bare `python3` is a host program like any other.** With
/// `monty = false` Box installs no runner, so the name reaches the file `[tool.python3]` declares,
/// after its own `shell:spawn` decision. While a runner is installed, Monty answers the same name.
#[test]
fn without_a_monty_runner_python3_runs_its_declared_program() {
    let directory = tempfile::tempdir().expect("tempdir");
    let python3 = directory
        .path()
        .canonicalize()
        .expect("canonical")
        .join("python3");
    std::fs::write(&python3, "").expect("a program file");
    let programs: box_shell::HostPrograms = Arc::new(std::collections::BTreeMap::from([(
        "python3".to_string(),
        python3.clone(),
    )]));
    let spawner: box_shell::HostSpawner = Arc::new(|spawn: box_shell::HostSpawn| {
        Box::pin(async move {
            Ok(box_shell::HostSpawnOutcome {
                status: 0,
                stdout: format!(
                    "spawned {} {}\n",
                    spawn.program.display(),
                    spawn.args.join(" ")
                )
                .into_bytes(),
                stderr: Vec::new(),
            })
        })
    });
    let shell = |python: Option<ScriptRunner>| {
        let kernel = ShellKernel::over(backend(&[]), adapter(policy(SPAWN_AND_EXEC)))
            .programs(Arc::clone(&programs))
            .spawner(Arc::clone(&spawner));
        limited(match python {
            Some(runner) => kernel.python(1024 * 1024, runner),
            None => kernel,
        })
    };

    let off = run(async { shell(None).run("python3 --version").await });
    assert_eq!(off.status, 0, "{}", off.stderr);
    assert_eq!(
        off.stdout,
        format!("spawned {} --version\n", python3.display())
    );

    // A program from stdin would arrive empty, so these refuse before the spawn instead of
    // succeeding with no output.
    for command in [
        "python3 <<'EOF'\nprint(1)\nEOF",
        "printf 'print(1)' | python3",
        "printf 'print(1)' | python3 -",
    ] {
        let refused = run(async { shell(None).run(command).await });
        assert_eq!(refused.status, 2, "{command}: {}", refused.stderr);
        assert!(
            refused
                .stderr
                .contains("python3: reading a program from stdin is not supported"),
            "{command}: {}",
            refused.stderr
        );
        assert!(
            !refused.stdout.contains("spawned"),
            "{command} started nothing: {}",
            refused.stdout
        );
    }

    let on = run(async { shell(Some(echoing())).run("python3 -c 'print(1)'").await });
    assert!(
        on.stdout.starts_with("ran "),
        "Monty answers while a runner is installed: {} {}",
        on.stdout,
        on.stderr
    );
}

/// **Monty's refusal of `-m` says how to run real Python**, since `python3 -m pytest` or `-m venv`
/// is the usual first try at it.
#[test]
fn monty_refuses_dash_m_and_names_the_real_python_switch() {
    let output = run(async {
        shell_with(SPAWN_AND_EXEC, Some(echoing()))
            .run("python3 -m pytest -q")
            .await
    });
    assert_eq!(output.status, 1, "{}", output.stderr);
    assert!(
        output
            .stderr
            .starts_with("python3: -m is not supported by Monty")
            && output.stderr.contains(box_shell::REAL_PYTHON_HINT),
        "{}",
        output.stderr
    );
    assert!(
        !output.stdout.contains("ran "),
        "nothing reached Monty: {}",
        output.stdout
    );
}
