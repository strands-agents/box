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
        let (mut program, _output, _control) =
            crate::run::broker::program::Program::adopt(hosted, None).expect("a program");
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
