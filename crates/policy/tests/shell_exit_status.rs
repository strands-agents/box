//! The exit status of a shell command, on `output.status` of its `::response`.

mod support;

use std::path::PathBuf;

use policy::{Decision, GovernedBox, Outcome, Policy, PolicyEngine, Principal, Request};

fn loaded(source: &str) -> PolicyEngine {
    support::open_policy(vec![Policy {
        origin: PathBuf::from("shell-exit-status.dw"),
        text: source.to_string(),
    }])
    .expect("policy loads")
}

fn governed() -> GovernedBox {
    GovernedBox::assigned("test-box")
}

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| (*w).to_string()).collect()
}

fn allows(policy: &PolicyEngine, request: &Request<'_>) -> bool {
    matches!(
        policy.decide(&governed(), &Principal::agent(), request),
        Decision::Allow { .. }
    )
}

fn spawn<'a>(command: &'a str, program: &'a str, words: &'a [String]) -> Request<'a> {
    Request::ShellSpawn {
        command,
        program,
        program_path: "/usr/bin/tool",
        credential_reads: &[],
        args: words,
        cwd: "/workspace",
    }
}

fn exec<'a>(command: &'a str, program: &'a str, words: &'a [String]) -> Request<'a> {
    Request::ShellExec {
        command,
        program,
        args: words,
        cwd: "/workspace",
    }
}

/// Admit one host binary, then record that it ended with `status`.
fn spawned(policy: &PolicyEngine, command: &str, program: &str, words: &[&str], status: i32) {
    let words = args(words);
    assert!(
        allows(policy, &spawn(command, program, &words)),
        "`{command}` must be admitted before it records an outcome"
    );
    policy
        .record(
            &governed(),
            &Principal::agent(),
            &Outcome::ShellSpawn {
                command,
                program,
                program_path: "/usr/bin/tool",
                credential_reads: &[],
                args: &words,
                cwd: "/workspace",
                status,
            },
        )
        .expect("history records the spawn");
}

/// Admit one Shell-implemented command, then record that it ended with `status`.
fn executed(policy: &PolicyEngine, command: &str, program: &str, words: &[&str], status: i32) {
    let words = args(words);
    assert!(
        allows(policy, &exec(command, program, &words)),
        "`{command}` must be admitted before it records an outcome"
    );
    policy
        .record(
            &governed(),
            &Principal::agent(),
            &Outcome::ShellRun {
                command,
                program,
                args: &words,
                cwd: "/workspace",
                status,
            },
        )
        .expect("history records the run");
}

const SPAWN_GATE: &str = r#"
permit (principal, action == Box::Action::"shell:spawn", resource);
@id("deploy_after_passing_check")
forbid (principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program == "deploy" }
unless temporal {
    formerly within 10m
    Box::Action::"shell:spawn"::response{ input.program: "check", output.status: 0 }
};
"#;

const EXEC_GATE: &str = r#"
permit (principal, action == Box::Action::"shell:exec", resource);
@id("deploy_after_passing_test")
forbid (principal, action == Box::Action::"shell:exec", resource)
when { context.input.program == "deploy" }
unless temporal {
    formerly within 10m
    Box::Action::"shell:exec"::response{ input.program: "test", output.status: 0 }
};
"#;

/// A `deploy` gate on a `check` spawn that ended with `status`.
fn spawn_gate_on(status: i32) -> String {
    SPAWN_GATE.replace("output.status: 0", &format!("output.status: {status}"))
}

#[test]
fn an_arbitrary_exit_code_reaches_history_unchanged() {
    let none = args(&[]);
    for (gate, permitted) in [(42, true), (0, false), (1, false)] {
        let policy = loaded(&spawn_gate_on(gate));
        spawned(&policy, "check", "check", &[], 42);
        assert_eq!(
            allows(&policy, &spawn("deploy", "deploy", &none)),
            permitted,
            "a check that exited 42 against `output.status: {gate}`"
        );
    }
}

#[test]
fn a_spawn_response_matches_on_its_exit_status() {
    let policy = loaded(SPAWN_GATE);
    let none = args(&[]);

    spawned(&policy, "check", "check", &[], 1);
    assert!(
        !allows(&policy, &spawn("deploy", "deploy", &none)),
        "a check that exited 1 must not satisfy `output.status: 0`"
    );

    spawned(&policy, "check", "check", &[], 0);
    assert!(
        allows(&policy, &spawn("deploy", "deploy", &none)),
        "a check that exited 0 must satisfy `output.status: 0`"
    );
}

#[test]
fn an_exec_response_matches_on_its_exit_status() {
    let policy = loaded(EXEC_GATE);
    let none = args(&[]);

    executed(&policy, "test -z x", "test", &["-z", "x"], 1);
    assert!(
        !allows(&policy, &exec("deploy", "deploy", &none)),
        "a test that exited 1 must not satisfy `output.status: 0`"
    );

    executed(&policy, "test -n x", "test", &["-n", "x"], 0);
    assert!(
        allows(&policy, &exec("deploy", "deploy", &none)),
        "a test that exited 0 must satisfy `output.status: 0`"
    );
}

const PUSH_AFTER_PASSING_TEST: &str = r#"
permit (principal, action == Box::Action::"shell:spawn", resource);
@id("push_after_passing_test")
forbid (principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program == "git" && context.input has arg1 && context.input.arg1 == "push" }
unless temporal {
    !Box::Action::"shell:spawn"::response{ input.program: "git", input.arg1: "commit" }
    since within 10m
    Box::Action::"shell:spawn"::response{ input.program: "npm", input.arg1: "test", output.status: 0 }
};
"#;

#[test]
fn a_push_needs_a_passing_test_since_the_last_commit() {
    let policy = loaded(PUSH_AFTER_PASSING_TEST);
    let push_words = args(&["push"]);
    let push = spawn("git push", "git", &push_words);

    assert!(
        !allows(&policy, &push),
        "no test has run, so the push is refused"
    );

    spawned(&policy, "npm test", "npm", &["test"], 1);
    assert!(
        !allows(&policy, &push),
        "a failing `npm test` must not permit the push"
    );

    spawned(&policy, "npm test", "npm", &["test"], 0);
    assert!(
        allows(&policy, &push),
        "a passing `npm test` must permit the push"
    );

    spawned(
        &policy,
        "git commit -m change",
        "git",
        &["commit", "-m", "change"],
        0,
    );
    assert!(
        !allows(&policy, &push),
        "a commit after the passing test must refuse the push again"
    );
}
