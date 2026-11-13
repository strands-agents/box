//! Shell semantics `main`'s vendored copy carried: a redirected group's status, `!` before a
//! compound, `set -e` under `!`, and stdin for a substitution, a subshell, and a compound stage.

mod support;

use strands_shell::Shell;

fn rt() -> (tokio::runtime::Runtime, tokio::task::LocalSet) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    (runtime, tokio::task::LocalSet::new())
}

macro_rules! shell_test {
    ($name:ident, $cmd:expr, $check:expr) => {
        #[test]
        fn $name() {
            let (rt, local) = rt();
            rt.block_on(local.run_until(async {
                let mut shell = support::builder().build().unwrap();
                let out = shell.run($cmd).await;
                #[allow(clippy::redundant_closure_call)]
                ($check)(&mut shell, out);
            }));
        }
    };
}

macro_rules! expect {
    ($name:ident, $cmd:expr, $stdout:expr) => {
        shell_test!(
            $name,
            $cmd,
            |_shell: &mut Shell, out: strands_shell::Output| {
                assert_eq!(out.stdout.trim(), $stdout, "stdout mismatch");
                assert_eq!(out.status, 0, "expected exit 0, got {}", out.status);
            }
        );
    };
}
// ── Status of a redirected group ────────────────────────────────────

expect!(
    a_redirected_group_keeps_its_failure_status,
    "{ false; } > /tmp/rgs1; echo $?",
    "1"
);
expect!(
    a_redirected_group_keeps_its_success_status,
    "{ true; } > /tmp/rgs2; echo $?",
    "0"
);
expect!(
    a_redirected_group_keeps_its_last_command_status,
    "{ echo out; (exit 7); } > /tmp/rgs3; echo $?; cat /tmp/rgs3",
    "7\nout"
);
expect!(
    a_condition_on_a_redirected_group_takes_the_failure_branch,
    "if { false; } > /tmp/rgs4; then echo allow; else echo deny; fi",
    "deny"
);
shell_test!(
    a_redirected_group_is_the_calls_status,
    "{ false; } 2> /tmp/rgs5",
    |_shell: &mut Shell, out: strands_shell::Output| {
        assert_eq!(out.status, 1, "the call must report the group's status");
    }
);

// ── Standard input reaches a command substitution and a subshell ────

/// Run `command` with `input` on the shell's standard input, then end-of-file.
async fn run_with_stdin(command: &str, input: &[u8]) -> strands_shell::Output {
    let mut shell = support::builder().build().unwrap();
    let (sender, receiver) = tokio::sync::mpsc::channel(4);
    sender
        .send(bytes::Bytes::copy_from_slice(input))
        .await
        .unwrap();
    drop(sender);
    shell.proc.set_channel_reader(0, receiver);
    shell.run(command).await
}

#[test]
fn a_command_substitution_reads_the_shells_stdin() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = run_with_stdin(r#"input=$(cat); printf '[%s]' "$input""#, b"{\"a\":1}\n").await;
        assert_eq!(out.stdout, "[{\"a\":1}]");
        assert_eq!(out.status, 0);
    }));
}

#[test]
fn a_subshell_reads_the_shells_stdin() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = run_with_stdin("(cat)", b"through a subshell").await;
        assert_eq!(out.stdout, "through a subshell");
    }));
}

#[test]
fn stdin_read_in_part_by_a_substitution_leaves_the_rest_to_the_shell() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let out = run_with_stdin(
            r#"first=$(read -r line; printf '%s' "$line"); rest=$(cat); printf '%s|%s' "$first" "$rest""#,
            b"one\ntwo\n",
        )
        .await;
        assert_eq!(out.stdout, "one|two");
    }));
}

// ── `!` before a compound command ───────────────────────────────────

expect!(
    negation_inverts_a_subshell,
    "! (false); echo $?; ! (true); echo $?",
    "0\n1"
);
expect!(
    negation_inverts_a_group,
    "! { false; }; echo $?; ! { true; }; echo $?",
    "0\n1"
);
expect!(
    negation_inverts_a_redirected_compound,
    "if ! (false) > /tmp/neg1; then echo then; else echo else; fi; ! { true; } 2> /tmp/neg2; echo $?",
    "then\n1"
);
expect!(
    negation_inverts_an_if_compound,
    "! if true; then true; fi; echo $?",
    "1"
);
expect!(
    negation_inverts_a_compound_inside_a_substitution,
    "out=$(! { false; } && echo ran); echo \"$out\"",
    "ran"
);

expect!(
    errexit_ignores_a_negated_command,
    "set -e; ! true; ! (true); ! { true; }; echo after",
    "after"
);

/// Commands that do not read stdin leave it for a later command, in a substitution, a subshell, or
/// a redirected stage.
#[test]
fn stdin_left_unread_by_a_command_reaches_the_next_reader() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        for (script, expected) in [
            ("x=$(jq -n 1); cat", "REAL"),
            ("x=$(date +%s); cat", "REAL"),
            ("(echo a | cat); cat", "a\nREAL"),
            (
                r#"d=$(dirname /a/b); x=$(cat); printf '[%s]' "$x""#,
                "[REAL]",
            ),
            ("(cat </dev/null); cat", "REAL"),
            ("x=$(cat </dev/null); cat", "REAL"),
            ("dirname /a >/dev/null; cat", "REAL"),
            ("x=$(printf inner | cat); cat", "REAL"),
            ("(printf x </dev/null); cat", "xREAL"),
            ("v=$(printf x </dev/null); cat", "REAL"),
            ("(printf x </absent); cat", "REAL"),
            ("printf x </dev/null; cat", "xREAL"),
        ] {
            let out = run_with_stdin(script, b"REAL").await;
            assert_eq!(
                out.stdout.trim_end(),
                expected,
                "{script}: stderr={}",
                out.stderr
            );
        }
    }));
}

expect!(
    errexit_ignores_a_failure_inside_a_negated_group,
    "set -e; ! { false; echo in; }; echo after",
    "in\nafter"
);

expect!(
    an_option_change_inside_a_negated_group_is_kept,
    "set +e; ! { set -e; true; }; case $- in *e*) echo on;; *) echo off;; esac",
    "on"
);
expect!(
    errexit_stays_suppressed_inside_a_negated_group_that_sets_it,
    "set -e; ! { set -e; false; echo inner; }; echo after",
    "inner\nafter"
);
shell_test!(
    errexit_set_inside_a_negated_group_applies_after_it,
    "set +e; ! { set -e; true; }; false; echo after",
    |_shell: &mut Shell, out: strands_shell::Output| {
        assert!(!out.stdout.contains("after"), "{}", out.stdout);
        assert_eq!(out.status, 1);
    }
);
expect!(
    errexit_cleared_inside_a_negated_group_stays_cleared,
    "set -e; ! { set +e; true; }; false; echo after",
    "after"
);

/// A call cancelled inside `!` leaves no errexit suppression for the next call on the same Shell.
#[test]
fn a_cancelled_negated_call_leaves_errexit_for_the_next_call() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = support::builder().build().unwrap();
        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            shell.run("set -e; ! { sleep 1; }; echo BEFORE"),
        )
        .await;
        assert!(
            cancelled.is_err(),
            "the first call must be cancelled mid-sleep"
        );
        let out = shell.run("set -e; false; echo AFTER").await;
        assert_eq!(out.stdout, "", "set -e must stop at false");
        assert_eq!(out.status, 1);
    }));
}

/// A compound command as the first stage of a pipeline reads the caller's stdin and leaves the rest
/// of it for a later command, in a substitution, in a subshell, and at the top level.
#[test]
fn a_compound_pipeline_hands_the_callers_stdin_back() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        for (script, expected) in [
            ("x=$({ printf x; } | cat); cat", "REAL\nNEXT\n"),
            ("x=$(printf x | cat); cat", "REAL\nNEXT\n"),
            ("x=$( (printf x) | cat); cat", "REAL\nNEXT\n"),
            ("x=$(if true; then printf x; fi | cat); cat", "REAL\nNEXT\n"),
            ("x=$(while false; do :; done | cat); cat", "REAL\nNEXT\n"),
            ("f() { printf x; }; x=$(f | cat); cat", "REAL\nNEXT\n"),
            ("({ printf x; } | cat >/dev/null); cat", "REAL\nNEXT\n"),
            ("( (printf x) | cat >/dev/null); cat", "REAL\nNEXT\n"),
            (
                "(if true; then printf x; fi | cat >/dev/null); cat",
                "REAL\nNEXT\n",
            ),
            ("{ printf x; } | cat >/dev/null; cat", "REAL\nNEXT\n"),
            ("x=$({ printf x; } | cat | cat); cat", "REAL\nNEXT\n"),
            (
                r#"x=$({ read a; printf %s "$a"; } | cat); printf '[%s]' "$x""#,
                "[REAL]",
            ),
            (r#"{ read a; printf %s "$a"; } | cat; printf '|'"#, "REAL|"),
        ] {
            let out = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                run_with_stdin(script, b"REAL\nNEXT\n"),
            )
            .await
            .expect("the command ends");
            assert_eq!(out.stdout, expected, "{script}: stderr={}", out.stderr);
            assert_eq!(out.status, 0, "{script}");
        }
    }));
}

/// A cancelled run stops the compound that starts a pipeline, so the end of input that arrives
/// later never lets it act on part of its input.
#[test]
fn a_cancelled_compound_pipeline_never_acts_after_its_run_is_dropped() {
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = support::builder().build().unwrap();
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        shell.proc.set_channel_reader(0, receiver);
        sender
            .send(bytes::Bytes::from_static(b"line\npart"))
            .await
            .unwrap();
        {
            let run =
                shell.run("{ read first; printf R > ready; x=$(cat); printf A > acted; } | cat");
            tokio::pin!(run);
            let _ = tokio::time::timeout(std::time::Duration::from_millis(300), &mut run).await;
        }
        drop(sender);
        for _ in 0..50 {
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let out = shell
            .run("cat ready; if [ -e acted ]; then printf ACTED; fi")
            .await;
        assert_eq!(
            out.stdout, "R",
            "a dropped run must not act on part of its input: {}",
            out.stderr
        );
    }));
}
