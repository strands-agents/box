//! Temporal policy enforced through the real Shell and its mediated kernel.
//!
//! This drives `Shell::run` and the direct file API, so the effects are the ones the
//! kernel actually resolves — not hand-built `Request` values. It proves the loop that
//! makes a history-dependent rule enforceable at the filesystem boundary:
//!
//! ```text
//! Shell::run -> Mediated::admit -> ShellPolicyInterceptor::intercept -> PolicyEngine::decide
//!                    |                                                       ^
//!                    '-> effect -> record_outcome -> PolicyEngine::record ----------'
//! ```

#![cfg(feature = "shell-adapter")]

mod support;

use std::path::PathBuf;
use std::sync::Arc;

use policy::{GovernedBox, Policy, PolicyEngine, Principal, ShellPolicyInterceptor};
use strands_shell::Shell;

/// Run a future on the current-thread runtime the Shell requires.
///
/// The Shell uses `spawn_local`, so it needs a `LocalSet`; a multi-thread runtime
/// panics.
fn run<F, T>(body: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime builds");
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(body))
}

fn shell_governed_by(source: &str) -> (Shell, Arc<PolicyEngine>) {
    let policy = Arc::new(
        support::open_policy(vec![Policy {
            origin: PathBuf::from("shell-temporal.dw"),
            text: source.to_string(),
        }])
        .expect("policy loads"),
    );
    let interceptor = ShellPolicyInterceptor::into_handle(
        Arc::clone(&policy),
        Principal::agent(),
        GovernedBox::assigned("test-box"),
    );
    let shell = Shell::builder()
        .effect_interceptor(interceptor)
        .build()
        .expect("shell builds");
    (shell, policy)
}

/// Permit every command and every filesystem operation.
const PERMIT_ALL: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:delete", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource);
"#;

#[test]
fn the_operation_reaches_policy_so_enumeration_is_separable_from_reading() {
    // The vocabulary extension, proven at the boundary: enumeration and content read
    // are both `fs:read`, so before `context.input.operation` existed a rule could not
    // permit listing a directory while refusing to read the files in it.
    let source = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when { context.input.operation != Box::FsReadOperation::"read_content" };
"#;
    let (mut shell, _policy) = shell_governed_by(source);

    run(async {
        // Writing and listing are permitted.
        shell
            .write_file("/tmp/visible.txt", b"payload")
            .await
            .expect("write is permitted");
        let listing = shell.run("ls /tmp").await;
        assert_eq!(
            listing.status, 0,
            "enumeration is permitted; stderr: {}",
            listing.stderr
        );
        assert!(listing.stdout.contains("visible.txt"));

        // Reading content is refused, though it is the same `fs:read` action.
        let read = shell.read_file("/tmp/visible.txt").await;
        assert!(
            read.is_err(),
            "a content read must be refused while enumeration is allowed"
        );
    });
}

#[test]
fn a_write_budget_denies_through_the_real_kernel_once_history_accumulates() {
    // A history-dependent rule at the filesystem boundary: permit a write only while
    // fewer than two writes have completed in the last 60 seconds.
    //
    // The count walks `fs:write::response` events, which exist only because the
    // permit records the outcome — so this fails if `record_outcome` is a no-op.
    let source = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when temporal {
    exists (total: Long). (
        (count for (t: Timepoint). where (
            formerly within 60s (
                Box::Action::"fs:write"::response{ input.path: _, input.operation: Box::FsWriteOperation::"write_content" } && tp(t)
            )
        )) == total
        && total < 6
    )
};
"#;
    let (mut shell, _policy) = shell_governed_by(source);

    run(async {
        // Each `write_file` raises more than one effect (a parent `create_dir` probe,
        // then the open), so the budget is consumed faster than one per call. What
        // matters is that it is consumed by *recorded history* and eventually denies.
        let mut wrote = 0usize;
        let mut denied_at = None;
        for index in 0..8 {
            let path = format!("/tmp/budget-{index}.txt");
            match shell.write_file(&path, b"x").await {
                Ok(()) => wrote += 1,
                Err(_) => {
                    denied_at = Some(index);
                    break;
                }
            }
        }

        assert!(wrote > 0, "the first write must be permitted");
        let denied_at = denied_at.expect("the write budget must eventually deny");
        assert!(
            denied_at > 0,
            "a denial on the very first write would mean the rule never permitted"
        );

        // Once tripped it stays tripped: the run is far shorter than the 60s window,
        // and a denied write records no completion.
        for index in 0..3 {
            let path = format!("/tmp/after-{index}.txt");
            assert!(
                shell.write_file(&path, b"x").await.is_err(),
                "the budget must hold for the whole window"
            );
        }
    });
}

#[test]
fn a_stateless_policy_permits_the_same_writes() {
    // The control for the test above. Same shell, same calls, no temporal clause: every
    // write succeeds. Without this, a denial could be any unrelated kernel refusal
    // rather than the budget.
    let (mut shell, _policy) = shell_governed_by(PERMIT_ALL);

    run(async {
        for index in 0..8 {
            let path = format!("/tmp/control-{index}.txt");
            shell
                .write_file(&path, b"x")
                .await
                .unwrap_or_else(|error| panic!("write {index} must be permitted: {error}"));
        }
    });
}

#[test]
fn a_denied_effect_does_not_happen() {
    // A denial must prevent the effect, not merely fail to report it.
    let source = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
"#;
    let (mut shell, _policy) = shell_governed_by(source);

    run(async {
        assert!(
            shell
                .write_file("/tmp/never.txt", b"payload")
                .await
                .is_err(),
            "no fs:write permit exists, so the write is refused"
        );
        // The file is absent, so reading it fails for absence rather than for policy.
        assert!(
            shell.read_file("/tmp/never.txt").await.is_err(),
            "a refused write must leave nothing behind"
        );
    });
}

#[test]
fn an_absent_policy_denies_every_effect() {
    // Deny-by-default at the boundary: an empty policy set loads, so nothing matches and
    // every effect is refused.
    let policy = Arc::new(support::open_policy(Vec::new()).expect("an empty policy set loads"));
    let interceptor = ShellPolicyInterceptor::into_handle(
        policy,
        Principal::agent(),
        GovernedBox::assigned("test-box"),
    );
    let mut shell = Shell::builder()
        .effect_interceptor(interceptor)
        .build()
        .expect("shell builds");

    run(async {
        assert!(shell.write_file("/tmp/x.txt", b"x").await.is_err());
        assert!(shell.read_file("/etc/passwd").await.is_err());
        let output = shell.run("ls /").await;
        assert_ne!(output.status, 0, "an unpermitted command must fail");
    });
}

#[test]
fn a_symlink_cannot_launder_a_denied_read() {
    // Two independent defenses, asserted together.
    //
    // 1. **Linking to a denied target is itself refused.** The source leg of a
    //    two-path operation is authorized as a content read as well as the operation,
    //    because the target's bytes become reachable through the new name. So the
    //    ordinary way to fence off a secret — a rule refusing reads of it — also stops
    //    the agent from linking to it.
    // 2. **Even if a link exists, reading through it is refused.** The kernel authorizes
    //    the *resolved* path, so policy sees the target rather than the link. This holds
    //    independently of (1), which is why the link is staged under a policy that
    //    permits it before the read is attempted.
    let denied_read = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
unless {
    context.input.operation == Box::FsReadOperation::"read_content" &&
    context.input.path like "*/forbidden*"
};
"#;

    // (1) The link is refused, because creating it reads the target it names.
    let (mut shell, _policy) = shell_governed_by(denied_read);
    run(async {
        shell
            .write_file("/tmp/forbidden.txt", b"secret")
            .await
            .expect("staging is permitted");
        let link = shell
            .run("ln -s /tmp/forbidden.txt /tmp/innocent.txt")
            .await;
        assert_ne!(
            link.status, 0,
            "linking to a read-denied target must be refused: {}",
            link.stderr
        );
    });

    // (2) With linking permitted, the read through the link is still refused on the
    // resolved path. `unless` now excludes only the link's own name, so creating it is
    // allowed and the denial can only come from resolving to the target.
    let link_allowed = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when { context.input.operation == Box::FsReadOperation::"read_content" && context.input.path like "*/forbidden*" };
"#;
    let (mut shell, _policy) = shell_governed_by(link_allowed);
    run(async {
        shell
            .write_file("/tmp/forbidden2.txt", b"secret")
            .await
            .expect("staging is permitted");
        // The `forbid` reaches the source leg, so this link is refused too — which is
        // the point of (1). Assert the read denial on a link made outside the Shell.
        std::os::unix::fs::symlink("/tmp/forbidden2.txt", "/tmp/innocent2.txt").ok();
        assert!(
            shell.read_file("/tmp/innocent2.txt").await.is_err(),
            "a symlink must not launder a denied read: policy sees the resolved target"
        );
        let _ = std::fs::remove_file("/tmp/innocent2.txt");
    });
}

#[test]
fn a_denied_attempt_satisfies_a_request_keyed_precondition() {
    // A KNOWN HAZARD, pinned so it cannot change silently.
    //
    // The engine observes an event into history *before* it decides, and the event
    // carries no verdict. So a temporal predicate keyed on `::request` matches an
    // attempt that was REFUSED: a step-up rule of the form "you may write only after
    // reading the approval" is defeated by asking for the approval and being denied.
    //
    // `::response` is the safe spelling — it exists only for an effect that actually
    // happened, because only `PolicyEngine::record` emits it. This test asserts the unsafe
    // spelling behaves as described rather than pretending it is safe; fixing it means
    // changing the engine's ingest order, which is upstream.
    let unsafe_precondition = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when { context.input.path like "/tmp/secret*" };
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when temporal {
    formerly within 3600s (
        Box::Action::"fs:read"::request{ input.path: "/tmp/secret-approval", input.operation: Box::FsReadOperation::"read_content" }
    )
};
"#;
    let (mut shell, _policy) = shell_governed_by(unsafe_precondition);
    run(async {
        assert!(
            shell.write_file("/tmp/pre-a.txt", b"x").await.is_err(),
            "the precondition has not been met, so the write is refused"
        );
        assert!(
            shell.read_file("/tmp/secret-approval").await.is_err(),
            "reading the approval is forbidden"
        );
        assert!(
            shell.write_file("/tmp/pre-b.txt", b"x").await.is_ok(),
            "KNOWN HAZARD: the refused read still satisfied the ::request predicate"
        );
    });
}

#[test]
fn a_resolution_keyed_precondition_is_not_satisfied_by_a_denied_attempt() {
    // The safe spelling, and the reason it is safe: a `::response` exists only when
    // `PolicyEngine::record` submitted one, and a refused effect never records. This is the
    // form an author must use for a precondition.
    let safe_precondition = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when { context.input.path like "/tmp/secret*" };
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when temporal {
    formerly within 3600s (
        Box::Action::"fs:read"::response{ input.path: "/tmp/secret-approval", input.operation: Box::FsReadOperation::"read_content" }
    )
};
"#;
    let (mut shell, _policy) = shell_governed_by(safe_precondition);
    run(async {
        assert!(shell.read_file("/tmp/secret-approval").await.is_err());
        assert!(
            shell.write_file("/tmp/safe.txt", b"x").await.is_err(),
            "a refused read records no resolution, so the precondition stays unmet"
        );
    });
}

#[test]
fn a_rename_source_satisfies_a_response_keyed_precondition() {
    // A rename authorizes the source as a content read, and the
    // temporal guard the product documents keys on `fs:read::response`, so a successful
    // rename must record that source read into history.
    let source = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource);
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when temporal {
    formerly within 3600s (
        Box::Action::"fs:read"::response{
            input.path: "/tmp/secret.txt",
            input.operation: Box::FsReadOperation::"read_content"
        }
    )
};
"#;
    let (mut shell, _policy) = shell_governed_by(source);

    run(async {
        shell
            .write_file("/tmp/secret.txt", b"TOPSECRET")
            .await
            .expect("staging the secret is permitted before any read");

        let renamed = shell.run("mv /tmp/secret.txt /tmp/loot.txt").await;
        assert_eq!(renamed.status, 0, "rename must succeed: {}", renamed.stderr);

        let read = shell.run("cat /tmp/loot.txt").await;
        assert_eq!(
            read.status, 0,
            "the moved file must stay readable: {}",
            read.stderr
        );
        assert_eq!(read.stdout.trim(), "TOPSECRET");

        assert!(
            shell.write_file("/tmp/exfil.txt", b"EXFIL").await.is_err(),
            "a rename of the secret must satisfy the response-keyed guard and deny the later write"
        );
    });
}

#[test]
fn an_ancestor_wildcard_cannot_enumerate_a_forbidden_directory() {
    // Regression guard. A glob authorizes the directory each match came out of, not
    // just the literal prefix before the first wildcard. Authorizing only the prefix
    // let `/tmp/*/*` read a directory a `forbid` protected: `ls /tmp/private` was
    // denied while `cat /tmp/*/key.pem` returned its contents.
    let source = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when {
    context.input.operation == Box::FsReadOperation::"enumerate" &&
    context.input.path like "/tmp/private*"
};
"#;
    let (mut shell, _policy) = shell_governed_by(source);
    run(async {
        shell.run("mkdir -p /tmp/private").await;
        shell
            .write_file("/tmp/private/key.pem", b"TOPSECRET")
            .await
            .expect("staging is permitted");

        // The direct spelling is denied.
        assert_ne!(shell.run("ls /tmp/private").await.status, 0);

        // And so is the ancestor-wildcard spelling: the pattern does not expand, so no
        // name is disclosed.
        let disclosed = shell.run("echo /tmp/*/*").await;
        assert!(
            !disclosed.stdout.contains("key.pem"),
            "an ancestor wildcard must not disclose names in a forbidden directory: {}",
            disclosed.stdout.trim()
        );

        // And the contents stay unreadable through it.
        let read = shell.run("cat /tmp/*/key.pem").await;
        assert!(
            !read.stdout.contains("TOPSECRET"),
            "an ancestor wildcard must not read through a forbidden directory"
        );
    });
}

#[test]
fn a_denied_workload_cannot_inflate_decision_latency() {
    // Regression guard for an availability defect. The engine observes a request into
    // history before deciding it, so an UNAUTHORIZED caller still grows the trace — and
    // with the frontend's default engine, which retains every event and rescans all of
    // history per decision, 8000 denied reads pushed one legitimate write from 1.9ms to
    // 3.7ms and climbing, with no bound.
    //
    // The window-pruning engine evicts events older than the installed leaves' lookback
    // reach, so cost is bounded by the policy's own window rather than by traffic. This
    // asserts the late latency is within a constant factor of the early latency; with the
    // unbounded engine the ratio grows without limit.
    let source = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when temporal {
    exists (n: Long). (
        (count for (t: Timepoint). where (
            formerly within 1s (Box::Action::"fs:write"::response{ input.path: _, input.operation: Box::FsWriteOperation::"write_content" } && tp(t))
        )) == n && n < 1000000
    )
};
"#;
    let (mut shell, _policy) = shell_governed_by(source);
    run(async {
        // Each round takes several write samples and reports the median, so a shared-runner
        // scheduling spike on one sample cannot trip an assertion the test only meant to
        // trip on a growth trend. The bound is a growth ratio, not an absolute latency.
        const ROUNDS: usize = 4;
        const SAMPLES_PER_ROUND: usize = 5;
        let mut medians = Vec::new();
        for round in 0..ROUNDS {
            // Denied reads: no `fs:read` permit exists, so none of these is authorized.
            for _ in 0..1500 {
                let _ = shell.read_file("/tmp/absent.txt").await;
            }
            let mut samples = Vec::with_capacity(SAMPLES_PER_ROUND);
            for sample in 0..SAMPLES_PER_ROUND {
                let start = std::time::Instant::now();
                let _ = shell
                    .write_file(&format!("/tmp/lat-{round}-{sample}.txt"), b"x")
                    .await;
                samples.push(start.elapsed());
            }
            samples.sort();
            medians.push(samples[SAMPLES_PER_ROUND / 2]);
        }

        let first = medians[0].as_micros().max(1);
        let last = medians[medians.len() - 1].as_micros();
        assert!(
            last < first * 4,
            "decision latency must stay bounded as a denied workload grows the trace; \
             first={first}us last={last}us medians={medians:?}"
        );
    });
}

/// One `Output`, rendered for an assertion message.
fn rendered(out: &strands_shell::Output) -> String {
    format!(
        "status={} stdout={:?} stderr={:?}",
        out.status, out.stdout, out.stderr
    )
}

/// A `PATH` entry that holds nothing leaves no `fs:read` event in history.
#[test]
fn a_path_walk_leaves_no_history_for_the_entries_that_hold_nothing() {
    let source = format!(
        r#"{PERMIT_ALL}
permit(principal == Box::Agent::"self", action == Box::Action::"shell:spawn", resource);
forbid(principal == Box::Agent::"self", action in [Box::Action::"shell:exec", Box::Action::"shell:spawn"], resource)
when temporal {{
    formerly within 3600s (
        Box::Action::"fs:read"::request{{ input.path: "/home/lash/one/tool", input.operation: _ }}
    )
}};
"#
    );
    let policy = Arc::new(
        support::open_policy(vec![Policy {
            origin: PathBuf::from("shell-temporal-path-walk.dw"),
            text: source,
        }])
        .expect("policy loads"),
    );
    let interceptor = ShellPolicyInterceptor::into_handle(
        Arc::clone(&policy),
        Principal::agent(),
        GovernedBox::assigned("test-box"),
    );
    let mut shell = Shell::builder()
        .effect_interceptor(interceptor)
        .env("PATH", "/home/lash/one:/home/lash/two:/home/lash/three")
        .build()
        .expect("shell builds");

    run(async {
        let planted = shell
            .run(
                "mkdir -p /home/lash/one /home/lash/two /home/lash/three && \
                 printf '#!/bin/sh\\necho FOUND-three\\n' > /home/lash/three/tool && \
                 chmod +x /home/lash/three/tool",
            )
            .await;
        assert_eq!(planted.status, 0, "setup: {}", planted.stderr);

        let out = shell.run("tool").await;
        assert_eq!(
            out.status, 0,
            "the entries that hold nothing must leave no history: {}",
            out.stderr
        );
        assert!(out.stdout.contains("FOUND-three"), "{}", rendered(&out));
    });
}

/// A shell whose paths under `home` reach policy spelled `~/…`.
fn shell_governed_under_home(source: &str, home: &str) -> Shell {
    let policy = Arc::new(
        support::open_policy(vec![Policy {
            origin: PathBuf::from("shell-temporal-cap.dw"),
            text: source.to_string(),
        }])
        .expect("policy loads"),
    );
    let interceptor = ShellPolicyInterceptor::into_handle_reporting_under(
        policy,
        Principal::agent(),
        GovernedBox::assigned("test-box"),
        home,
    );
    Shell::builder()
        .effect_interceptor(interceptor)
        .build()
        .expect("shell builds")
}

/// A narrow permit: content writes under `~/project`, plus the directory creation a write's
/// parent probe raises, and nothing else.
const NARROW_WRITE: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when { context.input.operation == Box::FsWriteOperation::"create_dir" };
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when { context.input.path like "~/project/*" };
"#;

/// The content writes completed in the last hour, as a temporal count.
const COMPLETED_WRITES: &str = r#"(count for (t: Timepoint). where (
    formerly within 3600s (
        Box::Action::"fs:write"::response{ input.path: _, input.operation: Box::FsWriteOperation::"write_content" } && tp(t)
    )
))"#;

#[test]
fn a_cap_written_as_a_permit_beside_a_broader_permit_is_refused_at_load() {
    // The load refuses the provable shape and warns on the heuristic one.
    let cap = format!(
        r#"@id("write_budget")
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when temporal {{
    exists (total: Long). ( {COMPLETED_WRITES} == total && total < 3 )
}};
"#
    );
    let beside_a_broad_permit = format!(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
@id("all_writes")
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
{cap}"#
    );
    match support::open_policy(vec![Policy {
        origin: PathBuf::from("shell-temporal-cap.dw"),
        text: beside_a_broad_permit,
    }]) {
        Err(policy::PolicyError::InertTemporalPermit(reason)) => assert_eq!(
            reason,
            "rule @id(\"write_budget\") (rule 3) carries a temporal clause beside rule \
             @id(\"all_writes\") (rule 2), which permits the same action with no condition; a permit \
             cannot narrow another permit, so write the cap as a forbid"
        ),
        Err(other) => panic!("expected the inert-cap refusal, got {other}"),
        Ok(_) => panic!("FAIL-OPEN: a cap written as a permit beside a broader permit loaded"),
    }

    let beside_narrow_permits = format!("{NARROW_WRITE}{cap}");
    let engine = support::open_policy(vec![Policy {
        origin: PathBuf::from("shell-temporal-cap.dw"),
        text: beside_narrow_permits.clone(),
    }])
    .expect("the heuristic shape loads with a warning");
    let warnings: Vec<String> = engine.warnings().iter().map(ToString::to_string).collect();
    assert_eq!(
        warnings.len(),
        2,
        "one warning per conditioned fs:write permit: {warnings:?}"
    );
    assert!(
        warnings.iter().all(|warning| {
            warning
                .starts_with("rule @id(\"write_budget\") (rule 5) carries a temporal clause beside")
                && warning.ends_with("so write a cap as a forbid")
        }),
        "{warnings:?}"
    );
}

#[test]
fn a_cap_written_as_a_permit_beside_narrow_permits_widens_the_policy_to_a_path_no_permit_names() {
    // The warned shape at the real kernel: the permit admits a write outside the narrow grant
    // while its count is under three, and it never limits an in-grant write.
    let source = format!(
        r#"{NARROW_WRITE}
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when temporal {{
    exists (total: Long). ( {COMPLETED_WRITES} == total && total < 3 )
}};
"#
    );
    let mut shell = shell_governed_under_home(&source, "/home/lash");

    run(async {
        assert!(
            shell
                .write_file("/home/lash/other/first", b"x")
                .await
                .is_ok(),
            "FAIL-OPEN: the permit form admits a write outside the narrow grant"
        );
        for name in ["a", "b"] {
            shell
                .write_file(&format!("/home/lash/project/{name}.txt"), b"x")
                .await
                .expect("an in-grant write is permitted");
        }
        assert!(
            shell
                .write_file("/home/lash/other/second", b"x")
                .await
                .is_err(),
            "three writes spent the permit, so the outside path is back to default deny"
        );
        assert!(
            shell
                .write_file("/home/lash/project/c.txt", b"x")
                .await
                .is_ok(),
            "the permit form never limits a write the narrow permit grants"
        );
    });
}

#[test]
fn a_cap_written_as_a_forbid_grants_nothing_and_denies_the_write_past_its_budget() {
    let source = format!(
        r#"{NARROW_WRITE}
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when temporal {{
    exists (total: Long). ( {COMPLETED_WRITES} == total && total >= 3 )
}};
"#
    );
    let mut shell = shell_governed_under_home(&source, "/home/lash");

    run(async {
        assert!(
            shell
                .write_file("/home/lash/other/first", b"x")
                .await
                .is_err(),
            "the forbid form grants nothing outside the narrow permit"
        );
        for name in ["a", "b", "c"] {
            shell
                .write_file(&format!("/home/lash/project/{name}.txt"), b"x")
                .await
                .unwrap_or_else(|error| panic!("write {name} is under the budget: {error}"));
        }
        for name in ["d", "e"] {
            assert!(
                shell
                    .write_file(&format!("/home/lash/project/{name}.txt"), b"x")
                    .await
                    .is_err(),
                "write {name} is past the budget, so the cap denies it inside the grant"
            );
        }
    });
}

/// A `printf` gated on a `false` response that ended with `status`.
fn gated_on_false_ending_with(status: i32) -> String {
    format!(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
@id("after_false")
forbid(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when {{ context.input.program == "printf" }}
unless temporal {{
    formerly within 60s
    Box::Action::"shell:exec"::response{{ input.program: "false", output.status: {status} }}
}};
"#
    )
}

#[test]
fn a_background_command_records_its_own_exit_status_when_it_ends() {
    run(async {
        let (mut shell, _policy) = shell_governed_by(&gated_on_false_ending_with(1));
        shell.run("false & wait").await;
        let gated = shell.run("printf gated").await;
        assert_eq!(gated.status, 0, "{}", rendered(&gated));

        let (mut shell, _policy) = shell_governed_by(&gated_on_false_ending_with(0));
        let launched = shell.run("false & wait").await;
        assert_eq!(launched.status, 1, "{}", rendered(&launched));
        let gated = shell.run("printf gated").await;
        assert_ne!(
            gated.status,
            0,
            "the launch of a background `false` must not record status 0: {}",
            rendered(&gated)
        );
    });
}

#[test]
fn a_shell_function_sets_the_exec_status_of_the_program_it_names() {
    run(async {
        let (mut shell, _policy) = shell_governed_by(
            r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
@id("after_npm")
forbid(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when { context.input.program == "printf" }
unless temporal {
    formerly within 60s
    Box::Action::"shell:exec"::response{ input.program: "npm", output.status: 0 }
};
"#,
        );
        let faked = shell.run("npm() { return 0; }; npm test").await;
        assert_eq!(faked.status, 0, "{}", rendered(&faked));
        let gated = shell.run("printf gated").await;
        assert_eq!(gated.status, 0, "{}", rendered(&gated));
    });
}

#[test]
fn a_permitted_binary_that_cannot_start_records_status_126() {
    run(async {
        let policy = Arc::new(
            support::open_policy(vec![Policy {
                origin: PathBuf::from("shell-launch-failure.dw"),
                text: r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"shell:spawn", resource);
@id("after_a_launch_failure")
forbid(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when { context.input.program == "printf" }
unless temporal {
    formerly within 60s
    Box::Action::"shell:spawn"::response{ input.program: "hostname", output.status: 126 }
};
"#
                .to_string(),
            }])
            .expect("policy loads"),
        );
        let refusing: strands_shell::os::HostSpawner =
            Arc::new(|_| Box::pin(async { Err(std::io::Error::other("the leaf cannot start")) }));
        let mut shell = Shell::builder()
            .effect_interceptor(ShellPolicyInterceptor::into_handle(
                policy,
                Principal::agent(),
                GovernedBox::assigned("test-box"),
            ))
            .host_spawner(refusing)
            .build()
            .expect("shell builds");

        let launched = shell.run("hostname").await;
        assert_eq!(launched.status, 126, "{}", rendered(&launched));
        let gated = shell.run("printf gated").await;
        assert_eq!(gated.status, 0, "{}", rendered(&gated));
    });
}
