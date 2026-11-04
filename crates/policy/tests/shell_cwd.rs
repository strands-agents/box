//! Working-directory policy spelling across shell decisions and history.

#![cfg(feature = "shell-adapter")]

mod support;

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use policy::{GovernedBox, Outcome, Policy, PolicyEngine, Principal, ShellPolicyInterceptor};
use strands_shell::{EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit};

const HOME: &str = "/home/operator";
const PROJECT: &str = "/home/operator/project";

fn interceptor(source: &str, home: Option<&str>) -> Arc<dyn EffectInterceptor> {
    let policy = Arc::new(
        support::open_policy(vec![Policy {
            origin: PathBuf::from("shell-cwd.dw"),
            text: source.to_string(),
        }])
        .expect("policy loads"),
    );
    match home {
        Some(home) => ShellPolicyInterceptor::into_handle_reporting_under(
            policy,
            Principal::agent(),
            GovernedBox::assigned("cwd-test"),
            home,
        ),
        None => ShellPolicyInterceptor::into_handle(
            policy,
            Principal::agent(),
            GovernedBox::assigned("cwd-test"),
        ),
    }
}

async fn admit(
    interceptor: &dyn EffectInterceptor,
    action: &str,
    program: &str,
    cwd: &str,
) -> io::Result<Box<dyn EffectPermit>> {
    let effect = match action {
        "shell:exec" => EffectAttempt::ShellRun {
            command: program,
            program,
            args: &[],
            literal: &[],
            cwd,
        },
        "shell:spawn" => EffectAttempt::ShellSpawn {
            command: program,
            program,
            program_path: "/usr/bin/printf",
            args: &[],
            literal: &[],
            cwd,
        },
        _ => panic!("unexpected test action"),
    };
    interceptor.intercept(&effect).await
}

async fn complete(permit: Box<dyn EffectPermit>) {
    permit
        .record_outcome(EffectOutcome::ShellCommand { reported_status: 0 })
        .await
        .expect("outcome records");
}

async fn assert_directory_restriction(action: &str) {
    for predicate in [
        r#"context.input.cwd == "~/project""#,
        r#"context.input.cwd like "~/project/*""#,
    ] {
        let source = format!(
            r#"permit(principal, action == Box::Action::"{action}", resource);
            @id("protected_directory")
            forbid(principal, action == Box::Action::"{action}", resource)
            when {{ {predicate} }};"#
        );
        let interceptor = interceptor(&source, Some(HOME));
        let protected = if predicate.contains("like") {
            "/home/operator/project/child"
        } else {
            PROJECT
        };
        let error = admit(interceptor.as_ref(), action, "printf", protected)
            .await
            .err()
            .expect("the protected directory must be denied");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("protected_directory"), "{error}");
        complete(
            admit(
                interceptor.as_ref(),
                action,
                "printf",
                "/home/operator/project-sibling",
            )
            .await
            .expect("the same command in a sibling must remain permitted"),
        )
        .await;
    }
}

#[tokio::test]
async fn an_exec_forbid_matches_exact_and_descendant_working_directories() {
    assert_directory_restriction("shell:exec").await;
}

#[tokio::test]
async fn a_spawn_forbid_matches_exact_and_descendant_working_directories() {
    assert_directory_restriction("shell:spawn").await;
}

#[tokio::test]
async fn shell_working_directories_follow_home_and_outside_home_boundaries() {
    for action in ["shell:exec", "shell:spawn"] {
        for (home, actual, reported) in [
            (Some(HOME), HOME, "~"),
            (Some(HOME), PROJECT, "~/project"),
            (Some(HOME), "/opt/project", "/opt/project"),
            (Some(HOME), "/home/operator-other", "/home/operator-other"),
            (None, PROJECT, PROJECT),
        ] {
            let source = format!(
                r#"permit(principal, action == Box::Action::"{action}", resource)
                when {{ context.input.cwd == "{reported}" }};"#
            );
            let interceptor = interceptor(&source, home);
            complete(
                admit(interceptor.as_ref(), action, "printf", actual)
                    .await
                    .unwrap_or_else(|error| {
                        panic!("{action}: {actual} must report as {reported}: {error}")
                    }),
            )
            .await;
            assert!(
                admit(interceptor.as_ref(), action, "printf", "/different")
                    .await
                    .is_err(),
                "a different directory must not inherit the permit"
            );
        }
    }
}

#[tokio::test]
async fn a_spawn_keeps_its_program_path_restriction_with_a_reported_working_directory() {
    let source = r#"
        permit(principal, action == Box::Action::"shell:spawn", resource);
        forbid(principal, action == Box::Action::"shell:spawn", resource)
        when { context.input.cwd == "~/project" && context.input.program_path == "/usr/bin/printf" };
    "#;
    let interceptor = interceptor(source, Some(HOME));
    assert!(
        admit(interceptor.as_ref(), "shell:spawn", "printf", PROJECT)
            .await
            .is_err(),
        "the resolved executable and reported working directory must both match"
    );
    complete(
        admit(
            interceptor.as_ref(),
            "shell:spawn",
            "printf",
            "/opt/project",
        )
        .await
        .expect("the program stays permitted outside the protected directory"),
    )
    .await;
}

#[tokio::test]
async fn temporal_rules_distinguish_requests_and_outcomes_in_the_reported_working_directory() {
    for action in ["shell:exec", "shell:spawn"] {
        let source = format!(
            r#"permit(principal, action == Box::Action::"{action}", resource);
            forbid(principal, action == Box::Action::"{action}", resource)
            when {{ context.input.program == "request_probe" }}
            unless temporal {{ formerly within 60s
                Box::Action::"{action}"::request{{ input.program: "seed", input.cwd: "~/project" }}
            }};
            forbid(principal, action == Box::Action::"{action}", resource)
            when {{ context.input.program == "response_probe" }}
            unless temporal {{ formerly within 60s
                Box::Action::"{action}"::response{{ input.program: "seed", input.cwd: "~/project", output.status: 0 }}
            }};"#
        );
        let interceptor = interceptor(&source, Some(HOME));
        for probe in ["request_probe", "response_probe"] {
            assert!(
                admit(interceptor.as_ref(), action, probe, PROJECT)
                    .await
                    .is_err()
            );
        }
        complete(
            admit(
                interceptor.as_ref(),
                action,
                "seed",
                "/home/operator/sibling",
            )
            .await
            .expect("sibling seed is permitted"),
        )
        .await;
        for probe in ["request_probe", "response_probe"] {
            assert!(
                admit(interceptor.as_ref(), action, probe, PROJECT)
                    .await
                    .is_err(),
                "the sibling event must not satisfy the protected-directory condition"
            );
        }
        let seed = admit(interceptor.as_ref(), action, "seed", PROJECT)
            .await
            .expect("protected-directory seed is permitted");
        complete(
            admit(interceptor.as_ref(), action, "request_probe", PROJECT)
                .await
                .expect("the request clause must see the reported directory"),
        )
        .await;
        assert!(
            admit(interceptor.as_ref(), action, "response_probe", PROJECT)
                .await
                .is_err(),
            "an admitted request must not count as a completed effect"
        );
        complete(seed).await;
        complete(
            admit(interceptor.as_ref(), action, "response_probe", PROJECT)
                .await
                .expect("the outcome clause must see the same reported directory"),
        )
        .await;
    }
}

#[tokio::test]
async fn a_directory_history_restriction_survives_a_long_run_of_denied_attempts() {
    for action in ["shell:exec", "shell:spawn"] {
        let source = format!(
            r#"permit(principal, action == Box::Action::"{action}", resource);
            forbid(principal, action == Box::Action::"{action}", resource)
            when {{ context.input.program == "probe" && context.input.cwd == "~/project" }}
            when temporal {{ formerly within 1h
                Box::Action::"{action}"::response{{ input.program: "seed", input.cwd: "~/project", output.status: 0 }}
            }};"#
        );
        let interceptor = interceptor(&source, Some(HOME));
        complete(
            admit(interceptor.as_ref(), action, "probe", PROJECT)
                .await
                .expect("the probe is permitted before the seed completes"),
        )
        .await;
        complete(
            admit(interceptor.as_ref(), action, "seed", PROJECT)
                .await
                .expect("the seed is permitted"),
        )
        .await;
        let started = Instant::now();
        for attempt in 0..512 {
            assert!(
                admit(interceptor.as_ref(), action, "probe", PROJECT)
                    .await
                    .is_err(),
                "{action}: attempt {attempt} must remain denied by directory history"
            );
            complete(
                admit(
                    interceptor.as_ref(),
                    action,
                    "probe",
                    "/home/operator/sibling",
                )
                .await
                .expect("the same program remains permitted in the sibling directory"),
            )
            .await;
        }
        assert!(
            started.elapsed() < Duration::from_secs(3600),
            "the run must fit within the policy window"
        );
    }
}

#[tokio::test]
async fn reopened_history_preserves_old_cwd_spelling_and_records_new_spelling() {
    let directory = tempfile::tempdir().expect("history directory");
    let history = directory.path().join("dogwood.redb");
    let sources = vec![Policy {
        origin: PathBuf::from("cwd-history-compatibility.dw"),
        text: format!(
            r#"permit(principal, action == Box::Action::"shell:spawn", resource);
            forbid(principal, action == Box::Action::"shell:spawn", resource)
            when {{ context.input.program == "old_probe" }}
            unless temporal {{ formerly within 60s
                Box::Action::"shell:spawn"::response{{ input.program: "seed", input.cwd: "{PROJECT}" }}
            }};
            forbid(principal, action == Box::Action::"shell:spawn", resource)
            when {{ context.input.program == "new_probe" }}
            unless temporal {{ formerly within 60s
                Box::Action::"shell:spawn"::response{{ input.program: "seed", input.cwd: "~/project" }}
            }};"#
        ),
    }];
    let policy = PolicyEngine::open(sources.clone(), &history).expect("initial policy opens");
    policy
        .record(
            &GovernedBox::assigned("cwd-test"),
            &Principal::agent(),
            &Outcome::ShellSpawn {
                command: "seed",
                program: "seed",
                program_path: "/usr/bin/printf",
                credential_reads: &[],
                args: &[],
                cwd: PROJECT,
                status: 0,
            },
        )
        .expect("historical absolute-directory outcome records");
    drop(policy);

    let policy = Arc::new(PolicyEngine::open(sources, &history).expect("history reopens"));
    let interceptor = ShellPolicyInterceptor::into_handle_reporting_under(
        policy,
        Principal::agent(),
        GovernedBox::assigned("cwd-test"),
        HOME,
    );
    complete(
        admit(interceptor.as_ref(), "shell:spawn", "old_probe", PROJECT)
            .await
            .expect("the absolute historical event keeps its spelling"),
    )
    .await;
    assert!(
        admit(interceptor.as_ref(), "shell:spawn", "new_probe", PROJECT)
            .await
            .is_err(),
        "reopening must not reinterpret the stored absolute event"
    );
    complete(
        admit(interceptor.as_ref(), "shell:spawn", "seed", PROJECT)
            .await
            .expect("a new spawn is admitted"),
    )
    .await;
    for probe in ["old_probe", "new_probe"] {
        complete(
            admit(interceptor.as_ref(), "shell:spawn", probe, PROJECT)
                .await
                .expect("both old and new observations remain available"),
        )
        .await;
    }
}
