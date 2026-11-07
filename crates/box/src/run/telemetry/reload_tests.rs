//! A policy reload waits for every decision in one remote tool request.

use super::{
    EffectiveDecision, EffectiveVerdict, EgressDecisionInterceptor, PENDING_EGRESS_DECISION,
    PolicyDecisionObserver,
};
use crate::run::hosted::reload_test_support::{isolated, spawn_reload, with_running_policy};
use crate::test_support::open_staged_policy;
use egress_gateway::{EffectAttempt, McpFrame};
use policy::{Decision, DecisionObserver, EgressPolicyInterceptor, GovernedBox, Policy, Principal};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

const HTTP: &str = r#"Box::Action::"http:request""#;
const MCP: &str = r#"Box::Action::"mcp:call""#;
const TOOL: &str = r#"demo::Action::"add""#;
const ALLOW: &str = "permit(principal, action, resource);";
const WAIT: Duration = Duration::from_secs(15);

struct PauseAfterDecision {
    action: &'static str,
    armed: AtomicBool,
    reached: mpsc::SyncSender<()>,
    resume: Mutex<mpsc::Receiver<()>>,
    seen: Mutex<Vec<(String, bool)>>,
}

impl DecisionObserver for PauseAfterDecision {
    fn observed(&self, action: &str, resource: &str, decision: &Decision) {
        PolicyDecisionObserver.observed(action, resource, decision);
        self.seen
            .lock()
            .expect("record observations")
            .push((action.to_string(), decision.is_allow()));
        if action == self.action && self.armed.swap(false, Ordering::SeqCst) {
            assert!(decision.is_allow(), "the paused decision must permit");
            self.reached.send(()).expect("report the paused decision");
            self.resume
                .lock()
                .expect("resume receiver")
                .recv_timeout(WAIT)
                .expect("resume the request");
        }
    }
}

fn sources(forbid: &str, annotation: &str) -> Vec<Policy> {
    vec![Policy {
        origin: "reload-egress.dw".into(),
        text: format!(
            r#"{ALLOW}
@id("{annotation}") forbid(principal, action == {forbid}, resource);"#
        ),
    }]
}

fn attempt() -> EffectAttempt<'static> {
    EffectAttempt::HttpRequest {
        host: "mcp-fixture.demo",
        port: 8931,
        method: "POST",
        path: "/mcp",
        body_bytes: 7,
        intercepted: false,
        mcp: Some(McpFrame::ToolCall {
            server: "demo",
            tool: "add",
            arguments: r#"{"a":2}"#,
        }),
    }
}

fn reload_after(
    pause_action: &'static str,
    old_forbid: &str,
    replacement_forbid: &str,
    expected: &[(&str, bool)],
) {
    let history = tempfile::tempdir().expect("history directory");
    let engine = open_staged_policy(
        sources(old_forbid, "old-denial"),
        &history.path().join("dogwood.redb"),
    );
    let schema = policy::generate_mcp_schema(
        "demo",
        r#"{"result":{"tools":[{"name":"add","inputSchema":{"type":"object","properties":{"a":{"type":"integer"}},"required":["a"]}}]}}"#,
    )
    .expect("tool schema generates");
    engine
        .stage_mcp_schema("demo", schema)
        .expect("tool schema stages");
    let (reached_tx, reached_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let observer = Arc::new(PauseAfterDecision {
        action: pause_action,
        armed: AtomicBool::new(true),
        reached: reached_tx,
        resume: Mutex::new(resume_rx),
        seen: Mutex::new(Vec::new()),
    });
    let engine = Arc::new(engine.observed_by(observer.clone()));
    with_running_policy(Arc::clone(&engine), || {
        let interceptor = EgressDecisionInterceptor::over(EgressPolicyInterceptor::into_handle(
            engine,
            Principal::agent(),
            GovernedBox::assigned("reload-egress"),
        ));
        let worker_interceptor = Arc::clone(&interceptor);
        let request = std::thread::spawn(move || {
            let result = worker_interceptor.intercept(&attempt()).map(|_| ());
            (result, take_effective_decision())
        });
        reached_rx.recv_timeout(WAIT).expect("request pauses");
        let reload = spawn_reload(sources(replacement_forbid, "new-denial"));
        let waiting = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reload.assert_waiting();
        }));
        resume_tx.send(()).expect("resume the paused request");
        let (decision, effective) = request.join().expect("request thread completes");
        if let Err(panic) = waiting {
            std::panic::resume_unwind(panic);
        }
        let reloaded = reload.finish();
        assert_eq!(
            decision.expect_err("the original policy denies").kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_denial(&effective, old_forbid, "old-denial");
        reloaded.expect("reload completes after request admission");
        assert_eq!(
            interceptor
                .intercept(&attempt())
                .err()
                .expect("the replacement policy denies")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_denial(&take_effective_decision(), replacement_forbid, "new-denial");
        let expected: Vec<_> = expected
            .iter()
            .map(|(action, allow)| (action.to_string(), *allow))
            .collect();
        assert_eq!(
            *observer.seen.lock().expect("observations"),
            expected,
            "each request records its decisions once without a retry"
        );
    });
}

fn take_effective_decision() -> EffectiveDecision {
    PENDING_EGRESS_DECISION.with(|pending| {
        pending
            .borrow_mut()
            .take()
            .expect("effective egress decision")
            .effective
    })
}

fn assert_denial(decision: &EffectiveDecision, action: &str, annotation: &str) {
    assert_eq!(decision.action, action);
    assert_eq!(decision.verdict, EffectiveVerdict::Deny);
    assert_eq!(decision.attribution.len(), 1);
    assert_eq!(
        decision.attribution[0].annotation_id.as_deref(),
        Some(annotation)
    );
}

#[test]
fn reload_waits_for_remote_tool_admission_after_the_http_decision() {
    isolated(
        "run::telemetry::reload_tests::reload_waits_for_remote_tool_admission_after_the_http_decision",
        || {
            reload_after(
                HTTP,
                MCP,
                HTTP,
                &[(HTTP, true), (MCP, false), (HTTP, false)],
            )
        },
    );
}

#[test]
fn reload_waits_for_remote_tool_admission_after_the_mcp_decision() {
    isolated(
        "run::telemetry::reload_tests::reload_waits_for_remote_tool_admission_after_the_mcp_decision",
        || {
            reload_after(
                MCP,
                TOOL,
                MCP,
                &[
                    (HTTP, true),
                    (MCP, true),
                    (TOOL, false),
                    (HTTP, true),
                    (MCP, false),
                ],
            );
        },
    );
}
