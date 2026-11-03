//! Concurrent reload coverage for local tool admission.

use super::{McpRequestAdmission, admit_tool_call};
use crate::run::hosted::reload_test_support::{isolated, spawn_reload, with_running_policy};
use crate::test_support::open_staged_policy;
use policy::{Decision, DecisionObserver, GovernedBox, Policy, PolicyEngine, Principal};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

const COARSE: &str = r#"Box::Action::"mcp:call""#;
const TOOL: &str = r#"alpha::Action::"read""#;
const FIRST: &str = r#"
permit(principal, action == Box::Action::"mcp:call", resource);
forbid(principal, action == alpha::Action::"read", resource);
"#;
const SECOND: &str = r#"
forbid(principal, action == Box::Action::"mcp:call", resource);
permit(principal, action == alpha::Action::"read", resource);
"#;
const FRAME: &str =
    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{}}}"#;

fn sources(text: &str) -> Vec<Policy> {
    vec![Policy {
        origin: "reload.dw".into(),
        text: text.into(),
    }]
}

fn admit(engine: &PolicyEngine) -> McpRequestAdmission {
    admit_tool_call(
        engine,
        &GovernedBox::assigned("reload-test"),
        &Principal::agent(),
        "alpha",
        FRAME,
    )
    .expect("valid tool call")
}

struct PauseAfterCoarse {
    armed: AtomicBool,
    reached: mpsc::SyncSender<()>,
    resume: Mutex<mpsc::Receiver<()>>,
    observed: Mutex<Vec<String>>,
}

impl DecisionObserver for PauseAfterCoarse {
    fn observed(&self, action: &str, resource: &str, decision: &Decision) {
        crate::run::telemetry::PolicyDecisionObserver.observed(action, resource, decision);
        self.observed.lock().unwrap().push(action.to_string());
        if action == COARSE && self.armed.swap(false, Ordering::SeqCst) {
            assert!(
                decision.is_allow(),
                "the first policy permits the coarse check"
            );
            self.reached.send(()).unwrap();
            self.resume
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .expect("admission resumes");
        }
    }
}

/// Both complete policies deny; reload cannot combine their separate permits into an allow.
#[test]
fn reload_waits_for_both_stdio_tool_checks() {
    isolated(
        "run::broker::mcp::admission::reload_tests::reload_waits_for_both_stdio_tool_checks",
        || {
            let history = tempfile::tempdir().expect("history directory");
            let (reached_tx, reached_rx) = mpsc::sync_channel(1);
            let (resume_tx, resume_rx) = mpsc::sync_channel(1);
            let observer = Arc::new(PauseAfterCoarse {
                armed: AtomicBool::new(false),
                reached: reached_tx,
                resume: Mutex::new(resume_rx),
                observed: Mutex::new(Vec::new()),
            });
            let engine = open_staged_policy(sources(FIRST), &history.path().join("history"));
            let schema = policy::generate_mcp_schema("alpha", r#"{"result":{"tools":[{"name":"read","inputSchema":{"type":"object","properties":{}}}]}}"#)
            .expect("tool schema generates");
            engine
                .stage_mcp_schema("alpha", schema)
                .expect("schema stages");
            let engine = Arc::new(engine.observed_by(observer.clone()));
            with_running_policy(Arc::clone(&engine), || {
                assert!(matches!(admit(&engine), McpRequestAdmission::Denied { .. }));
                crate::reload(&sources(SECOND)).expect("second policy installs");
                assert!(matches!(admit(&engine), McpRequestAdmission::Denied { .. }));
                crate::reload(&sources(FIRST)).expect("first policy restores");
                observer.observed.lock().unwrap().clear();
                observer.armed.store(true, Ordering::SeqCst);

                std::thread::scope(|scope| {
                    let pending = scope.spawn(|| admit(&engine));
                    reached_rx
                        .recv_timeout(Duration::from_secs(10))
                        .expect("coarse check permits");
                    let reload = spawn_reload(sources(SECOND));
                    reload.assert_waiting();
                    resume_tx.send(()).unwrap();
                    let McpRequestAdmission::Denied { decision, .. } = pending.join().unwrap()
                    else {
                        panic!("the first policy must deny the complete request");
                    };
                    assert_eq!(decision.parts().0, TOOL);
                    reload.finish().expect("reload installs after admission");
                });
                let McpRequestAdmission::Denied { decision, .. } = admit(&engine) else {
                    panic!("the replacement policy must deny the next request");
                };
                assert_eq!(decision.parts().0, COARSE);
                assert_eq!(
                    *observer.observed.lock().unwrap(),
                    [COARSE, TOOL, COARSE],
                    "each check records once; reload must not retry admission"
                );
            });
        },
    );
}
