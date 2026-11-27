//! In log-only mode a policy denial is recorded and let through, and every other denial still holds.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use policy::{
    Decision, DecisionObserver, DenyReason, GovernedBox, McpReply, Outcome, Policy, PolicyEngine,
    Principal, Request, SchemaStage, generate_mcp_schema,
};
use serde_json::{Value, json};

const DESK_TOOLS: &str = r#"{"result": {"tools": [
    {"name": "verify_identity", "inputSchema": {"type": "object",
        "properties": {"user_name": {"type": "string"}}, "required": ["user_name"]}},
    {"name": "reset_password", "inputSchema": {"type": "object",
        "properties": {"user_name": {"type": "string"}}, "required": ["user_name"]}}
]}}"#;

const DESK_CALLS: &str = r#"
permit(principal, action == Box::Action::"mcp:call", resource)
when { context.input.server == "desk" };
"#;

fn source(text: &str) -> Policy {
    Policy {
        origin: PathBuf::from("policy.dw"),
        text: text.to_string(),
    }
}

/// An engine over `policy` with `desk`'s tools staged, in log-only mode when `log_only` holds.
fn desk(policy: &str, history: &Path, log_only: bool) -> PolicyEngine {
    let engine = PolicyEngine::open_staged(
        &policy::Operator::unanchored(),
        vec![source(&format!("{DESK_CALLS}{policy}"))],
        history,
    )
    .expect("the policy opens");
    assert_eq!(
        engine
            .stage_mcp_schema(
                "desk",
                generate_mcp_schema("desk", DESK_TOOLS).expect("the desk schema generates"),
            )
            .expect("desk's schema stages"),
        SchemaStage::Accepted {
            authority_ready: true,
        }
    );
    if log_only { engine.log_only() } else { engine }
}

/// One `tools/call` the way the broker runs it, recording both response legs when it goes ahead.
fn call(engine: &PolicyEngine, tool: &str, arguments: Value) -> Decision {
    let governed = GovernedBox::assigned("test-box");
    let (decision, request_id) = engine.decide(
        &governed,
        &Principal::agent(),
        &Request::McpCall {
            server: "desk",
            method: "tools/call",
            tool: Some(tool),
            prompt: None,
            uri: None,
            arguments: None,
        },
    );
    if !decision.is_allow() {
        return decision;
    }
    let (refined, pending) =
        engine.refine_tool_call(&governed, &Principal::agent(), "desk", tool, &arguments);
    if !refined.is_allow() {
        return refined;
    }
    engine
        .record(
            &governed,
            &Principal::agent(),
            &request_id.expect("a call that goes ahead has a request id"),
            &Outcome::Mcp {
                server: "desk",
                method: "tools/call",
                tool: Some(tool),
                prompt: None,
                uri: None,
            },
        )
        .expect("the coarse response records");
    if let Some(pending) = pending {
        engine
            .record_tool_response(pending, McpReply::Result)
            .expect("the tool response records");
    }
    refined
}

const FORBID_RESET: &str = r#"
permit(principal, action == desk::Action::"verify_identity", resource);
@id("no-reset")
forbid(principal, action == desk::Action::"reset_password", resource);
"#;

#[test]
fn a_forbidden_call_goes_ahead_in_log_only_mode_and_names_the_forbid() {
    let directory = tempfile::tempdir().expect("history directory");
    let engine = desk(FORBID_RESET, &directory.path().join("dogwood.redb"), true);

    let decision = call(&engine, "reset_password", json!({ "user_name": "u" }));
    assert!(decision.is_allow(), "{decision:?}");
    assert_eq!(decision.would_deny(), Some(&DenyReason::Forbidden));
    assert!(
        decision
            .attribution()
            .iter()
            .any(|entry| entry.annotation_id.as_deref() == Some("no-reset")),
        "the would-deny keeps the forbid that decided it: {decision:?}"
    );

    // A real permit is not marked.
    let permitted = call(&engine, "verify_identity", json!({ "user_name": "u" }));
    assert!(permitted.is_allow());
    assert_eq!(permitted.would_deny(), None);
}

#[test]
fn the_same_call_is_denied_when_the_policy_enforces() {
    let directory = tempfile::tempdir().expect("history directory");
    let engine = desk(FORBID_RESET, &directory.path().join("dogwood.redb"), false);

    let decision = call(&engine, "reset_password", json!({ "user_name": "u" }));
    assert!(
        matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::Forbidden,
                ..
            }
        ),
        "{decision:?}"
    );
}

#[test]
fn a_request_no_permit_matches_goes_ahead_in_log_only_mode() {
    let directory = tempfile::tempdir().expect("history directory");
    let engine = desk("", &directory.path().join("dogwood.redb"), true);

    let (decision, request_id) = engine.decide(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        // No `permit` names this server.
        &Request::McpCall {
            server: "elsewhere",
            method: "tools/call",
            tool: Some("lookup"),
            prompt: None,
            uri: None,
            arguments: None,
        },
    );
    assert!(decision.is_allow(), "{decision:?}");
    assert_eq!(decision.would_deny(), Some(&DenyReason::NoMatch));
    assert!(
        request_id.is_some(),
        "a let-through request can record its outcome"
    );
}

/// A call log-only mode lets through really ran, so its `::response` satisfies a later
/// precondition, as the call did in fact happen.
#[test]
fn a_call_let_through_satisfies_a_later_precondition_on_its_response() {
    let directory = tempfile::tempdir().expect("history directory");
    let engine = desk(
        r#"
@id("no-verify")
forbid(principal, action == desk::Action::"verify_identity", resource);
@id("reset-after-verify")
forbid(principal, action == desk::Action::"reset_password", resource)
unless temporal { formerly within 1h ( desk::Action::"verify_identity"::response{
  output.reply: "result" } ) };
"#,
        &directory.path().join("dogwood.redb"),
        true,
    );

    let early = call(&engine, "reset_password", json!({ "user_name": "u" }));
    assert_eq!(
        early.would_deny(),
        Some(&DenyReason::Forbidden),
        "with no verification yet, the reset is a would-deny: {early:?}"
    );
    let verify = call(&engine, "verify_identity", json!({ "user_name": "u" }));
    assert_eq!(verify.would_deny(), Some(&DenyReason::Forbidden));

    let reset = call(&engine, "reset_password", json!({ "user_name": "u" }));
    assert!(reset.is_allow(), "{reset:?}");
    assert_eq!(
        reset.would_deny(),
        None,
        "the verification ran, so the reset is a real permit: {reset:?}"
    );
}

/// A tool whose rule waits on its schema stays held in log-only mode, so a missing policy does
/// not fail open.
#[test]
fn a_pending_tool_still_denies_in_log_only_mode() {
    let directory = tempfile::tempdir().expect("history directory");
    let engine = PolicyEngine::open_staged(
        &policy::Operator::unanchored(),
        vec![source(&format!("{DESK_CALLS}{FORBID_RESET}"))],
        &directory.path().join("dogwood.redb"),
    )
    .expect("the policy opens")
    .log_only();

    let (decision, pending) = engine.refine_tool_call(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        "desk",
        "reset_password",
        &json!({ "user_name": "u" }),
    );
    assert!(
        matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::PolicyPending,
                ..
            }
        ),
        "{decision:?}"
    );
    assert!(pending.is_none());
}

/// The observer sees the same verdict the caller acts on, so a record built from either names the
/// would-deny.
#[test]
fn the_observer_sees_the_let_through_verdict() {
    #[derive(Default)]
    struct Seen(Mutex<Vec<Decision>>);
    impl DecisionObserver for Seen {
        fn observed(&self, _action: &str, _resource: &str, decision: &Decision) {
            self.0.lock().expect("seen").push(decision.clone());
        }
    }

    let directory = tempfile::tempdir().expect("history directory");
    let seen = Arc::new(Seen::default());
    let engine = desk(FORBID_RESET, &directory.path().join("dogwood.redb"), true)
        .observed_by(Arc::clone(&seen) as Arc<dyn DecisionObserver>);

    let decision = call(&engine, "reset_password", json!({ "user_name": "u" }));
    let observed = seen.0.lock().expect("seen").clone();
    assert!(
        observed.contains(&decision),
        "the per-tool verdict reached the observer: {observed:?}"
    );
    assert_eq!(decision.would_deny(), Some(&DenyReason::Forbidden));
}

/// A reload swaps the policy text and keeps the mode, so a trial stays a trial.
#[test]
fn a_reload_keeps_log_only_mode() {
    let directory = tempfile::tempdir().expect("history directory");
    let engine = desk(FORBID_RESET, &directory.path().join("dogwood.redb"), true);
    engine
        .reload(&[source(&format!(
            "{DESK_CALLS}{FORBID_RESET}@id(\"no-verify\")\nforbid(principal, action == desk::Action::\"verify_identity\", resource);\n"
        ))])
        .expect("the policy reloads");

    let decision = call(&engine, "verify_identity", json!({ "user_name": "u" }));
    assert_eq!(
        decision.would_deny(),
        Some(&DenyReason::Forbidden),
        "the reloaded forbid is let through: {decision:?}"
    );
}

/// An engine with no authored policy denies by default even in log-only mode, so turning the mode
/// on while the policy is missing never makes a permit-all box.
#[test]
fn an_absent_policy_still_denies_in_log_only_mode() {
    let directory = tempfile::tempdir().expect("history directory");
    let engine = PolicyEngine::open(Vec::new(), &directory.path().join("dogwood.redb"))
        .expect("an empty policy set opens")
        .log_only();
    let connect = Request::Connect {
        host: "169.254.169.254",
        ip: None,
        port: 80,
        enrichment: &policy::EnrichmentFacts::NONE,
    };
    let (decision, _) = engine.decide(
        &GovernedBox::assigned("test-box"),
        &Principal::agent(),
        &connect,
    );
    assert!(
        matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::NoMatch,
                ..
            }
        ),
        "{decision:?}"
    );
}

/// A reload that removes every authored source takes log-only mode with it, as an absent policy
/// never lets a request through.
#[test]
fn a_reload_to_no_policy_stops_letting_denials_through() {
    let directory = tempfile::tempdir().expect("history directory");
    let engine = PolicyEngine::open_staged(
        &policy::Operator::unanchored(),
        vec![source(
            r#"permit(principal, action == Box::Action::"fs:read", resource);"#,
        )],
        &directory.path().join("dogwood.redb"),
    )
    .expect("the policy opens")
    .log_only();
    engine
        .finish_mcp_discovery()
        .expect("discovery finishes with no server");
    let connect = Request::Connect {
        host: "example.com",
        ip: None,
        port: 443,
        enrichment: &policy::EnrichmentFacts::NONE,
    };
    let governed = GovernedBox::assigned("test-box");
    let (before, _) = engine.decide(&governed, &Principal::agent(), &connect);
    assert_eq!(
        before.would_deny(),
        Some(&DenyReason::NoMatch),
        "{before:?}"
    );

    engine.reload(&[]).expect("the empty set reloads");
    let (after, _) = engine.decide(&governed, &Principal::agent(), &connect);
    assert!(!after.is_allow(), "{after:?}");
}

/// An enforcing engine reopened on a trial's history inherits it: what the trial let through really
/// happened, so a later rule over the past counts it. A fresh history is the paired control.
#[test]
fn an_enforcing_run_inherits_the_history_a_trial_recorded() {
    const GATED: &str = r#"
@id("no-verify")
forbid(principal, action == desk::Action::"verify_identity", resource);
@id("reset-after-verify")
forbid(principal, action == desk::Action::"reset_password", resource)
unless temporal { formerly within 1h ( desk::Action::"verify_identity"::response{
  output.reply: "result" } ) };
"#;
    let directory = tempfile::tempdir().expect("history directory");
    let history = directory.path().join("dogwood.redb");
    let trial = desk(GATED, &history, true);
    let verify = call(&trial, "verify_identity", json!({ "user_name": "u" }));
    assert_eq!(
        verify.would_deny(),
        Some(&DenyReason::Forbidden),
        "{verify:?}"
    );
    drop(trial);

    let enforcing = desk(GATED, &history, false);
    let reset = call(&enforcing, "reset_password", json!({ "user_name": "u" }));
    assert!(
        reset.is_allow() && reset.would_deny().is_none(),
        "the trial's verification counts for the enforcing run: {reset:?}"
    );

    let fresh = tempfile::tempdir().expect("a fresh history");
    let control = desk(GATED, &fresh.path().join("dogwood.redb"), false);
    let reset = call(&control, "reset_password", json!({ "user_name": "u" }));
    assert!(
        !reset.is_allow(),
        "with no trial behind it, the reset is denied: {reset:?}"
    );
}
