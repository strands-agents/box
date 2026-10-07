//! Policy load-contract regression tests (Definition of Done).
//!
//! These tests drive the public `PolicyEngine::open` path.
//!
//! Covers:
//! - unknown action and undeclared attribute: the schema strict gate
//! - disabled information providers
//! - the enforced temporal surface
//!   (docs/design/decisions.md#temporal-rules-are-enforced-against-recorded-history)

mod support;

use std::path::PathBuf;

// `Decision` and `DenyReason` came off with the removed guardrails test, which was the only
// consumer of a full decision here. What is left asserts on load errors and on `is_allow`.
use policy::{GovernedBox, Policy, PolicyError, Principal, Request};

fn src(text: &str) -> Policy {
    Policy {
        origin: "fail-closed-test".into(),
        text: text.to_string(),
    }
}

/// The load must fail — a guard that lets one of these through has reopened the
/// fail-open class. Returns the error so a test can assert its variant.
fn expect_load_error(text: &str) -> PolicyError {
    match support::open_policy(vec![src(text)]) {
        Ok(_) => panic!("load should have aborted for policy:\n{text}"),
        Err(e) => e,
    }
}

#[test]
fn unknown_action_aborts_startup() {
    // A typo'd action is a hard load error, not a silent no-match.
    let e = expect_load_error(r#"permit(principal, action == Box::Action::"fs:raed", resource);"#);
    assert!(
        matches!(e, PolicyError::UnknownAction(_)),
        "expected UnknownAction, got {e:?}"
    );
}

#[test]
fn undeclared_attribute_aborts_startup() {
    // An attribute not in the schema is a hard load error.
    let e = expect_load_error(
        r#"permit(principal, action == Box::Action::"net:connect", resource)
           when { context.input.nonexistent == "x" };"#,
    );
    assert!(
        matches!(e, PolicyError::Schema(_)),
        "expected Schema, got {e:?}"
    );
}

#[test]
fn a_catch_all_permit_loads_and_grants_what_it_says() {
    // A catch-all permit means what Cedar says it means: it grants every action in the
    // schema. This was once rejected at load, but for an unrelated reason — the
    // credential projection could not extract a concrete locator from `action` unbound,
    // so the whole document failed with `UnsupportedClause`. That rejection was an
    // artifact of the projection, not a judgement that catch-alls are unsafe, and it
    // reported a credential problem for a policy that mentioned no credential.
    //
    // Removing the projection removes the artifact. The operator writing this in their
    // own box's policy file gets exactly what they asked for, which is the honest
    // reading. What still holds beneath it is the part policy cannot weaken: the
    // compiled SSRF floor and containment, neither of which any permit reaches.
    let policy = support::open_policy(vec![Policy {
        origin: PathBuf::from("catch-all.cedar"),
        text: r#"permit(principal, action, resource);"#.to_string(),
    }])
    .expect("a catch-all permit is a valid policy");

    assert!(
        policy
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::Connect {
                    host: "api.example.com",
                    ip: None,
                    port: 443,
                },
            )
            .is_allow(),
        "a catch-all permit grants net:connect"
    );
}

#[test]
fn removed_actions_are_unknown() {
    for action in ["tool:invoke", "model:invoke", "agent:invoke"] {
        let e = expect_load_error(&format!(
            r#"forbid(principal, action == Box::Action::"{action}", resource);"#
        ));
        assert!(
            matches!(e, PolicyError::UnknownAction(_)),
            "expected UnknownAction for {action}, got {e:?}"
        );
    }
}

#[test]
fn an_information_provider_aborts_startup() {
    let error = expect_load_error(
        r#"permit(principal, action == Box::Action::"net:connect", resource)
           when { Risk::Elevated(context.input.host).high == false };"#,
    );
    assert!(
        matches!(error, PolicyError::Parse(ref message) if message.contains("information providers")),
        "the disabled provider contract must reject the policy: {error:?}"
    );
}

// REMOVED 2026-08-20: `a_provider_free_guardrails_tag_enforces_its_cedar_body`.
//
// **It had not compiled since the two features it tested were deleted, so it was not running.** It
// asserted that a `when guardrails { … }` tag preserved its Cedar condition, using the principal
// `AgentGateway::"self"` and `Principal::agent_gateway()`.
//
// Both are gone. `guardrails` handling was removed in `206ecb8`, and a later change collapsed the
// principals to one `Agent` — `Principal` now offers `agent()` alone. So the test could not be
// repaired by renaming the principal: its policy text names a tag the parser no longer accepts.
//
// This is worse than dead code. `cargo test -p strands-box-policy` failed to build this target, so
// every OTHER test in this file was skipped too, silently, while the crate reported a compile error
// that read as a known-migration artifact.

#[test]
fn an_undefined_function_is_a_hard_load_error() {
    // What this actually proves: the engine refuses a function it does not define. That is
    // worth pinning — it is the "silent no-match" the strict gate exists to prevent.
    //
    // **It was named `temporal_fact_aborts_startup` until 2026-08-08, and
    // it never tested that.** `spent_today()` is a *Cedar-shaped* stateful fact, a spelling
    // the Dogwood engine never sees; it fails as `unknown function or macro`, which it would
    // do whether or not temporal were supported. The engine's real spelling —
    // `when temporal { … }` — loads and enforces, so the requirement the old name claimed
    // to hold was contradicted by the code while this test passed. See
    // `a_temporal_clause_loads_and_enforces` below.
    let e = expect_load_error(
        r#"permit(principal, action == Box::Action::"net:connect", resource)
           when { spent_today() < 100 };"#,
    );
    assert!(
        matches!(e, PolicyError::Parse(_) | PolicyError::Schema(_)),
        "expected a parse or schema error, got {e:?}"
    );
}

/// A real `when temporal { … }` clause **loads** — temporal is enforced in v1.
///
/// The clause is written in the engine's own grammar, which is the whole point — the test it
/// replaces used a shape the engine cannot parse and so proved nothing about temporal. That the
/// rule *enforces* (and not merely loads) is covered by `tests/temporal_egress_budget.rs`;
/// here the assertion is only that the load path admits it.
#[test]
fn a_temporal_clause_loads_and_enforces() {
    let loaded = support::open_policy(vec![src(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
when temporal {
    exists (total: Long). (
        (sum b for (b: Long), (t: Timepoint). where (
            formerly within 60s (
                Box::Action::"http:request"::response{ input.host: _, input.body_bytes: b } && tp(t)
            )
        )) == total
        && total < 100
    )
};"#,
    )]);
    assert!(
        loaded.is_ok(),
        "a temporal clause must load and enforce \
         (docs/design/decisions.md#temporal-rules-are-enforced-against-recorded-history): \
         {loaded:?}"
    );
}

#[test]
fn a_clean_enforced_policy_still_loads() {
    // Guard against over-eager guards: an ordinary enforced policy must still compose.
    let ok = support::open_policy(vec![src(
        r#"permit(principal, action == Box::Action::"net:connect", resource)
           when { context.input.host == "api.github.com" && context.input.port == 443 };"#,
    )]);
    assert!(ok.is_ok(), "a clean policy must load: {ok:?}");
}
