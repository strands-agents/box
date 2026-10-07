//! A temporal outbound byte budget, enforced through the policy facade.
//!
//! This is the rule shape Cedar cannot express: the verdict for request N depends on
//! how many bytes requests 1..N-1 actually delivered. It proves the whole loop —
//! `decide` authorizes, `record` submits what happened, and a later `decide` denies
//! because of it.
//!
//! Requires the `dogwood` feature (the temporal engine) and `egress-adapter` for the
//! outbound principal.

mod support;

use std::path::PathBuf;

use policy::{Decision, Delivery, GovernedBox, Outcome, Policy, PolicyEngine, Principal, Request};

/// The budget rule: sum delivered bytes over `http:request::response` in the last 60s,
/// permit only while under 100.
const BUDGET_POLICY: &str = include_str!("policies/egress_byte_budget.dw");

fn budget_policy() -> PolicyEngine {
    support::open_policy(vec![Policy {
        origin: PathBuf::from("egress_byte_budget.dw"),
        text: BUDGET_POLICY.to_string(),
    }])
    .expect("temporal policy loads")
}

/// One outbound request of `body_bytes`, as the egress proxy would present it.
fn request(body_bytes: usize) -> Request<'static> {
    Request::Http {
        host: "api.example.com",
        port: 443,
        method: "POST",
        path: "/v1/upload",
        body_bytes,
        intercepted: true,
    }
}

/// The matching outcome: `delivered` bytes actually left the box.
fn delivered(bytes: usize) -> Outcome<'static> {
    Outcome::Http {
        host: "api.example.com",
        port: 443,
        method: "POST",
        path: "/v1/upload",
        delivery: Delivery::Completed { bytes },
        status: Some(200),
    }
}

#[test]
fn budget_allows_until_recorded_deliveries_exceed_it() {
    let policy = budget_policy();
    let egress = Principal::agent();

    // Nothing has egressed: the sum is 0, under budget.
    assert!(
        policy
            .decide(&GovernedBox::assigned("test-box"), &egress, &request(60))
            .is_allow(),
        "first request is under the empty budget"
    );
    policy
        .record(&GovernedBox::assigned("test-box"), &egress, &delivered(60))
        .expect("history records");

    // 60 delivered, still under 100.
    assert!(
        policy
            .decide(&GovernedBox::assigned("test-box"), &egress, &request(60))
            .is_allow(),
        "second request is still under budget"
    );
    policy
        .record(&GovernedBox::assigned("test-box"), &egress, &delivered(60))
        .expect("history records");

    // 120 delivered: over budget. This is the assertion the whole integration exists
    // for — a request identical to the two that were allowed is now denied, purely
    // because of recorded history.
    let verdict = policy.decide(&GovernedBox::assigned("test-box"), &egress, &request(60));
    assert!(
        !verdict.is_allow(),
        "third request must be denied by the byte budget, got {verdict:?}"
    );
}

#[test]
fn an_unrecorded_delivery_does_not_consume_budget() {
    // The load-bearing consequence of `record` being a separate, fallible call: if a
    // PEP authorizes an effect but never reports it, the budget never advances. This
    // test pins that behaviour so it is a known property rather than a surprise — it
    // is exactly why `PolicyEngine::record` returns a `Result` a caller must not discard.
    let policy = budget_policy();
    let egress = Principal::agent();

    for _ in 0..5 {
        assert!(
            policy
                .decide(&GovernedBox::assigned("test-box"), &egress, &request(60))
                .is_allow(),
            "without recorded history the budget is never consumed"
        );
    }
}

#[test]
fn a_denied_request_still_advances_history() {
    // Dogwood observes an event before deciding it, so a denial is not free: it is
    // recorded in the trace that later rules read. This is a real behavioural
    // difference from the stateless engine, and on an adversarial workload it is a
    // denial-of-policy consideration — pinned here so a future change to the engine
    // cannot silently alter it.
    let policy = budget_policy();
    let egress = Principal::agent();

    // Exhaust the budget through recorded deliveries.
    for _ in 0..2 {
        assert!(
            policy
                .decide(&GovernedBox::assigned("test-box"), &egress, &request(60))
                .is_allow()
        );
        policy
            .record(&GovernedBox::assigned("test-box"), &egress, &delivered(60))
            .expect("records");
    }
    assert!(
        !policy
            .decide(&GovernedBox::assigned("test-box"), &egress, &request(60))
            .is_allow()
    );

    // The denied attempt above was still observed. The budget is unchanged by it (a
    // denied request produces no *resolution*), so the verdict stays a denial rather
    // than flipping.
    assert!(
        !policy
            .decide(&GovernedBox::assigned("test-box"), &egress, &request(60))
            .is_allow(),
        "a denial is stable: denied attempts add no delivered bytes"
    );
}

#[test]
fn a_non_temporal_request_is_unaffected_by_the_budget() {
    // The budget rule scopes to `http:request`. A different action must not inherit its
    // temporal condition — if it did, one rule would silently govern every verb.
    let policy = budget_policy();
    let egress = Principal::agent();

    let connect = Request::Connect {
        host: "api.example.com",
        ip: None,
        port: 443,
    };
    // No `permit` covers `net:connect`, so this denies by default — not by budget.
    assert!(matches!(
        policy.decide(&GovernedBox::assigned("test-box"), &egress, &connect),
        Decision::Deny { .. }
    ));
}

/// **One exchange charges the budget ONCE, and the reply charges nothing.**
///
/// One exchange records one `http:request::response`, at reply time, carrying the delivered
/// request bytes as `input.body_bytes` and the reply as `output.status`. A reply's size is not
/// recorded, so a large reply body cannot consume an outbound budget.
///
/// Asserted as a *verdict* rather than by counting events, because the verdict is what an
/// operator gets. 60 outbound bytes with a reply is 60 against a budget of 100: the next 60-byte
/// request must still be permitted, and the one after it is denied at the same threshold as a
/// reply-less exchange.
#[test]
fn a_reply_adds_nothing_to_an_outbound_budget() {
    let policy = budget_policy();
    let egress = Principal::agent();
    let governed = GovernedBox::assigned("test-box");

    assert!(
        policy.decide(&governed, &egress, &request(60)).is_allow(),
        "nothing has egressed yet"
    );
    policy
        .record(&governed, &egress, &delivered(60))
        .expect("the exchange records once, with its reply");

    assert!(
        policy.decide(&governed, &egress, &request(60)).is_allow(),
        "one exchange delivering 60 bytes must charge 60 against a budget of 100, whatever the \
         reply carried"
    );
    policy
        .record(&governed, &egress, &delivered(60))
        .expect("the second exchange records");
    assert!(
        !policy.decide(&governed, &egress, &request(60)).is_allow(),
        "120 delivered bytes exceed the budget at the same threshold as before"
    );
}

/// A request that got no reply records with no `output`, and still charges its delivered bytes.
#[test]
fn a_delivery_with_no_reply_still_charges_the_budget() {
    let policy = budget_policy();
    let egress = Principal::agent();
    let governed = GovernedBox::assigned("test-box");

    for _ in 0..2 {
        assert!(policy.decide(&governed, &egress, &request(60)).is_allow());
        policy
            .record(
                &governed,
                &egress,
                &Outcome::Http {
                    host: "api.example.com",
                    port: 443,
                    method: "POST",
                    path: "/v1/upload",
                    delivery: Delivery::Completed { bytes: 60 },
                    status: None,
                },
            )
            .expect("a reply-less delivery records");
    }
    assert!(
        !policy.decide(&governed, &egress, &request(60)).is_allow(),
        "bytes that left the box count whether or not a reply came back"
    );
}
