//! A WebSocket through the policy facade: the handshake and each later check are `http:request`
//! decisions with `upgrade` "websocket", and each check records the bytes it let out.

mod support;

use std::path::PathBuf;

use policy::{Delivery, GovernedBox, Outcome, Policy, PolicyEngine, Principal, Request};

fn open(text: &str) -> PolicyEngine {
    support::open_policy(vec![Policy {
        origin: PathBuf::from("websocket.dw"),
        text: text.to_string(),
    }])
    .expect("policy loads")
}

/// A decision on `/chat`: the handshake has no body, and a check carries the bytes it allows.
fn http(body_bytes: usize, upgrade: Option<&'static str>) -> Request<'static> {
    Request::Http {
        host: "api.example.com",
        port: 443,
        method: "GET",
        path: "/chat",
        body_bytes,
        intercepted: true,
        upgrade,
    }
}

/// What a handshake or a check let out.
fn sent(bytes: usize, upgrade: Option<&'static str>) -> Outcome<'static> {
    Outcome::Http {
        host: "api.example.com",
        port: 443,
        method: "GET",
        path: "/chat",
        delivery: Delivery::Completed { bytes },
        status: Some(if upgrade.is_some() { 101 } else { 200 }),
        intercepted: true,
        upgrade,
    }
}

fn allowed(policy: &PolicyEngine, request: &Request<'_>) -> bool {
    policy
        .decide(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            request,
        )
        .is_allow()
}

fn record(policy: &PolicyEngine, outcome: &Outcome<'_>) {
    policy
        .record(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            outcome,
        )
        .expect("history records");
}

#[test]
fn a_rule_can_name_a_websocket_with_upgrade() {
    let policy = open(
        r#"
permit (principal, action == Box::Action::"http:request", resource);
@id("no_websocket_upload")
forbid (principal, action == Box::Action::"http:request", resource)
when { context.input has upgrade && context.input.upgrade == "websocket" && context.input.body_bytes > 0 };
"#,
    );
    assert!(
        allowed(&policy, &http(100, None)),
        "a plain GET with a body"
    );
    assert!(
        allowed(&policy, &http(0, Some("websocket"))),
        "the handshake"
    );
    assert!(
        !allowed(&policy, &http(65536, Some("websocket"))),
        "a check"
    );
}

#[test]
fn a_byte_budget_counts_the_bytes_of_each_check() {
    let policy = open(include_str!("policies/egress_byte_budget.dw"));
    assert!(allowed(&policy, &http(0, Some("websocket"))));
    record(&policy, &sent(50, Some("websocket")));
    assert!(
        allowed(&policy, &http(65536, Some("websocket"))),
        "50 bytes sent"
    );
    record(&policy, &sent(60, Some("websocket")));
    assert!(
        !allowed(&policy, &http(65536, Some("websocket"))),
        "110 bytes sent: the rule refuses with no edit"
    );
}

#[test]
fn a_temporal_rule_can_count_only_websocket_bytes() {
    let policy = open(
        r#"
permit (principal, action == Box::Action::"http:request", resource);
@id("websocket_budget")
forbid (principal, action == Box::Action::"http:request", resource)
when temporal {
  exists (total: Long). (
    (sum b for (b: Long), (t: Timepoint). where (
      formerly within 60s (
        Box::Action::"http:request"::response{ input.upgrade: "websocket", input.body_bytes: b } && tp(t)
      )
    )) == total && total >= 100
  )
};
"#,
    );
    record(&policy, &sent(500, None));
    assert!(
        allowed(&policy, &http(65536, Some("websocket"))),
        "plain request bytes do not count"
    );
    record(&policy, &sent(120, Some("websocket")));
    assert!(!allowed(&policy, &http(65536, Some("websocket"))));
}
