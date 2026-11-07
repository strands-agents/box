//! The temporal byte budget enforced through the **real** MITM egress proxy.
//!
//! `temporal_egress_budget.rs` proves the rule at the facade, calling `decide`/`record`
//! directly. This drives actual TLS traffic through `MitmInterceptor` and asserts a
//! later request is refused with 403 *because* the deliveries of the earlier ones
//! exhausted the budget — the whole loop, over sockets:
//!
//! ```text
//! workload --TLS--> proxy --> EgressPolicyInterceptor::intercept --> PolicyEngine::decide
//!                     |                                                   ^
//!                     '--> write upstream --> record_outcome --> PolicyEngine::record
//! ```
//!
//! The interceptor under test is the shipped `EgressPolicyInterceptor`, not a test
//! double, so what passes here is the real integration.

#![cfg(feature = "egress-adapter")]

#[path = "../../egress-gateway/tests/harness/mod.rs"]
mod harness;

mod support;

use std::path::PathBuf;
use std::sync::Arc;

use egress_gateway::{
    AuditDecision, CapabilitySet, EffectAttempt, MitmConfig, MitmHandle, MitmInterceptor,
    StubEmitter,
};
use policy::{
    EgressPolicyInterceptor, GovernedBox, Policy, PolicyEngine, Principal, generate_mcp_schema,
};

use harness::{TlsUpstream, WorkloadClient};

/// The budget rule, calibrated for wire bytes (headers included).
const BUDGET_POLICY: &str = include_str!("policies/egress_byte_budget_e2e.dw");

/// A permit for the transport legs the budget rule does not govern.
///
/// The shipped schema has no `permit` for `net:connect`, so a
/// budget-only policy would deny the connect and the test would never reach an HTTP
/// request. These two rules exist to isolate the temporal decision to `http:request`.
const TRANSPORT_POLICY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource);
"#;

fn proxy_port(handle: &MitmHandle) -> u16 {
    handle.port().expect("a TCP-mode proxy always has a port")
}

fn budget_policy() -> Arc<PolicyEngine> {
    Arc::new(
        support::open_policy(vec![
            Policy {
                origin: PathBuf::from("egress_byte_budget_e2e.dw"),
                text: BUDGET_POLICY.to_string(),
            },
            Policy {
                origin: PathBuf::from("transport.dw"),
                text: TRANSPORT_POLICY.to_string(),
            },
        ])
        .expect("temporal policy loads"),
    )
}

#[test]
fn the_byte_budget_denies_a_later_request_through_the_real_proxy() {
    let host = "api.budget.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();

    let policy = budget_policy();
    let interceptor = EgressPolicyInterceptor::into_handle(
        Arc::clone(&policy),
        Principal::agent(),
        GovernedBox::assigned("test-box"),
    );

    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem()],
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        ..MitmConfig::default()
    };
    let records = StubEmitter::new();
    let handle = MitmInterceptor::start_with(
        config,
        CapabilitySet::default(),
        interceptor,
        Box::new(records.clone()),
        None,
    )
    .expect("proxy starts");

    // One connection carries one request: the proxy answers `Connection: close` and
    // handles a single request/response pair per tunnel. So each iteration is a fresh
    // client, and each fires its own connect + request + response effects.
    // 24 iterations, not 6. An earlier version of this test stopped at 6 and asserted
    // the denial was "stable once tripped" — which passed only because the run was too
    // short to observe otherwise. The budget is a 60-second window, so a long run must
    // stay denied for the whole window rather than sawtooth back to 200.
    let mut statuses = Vec::new();
    for _ in 0..24 {
        let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
        client.send_request("POST", "/v1/upload", &[], b"0123456789");
        statuses.push(client.read_status());
    }

    // The first request meets an empty budget and is allowed.
    assert_eq!(
        statuses[0], 200,
        "the first request is under the empty budget: {statuses:?}"
    );

    // Some later request is refused. This is the assertion the integration exists for:
    // an identical request, allowed earlier, is now denied purely because of what the
    // earlier ones delivered.
    let denied_at = statuses
        .iter()
        .position(|status| *status == 403)
        .unwrap_or_else(|| panic!("the budget must eventually deny: {statuses:?}"));

    // Once tripped the denial holds for the rest of the run, because the run is far
    // shorter than the 60-second window and denied requests deliver nothing.
    //
    // This is the assertion that caught the real defect: while the event clock was a
    // counter, `within 60s` meant "the last 60 events", so denied attempts aged the
    // budget out and a 200 reappeared 13 iterations after the first 403. A sawtooth here
    // means the window is measuring traffic instead of time.
    assert!(
        statuses[denied_at..].iter().all(|status| *status == 403),
        "a budget denial must hold for the whole window; a 200 reappearing means the \
         window is counting events, not seconds: {statuses:?}"
    );

    // The upstream saw exactly the allowed requests. This is what makes the denial
    // real rather than cosmetic — a denied request never reached the network.
    assert_eq!(
        upstream.request_count(),
        denied_at,
        "a denied request must never reach the upstream: {statuses:?}"
    );

    // The denial is recorded.
    assert!(
        records
            .records()
            .iter()
            .any(|record| record.decision == AuditDecision::Deny),
        "the request-leg denial must be recorded"
    );
}

#[test]
fn a_stateless_policy_allows_every_request_through_the_same_proxy() {
    // The control. Same proxy, same traffic, same principal — but a policy with no
    // temporal clause. Every request is allowed, which proves the denials in the test
    // above come from accumulated history and not from some unrelated property of the
    // harness (a header limit, a connection cap, a flaky upstream).
    let host = "api.stateless.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();

    let policy = Arc::new(
        support::open_policy(vec![Policy {
            origin: PathBuf::from("stateless.dw"),
            text: format!(
                "{TRANSPORT_POLICY}\npermit(principal == Box::Agent::\"self\", action == Box::Action::\"http:request\", resource);"
            ),
        }])
        .expect("stateless policy loads"),
    );
    let interceptor = EgressPolicyInterceptor::into_handle(
        Arc::clone(&policy),
        Principal::agent(),
        GovernedBox::assigned("test-box"),
    );

    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem()],
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        ..MitmConfig::default()
    };
    let handle = MitmInterceptor::start(config, CapabilitySet::default(), interceptor)
        .expect("proxy starts");

    for index in 0..6 {
        let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
        client.send_request("POST", "/v1/upload", &[], b"0123456789");
        assert_eq!(
            client.read_status(),
            200,
            "request {index} must be allowed without a temporal budget"
        );
    }
    assert_eq!(upstream.request_count(), 6);
}

#[test]
fn streamed_http_and_mcp_history_waits_for_upstream_termination() {
    use std::io::Read;
    use std::time::{Duration, Instant};

    for (end, disconnect) in [
        ("complete", false),
        ("truncated", false),
        ("complete", true),
        ("truncated", true),
        ("deadline", true),
    ] {
        let host = "mcp-history.test";
        let (upstream, sender) = TlsUpstream::start_controlled(host);
        let schema = generate_mcp_schema(
            "demo",
            r#"{"result":{"tools":[{"name":"act","inputSchema":{"type":"object"}}]}}"#,
        )
        .unwrap();
        let policy = support::open_policy_with_mcp_schemas(
            vec![Policy {
                origin: PathBuf::from("stream-history.dw"),
                text: format!(
                    r#"{TRANSPORT_POLICY}
                    permit(principal, action == Box::Action::"mcp:call", resource);
                    permit(principal, action == Box::Action::"http:request", resource)
                    when {{ context.input.path == "/mcp" }};
                    permit(principal, action == Box::Action::"http:request", resource)
                    when {{ context.input.path == "/after-http" }}
                    when temporal {{
                        formerly within 300s (
                            Box::Action::"http:request"::response{{ input.path: "/mcp", output.status: 200 }}
                        )
                    }};
                    permit(principal, action == Box::Action::"http:request", resource)
                    when {{ context.input.path == "/after-mcp" }}
                    when temporal {{
                        formerly within 300s (
                            Box::Action::"mcp:call"::response{{ input.server: "demo", input.tool: "act" }}
                        )
                    }};"#
                ),
            }],
            &[schema],
        )
        .unwrap();
        let interceptor = EgressPolicyInterceptor::into_handle(
            Arc::new(policy),
            Principal::agent(),
            GovernedBox::assigned("test-box"),
        );
        let handle = MitmInterceptor::start(
            MitmConfig {
                upstream_ca_pems: vec![upstream.ca_pem()],
                dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
                mcp_servers: vec![(host.to_string(), "demo".to_string())],
                upstream_read_deadline: Duration::from_secs(2),
                ..MitmConfig::default()
            },
            CapabilitySet::default(),
            interceptor.clone(),
        )
        .unwrap();
        let probe = |path| {
            interceptor.intercept(&EffectAttempt::HttpRequest {
                host,
                port: upstream.port(),
                method: "GET",
                path,
                body_bytes: 0,
                intercepted: true,
                mcp: None,
            })
        };
        let mut client = WorkloadClient::connect(proxy_port(&handle), host, upstream.port());
        client.set_read_timeout(Duration::from_secs(3));
        client.send_request(
            "POST",
            "/mcp",
            &[("Content-Type", "application/json")],
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"act","arguments":{}}}"#,
        );
        sender
            .send(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n6\r\ndata:\n\r\n"
                    .to_vec(),
            )
            .unwrap();
        let head = client.read_head();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let mut prefix = [0; 6];
        client.response_body(&head).read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"data:\n");
        let mut client = if disconnect {
            client.abort();
            for _ in 0..2 {
                let _ = sender.send(b"6\r\ndata:\n\r\n".to_vec());
                std::thread::sleep(Duration::from_millis(50));
            }
            None
        } else {
            Some(client)
        };
        for path in ["/after-http", "/after-mcp"] {
            assert!(
                probe(path).is_err(),
                "{end}, disconnect={disconnect}: {path} became available during the response"
            );
        }
        if end == "complete" {
            sender.send(b"0\r\n\r\n".to_vec()).unwrap();
        }
        let held_sender = (end == "deadline").then_some(sender);
        if let Some(client) = &mut client {
            assert_eq!(
                client
                    .response_body(&head)
                    .read_to_end(&mut Vec::new())
                    .is_ok(),
                end == "complete"
            );
        }
        for path in ["/after-http", "/after-mcp"] {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match probe(path) {
                    Ok(permit) => {
                        permit.mark_indeterminate();
                        break;
                    }
                    Err(error) => {
                        assert!(
                            Instant::now() < deadline,
                            "{end}, disconnect={disconnect}: {path} missing after termination: {error}"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        }
        drop(held_sender);
    }
}
