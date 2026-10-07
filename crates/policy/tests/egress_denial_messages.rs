#![cfg(feature = "egress-adapter")]

#[path = "../../egress-gateway/tests/harness/mod.rs"]
mod harness;
mod support;

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use egress_gateway::{
    AuditDecision, CapabilitySet, MitmConfig, MitmHandle, MitmInterceptor, StubEmitter,
};
use harness::{TlsUpstream, WorkloadClient};
use policy::{EgressPolicyInterceptor, GovernedBox, Policy, Principal, generate_mcp_schema};
use serde_json::{Value, json};

const HOST: &str = "denial.test";
const CONNECT: &str = r#"permit(principal, action == Box::Action::"net:connect", resource);"#;
const HTTP: &str = r#"permit(principal, action == Box::Action::"http:request", resource);"#;
const MCP: &str = r#"permit(principal, action == Box::Action::"mcp:call", resource);"#;
/// The resource each expected message names, filled in per gateway.
const RESOURCE: &str = "<resource>";
const DEFAULT_DENY: &str = "policy denied this operation on '<resource>' [default-deny]: No permit policy matched this request.";
const EVALUATION_FAILURE: &str =
    "policy denied this operation on '<resource>' because the request could not be evaluated.";

fn cases(action: &str) -> Vec<(String, String)> {
    vec![
        (
            format!(
                r#"@id("restricted") @description("Use the approved endpoint.")
                forbid(principal, action == {action}, resource);"#
            ),
            "policy denied this operation on '<resource>' [policy: restricted]: Use the approved endpoint."
                .to_string(),
        ),
        (
            format!(r#"@id("restricted") forbid(principal, action == {action}, resource);"#),
            "policy denied this operation on '<resource>' [policy: restricted].".to_string(),
        ),
        (String::new(), DEFAULT_DENY.to_string()),
        (
            format!(
                r#"@id("not-the-cause") @description("Do not print this annotation.")
                permit(principal, action == {action}, resource);
                forbid(principal, action == {action}, resource)
                when {{ 9223372036854775807 + 1 > 0 }};"#
            ),
            EVALUATION_FAILURE.to_string(),
        ),
    ]
}

fn gateway(source: &str, mut config: MitmConfig) -> (MitmHandle, StubEmitter) {
    let schema = generate_mcp_schema(
        "demo",
        r#"{"result":{"tools":[{"name":"add","inputSchema":{"type":"object",
        "properties":{"a":{"type":"integer"}},"required":["a"]}}]}}"#,
    )
    .unwrap();
    let sources = vec![Policy {
        origin: PathBuf::from("egress-denial-messages.dw"),
        text: source.to_string(),
    }];
    let engine = if config.mcp_servers.is_empty() {
        support::open_policy(sources)
    } else {
        support::open_policy_with_mcp_schemas(sources, &[schema])
    }
    .unwrap();
    config.dns_overrides = vec![(HOST.to_string(), "127.0.0.1".parse().unwrap())];
    let emitter = StubEmitter::new();
    let handle = MitmInterceptor::start_with_emitter(
        config,
        CapabilitySet::default(),
        EgressPolicyInterceptor::into_handle(
            Arc::new(engine),
            Principal::agent(),
            GovernedBox::assigned("denial-messages"),
        ),
        Box::new(emitter.clone()),
    )
    .unwrap();
    (handle, emitter)
}

fn response_body(response: &str) -> &str {
    let (head, body) = response.split_once("\r\n\r\n").expect("HTTP response");
    assert!(head.starts_with("HTTP/1.1 403 "), "{response}");
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .expect("content length");
    assert_eq!(length, body.len(), "{response}");
    body
}

fn raw_response(stream: &mut (impl Read + Write), request: &str) -> String {
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn connect_refusals_reach_tcp_and_unix_workloads_without_opening_upstream() {
    let mut correlations = HashSet::new();
    for (source, expected) in cases(r#"Box::Action::"net:connect""#) {
        for transport in ["connect", "plain", "unix"] {
            let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
            upstream.set_nonblocking(true).unwrap();
            let port = upstream.local_addr().unwrap().port();
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("gateway.sock");
            let config = MitmConfig {
                unix_socket_path: (transport == "unix").then(|| socket.clone()),
                ..MitmConfig::default()
            };
            let (handle, emitter) = gateway(&source, config);
            let request = if transport == "plain" {
                format!("GET http://{HOST}:{port}/ HTTP/1.1\r\nHost: {HOST}:{port}\r\n\r\n")
            } else {
                format!("CONNECT {HOST}:{port} HTTP/1.1\r\nHost: {HOST}:{port}\r\n\r\n")
            };
            for exchange in 0..2 {
                let response = if transport == "unix" {
                    let mut stream = UnixStream::connect(&socket).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    raw_response(&mut stream, &request)
                } else {
                    let mut stream =
                        TcpStream::connect(("127.0.0.1", handle.port().unwrap())).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    raw_response(&mut stream, &request)
                };
                assert_eq!(
                    response_body(&response),
                    expected.replace(RESOURCE, &format!("{HOST}:{port}")),
                    "{transport}"
                );
                assert_eq!(
                    upstream.accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                let events = handle.drain_audit_events();
                assert_eq!(events.len(), 1);
                assert_eq!(events[0].decision, AuditDecision::Deny);
                assert_eq!(events[0].host, HOST);
                assert_eq!(events[0].port, port);
                let correlation = events[0].correlation.as_str();
                assert!(!correlation.is_empty());
                let decisions = emitter.records();
                assert_eq!(decisions.len(), exchange + 1);
                assert_eq!(decisions[exchange].decision, AuditDecision::Deny);
                assert_eq!(decisions[exchange].correlation.as_str(), correlation);
                assert!(
                    correlations.insert(correlation.to_owned()),
                    "separate exchanges must have distinct correlation IDs"
                );
            }
        }
    }
}

fn tls_gateway(source: &str, remote: bool) -> (MitmHandle, TlsUpstream, StubEmitter) {
    let upstream = TlsUpstream::start(HOST);
    let (handle, emitter) = gateway(
        source,
        MitmConfig {
            upstream_ca_pems: vec![upstream.ca_pem()],
            mcp_servers: if remote {
                vec![(HOST.to_string(), "demo".to_string())]
            } else {
                Vec::new()
            },
            ..MitmConfig::default()
        },
    );
    (handle, upstream, emitter)
}

fn tls_response(handle: &MitmHandle, upstream: &TlsUpstream, body: &[u8]) -> String {
    let mut client = WorkloadClient::connect(handle.port().unwrap(), HOST, upstream.port());
    client.send_request(
        "POST",
        "/mcp",
        &[("Content-Type", "application/json")],
        body,
    );
    client.read_response()
}

#[test]
fn http_refusals_reach_the_workload_without_forwarding_the_request() {
    let mut correlations = HashSet::new();
    for (source, expected) in cases(r#"Box::Action::"http:request""#) {
        let (handle, upstream, emitter) = tls_gateway(&format!("{CONNECT}\n{source}"), false);
        let expected = expected.replace(RESOURCE, &format!("{HOST}:{}/mcp", upstream.port()));
        for exchange in 0..2 {
            let response = tls_response(&handle, &upstream, b"private request body");
            assert_eq!(
                response_body(&response),
                format!("http:request gate: {expected}")
            );
            assert_eq!(upstream.request_count(), 0);
            let events = handle.drain_audit_events();
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.decision == AuditDecision::Deny)
                    .count(),
                1
            );
            assert!(
                events
                    .iter()
                    .all(|event| event.host == HOST && event.port == upstream.port())
            );
            let correlation = events[0].correlation.as_str();
            assert!(!correlation.is_empty());
            assert!(
                events
                    .iter()
                    .all(|event| event.correlation.as_str() == correlation),
                "related events must share the exchange correlation ID"
            );
            let decisions = emitter.records();
            assert_eq!(decisions.len(), 2 * (exchange + 1));
            let current = &decisions[2 * exchange..];
            assert_eq!(current[0].decision, AuditDecision::Allow);
            assert_eq!(current[1].decision, AuditDecision::Deny);
            assert_eq!(current[1].method, "POST");
            assert_eq!(current[1].path, "/mcp");
            assert!(
                current
                    .iter()
                    .all(|decision| decision.correlation.as_str() == correlation),
                "CONNECT and HTTP decisions must match the exchange audit ID"
            );
            assert!(
                correlations.insert(correlation.to_owned()),
                "separate exchanges must have distinct correlation IDs"
            );
        }
    }
}

#[test]
fn remote_mcp_refusals_keep_the_request_id_and_explain_the_deciding_gate() {
    for (action, permits, prefix, resource) in [
        (
            r#"Box::Action::"http:request""#,
            CONNECT.to_string(),
            "http:request gate: ",
            None,
        ),
        (
            r#"Box::Action::"mcp:call""#,
            format!("{CONNECT}\n{HTTP}"),
            "mcp:call gate (server \"demo\" method \"tools/call\"): ",
            Some("demo/add"),
        ),
        (
            r#"demo::Action::"add""#,
            format!("{CONNECT}\n{HTTP}\n{MCP}"),
            "per-tool gate (demo::Action::\"add\"): ",
            Some("demo/add"),
        ),
    ] {
        for (source, expected) in cases(action) {
            if source.is_empty() && action.starts_with("demo::") {
                continue;
            }
            let (handle, upstream, _) = tls_gateway(&format!("{permits}\n{source}"), true);
            let expected = expected.replace(
                RESOURCE,
                resource.unwrap_or(&format!("{HOST}:{}/mcp", upstream.port())),
            );
            for id in [json!(17), json!("request-\"\\\n\u{202e}"), json!(u64::MAX)] {
                let frame = json!({
                    "jsonrpc": "2.0", "id": id, "method": "tools/call",
                    "params": {"name": "add", "arguments": {"a": 7}}
                });
                let response = tls_response(&handle, &upstream, frame.to_string().as_bytes());
                assert!(
                    response
                        .to_ascii_lowercase()
                        .contains("content-type: application/json\r\n")
                );
                let reply: Value = serde_json::from_str(response_body(&response)).unwrap();
                assert_eq!(
                    reply,
                    json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": {"code": -32001, "message": format!("{prefix}{expected}")}
                    })
                );
                assert_eq!(upstream.request_count(), 0);
            }
        }
    }
}

#[test]
fn gateway_explanations_preserve_annotation_escaping_and_bounds() {
    for description in [
        "Use \"approved\".\\\n\r\t\u{1b}\u{202e}".to_string(),
        "🦀".repeat(5000),
    ] {
        let literal = format!("{description:?}");
        let source = format!(
            r#"{CONNECT} {HTTP}
            @id("restricted") @description({literal})
            forbid(principal, action == Box::Action::"mcp:call", resource);"#
        );
        let (handle, upstream, _) = tls_gateway(&source, true);
        let frame = br#"{"jsonrpc":"2.0","id":"escaped","method":"tools/call","params":{"name":"add","arguments":{"a":7}}}"#;
        let response = tls_response(&handle, &upstream, frame);
        let reply: Value = serde_json::from_str(response_body(&response)).unwrap();
        let message = reply["error"]["message"].as_str().unwrap();
        let explanation = message.split_once(": policy denied").unwrap().1;
        assert!(explanation.len() + "policy denied".len() <= 4096);
        assert!(!message.chars().any(char::is_control));
        assert!(!message.contains('\u{202e}'));
        if description.starts_with("Use") {
            assert!(
                message.contains(r#"Use "approved".\\\n\r\t\u{1b}\u{202e}"#),
                "{message}"
            );
        } else {
            assert!(message.ends_with("..."), "{message}");
            assert!(message.contains('🦀'));
        }
        assert_eq!(upstream.request_count(), 0);
    }
}

#[test]
fn remote_mcp_refusals_form_rpc_errors_only_for_valid_request_ids() {
    let (handle, upstream, _) = tls_gateway(CONNECT, true);
    let default_deny = DEFAULT_DENY.replace(RESOURCE, &format!("{HOST}:{}/mcp", upstream.port()));
    for method in ["tools/list", "ping", "notifications/initialized"] {
        let frame = json!({"jsonrpc": "2.0", "id": 7, "method": method});
        let response = tls_response(&handle, &upstream, frame.to_string().as_bytes());
        let reply: Value = serde_json::from_str(response_body(&response)).unwrap();
        assert_eq!(
            reply,
            json!({
                "jsonrpc": "2.0", "id": 7,
                "error": {"code": -32001, "message": format!("http:request gate: {default_deny}")}
            })
        );
        assert_eq!(upstream.request_count(), 0);
    }
    for frame in [
        r#"{"jsonrpc":"2.0","method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":null,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":{},"method":"tools/list"}"#,
        r#"{"jsonrpc":"1.0","id":7,"method":"tools/list"}"#,
    ] {
        let response = tls_response(&handle, &upstream, frame.as_bytes());
        assert_eq!(
            response_body(&response),
            format!("http:request gate: {default_deny}")
        );
        assert_eq!(upstream.request_count(), 0);
    }
}
