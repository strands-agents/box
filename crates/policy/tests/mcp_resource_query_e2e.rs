//! Production policy and gateway forwarding preserve an admitted MCP resource URI through plain HTTP and TLS fetches.

#![cfg(feature = "egress-adapter")]

#[path = "../../egress-gateway/tests/harness/mod.rs"]
mod harness;
mod support;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use egress_gateway::{CapabilitySet, MitmConfig, MitmInterceptor};
use policy::{EgressPolicyInterceptor, GovernedBox, Policy, Principal};
use serde_json::{Value, json};

use harness::{ResponseBody, TlsUpstream, WorkloadClient, read_http_head};

const MCP_HOST: &str = "mcp.query.test";
const RESOURCE_HOST: &str = "resource.query.test";

#[test]
fn an_exact_uri_forbid_cannot_be_bypassed_by_an_empty_query_over_plain_http() {
    resource_read_preserves_the_admitted_uri(false, false);
}

#[test]
fn an_exact_uri_forbid_cannot_be_bypassed_by_an_empty_query_over_tls() {
    resource_read_preserves_the_admitted_uri(true, false);
}

#[test]
fn an_exact_empty_query_forbid_still_allows_the_queryless_uri_over_plain_http() {
    resource_read_preserves_the_admitted_uri(false, true);
}

#[test]
fn an_exact_empty_query_forbid_still_allows_the_queryless_uri_over_tls() {
    resource_read_preserves_the_admitted_uri(true, true);
}

fn resource_read_preserves_the_admitted_uri(tls: bool, forbid_empty_query: bool) {
    let tls_origin = tls.then(|| TlsUpstream::start(RESOURCE_HOST));
    let plain_origin = (!tls).then(|| PlainServer::start(|_| "ok".to_owned()));
    let origin_port = tls_origin
        .as_ref()
        .map_or_else(|| plain_origin.as_ref().unwrap().port, TlsUpstream::port);
    let scheme = if tls { "https" } else { "http" };
    let resource_prefix = format!("{scheme}://{RESOURCE_HOST}:{origin_port}");
    let forbidden_target = if forbid_empty_query {
        "/report?"
    } else {
        "/report"
    };
    let allowed_target = if forbid_empty_query {
        "/report"
    } else {
        "/report?"
    };
    let forbidden_uri = format!("{resource_prefix}{forbidden_target}");
    let allowed_uri = format!("{resource_prefix}{allowed_target}");

    // Permit every resource on this server except this exact URI. Without agreement
    // between admission and forwarding, X? passes the forbid but is fetched as X.
    let policy = support::open_policy(vec![Policy {
        origin: PathBuf::from("resource-empty-query.dw"),
        text: format!(
            r#"
            permit(principal, action == Box::Action::"net:connect", resource);
            permit(principal, action == Box::Action::"http:request", resource);
            permit(principal, action == Box::Action::"mcp:call", resource)
            when {{ context.input.server == "notes" }};
            forbid(principal, action == Box::Action::"mcp:call", resource)
            when {{ context.input has uri && context.input.uri == "{forbidden_uri}" }};
            "#
        ),
    }])
    .expect("the exact-URI forbid and broader server permit load");
    let interceptor = EgressPolicyInterceptor::into_handle(
        Arc::new(policy),
        Principal::agent(),
        GovernedBox::assigned("resource-query-test"),
    );
    let handle = MitmInterceptor::start(
        MitmConfig {
            upstream_ca_pems: tls_origin.iter().map(TlsUpstream::ca_pem).collect(),
            dns_overrides: vec![
                (MCP_HOST.to_owned(), "127.0.0.1".parse().unwrap()),
                (RESOURCE_HOST.to_owned(), "127.0.0.1".parse().unwrap()),
            ],
            mcp_servers: vec![(MCP_HOST.to_owned(), "notes".to_owned())],
            ..MitmConfig::default()
        },
        CapabilitySet::default(),
        interceptor,
    )
    .expect("the real gateway starts");
    let proxy_port = handle.port().unwrap();

    let server = PlainServer::start(move |request| {
        let frame: Value = serde_json::from_str(http_body(request)).unwrap();
        let uri = frame["params"]["uri"].as_str().unwrap();
        // Derive the fetch target from the frame actually received by the MCP
        // server. Do not substitute the URI submitted by the test client.
        let target = uri.strip_prefix(&resource_prefix).unwrap();
        let response = if tls {
            let mut fetch = WorkloadClient::connect(proxy_port, RESOURCE_HOST, origin_port);
            fetch.set_read_timeout(Duration::from_secs(10));
            fetch.send_request("GET", target, &[], b"");
            fetch.read_response()
        } else {
            plain_request(proxy_port, RESOURCE_HOST, origin_port, "GET", target, b"")
        };
        assert_status(&response, 200);
        json!({
            "jsonrpc": "2.0",
            "id": frame["id"],
            "result": {"contents": [{"uri": uri, "text": http_body(&response)}]}
        })
        .to_string()
    });

    let forbidden_frame = resource_frame(&forbidden_uri);
    let denied = plain_request(
        proxy_port,
        MCP_HOST,
        server.port,
        "POST",
        "/mcp",
        &serde_json::to_vec(&forbidden_frame).unwrap(),
    );
    assert_status(&denied, 403);
    assert!(
        server.requests().is_empty(),
        "the exact forbidden URI must never reach the MCP server"
    );
    assert_eq!(
        origin_request_count(&tls_origin, &plain_origin),
        0,
        "the denied resource must never be fetched"
    );

    let allowed_frame = resource_frame(&allowed_uri);
    let allowed = plain_request(
        proxy_port,
        MCP_HOST,
        server.port,
        "POST",
        "/mcp",
        &serde_json::to_vec(&allowed_frame).unwrap(),
    );
    assert_status(&allowed, 200);
    let requests = server.requests();
    assert_eq!(requests.len(), 1, "only the permitted read reaches MCP");
    let forwarded: Value = serde_json::from_str(http_body(&requests[0])).unwrap();
    assert_eq!(
        forwarded, allowed_frame,
        "MCP receives the whole admitted frame"
    );
    assert_eq!(origin_request_count(&tls_origin, &plain_origin), 1);
    let origin_request = tls_origin.as_ref().map_or_else(
        || plain_origin.as_ref().unwrap().requests()[0].clone(),
        |origin| origin.last_request().raw,
    );
    assert_eq!(
        origin_request.lines().next(),
        Some(format!("GET {allowed_target} HTTP/1.1").as_str()),
        "the permitted URI must not become the forbidden URI at the resource origin"
    );
    let reply: Value = serde_json::from_str(http_body(&allowed)).unwrap();
    assert_eq!(reply["result"]["contents"][0]["uri"], allowed_uri);
    assert_eq!(reply["result"]["contents"][0]["text"], "ok");
}

fn resource_frame(uri: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "read-report",
        "method": "resources/read",
        "params": {"uri": uri, "_meta": {"trace": "empty-query"}}
    })
}

fn origin_request_count(tls: &Option<TlsUpstream>, plain: &Option<PlainServer>) -> usize {
    tls.as_ref().map_or_else(
        || plain.as_ref().unwrap().requests().len(),
        TlsUpstream::request_count,
    )
}

fn http_body(message: &str) -> &str {
    message.split_once("\r\n\r\n").unwrap().1
}

fn assert_status(response: &str, expected: u16) {
    assert_eq!(
        response.split_whitespace().nth(1),
        Some(expected.to_string().as_str()),
        "unexpected gateway response: {response}"
    );
}

/// Send an absolute-form HTTP request through the gateway and decode its response.
fn plain_request(
    proxy_port: u16,
    host: &str,
    port: u16,
    method: &str,
    target: &str,
    body: &[u8],
) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "{method} http://{host}:{port}{target} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body).unwrap();
    read_message(&mut stream)
}

fn read_message(stream: &mut TcpStream) -> String {
    let head = read_http_head(stream);
    let mut body = String::new();
    ResponseBody::new(stream, &head)
        .read_to_string(&mut body)
        .unwrap();
    format!("{head}{body}")
}

/// Record complete requests before responding, so a 403 can prove non-delivery.
struct PlainServer {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

impl PlainServer {
    fn start(respond: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let respond = Arc::new(respond);
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let seen = Arc::clone(&record);
                let respond = Arc::clone(&respond);
                std::thread::spawn(move || {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    let request = read_message(&mut stream);
                    if !request.contains("HTTP/") {
                        return;
                    }
                    seen.lock().unwrap().push(request.clone());
                    let body = respond(&request);
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                });
            }
        });
        Self { port, seen }
    }

    fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}
