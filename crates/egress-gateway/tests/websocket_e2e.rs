//! WebSocket through the egress gateway, end to end over real TLS.
//!
//! A real `MitmInterceptor` stands between a TLS workload client and a TLS WebSocket upstream that
//! this file implements, so every handshake crosses the gateway, and the upstream records what
//! reached it. Authorization comes from `PathPolicy`, the test's stand-in for the policy: the
//! handshake is an ordinary `http:request` `GET`, decided on its host and path.
//!
//! Requires the default-on `tls-intercept` feature.

#![cfg(feature = "tls-intercept")]

mod harness;

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use egress_gateway::{
    AuditDecision, CapabilitySet, EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit,
    MitmConfig, MitmHandle, MitmInterceptor,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use harness::{TlsUpstream, WorkloadClient};

/// The RFC 6455 example key.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

// ============================================================================================
// The policy stand-in: the handshake is an `http:request` `GET`
// ============================================================================================

/// Permits a connection to `hosts`, and each `HttpRequest` to them but the `(host, path)` pairs in
/// `denied`. It logs each request and release it decides, and the outcome each permit receives.
struct PathPolicy {
    hosts: Vec<String>,
    denied: Vec<(String, String)>,
    log: Arc<Mutex<Vec<String>>>,
}

impl PathPolicy {
    fn new(hosts: &[&str], denied: &[(&str, &str)]) -> Arc<Self> {
        Arc::new(Self {
            hosts: hosts.iter().map(|host| (*host).to_string()).collect(),
            denied: denied
                .iter()
                .map(|(host, path)| ((*host).to_string(), (*path).to_string()))
                .collect(),
            log: Arc::default(),
        })
    }

    /// Permit the connection and every request to `host`.
    fn permitting(host: &str) -> Arc<Self> {
        Self::new(&[host], &[])
    }

    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    /// The request entries of the log.
    fn requests(&self) -> Vec<String> {
        self.log()
            .into_iter()
            .filter(|entry| entry.starts_with("request "))
            .collect()
    }
}

fn listed(hosts: &[String], host: &str) -> bool {
    hosts.iter().any(|listed| listed.eq_ignore_ascii_case(host))
}

impl EffectInterceptor for PathPolicy {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        let denied = |message: &str| Err(io::Error::new(io::ErrorKind::PermissionDenied, message));
        let entry =
            match attempt {
                EffectAttempt::Resolve { host, .. } | EffectAttempt::Connect { host, .. } => {
                    if !listed(&self.hosts, host) {
                        return denied("connect denied by test policy");
                    }
                    None
                }
                EffectAttempt::HttpRequest {
                    host, method, path, ..
                } => {
                    if self.denied.iter().any(|(denied_host, denied_path)| {
                        denied_host == host && denied_path == path
                    }) {
                        return denied("http:request gate: denied by test policy");
                    }
                    Some(format!("request {method} {path}"))
                }
                EffectAttempt::ResponseRelease { status, .. } => {
                    Some(format!("release status={status}"))
                }
                _ => None,
            };
        if let Some(entry) = &entry {
            self.log.lock().unwrap().push(entry.clone());
        }
        Ok(Box::new(LoggedPermit {
            log: entry.map(|_| self.log.clone()),
        }))
    }
}

struct LoggedPermit {
    log: Option<Arc<Mutex<Vec<String>>>>,
}

impl EffectPermit for LoggedPermit {
    fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
        if let Some(log) = self.log {
            log.lock().unwrap().push(format!("outcome {outcome:?}"));
        }
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {
        if let Some(log) = self.log {
            log.lock().unwrap().push("indeterminate".to_string());
        }
    }
}

// ============================================================================================
// Heads on the wire
// ============================================================================================

/// Read an HTTP head up to its blank line, one byte at a time so no frame byte is taken with it.
fn read_head<R: Read>(stream: &mut R) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 64 * 1024 {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// The value of header `name` in a raw head, if present.
fn header(head: &str, name: &str) -> Option<String> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (field, value) = line.split_once(':')?;
        field
            .trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

fn status(head: &str) -> u16 {
    head.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

// ============================================================================================
// The WebSocket upstream
// ============================================================================================

/// How the upstream answers a handshake.
#[derive(Clone, Copy)]
enum Answer {
    /// Answer with this response instead of a 101.
    Fixed(&'static str),
}

/// What reached the upstream.
#[derive(Default)]
struct Seen {
    handshakes: Vec<String>,
}

/// A TLS server that records each handshake head and answers it.
struct WsUpstream {
    port: u16,
    ca_pem: String,
    seen: Arc<Mutex<Seen>>,
}

impl WsUpstream {
    fn start(host: &str, answer: Answer) -> Self {
        let certified =
            rcgen::generate_simple_self_signed(vec![host.to_string(), "localhost".to_string()])
                .unwrap();
        let config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(certified.cert.der().to_vec())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        certified.signing_key.serialize_der(),
                    )),
                )
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let record = seen.clone();
        std::thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let config = config.clone();
                let record = record.clone();
                std::thread::spawn(move || {
                    let tls = StreamOwned::new(ServerConnection::new(config).unwrap(), tcp);
                    let _ = serve(tls, answer, &record);
                });
            }
        });
        Self {
            port,
            ca_pem: certified.cert.pem(),
            seen,
        }
    }

    fn handshakes(&self) -> Vec<String> {
        std::thread::sleep(Duration::from_millis(100));
        self.seen.lock().unwrap().handshakes.clone()
    }
}

fn serve(
    mut tls: StreamOwned<ServerConnection, TcpStream>,
    answer: Answer,
    seen: &Mutex<Seen>,
) -> io::Result<()> {
    tls.sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    let head = read_head(&mut tls);
    if !head.contains("HTTP/") {
        return Ok(());
    }
    seen.lock().unwrap().handshakes.push(head);
    match answer {
        Answer::Fixed(response) => {
            tls.write_all(response.as_bytes())?;
            tls.flush()
        }
    }
}

// ============================================================================================
// The workload client
// ============================================================================================

fn handshake_head(host: &str, port: u16, extra: &str) -> String {
    format!(
        "GET /chat HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
    )
}

/// A WebSocket workload over a TLS tunnel through the gateway.
struct WsClient<S: Read + Write> {
    tls: StreamOwned<ClientConnection, S>,
}

impl WsClient<TcpStream> {
    /// CONNECT through the gateway's TCP port and complete TLS with its minted leaf.
    fn connect(handle: &MitmHandle, host: &str, port: u16) -> Self {
        let tls = WorkloadClient::connect(handle.port().unwrap(), host, port).into_tls();
        tls.sock
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        Self { tls }
    }

    /// Connect and send a handshake with `extra` header lines; returns the client and the reply.
    fn open(handle: &MitmHandle, host: &str, port: u16, extra: &str) -> (Self, String) {
        let mut client = Self::connect(handle, host, port);
        let reply = client.request(&handshake_head(host, port, extra));
        (client, reply)
    }
}

impl<S: Read + Write> WsClient<S> {
    /// Send a request head and read the reply head, with its body when it has a length.
    fn request(&mut self, head: &str) -> String {
        self.tls.write_all(head.as_bytes()).unwrap();
        self.tls.flush().unwrap();
        let mut reply = read_head(&mut self.tls);
        if let Some(length) = header(&reply, "content-length") {
            let mut body = vec![0u8; length.parse().unwrap()];
            self.tls.read_exact(&mut body).unwrap();
            reply.push_str(&String::from_utf8_lossy(&body));
        }
        reply
    }
}

// ============================================================================================
// Gateway setup
// ============================================================================================

fn start_gateway(
    host: &str,
    upstream: &WsUpstream,
    policy: Arc<PathPolicy>,
    config: MitmConfig,
) -> MitmHandle {
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem.clone()],
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        ..config
    };
    MitmInterceptor::start(config, CapabilitySet::default(), policy).unwrap()
}

/// The deny reasons in the gateway's audit log.
fn denials(handle: &MitmHandle) -> Vec<String> {
    handle
        .drain_audit_events()
        .into_iter()
        .filter(|event| event.decision == AuditDecision::Deny)
        .map(|event| event.reason)
        .collect()
}

/// A reply that a server with no WebSocket endpoint gives.
const NOT_FOUND: &str = "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnone";

// ============================================================================================
// Refusals before policy and before the upstream sees a request
// ============================================================================================

#[test]
fn an_upgrade_to_an_mcp_host_is_refused() {
    let host = "mcp.ws.test";
    let upstream = WsUpstream::start(host, Answer::Fixed(NOT_FOUND));
    let policy = PathPolicy::permitting(host);
    let handle = start_gateway(
        host,
        &upstream,
        policy.clone(),
        MitmConfig {
            mcp_servers: vec![(host.to_string(), "tools".to_string())],
            ..MitmConfig::default()
        },
    );

    let (_client, reply) = WsClient::open(&handle, host, upstream.port, "");
    assert_eq!(status(&reply), 403, "{reply:?}");
    assert!(reply.ends_with("WebSocket refused for an MCP server"));
    assert!(header(&reply, egress_gateway::PROXY_ORIGIN_HEADER).is_some());
    assert!(upstream.handshakes().is_empty());
    assert!(
        denials(&handle)
            .iter()
            .any(|reason| reason == "websocket: upgrade to a remote MCP server")
    );
    assert_eq!(
        policy.requests(),
        Vec::<String>::new(),
        "the refusal comes before policy"
    );
}

#[test]
fn a_malformed_handshake_is_refused_with_400() {
    let host = "malformed.ws.test";
    let upstream = WsUpstream::start(host, Answer::Fixed(NOT_FOUND));
    let policy = PathPolicy::permitting(host);
    let handle = start_gateway(host, &upstream, policy.clone(), MitmConfig::default());

    let mut client = WsClient::connect(&handle, host, upstream.port);
    let reply = client
        .request(&handshake_head(host, upstream.port, "").replace("Version: 13", "Version: 8"));
    assert_eq!(status(&reply), 400, "{reply:?}");
    assert!(
        reply.ends_with("malformed WebSocket handshake"),
        "{reply:?}"
    );
    assert!(header(&reply, egress_gateway::PROXY_ORIGIN_HEADER).is_some());
    assert!(upstream.handshakes().is_empty());
    assert!(
        denials(&handle)
            .iter()
            .any(|reason| reason == "websocket: handshake version is not 13")
    );
    assert_eq!(policy.requests(), Vec::<String>::new());
}

/// A `POST` that names `websocket` in `Upgrade` was stripped and forwarded before; now it is a
/// malformed handshake.
#[test]
fn a_post_that_asks_for_websocket_is_refused_with_400() {
    let host = "post.ws.test";
    let upstream = WsUpstream::start(host, Answer::Fixed(NOT_FOUND));
    let handle = start_gateway(
        host,
        &upstream,
        PathPolicy::permitting(host),
        MitmConfig::default(),
    );

    let mut client = WsClient::connect(&handle, host, upstream.port);
    let reply = client.request(
        &handshake_head(host, upstream.port, "Content-Length: 0\r\n").replacen("GET", "POST", 1),
    );
    assert_eq!(status(&reply), 400, "{reply:?}");
    assert!(upstream.handshakes().is_empty());
    assert!(
        denials(&handle)
            .iter()
            .any(|reason| reason == "websocket: handshake method is not GET")
    );
}

#[test]
fn a_plaintext_websocket_handshake_is_refused() {
    let host = "plain.ws.test";
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = origin.local_addr().unwrap().port();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let record = heads.clone();
    std::thread::spawn(move || {
        for mut stream in origin.incoming().flatten() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let head = read_head(&mut stream);
            if !head.is_empty() {
                record.lock().unwrap().push(head);
            }
        }
    });
    let policy = PathPolicy::permitting(host);
    let handle = MitmInterceptor::start(
        MitmConfig {
            dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
            ..MitmConfig::default()
        },
        CapabilitySet::default(),
        policy.clone(),
    )
    .unwrap();

    let mut proxy = TcpStream::connect(("127.0.0.1", handle.port().unwrap())).unwrap();
    proxy
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let request = handshake_head(host, port, "").replacen(
        "GET /chat",
        &format!("GET http://{host}:{port}/chat"),
        1,
    );
    proxy.write_all(request.as_bytes()).unwrap();
    let mut reply = String::new();
    let _ = proxy.read_to_string(&mut reply);

    assert!(reply.starts_with("HTTP/1.1 403"), "{reply:?}");
    assert!(reply.ends_with("WebSocket requires TLS"), "{reply:?}");
    assert!(header(&reply, egress_gateway::PROXY_ORIGIN_HEADER).is_some());
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        heads.lock().unwrap().is_empty(),
        "the origin sees no request"
    );
    assert_eq!(policy.requests(), Vec::<String>::new());
    assert!(
        denials(&handle)
            .iter()
            .any(|reason| reason == "websocket: upgrade on a plaintext request")
    );
}

// ============================================================================================
// The handshake as forwarded
// ============================================================================================

/// The offer of `permessage-deflate` never reaches the upstream, so no message is compressed
/// before the gateway reads it.
#[test]
fn extensions_are_removed_from_the_handshake() {
    let host = "extensions.ws.test";
    let upstream = WsUpstream::start(host, Answer::Fixed(NOT_FOUND));
    let policy = PathPolicy::permitting(host);
    let handle = start_gateway(host, &upstream, policy.clone(), MitmConfig::default());

    let (_client, reply) = WsClient::open(
        &handle,
        host,
        upstream.port,
        "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\
         Sec-WebSocket-Extensions: x-other\r\n",
    );
    assert_eq!(status(&reply), 404, "{reply:?}");
    let handshake = &upstream.handshakes()[0];
    assert_eq!(header(handshake, "sec-websocket-extensions"), None);
    assert_eq!(header(handshake, "sec-websocket-key").as_deref(), Some(KEY));
    assert_eq!(
        header(handshake, "sec-websocket-version").as_deref(),
        Some("13")
    );
    assert_eq!(policy.requests(), ["request GET /chat"]);
}

/// A normal request that asks for `h2c` still loses its upgrade fields and is forwarded as before.
#[test]
fn an_h2c_upgrade_on_a_normal_request_is_still_stripped() {
    let host = "h2c.ws.test";
    let upstream = TlsUpstream::start(host);
    let policy = PathPolicy::permitting(host);
    let handle = MitmInterceptor::start(
        MitmConfig {
            upstream_ca_pems: vec![upstream.ca_pem()],
            dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
            ..MitmConfig::default()
        },
        CapabilitySet::default(),
        policy.clone(),
    )
    .unwrap();

    let mut client = WorkloadClient::connect(handle.port().unwrap(), host, upstream.port());
    client.send_request(
        "GET",
        "/",
        &[
            ("Upgrade", "h2c"),
            ("Connection", "Upgrade, HTTP2-Settings"),
            ("HTTP2-Settings", "AAMAAABkAAQAAP__"),
        ],
        b"",
    );
    assert_eq!(client.read_status(), 200);

    let seen = upstream.last_request();
    assert_eq!(seen.header("upgrade"), None);
    assert_eq!(seen.header("http2-settings"), None);
    assert_eq!(seen.header("connection").as_deref(), Some("close"));
    assert_eq!(policy.requests(), ["request GET /"]);
}
