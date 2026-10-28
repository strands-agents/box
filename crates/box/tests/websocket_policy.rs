//! A WebSocket through the gateway and the real policy engine.
//!
//! The handshake is an ordinary `http:request` `GET` on its path, and the messages of the session
//! raise no decision. These tests pin what that means for a policy author, with the shipped
//! `EgressPolicyInterceptor` and Dogwood, not a test double:
//!
//! - a `GET` permit admits a WebSocket;
//! - a `GET`-only, `body_bytes == 0` permit admits a two-way channel, and a byte budget over
//!   `http:request` counts only the handshake;
//! - a `forbid` on the handshake path refuses that path only;
//! - history records one `http:request` event with status 101 for a session;
//! - a temporal rule that matches after the handshake does not close the open WebSocket.

#[path = "../../egress-gateway/tests/harness/mod.rs"]
mod harness;

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use egress_gateway::{CapabilitySet, MitmConfig, MitmHandle, MitmInterceptor};
use harness::WorkloadClient;
use policy::{EgressPolicyInterceptor, GovernedBox, Policy, PolicyEngine, Principal};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConnection, ServerConnection, StreamOwned};

const HOST: &str = "ws.policy.test";

/// The RFC 6455 example key, and its accept value, so that the upstream needs no SHA-1.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

const TEXT: u8 = 0x1;
const BINARY: u8 = 0x2;
const CLOSE: u8 = 0x8;

/// The connection permit that every policy in this file has.
const CONNECT: &str = r#"permit(principal, action == Box::Action::"net:connect", resource)
when { context.input.host == "ws.policy.test" };"#;

/// A permit for each `GET` to [`HOST`].
const GET: &str = r#"permit(principal, action == Box::Action::"http:request", resource)
when { context.input.host == "ws.policy.test" && context.input.method == "GET" };"#;

// ============================================================================================
// The upstream, the workload, and the gateway
// ============================================================================================

/// A TLS server for [`HOST`]. It accepts a WebSocket handshake and echoes each message, answers
/// any other request with `200`, and counts the handshakes and the message bytes that reach it.
struct Upstream {
    port: u16,
    ca_pem: String,
    handshakes: Arc<AtomicUsize>,
    message_bytes: Arc<AtomicUsize>,
}

impl Upstream {
    fn start() -> Self {
        let certified = rcgen::generate_simple_self_signed(vec![HOST.to_string()]).unwrap();
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
        let handshakes = Arc::new(AtomicUsize::new(0));
        let message_bytes = Arc::new(AtomicUsize::new(0));
        let counts = (handshakes.clone(), message_bytes.clone());
        std::thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let config = config.clone();
                let (handshakes, message_bytes) = (counts.0.clone(), counts.1.clone());
                std::thread::spawn(move || {
                    let tls = StreamOwned::new(ServerConnection::new(config).unwrap(), tcp);
                    let _ = serve(tls, &handshakes, &message_bytes);
                });
            }
        });
        Self {
            port,
            ca_pem: certified.cert.pem(),
            handshakes,
            message_bytes,
        }
    }

    fn handshakes(&self) -> usize {
        self.handshakes.load(Ordering::SeqCst)
    }
}

fn serve(
    mut tls: StreamOwned<ServerConnection, TcpStream>,
    handshakes: &AtomicUsize,
    message_bytes: &AtomicUsize,
) -> io::Result<()> {
    tls.sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    let head = read_head(&mut tls)?;
    if !head.to_ascii_lowercase().contains("upgrade: websocket") {
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")?;
        return tls.flush();
    }
    handshakes.fetch_add(1, Ordering::SeqCst);
    tls.write_all(
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {ACCEPT}\r\n\r\n"
        )
        .as_bytes(),
    )?;
    tls.flush()?;
    loop {
        let (opcode, payload) = read_frame(&mut tls)?;
        let mut echo = Vec::new();
        encode(&mut echo, opcode, &payload, None);
        tls.write_all(&echo)?;
        tls.flush()?;
        if opcode == CLOSE {
            tls.conn.send_close_notify();
            return tls.flush();
        }
        message_bytes.fetch_add(payload.len(), Ordering::SeqCst);
    }
}

/// A WebSocket that the workload opened through the gateway.
struct WebSocket {
    tls: StreamOwned<ClientConnection, TcpStream>,
}

impl WebSocket {
    /// Send a handshake on `path`; the status of the reply, and the socket.
    fn open(handle: &MitmHandle, upstream: &Upstream, path: &str) -> (u16, Self) {
        let mut tls = WorkloadClient::connect(proxy_port(handle), HOST, upstream.port).into_tls();
        tls.sock
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let port = upstream.port;
        tls.write_all(
            format!(
                "GET {path} HTTP/1.1\r\nHost: {HOST}:{port}\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        tls.flush().unwrap();
        let head = read_head(&mut tls).unwrap();
        (status(&head), Self { tls })
    }

    /// Send one message and return the server's echo of it.
    fn echo(&mut self, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        encode(&mut frame, opcode, payload, Some([0x11, 0x22, 0x33, 0x44]));
        self.tls.write_all(&frame).unwrap();
        self.tls.flush().unwrap();
        let (echoed, payload) = read_frame(&mut self.tls).unwrap();
        assert_eq!(echoed, opcode);
        payload
    }
}

/// The status of one plain request to [`HOST`] on its own connection.
fn request(handle: &MitmHandle, upstream: &Upstream, method: &str, path: &str, body: &[u8]) -> u16 {
    let mut client = WorkloadClient::connect(proxy_port(handle), HOST, upstream.port);
    client.send_request(method, path, &[], body);
    client.read_status()
}

/// A gateway that `rules` and [`CONNECT`] decide through the real engine, with its history in
/// `history`.
fn gateway(upstream: &Upstream, rules: &str, history: &Path) -> MitmHandle {
    let engine = PolicyEngine::open(
        vec![Policy {
            origin: PathBuf::from("websocket-policy.dw"),
            text: format!("{CONNECT}\n{rules}"),
        }],
        &history.join("dogwood.redb"),
    )
    .expect("the policy opens");
    let interceptor = EgressPolicyInterceptor::into_handle(
        Arc::new(engine),
        Principal::agent(),
        GovernedBox::assigned("websocket-policy"),
    );
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem.clone()],
        dns_overrides: vec![(HOST.to_string(), "127.0.0.1".parse().unwrap())],
        ..MitmConfig::default()
    };
    MitmInterceptor::start(config, CapabilitySet::default(), interceptor)
        .expect("the gateway starts")
}

fn proxy_port(handle: &MitmHandle) -> u16 {
    handle.port().expect("a TCP gateway has a port")
}

// ============================================================================================
// The frame format and the heads
// ============================================================================================

/// One final frame with `payload`, masked with `mask` when it has one.
fn encode(out: &mut Vec<u8>, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) {
    out.push(0x80 | opcode);
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    if payload.len() < 126 {
        out.push(mask_bit | payload.len() as u8);
    } else if payload.len() <= 0xFFFF {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            out.extend(
                payload
                    .iter()
                    .enumerate()
                    .map(|(i, byte)| byte ^ key[i % 4]),
            );
        }
        None => out.extend_from_slice(payload),
    }
}

/// The opcode and the unmasked payload of the next frame.
fn read_frame<R: Read>(stream: &mut R) -> io::Result<(u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head)?;
    let length = match head[1] & 0x7F {
        126 => {
            let mut length = [0u8; 2];
            stream.read_exact(&mut length)?;
            u64::from(u16::from_be_bytes(length))
        }
        127 => {
            let mut length = [0u8; 8];
            stream.read_exact(&mut length)?;
            u64::from_be_bytes(length)
        }
        short => u64::from(short),
    };
    let mut key = None;
    if head[1] & 0x80 != 0 {
        let mut bytes = [0u8; 4];
        stream.read_exact(&mut bytes)?;
        key = Some(bytes);
    }
    let mut payload = vec![0u8; length as usize];
    stream.read_exact(&mut payload)?;
    if let Some(key) = key {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[index % 4];
        }
    }
    Ok((head[0] & 0x0F, payload))
}

/// Read an HTTP head up to its blank line, one byte at a time so that no frame byte goes with it.
fn read_head<R: Read>(stream: &mut R) -> io::Result<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

fn status(head: &str) -> u16 {
    head.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_default()
}

// ============================================================================================
// What a `GET` permit admits
// ============================================================================================

/// A `GET` permit admits a WebSocket, and messages pass in both directions. With no `http:request`
/// permit, the same handshake is refused before the upstream.
#[test]
fn a_get_permit_admits_a_websocket_handshake() {
    let upstream = Upstream::start();
    let history = tempfile::tempdir().unwrap();
    let handle = gateway(&upstream, GET, history.path());
    let (status, mut socket) = WebSocket::open(&handle, &upstream, "/chat");
    assert_eq!(status, 101);
    assert_eq!(socket.echo(TEXT, b"hello"), b"hello");
    assert_eq!(upstream.handshakes(), 1);

    let refusing = tempfile::tempdir().unwrap();
    let handle = gateway(&upstream, "", refusing.path());
    let (status, _) = WebSocket::open(&handle, &upstream, "/chat");
    assert_eq!(
        status, 403,
        "with no http:request permit, default deny refuses"
    );
    assert_eq!(upstream.handshakes(), 1, "the refused handshake never left");
}

/// A permit written as read-only (`GET` with `body_bytes == 0`) refuses an upload over HTTP, but it
/// admits a WebSocket, which then carries 1 MiB to the server. A 1 KiB byte budget over
/// `http:request` counts only the bytes of the handshake, so it never fires for the session; it
/// fires for plain requests. This pins the gap in the stage 2 design: a later fix changes this test.
#[test]
fn a_get_only_permit_and_a_byte_budget_admit_an_upload_over_a_websocket() {
    let upstream = Upstream::start();
    let history = tempfile::tempdir().unwrap();
    let rules = r#"
@id("read_only")
permit(principal, action == Box::Action::"http:request", resource)
when { context.input.host == "ws.policy.test" && context.input.method == "GET"
    && context.input.body_bytes == 0 };

@id("byte_budget")
forbid(principal, action == Box::Action::"http:request", resource)
when temporal {
  exists (total: Long). (
    (sum b for (b: Long), (t: Timepoint). where (
      formerly within 60s (
        Box::Action::"http:request"::response{ input.host: _, input.body_bytes: b } && tp(t)
      )
    )) == total && total >= 1024
  )
};"#;
    let handle = gateway(&upstream, rules, history.path());

    assert_eq!(
        request(&handle, &upstream, "POST", "/upload", b"0123456789"),
        403,
        "the permit refuses an upload over HTTP"
    );

    let (status, mut socket) = WebSocket::open(&handle, &upstream, "/chat");
    assert_eq!(status, 101);
    let message = vec![0x5A; 64 * 1024];
    for _ in 0..16 {
        assert_eq!(socket.echo(BINARY, &message).len(), message.len());
    }
    assert_eq!(
        upstream.message_bytes.load(Ordering::SeqCst),
        1024 * 1024,
        "1 MiB of client messages reached the server"
    );

    let (status, _second) = WebSocket::open(&handle, &upstream, "/chat");
    assert_eq!(status, 101, "the budget never counted the messages");

    let statuses: Vec<u16> = (0..40)
        .map(|_| request(&handle, &upstream, "GET", "/api", b""))
        .collect();
    assert_eq!(statuses[0], 200, "{statuses:?}");
    assert!(
        statuses.contains(&403),
        "the budget fires for plain requests: {statuses:?}"
    );
}

/// A `forbid` on the handshake path refuses a handshake and a plain `GET` there, and nothing else.
#[test]
fn a_forbid_on_the_handshake_path_refuses_only_that_path() {
    let upstream = Upstream::start();
    let history = tempfile::tempdir().unwrap();
    let rules = format!(
        r#"{GET}
@id("no_ws_path")
forbid(principal, action == Box::Action::"http:request", resource)
when {{ context.input.path == "/ws" }};"#
    );
    let handle = gateway(&upstream, &rules, history.path());

    let (status, _) = WebSocket::open(&handle, &upstream, "/ws");
    assert_eq!(status, 403);
    assert_eq!(upstream.handshakes(), 0, "the upstream sees no handshake");
    assert_eq!(request(&handle, &upstream, "GET", "/ws", b""), 403);

    let (status, mut socket) = WebSocket::open(&handle, &upstream, "/chat");
    assert_eq!(status, 101);
    assert_eq!(socket.echo(TEXT, b"other path"), b"other path");
    assert_eq!(request(&handle, &upstream, "GET", "/api", b""), 200);
}

// ============================================================================================
// History and temporal rules
// ============================================================================================

/// A session reaches history once, as one `http:request` response with status 101, however many
/// messages it carries: a rule that counts two such events fires only after the second session.
#[test]
fn an_opened_websocket_reaches_history_once_as_status_101() {
    let upstream = Upstream::start();
    let history = tempfile::tempdir().unwrap();
    let rules = format!(
        r#"{GET}
@id("two_sessions")
forbid(principal, action == Box::Action::"http:request", resource)
when {{ context.input.host == "ws.policy.test" }}
when temporal {{
  exists (total: Long). (
    (count for (t: Timepoint). where (
      formerly within 1h (
        Box::Action::"http:request"::response{{ input.host: "ws.policy.test", output.status: 101 }} && tp(t)
      )
    )) == total && total >= 2
  )
}};"#
    );
    let handle = gateway(&upstream, &rules, history.path());

    let (status, mut first) = WebSocket::open(&handle, &upstream, "/chat");
    assert_eq!(status, 101);
    for index in 0..20 {
        let message = format!("message {index}");
        assert_eq!(first.echo(TEXT, message.as_bytes()), message.as_bytes());
    }
    assert_eq!(
        request(&handle, &upstream, "GET", "/api", b""),
        200,
        "one session is one event, not one per message"
    );

    let (status, _second) = WebSocket::open(&handle, &upstream, "/chat");
    assert_eq!(status, 101);
    assert_eq!(
        request(&handle, &upstream, "GET", "/api", b""),
        403,
        "the second session is the second event with status 101"
    );
}

/// A temporal rule that starts to match after the handshake refuses the next request and the next
/// handshake, but it does not close the WebSocket that is open: its decisions are made.
#[test]
fn a_temporal_rule_that_matches_later_does_not_close_an_open_websocket() {
    let upstream = Upstream::start();
    let history = tempfile::tempdir().unwrap();
    let rules = format!(
        r#"{GET}
@id("after_flag")
forbid(principal, action == Box::Action::"http:request", resource)
when temporal {{
  formerly within 1h (
    Box::Action::"http:request"::response{{ input.host: "ws.policy.test", input.path: "/flag" }}
  )
}};"#
    );
    let handle = gateway(&upstream, &rules, history.path());

    let (status, mut open) = WebSocket::open(&handle, &upstream, "/chat");
    assert_eq!(status, 101);
    assert_eq!(open.echo(TEXT, b"before"), b"before");

    assert_eq!(request(&handle, &upstream, "GET", "/flag", b""), 200);
    assert_eq!(
        request(&handle, &upstream, "GET", "/api", b""),
        403,
        "the rule matches now"
    );
    let (status, _) = WebSocket::open(&handle, &upstream, "/chat");
    assert_eq!(status, 403, "the next handshake is refused");

    assert_eq!(
        open.echo(TEXT, b"after"),
        b"after",
        "the open WebSocket still carries messages"
    );
    assert_eq!(upstream.handshakes(), 1);
}
