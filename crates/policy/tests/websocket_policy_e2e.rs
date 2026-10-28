//! WebSocket through the real egress gateway and the shipped policy adapter.
//!
//! A real `MitmInterceptor` decides through `EgressPolicyInterceptor` on one `PolicyEngine`, in
//! front of a TLS WebSocket echo upstream written here, so the attempt the gateway raises and the
//! gate the adapter decides meet as they do in a box.

#![cfg(feature = "egress-adapter")]

#[path = "../../egress-gateway/tests/harness/mod.rs"]
mod harness;
mod support;

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use egress_gateway::{CapabilitySet, MitmConfig, MitmHandle, MitmInterceptor};
use policy::{EgressPolicyInterceptor, GovernedBox, Policy, PolicyEngine, Principal, Request};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use harness::WorkloadClient;

const BOX_NAME: &str = "websocket-policy";

/// The RFC 6455 example key and its accept value.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

const TEXT: u8 = 0x1;
const BINARY: u8 = 0x2;
const CLOSE: u8 = 0x8;

const CONNECT: &str = r#"permit(principal, action == Box::Action::"net:connect", resource);"#;
const REQUEST: &str = r#"permit(principal, action == Box::Action::"http:request", resource);"#;
const UPGRADE: &str = r#"permit(principal, action == Box::Action::"http:upgrade", resource)
when { context.input.protocol == "websocket" };"#;

fn encode(out: &mut Vec<u8>, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) {
    out.push(0x80 | opcode);
    let bit = if mask.is_some() { 0x80 } else { 0 };
    if payload.len() < 126 {
        out.push(bit | payload.len() as u8);
    } else if payload.len() <= 0xFFFF {
        out.push(bit | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(bit | 127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            out.extend(
                payload
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ key[index % 4]),
            );
        }
        None => out.extend_from_slice(payload),
    }
}

/// Read one frame; returns its opcode and unmasked payload.
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
    let mut key = [0u8; 4];
    let masked = head[1] & 0x80 != 0;
    if masked {
        stream.read_exact(&mut key)?;
    }
    let mut payload = vec![0u8; length as usize];
    stream.read_exact(&mut payload)?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[index % 4];
        }
    }
    Ok((head[0] & 0x0F, payload))
}

/// Read an HTTP head one byte at a time, so no frame byte is taken with it.
fn read_head<R: Read>(stream: &mut R) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// A TLS upstream that accepts a WebSocket handshake and echoes each message, answers any other
/// request `200 ok`, and records the handshakes and the messages that reached it.
struct WsUpstream {
    port: u16,
    ca_pem: String,
    handshakes: Arc<Mutex<usize>>,
    messages: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl WsUpstream {
    fn start(host: &str) -> Self {
        let certified = rcgen::generate_simple_self_signed(vec![host.to_string()]).unwrap();
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
        let handshakes = Arc::new(Mutex::new(0));
        let messages = Arc::new(Mutex::new(Vec::new()));
        let (counted, recorded) = (handshakes.clone(), messages.clone());
        std::thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let (config, counted, recorded) =
                    (config.clone(), counted.clone(), recorded.clone());
                std::thread::spawn(move || {
                    let mut tls = StreamOwned::new(ServerConnection::new(config).unwrap(), tcp);
                    let _ = serve(&mut tls, &counted, &recorded);
                });
            }
        });
        Self {
            port,
            ca_pem: certified.cert.pem(),
            handshakes,
            messages,
        }
    }

    fn handshakes(&self) -> usize {
        std::thread::sleep(Duration::from_millis(100));
        *self.handshakes.lock().unwrap()
    }

    fn messages(&self) -> Vec<Vec<u8>> {
        self.messages.lock().unwrap().clone()
    }
}

fn serve(
    tls: &mut StreamOwned<ServerConnection, TcpStream>,
    handshakes: &Mutex<usize>,
    messages: &Mutex<Vec<Vec<u8>>>,
) -> io::Result<()> {
    tls.sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    let head = read_head(tls);
    if !head.to_ascii_lowercase().contains("upgrade: websocket") {
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")?;
        return tls.flush();
    }
    *handshakes.lock().unwrap() += 1;
    tls.write_all(
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {ACCEPT}\r\n\r\n"
        )
        .as_bytes(),
    )?;
    tls.flush()?;
    loop {
        let (opcode, payload) = read_frame(tls)?;
        let mut out = Vec::new();
        encode(&mut out, opcode, &payload, None);
        if opcode != CLOSE {
            messages.lock().unwrap().push(payload);
        }
        tls.write_all(&out)?;
        tls.flush()?;
        if opcode == CLOSE {
            return Ok(());
        }
    }
}

fn open(sources: &[&str]) -> Arc<PolicyEngine> {
    Arc::new(
        support::open_policy(vec![Policy {
            origin: PathBuf::from("websocket-policy.dw"),
            text: sources.join("\n"),
        }])
        .expect("policy loads"),
    )
}

fn gateway(host: &str, upstream: &WsUpstream, policy: &Arc<PolicyEngine>) -> MitmHandle {
    MitmInterceptor::start(
        MitmConfig {
            upstream_ca_pems: vec![upstream.ca_pem.clone()],
            dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
            ..MitmConfig::default()
        },
        CapabilitySet::default(),
        EgressPolicyInterceptor::into_handle(
            Arc::clone(policy),
            Principal::agent(),
            GovernedBox::assigned(BOX_NAME),
        ),
    )
    .expect("gateway starts")
}

/// Send a WebSocket handshake through the gateway; returns the stream and the reply head and body.
fn handshake(
    handle: &MitmHandle,
    host: &str,
    port: u16,
) -> (StreamOwned<ClientConnection, TcpStream>, String) {
    let mut tls = WorkloadClient::connect(handle.port().unwrap(), host, port).into_tls();
    tls.sock
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let head = format!(
        "GET /socket HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    tls.write_all(head.as_bytes()).unwrap();
    tls.flush().unwrap();
    let mut reply = read_head(&mut tls);
    let length = reply.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().unwrap())
    });
    if let Some(length) = length {
        let mut body = vec![0u8; length];
        tls.read_exact(&mut body).unwrap();
        reply.push_str(&String::from_utf8_lossy(&body));
    }
    (tls, reply)
}

/// Send one message on an open WebSocket and return the echo.
fn exchange(
    tls: &mut StreamOwned<ClientConnection, TcpStream>,
    opcode: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    encode(&mut out, opcode, payload, Some([1, 2, 3, 4]));
    tls.write_all(&out).unwrap();
    tls.flush().unwrap();
    let (echoed_opcode, echoed) = read_frame(tls).expect("the echo");
    assert_eq!(echoed_opcode, opcode);
    echoed
}

fn post(handle: &MitmHandle, host: &str, port: u16) -> u16 {
    let mut client = WorkloadClient::connect(handle.port().unwrap(), host, port);
    client.send_request("POST", "/v1/upload", &[], b"0123456789");
    client.read_status()
}

#[test]
fn both_permits_open_a_websocket_through_the_gateway() {
    let host = "echo.ws-policy.test";
    let upstream = WsUpstream::start(host);
    let policy = open(&[CONNECT, REQUEST, UPGRADE]);
    let handle = gateway(host, &upstream, &policy);

    let (mut tls, reply) = handshake(&handle, host, upstream.port);
    assert!(reply.starts_with("HTTP/1.1 101 "), "{reply:?}");
    assert_eq!(exchange(&mut tls, TEXT, b"hello"), b"hello");
    assert_eq!(upstream.messages(), vec![b"hello".to_vec()]);
}

/// The `101` records `http:upgrade::response`, so a temporal cap on it counts each WebSocket the
/// gateway opened.
#[test]
fn a_temporal_cap_on_http_upgrade_refuses_the_next_websocket() {
    let host = "cap.ws-policy.test";
    let upstream = WsUpstream::start(host);
    let cap = r#"forbid(principal, action == Box::Action::"http:upgrade", resource)
when temporal {
    formerly within 3600s Box::Action::"http:upgrade"::response{ input.protocol: "websocket" }
};"#;
    let policy = open(&[CONNECT, REQUEST, UPGRADE, cap]);
    let handle = gateway(host, &upstream, &policy);

    let (_first, reply) = handshake(&handle, host, upstream.port);
    assert!(reply.starts_with("HTTP/1.1 101 "), "{reply:?}");
    let (_second, reply) = handshake(&handle, host, upstream.port);
    assert!(reply.starts_with("HTTP/1.1 403 "), "{reply:?}");
    assert!(reply.contains("http:upgrade gate: "), "{reply:?}");
    assert_eq!(upstream.handshakes(), 1, "the second handshake never left");
}

/// A rule whose scope names no action admits `http:upgrade` as well.
#[test]
fn a_permit_that_names_no_action_also_admits_the_upgrade() {
    let host = "unscoped.ws-policy.test";
    let upstream = WsUpstream::start(host);
    let unscoped = format!(
        r#"permit(principal, action, resource)
when {{ context.input has host && context.input.host == "{host}" }};"#
    );
    let policy = open(&[&unscoped]);
    let handle = gateway(host, &upstream, &policy);

    let (_tls, reply) = handshake(&handle, host, upstream.port);
    assert!(reply.starts_with("HTTP/1.1 101 "), "{reply:?}");
}

#[test]
fn a_protocol_literal_in_another_case_never_matches() {
    let policy = open(&[
        r#"permit(principal, action == Box::Action::"http:upgrade", resource);"#,
        r#"forbid(principal, action == Box::Action::"http:upgrade", resource)
when { context.input.protocol == "WebSocket" };"#,
    ]);
    let decision = policy.decide(
        &GovernedBox::assigned(BOX_NAME),
        &Principal::agent(),
        &Request::HttpUpgrade {
            host: "echo.example.com",
            port: 443,
            path: "/socket",
            protocol: "websocket",
        },
    );
    assert!(
        decision.is_allow(),
        "the gateway spells the protocol in lowercase"
    );
}

/// LIVE GAP: no WebSocket message reaches history, so a byte budget over
/// `http:request::response` counts none of the bytes an open WebSocket carries.
#[test]
fn a_byte_budget_counts_no_websocket_message() {
    let host = "budget.ws-policy.test";
    let upstream = WsUpstream::start(host);
    let budget = include_str!("policies/egress_byte_budget_e2e.dw");
    let policy = open(&[CONNECT, budget, UPGRADE]);
    let handle = gateway(host, &upstream, &policy);

    let (mut tls, reply) = handshake(&handle, host, upstream.port);
    assert!(reply.starts_with("HTTP/1.1 101 "), "{reply:?}");
    let message = vec![0x5A; 1 << 20];
    assert_eq!(exchange(&mut tls, BINARY, &message).len(), message.len());
    assert_eq!(upstream.messages()[0].len(), 1 << 20, "a MiB left the box");

    assert_eq!(
        post(&handle, host, upstream.port),
        200,
        "the MiB charged nothing to the 400-byte budget"
    );
}

/// LIVE GAP: policy decides the handshake once, so a temporal forbid that arms after the `101`
/// stops new egress and leaves the open WebSocket carrying messages.
#[cfg(feature = "shell-adapter")]
#[test]
fn an_open_websocket_outlives_a_temporal_forbid_that_arms_after_its_handshake() {
    use policy::ShellPolicyInterceptor;
    use strands_shell::Shell;

    let host = "exfil.ws-policy.test";
    let upstream = WsUpstream::start(host);
    let unless_secret_read = r#"
unless temporal {
    formerly within 300s
    Box::Action::"fs:read"::response{ input.path: "/tmp/secrets/ws-token", input.operation: Box::FsReadOperation::"read_content" }
};"#;
    let request = format!(
        r#"permit(principal, action == Box::Action::"http:request", resource) {unless_secret_read}"#
    );
    let upgrade = format!(
        r#"permit(principal, action == Box::Action::"http:upgrade", resource) {unless_secret_read}"#
    );
    let shell_access = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"fs:read", resource);
permit(principal, action == Box::Action::"fs:write", resource);"#;
    let policy = open(&[CONNECT, shell_access, &request, &upgrade]);
    let handle = gateway(host, &upstream, &policy);
    let mut shell = Shell::builder()
        .effect_interceptor(ShellPolicyInterceptor::into_handle(
            Arc::clone(&policy),
            Principal::agent(),
            GovernedBox::assigned(BOX_NAME),
        ))
        .build()
        .expect("shell builds");

    let (mut tls, reply) = handshake(&handle, host, upstream.port);
    assert!(reply.starts_with("HTTP/1.1 101 "), "{reply:?}");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime builds");
    let secret = tokio::task::LocalSet::new().block_on(&runtime, async {
        shell
            .write_file("/tmp/secrets/ws-token", b"super-secret")
            .await
            .expect("staging the secret is permitted");
        shell
            .read_file("/tmp/secrets/ws-token")
            .await
            .expect("reading the secret is permitted")
    });

    assert_eq!(post(&handle, host, upstream.port), 403, "new egress closes");
    let (_late, reply) = handshake(&handle, host, upstream.port);
    assert!(
        reply.starts_with("HTTP/1.1 403 "),
        "a new WebSocket is refused: {reply:?}"
    );

    assert_eq!(exchange(&mut tls, BINARY, &secret), b"super-secret");
    assert!(
        upstream.messages().contains(&b"super-secret".to_vec()),
        "the open WebSocket carried the secret after the forbid armed"
    );
}
