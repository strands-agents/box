#![cfg(feature = "tls-intercept")]

mod harness;

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use credentials::{
    Backend, DestinationPattern, InjectMode, Locator, RouteSpec, Vault, VaultConfig,
};
use egress_gateway::{
    AuditDecision, CapabilitySet, CredentialCapability, EffectAttempt, EffectInterceptor,
    EffectOutcome, EffectPermit, MitmConfig, MitmInterceptor, ResponseLimits, StubEmitter,
};
use harness::{SeenRequest, TlsUpstream, UpstreamTls, WorkloadClient, header_value};

const HOST: &str = "realtime.example.test";
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const LIMIT: usize = 1024;
const SECRET: &str = "sk_live_REALSECRET";
const FLOOD: usize = 15 << 20;

#[derive(Default)]
struct MessagePolicy(Arc<Mutex<Vec<String>>>);

impl EffectInterceptor for MessagePolicy {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        let entry = match attempt {
            EffectAttempt::HttpRequest { upgrade, .. } => format!("http {upgrade:?}"),
            EffectAttempt::WebSocketSend {
                opcode,
                payload_bytes,
                ..
            } => format!("send {opcode:?} {payload_bytes}"),
            EffectAttempt::WebSocketReceive {
                opcode,
                payload_bytes,
                ..
            } => format!("receive {opcode:?} {payload_bytes}"),
            _ => return Ok(Box::new(Logged(None))),
        };
        self.0.lock().unwrap().push(entry.clone());
        if matches!(attempt, EffectAttempt::WebSocketSend { payload_bytes, .. } if *payload_bytes > 100)
        {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "too long"));
        }
        Ok(Box::new(Logged(Some((entry, Arc::clone(&self.0))))))
    }
}

struct Logged(Option<(String, Arc<Mutex<Vec<String>>>)>);

impl EffectPermit for Logged {
    fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
        if let Some((entry, log)) = self.0 {
            log.lock().unwrap().push(format!("{entry} -> {outcome:?}"));
        }
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

const WORKLOAD_KEY: [u8; 4] = [1, 2, 3, 4];

type Frame = (bool, u8, Vec<u8>);

fn frame(fin: bool, opcode: u8, payload: &[u8], mask: bool) -> Vec<u8> {
    let mut out = vec![u8::from(fin) << 7 | opcode];
    let bit = u8::from(mask) << 7;
    match payload.len() {
        len @ 0..=125 => out.push(bit | len as u8),
        len @ 126..=0xffff => {
            out.push(bit | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        len => {
            out.push(bit | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    let key = if mask { WORKLOAD_KEY } else { [0; 4] };
    if mask {
        out.extend_from_slice(&key);
    }
    out.extend(payload.iter().zip(key.iter().cycle()).map(|(b, k)| b ^ k));
    out
}

fn read_frame(stream: &mut impl Read) -> Option<Frame> {
    read_frame_masked(stream, false)
}

fn read_frame_masked(stream: &mut impl Read, masked: bool) -> Option<Frame> {
    let mut head = [0; 2];
    stream.read_exact(&mut head).ok()?;
    let mut len = usize::from(head[1] & 0x7f);
    if len == 126 {
        let mut extended = [0; 2];
        stream.read_exact(&mut extended).ok()?;
        len = usize::from(u16::from_be_bytes(extended));
    }
    let mut key = [0; 4];
    if (head[1] & 0x80 != 0) != masked {
        return None;
    }
    if masked {
        stream.read_exact(&mut key).ok()?;
        (key != WORKLOAD_KEY).then_some(())?;
    }
    let mut payload = vec![0; len];
    stream.read_exact(&mut payload).ok()?;
    let payload = payload.iter().zip(key.iter().cycle()).map(|(b, k)| b ^ k);
    Some((head[0] & 0x80 != 0, head[0] & 0x0f, payload.collect()))
}

fn echo(frames: Arc<Mutex<Vec<Frame>>>) -> impl Fn(&mut UpstreamTls, &SeenRequest) + Send + Sync {
    move |tls, request| {
        let key = request.header("sec-websocket-key").unwrap();
        let mut digest = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
        digest.update(key.as_bytes());
        digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let accept = base64::engine::general_purpose::STANDARD.encode(digest.finish());
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        tls.write_all(head.as_bytes()).unwrap();
        while let Some((fin, opcode, payload)) = read_frame_masked(tls, true) {
            frames.lock().unwrap().push((fin, opcode, payload.clone()));
            let (opcode, reply) = match &payload[..] {
                b"leak" => (opcode, format!("token={SECRET}").into_bytes()),
                b"flood" => (2, vec![0; FLOOD]),
                b"big" => (2, vec![7; 300]),
                _ => (opcode, payload),
            };
            let _ = tls.write_all(&frame(true, opcode, &reply, false));
            if opcode == 8 {
                return;
            }
        }
    }
}

struct Session {
    gateway: egress_gateway::MitmHandle,
    upstream: TlsUpstream,
    client: WorkloadClient,
    policy: Arc<Mutex<Vec<String>>>,
    records: StubEmitter,
    phantom: Option<String>,
}

impl Session {
    fn start(
        credential: bool,
        limit: usize,
        handler: impl Fn(&mut UpstreamTls, &SeenRequest) + Send + Sync + 'static,
    ) -> Self {
        let upstream = TlsUpstream::start_custom(HOST, handler);
        let (controls, phantom) = if credential {
            let (controls, phantom) = bearer(upstream.port());
            (controls, Some(phantom))
        } else {
            (CapabilitySet::default(), None)
        };
        let config = MitmConfig {
            upstream_ca_pems: vec![upstream.ca_pem()],
            dns_overrides: vec![(HOST.to_string(), "127.0.0.1".parse().unwrap())],
            response_limits: ResponseLimits {
                max_body_bytes: limit,
            },
            ..MitmConfig::default()
        };
        let policy = MessagePolicy::default();
        let log = Arc::clone(&policy.0);
        let records = StubEmitter::new();
        let gateway = MitmInterceptor::start_with(
            config,
            controls,
            Arc::new(policy),
            Box::new(records.clone()),
            None,
        )
        .unwrap();
        let client = WorkloadClient::connect(gateway.port().unwrap(), HOST, upstream.port());
        client.set_read_timeout(Duration::from_secs(5));
        Self {
            gateway,
            upstream,
            client,
            policy: log,
            records,
            phantom,
        }
    }

    fn handshake(&mut self, extra: &str) -> String {
        let port = self.upstream.port();
        self.client.send_raw(
            format!(
                "GET /v1/realtime HTTP/1.1\r\nHost: {HOST}:{port}\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n\
                 {extra}\r\n"
            )
            .as_bytes(),
        );
        self.client.read_head()
    }

    fn send(&mut self, fin: bool, opcode: u8, payload: &[u8]) {
        self.client.send_raw(&frame(fin, opcode, payload, true));
    }

    fn denials(&self) -> Vec<String> {
        let records = self.records.records().into_iter();
        let denials = records.filter(|record| record.decision == AuditDecision::Deny);
        denials.map(|record| record.reason).collect()
    }

    fn decided(&self) -> Vec<String> {
        self.policy.lock().unwrap().clone()
    }

    fn wait_for(&self, prefix: &str) -> String {
        for _ in 0..100 {
            if let Some(entry) = self.decided().into_iter().find(|e| e.starts_with(prefix)) {
                return entry;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("no {prefix:?} in {:?}", self.decided());
    }
}

fn close(code: u16) -> Vec<u8> {
    code.to_be_bytes().to_vec()
}

#[test]
fn each_message_is_decided_and_sent_on_as_one_frame() {
    let frames = Arc::new(Mutex::new(Vec::new()));
    let mut session = Session::start(false, LIMIT, echo(Arc::clone(&frames)));
    let head = session.handshake("Sec-WebSocket-Extensions: permessage-deflate\r\n");
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert_eq!(header_value(&head, "upgrade"), Some("websocket"));
    let seen = session.upstream.last_request();
    assert_eq!(seen.header("upgrade").as_deref(), Some("websocket"));
    assert_eq!(seen.header("sec-websocket-extensions"), None);

    session.send(false, 1, b"hel");
    session.send(true, 9, b"p");
    session.send(true, 0, b"lo");
    assert_eq!(
        read_frame(&mut session.client),
        Some((true, 9, b"p".to_vec()))
    );
    assert_eq!(
        read_frame(&mut session.client),
        Some((true, 1, b"hello".to_vec()))
    );
    session.send(true, 8, &close(1000));
    assert_eq!(
        read_frame(&mut session.client),
        Some((true, 8, close(1000)))
    );

    let expected = [(9, &b"p"[..]), (1, b"hello"), (8, &close(1000))];
    let expected: Vec<Frame> = expected
        .map(|(op, payload)| (true, op, payload.to_vec()))
        .into();
    assert_eq!(*frames.lock().unwrap(), expected);
    let decided = session.decided();
    let sent: Vec<_> = decided
        .iter()
        .filter(|entry| entry.starts_with("send"))
        .collect();
    assert_eq!(
        sent,
        [
            "send Ping 1",
            "send Ping 1 -> Completed(1)",
            "send Text 5",
            "send Text 5 -> Completed(5)",
            "send Close 2",
            "send Close 2 -> Completed(2)",
        ]
    );
    assert_eq!(decided[0], r#"http "websocket""#);
    let recorded = decided
        .iter()
        .position(|entry| entry.contains("status: 101"));
    let first_send = decided.iter().position(|entry| entry.starts_with("send"));
    assert!(recorded.is_some() && recorded < first_send, "{decided:?}");
    assert!(decided.contains(&"receive Text 5 -> Completed(5)".to_string()));
    assert!(session.denials().is_empty());
}

#[test]
fn a_refused_message_never_leaves_and_both_sides_close() {
    let frames = Arc::new(Mutex::new(Vec::new()));
    let mut session = Session::start(false, LIMIT, echo(Arc::clone(&frames)));
    assert!(session.handshake("").starts_with("HTTP/1.1 101"));
    session.send(true, 2, &[0; 200]);
    assert_eq!(
        read_frame(&mut session.client),
        Some((true, 8, close(1008)))
    );
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(*frames.lock().unwrap(), [(true, 8, close(1001))]);
    assert_eq!(session.denials().len(), 1, "{:?}", session.denials());
}

#[test]
fn a_message_over_the_cap_closes_with_1009_and_no_decision() {
    let mut session = Session::start(false, LIMIT, echo(Arc::default()));
    assert!(session.handshake("").starts_with("HTTP/1.1 101"));
    session.send(false, 2, &[0; 1000]);
    session.send(true, 0, &[0; 100]);
    assert_eq!(
        read_frame(&mut session.client),
        Some((true, 8, close(1009)))
    );
    let decided = session.decided();
    assert!(
        !decided.iter().any(|entry| entry.starts_with("send")),
        "{decided:?}"
    );
}

#[test]
fn a_workload_binary_message_is_decided_after_its_last_byte() {
    let frames = Arc::new(Mutex::new(Vec::new()));
    let mut session = Session::start(false, 100, echo(Arc::clone(&frames)));
    assert!(session.handshake("").starts_with("HTTP/1.1 101"));
    let payload: Vec<u8> = (0..80).collect();
    let wire = frame(true, 2, &payload, true);
    session.client.send_raw(&wire[..41]);
    std::thread::sleep(Duration::from_millis(100));
    let decided = session.decided();
    assert!(
        !decided.iter().any(|entry| entry.starts_with("send")),
        "{decided:?}"
    );
    session.client.send_raw(&wire[41..]);
    assert_eq!(
        read_frame(&mut session.client),
        Some((true, 2, payload.clone()))
    );
    assert_eq!(*frames.lock().unwrap(), [(true, 2, payload)]);
    assert!(
        session
            .decided()
            .contains(&"send Binary 80 -> Completed(80)".to_string())
    );
}

#[test]
fn a_binary_frame_over_the_cap_streams_from_the_server_and_closes_from_the_workload() {
    let mut session = Session::start(false, 50, echo(Arc::default()));
    assert!(session.handshake("").starts_with("HTTP/1.1 101"));
    session.send(true, 1, b"big");
    assert_eq!(
        read_frame(&mut session.client),
        Some((true, 2, vec![7; 300]))
    );
    session.send(true, 2, &[0; 80]);
    assert_eq!(
        read_frame(&mut session.client),
        Some((true, 8, close(1009)))
    );
    let decided = session.decided();
    assert!(
        decided.contains(&"receive Binary 300 -> Completed(300)".to_string()),
        "{decided:?}"
    );
    assert!(
        !decided.iter().any(|entry| entry.starts_with("send Binary")),
        "{decided:?}"
    );
}

#[test]
fn a_server_message_that_carries_the_credential_is_scrubbed() {
    let mut session = Session::start(true, LIMIT, echo(Arc::default()));
    let phantom = session.phantom.clone().unwrap();
    let head = session.handshake(&format!("Authorization: Bearer {phantom}\r\n"));
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    let seen = session.upstream.last_request();
    assert_eq!(
        seen.header("authorization"),
        Some(format!("Bearer {SECRET}"))
    );

    session.send(true, 1, b"leak");
    let (_, opcode, payload) = read_frame(&mut session.client).unwrap();
    let text = String::from_utf8(payload).unwrap();
    assert_eq!(opcode, 1);
    assert!(
        !text.contains(SECRET) && text.starts_with("token="),
        "{text}"
    );
    assert!(
        session
            .decided()
            .contains(&format!("receive Text {}", 6 + SECRET.len()))
    );
}

#[test]
fn a_wrong_101_is_refused_with_502() {
    let mut session = Session::start(false, LIMIT, |tls, _| {
        let head = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                    Connection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n";
        tls.write_all(head.as_bytes()).unwrap();
    });
    let head = session.handshake("");
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert_eq!(session.denials().len(), 1);
}

#[test]
fn a_plain_handshake_is_refused_with_403() {
    let session = Session::start(false, LIMIT, echo(Arc::default()));
    let authority = format!("{HOST}:{}", session.upstream.port());
    let mut plain = TcpStream::connect(("127.0.0.1", session.gateway.port().unwrap())).unwrap();
    let handshake = format!(
        "GET http://{authority}/v1/realtime?access_token=abc HTTP/1.1\r\nHost: {authority}\r\n\
         Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: {KEY}\r\n\r\n"
    );
    plain.write_all(handshake.as_bytes()).unwrap();
    let head = harness::read_http_head(&mut plain);
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert_eq!(session.denials().len(), 1);
    let records = session.records.records().into_iter();
    let denied = records.filter(|record| record.decision == AuditDecision::Deny);
    assert_eq!(
        denied.map(|record| record.path).collect::<Vec<_>>(),
        ["/v1/realtime"]
    );
    assert!(session.decided().is_empty());
    assert_eq!(session.upstream.request_count(), 0);
}

fn bearer(port: u16) -> (CapabilitySet, String) {
    let variable = format!("WEBSOCKET_E2E_SECRET_{port}");
    unsafe { std::env::set_var(&variable, SECRET) };
    let pattern = || DestinationPattern::parse(&format!("{HOST}:{port}")).unwrap();
    let route = RouteSpec::opaque(
        pattern(),
        Locator::parse_uri(&format!("env://{variable}")).unwrap(),
        InjectMode::header("Bearer {}".to_string(), None).unwrap(),
    );
    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant").route(route)).unwrap();
    let phantom = opened.phantoms()[0].token().to_string();
    let store = Arc::new(opened.into_vault());
    let controls = CapabilitySet::new(vec![CredentialCapability::new(pattern(), store)]);
    (controls, phantom)
}

#[test]
fn an_unmasked_workload_frame_closes_with_1002() {
    let mut session = Session::start(false, LIMIT, echo(Arc::default()));
    assert!(session.handshake("").starts_with("HTTP/1.1 101"));
    session.client.send_raw(&frame(true, 1, b"hi", false));
    assert_eq!(
        read_frame(&mut session.client),
        Some((true, 8, close(1002)))
    );
}

#[test]
fn a_workload_drop_closes_the_server_with_1001() {
    let frames = Arc::new(Mutex::new(Vec::new()));
    let mut session = Session::start(false, LIMIT, echo(Arc::clone(&frames)));
    assert!(session.handshake("").starts_with("HTTP/1.1 101"));
    session.client.abort();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(*frames.lock().unwrap(), [(true, 8, close(1001))]);
}

#[test]
fn a_cut_off_message_records_the_bytes_the_other_side_took() {
    let mut session = Session::start(false, 16 << 20, echo(Arc::default()));
    assert!(session.handshake("").starts_with("HTTP/1.1 101"));
    session.send(true, 1, b"flood");
    let flood = format!("receive Binary {FLOOD}");
    session.wait_for(&flood);
    session.client.send_raw(&frame(true, 1, b"x", false));
    let outcome = session.wait_for(&format!("{flood} -> "));
    assert!(outcome.contains("Partial"), "{outcome}");
    let mut delivered = Vec::new();
    let ended = session.client.read_to_end(&mut delivered);
    let timed_out = |kind| matches!(kind, io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut);
    assert!(
        !ended.as_ref().is_err_and(|e| timed_out(e.kind())),
        "{ended:?}"
    );
    assert!(delivered.len() < 10 + FLOOD, "{}", delivered.len());
}
