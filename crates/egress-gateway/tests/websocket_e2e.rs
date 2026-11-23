#![cfg(feature = "tls-intercept")]

mod harness;

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use credentials::{
    Backend, DestinationPattern, InjectMode, Locator, RouteSpec, Vault, VaultConfig,
};
use egress_gateway::{
    AuditDecision, BackendDial, CapabilitySet, CredentialCapability, EffectAttempt,
    EffectInterceptor, EffectOutcome, EffectPermit, MitmConfig, MitmInterceptor, ResponseLimits,
    StubEmitter,
};
use harness::{SeenRequest, TlsUpstream, UpstreamTls, WorkloadClient, header_value};

const HOST: &str = "realtime.example.test";
const BACKEND: &str = "gw.example.test";
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
const LIMIT: usize = 1024;
const SECRET: &str = "sk_live_REALSECRET";
const ENDED: Frame = (true, 0xF, Vec::new());

#[derive(Default)]
struct Decisions(Arc<Mutex<Vec<String>>>);

impl EffectInterceptor for Decisions {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        let EffectAttempt::HttpRequest { websocket, .. } = attempt else {
            return Ok(Box::new(Logged(None)));
        };
        let entry = format!("http websocket={websocket}");
        self.0.lock().unwrap().push(entry.clone());
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
        (key == WORKLOAD_KEY).then_some(())?;
    }
    let mut payload = vec![0; len];
    stream.read_exact(&mut payload).ok()?;
    let payload = payload.iter().zip(key.iter().cycle()).map(|(b, k)| b ^ k);
    Some((head[0] & 0x80 != 0, head[0] & 0x0f, payload.collect()))
}

fn echo(frames: Arc<Mutex<Vec<Frame>>>) -> impl Fn(&mut UpstreamTls, &SeenRequest) + Send + Sync {
    move |tls, _| {
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {ACCEPT}\r\nX-Echo: {SECRET}\r\n\r\n"
        );
        tls.write_all(head.as_bytes()).unwrap();
        while let Some((fin, opcode, payload)) = read_frame_masked(tls, true) {
            frames.lock().unwrap().push((fin, opcode, payload.clone()));
            let (opcode, reply) = match &payload[..] {
                b"leak" => (opcode, format!("token={SECRET}").into_bytes()),
                b"big" => (2, vec![7; 300]),
                _ => (opcode, payload),
            };
            let _ = tls.write_all(&frame(fin, opcode, &reply, false));
            if opcode == 8 {
                break;
            }
        }
        frames.lock().unwrap().push(ENDED);
    }
}

#[derive(Clone, Copy)]
enum Route {
    Direct,
    Backend,
    Mcp,
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
        Self::open(
            credential,
            limit,
            Route::Direct,
            Duration::from_secs(300),
            handler,
        )
    }

    fn open(
        credential: bool,
        limit: usize,
        route: Route,
        idle: Duration,
        handler: impl Fn(&mut UpstreamTls, &SeenRequest) + Send + Sync + 'static,
    ) -> Self {
        let backend = match route {
            Route::Backend => Some(BACKEND),
            Route::Direct | Route::Mcp => None,
        };
        let upstream = TlsUpstream::start_custom(backend.unwrap_or(HOST), handler);
        let port = upstream.port();
        let (controls, phantom) = match (credential, backend) {
            (false, _) => (CapabilitySet::default(), None),
            (true, None) => {
                let (controls, phantom) = bearer(port);
                (controls, Some(phantom))
            }
            (true, Some(_)) => (box_owned(port), None),
        };
        let backends = backend.map(|host| {
            let dial = BackendDial {
                host: host.to_string(),
                port,
                tls: true,
                path_prefix: "/rt".to_string(),
            };
            (destination(port), dial)
        });
        let config = MitmConfig {
            upstream_ca_pems: vec![upstream.ca_pem()],
            dns_overrides: vec![(
                backend.unwrap_or(HOST).to_string(),
                "127.0.0.1".parse().unwrap(),
            )],
            backends: backends.into_iter().collect(),
            mcp_servers: match route {
                Route::Mcp => vec![(HOST.to_string(), "realtime-mcp".to_string())],
                Route::Direct | Route::Backend => Vec::new(),
            },
            response_limits: ResponseLimits {
                max_body_bytes: limit,
            },
            upstream_read_deadline: idle,
            ..MitmConfig::default()
        };
        let policy = Decisions::default();
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

    fn handshake_with_credential(&mut self) -> String {
        let phantom = self.phantom.clone().unwrap();
        let head = self.handshake(&format!("Authorization: Bearer {phantom}\r\n"));
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        head
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
}

fn close(code: u16) -> Vec<u8> {
    code.to_be_bytes().to_vec()
}

fn ended(frames: &Mutex<Vec<Frame>>) -> bool {
    for _ in 0..100 {
        if frames.lock().unwrap().last() == Some(&ENDED) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn one_decision_admits_the_websocket_and_its_frames_pass_as_they_are() {
    let frames = Arc::new(Mutex::new(Vec::new()));
    let mut session = Session::start(false, LIMIT, echo(Arc::clone(&frames)));
    let head = session.handshake("Sec-WebSocket-Extensions: permessage-deflate\r\n");
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert_eq!(header_value(&head, "upgrade"), Some("websocket"));
    let seen = session.upstream.last_request();
    assert_eq!(seen.header("upgrade").as_deref(), Some("websocket"));
    assert_eq!(
        seen.header("sec-websocket-extensions").as_deref(),
        Some("permessage-deflate")
    );

    let sent: [Frame; 4] = [
        (false, 1, b"hel".to_vec()),
        (true, 9, b"p".to_vec()),
        (true, 0, b"lo".to_vec()),
        (true, 8, close(1000)),
    ];
    for (fin, opcode, payload) in &sent {
        session.send(*fin, *opcode, payload);
    }
    for expected in &sent {
        assert_eq!(read_frame(&mut session.client).as_ref(), Some(expected));
    }
    assert!(ended(&frames));
    assert_eq!(*frames.lock().unwrap(), [&sent[..], &[ENDED]].concat());
    let decided = session.decided();
    assert_eq!(decided.len(), 2, "{decided:?}");
    assert_eq!(decided[0], "http websocket=true");
    assert!(decided[1].ends_with("status: 101 }"), "{decided:?}");
    assert!(session.denials().is_empty());
}

#[test]
fn the_credential_is_removed_from_the_101_and_server_frames_pass_as_they_are() {
    let mut session = Session::start(true, 50, echo(Arc::default()));
    let head = session.handshake_with_credential();
    assert_eq!(header_value(&head, "x-echo"), Some("[REDACTED]"));
    let seen = session.upstream.last_request();
    assert_eq!(
        seen.header("authorization"),
        Some(format!("Bearer {SECRET}"))
    );
    session.send(true, 1, b"leak");
    assert_eq!(
        read_frame(&mut session.client),
        Some((true, 1, format!("token={SECRET}").into_bytes()))
    );
    session.send(true, 1, b"big");
    assert_eq!(
        read_frame(&mut session.client),
        Some((true, 2, vec![7; 300]))
    );
    assert!(session.denials().is_empty());
}

#[test]
fn a_handshake_to_an_mcp_server_host_is_refused_with_403() {
    let mut session = Session::open(
        false,
        LIMIT,
        Route::Mcp,
        Duration::from_secs(300),
        echo(Arc::default()),
    );
    let head = session.handshake("");
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert_eq!(
        session.denials(),
        ["websocket: handshake to a remote MCP server"]
    );
    assert!(session.decided().is_empty());
    assert_eq!(session.upstream.request_count(), 0);
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
    let records = session.records.records().into_iter();
    let denied = records.filter(|record| record.decision == AuditDecision::Deny);
    assert_eq!(
        denied.map(|record| record.path).collect::<Vec<_>>(),
        ["/v1/realtime"]
    );
    assert!(session.decided().is_empty());
    assert_eq!(session.upstream.request_count(), 0);
}

fn destination(port: u16) -> DestinationPattern {
    DestinationPattern::parse(&format!("{HOST}:{port}")).unwrap()
}

fn secret(port: u16) -> Locator {
    let variable = format!("WEBSOCKET_E2E_SECRET_{port}");
    unsafe { std::env::set_var(&variable, SECRET) };
    Locator::parse_uri(&format!("env://{variable}")).unwrap()
}

fn bearer(port: u16) -> (CapabilitySet, String) {
    let inject = InjectMode::header("Bearer {}".to_string(), None).unwrap();
    let route = RouteSpec::opaque(destination(port), secret(port), inject);
    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant").route(route)).unwrap();
    let phantom = opened.phantoms()[0].token().to_string();
    let store = Arc::new(opened.into_vault());
    let controls = CapabilitySet::new(vec![CredentialCapability::new(destination(port), store)]);
    (controls, phantom)
}

fn box_owned(port: u16) -> CapabilitySet {
    let inject = InjectMode::header("Bearer {}".to_string(), None).unwrap();
    let route = RouteSpec::box_owned(destination(port), secret(port), inject);
    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant").route(route)).unwrap();
    let store = Arc::new(opened.into_vault());
    CapabilitySet::new(vec![CredentialCapability::new(destination(port), store)])
}

#[test]
fn a_websocket_through_a_backend_reroute_reaches_the_backend_and_is_judged_on_the_original() {
    let mut session = Session::open(
        true,
        LIMIT,
        Route::Backend,
        Duration::from_secs(300),
        echo(Arc::default()),
    );
    let head = session.handshake("");
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    let seen = session.upstream.last_request();
    let port = session.upstream.port();
    assert_eq!(seen.header("host"), Some(format!("{BACKEND}:{port}")));
    assert!(
        seen.raw.starts_with("GET /rt/v1/realtime "),
        "{:?}",
        seen.raw.lines().next()
    );
    assert_eq!(
        seen.header("authorization"),
        Some(format!("Bearer {SECRET}"))
    );

    session.send(true, 1, b"hi");
    assert_eq!(
        read_frame(&mut session.client),
        Some((true, 1, b"hi".to_vec()))
    );
    let records = session.records.records();
    assert!(records.iter().any(|record| record.host == HOST));
    assert!(!records.iter().any(|record| record.host == BACKEND));
}

#[test]
fn a_workload_drop_ends_the_server_connection() {
    let frames = Arc::new(Mutex::new(Vec::new()));
    let mut session = Session::start(false, LIMIT, echo(Arc::clone(&frames)));
    assert!(session.handshake("").starts_with("HTTP/1.1 101"));
    session.client.abort();
    assert!(ended(&frames));
    assert_eq!(*frames.lock().unwrap(), [ENDED]);
}

#[test]
fn an_idle_websocket_ends_both_connections() {
    let frames = Arc::new(Mutex::new(Vec::new()));
    let idle = Duration::from_millis(500);
    let mut session = Session::open(false, LIMIT, Route::Direct, idle, echo(Arc::clone(&frames)));
    assert!(session.handshake("").starts_with("HTTP/1.1 101"));
    session.send(true, 1, b"hi");
    assert_eq!(
        read_frame(&mut session.client),
        Some((true, 1, b"hi".to_vec()))
    );
    assert_eq!(read_frame(&mut session.client), None);
    assert!(ended(&frames));
    assert!(session.denials().is_empty());
}
