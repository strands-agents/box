//! Each exit of an exchange leaves the records that say how it ended.

#![cfg(feature = "tls-intercept")]

mod harness;

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use credentials::{
    Backend, DestinationPattern, InjectMode, Locator, PhantomCheck, RouteSpec, Vault, VaultConfig,
};
use egress_gateway::{
    AuditDecision, CapabilitySet, CredentialCapability, EffectAttempt, EffectInterceptor,
    EffectOutcome, EffectPermit, EgressDecision, MitmConfig, MitmHandle, MitmInterceptor,
    NetworkAuditEvent, ResponseLimits, StubEmitter,
};

use harness::{TlsUpstream, WorkloadClient};

/// The destination of every exchange in this file, pinned to loopback.
const HOST: &str = "exit.records.test";

/// The reply of an upstream that accepts each request.
const OK_REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

/// A reply that the upstream cuts inside its body.
const CUT_REPLY: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort";

/// A reply whose body is larger than [`SMALL_LIMIT`].
const LONG_REPLY: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nsixteen-bytes-ok";

/// A reply that asks to switch protocols.
const UPGRADE_REPLY: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

/// The coding that [`MARKED_REPLY`] names, which no record and no audit line may carry.
const PLANTED_CODING: &str = "x-planted-coding-5d1c";

/// A reply in a coding that the leak-back scrub cannot read.
const MARKED_REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Encoding: x-planted-coding-5d1c\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

/// A body limit that the long reply and the long request pass.
const SMALL_LIMIT: usize = 8;

/// The secret that the credential routes in this file attach.
const SECRET: &str = "sk_live_exit_records_secret";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Resolve,
    Connect,
    HttpRequest,
    ResponseRelease,
}

/// An authority that permits each attempt, refuses the `deny` kind, and fails to record the outcome
/// of the `unrecorded` kind.
#[derive(Default)]
struct TestAuthority {
    deny: Option<Kind>,
    unrecorded: Option<Kind>,
}

impl TestAuthority {
    fn denying(kind: Kind) -> Self {
        Self {
            deny: Some(kind),
            unrecorded: None,
        }
    }

    fn unrecording(kind: Kind) -> Self {
        Self {
            deny: None,
            unrecorded: Some(kind),
        }
    }
}

impl EffectInterceptor for TestAuthority {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        let kind = match attempt {
            EffectAttempt::Resolve { .. } => Kind::Resolve,
            EffectAttempt::Connect { .. } => Kind::Connect,
            EffectAttempt::HttpRequest { .. } => Kind::HttpRequest,
            EffectAttempt::ResponseRelease { .. } => Kind::ResponseRelease,
            _ => panic!("unexpected future effect attempt"),
        };
        if self.deny == Some(kind) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "denied by test authority",
            ));
        }
        Ok(Box::new(TestPermit {
            unrecorded: self.unrecorded == Some(kind),
        }))
    }
}

struct TestPermit {
    unrecorded: bool,
}

impl EffectPermit for TestPermit {
    fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> io::Result<()> {
        if self.unrecorded {
            return Err(io::Error::other("test outcome sink failed"));
        }
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

/// A gateway that pins [`HOST`] to loopback and keeps every record that it emits.
struct Gateway {
    handle: MitmHandle,
    emitter: StubEmitter,
}

impl Gateway {
    fn start(config: MitmConfig, controls: CapabilitySet, authority: TestAuthority) -> Self {
        let emitter = StubEmitter::new();
        let config = MitmConfig {
            dns_overrides: vec![(HOST.to_string(), "127.0.0.1".parse().unwrap())],
            ..config
        };
        let handle = MitmInterceptor::start_with_emitter(
            config,
            controls,
            Arc::new(authority),
            Box::new(emitter.clone()),
        )
        .unwrap();
        Self { handle, emitter }
    }

    fn port(&self) -> u16 {
        self.handle.port().expect("a gateway on TCP")
    }

    /// What the exchange left, after its connection pushed its one audit event.
    fn ended(&self, reply: String) -> Ended {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut audit = Vec::new();
        while audit.is_empty() {
            assert!(
                Instant::now() < deadline,
                "the connection pushed no audit event"
            );
            std::thread::sleep(Duration::from_millis(5));
            audit.extend(self.handle.drain_audit_events());
        }
        // Give a second event the time to arrive, so that a test can see that none did.
        std::thread::sleep(Duration::from_millis(50));
        audit.extend(self.handle.drain_audit_events());
        Ended {
            reply,
            records: self.emitter.records(),
            audit,
        }
    }
}

/// What one exchange left: the reply that the workload read, the records, and the audit events.
struct Ended {
    reply: String,
    records: Vec<EgressDecision>,
    audit: Vec<NetworkAuditEvent>,
}

impl Ended {
    fn denials(&self) -> Vec<&EgressDecision> {
        self.records
            .iter()
            .filter(|record| record.decision == AuditDecision::Deny)
            .collect()
    }

    /// Assert that the last record is the one denial, of `method` and `path` for `reason`, and that
    /// every record names one correlation.
    fn assert_one_denial(&self, method: &str, path: &str, reason: &str) {
        assert_eq!(self.denials().len(), 1, "{:#?}", self.records);
        let last = self.records.last().expect("the exchange is recorded");
        assert!(
            last.decision == AuditDecision::Deny
                && last.method == method
                && last.path == path
                && last.reason == reason,
            "the exchange ends with the denial of {method:?} {path:?} for {reason:?}: {:#?}",
            self.records
        );
        let correlation = self.records[0].correlation.as_str();
        assert!(
            self.records
                .iter()
                .all(|record| record.correlation.as_str() == correlation),
            "the records of one exchange share its correlation: {:#?}",
            self.records
        );
    }

    /// Assert that no record is a denial, and that the permit of `GET /exit` is the last record.
    fn assert_ends_with_the_request_permit(&self) {
        assert!(self.denials().is_empty(), "{:#?}", self.records);
        let last = self.records.last().expect("the exchange is recorded");
        assert_eq!(
            (last.method.as_str(), last.path.as_str(), last.decision),
            ("GET", "/exit", AuditDecision::Allow),
            "{:#?}",
            self.records
        );
    }

    /// Assert that the audit log holds only the one line of the connection's handler error.
    fn assert_handler_error(&self) {
        assert!(
            matches!(self.audit.as_slice(), [event]
                if event.decision == AuditDecision::Deny
                    && event.reason.starts_with("connection handler error")),
            "{:?}",
            self.audit
        );
    }
}

/// The configuration that trusts `upstream`.
fn trusting(upstream: &TlsUpstream, config: MitmConfig) -> MitmConfig {
    MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem()],
        ..config
    }
}

/// Send `GET /exit` through a gateway that trusts `upstream`, and return what the exchange left.
fn get(upstream: &TlsUpstream, config: MitmConfig, authority: TestAuthority) -> Ended {
    get_with(upstream, trusting(upstream, config), authority)
}

/// Send `GET /exit` through a gateway with `config` to `upstream`, and return what the exchange left.
fn get_with(upstream: &TlsUpstream, config: MitmConfig, authority: TestAuthority) -> Ended {
    let gateway = Gateway::start(config, CapabilitySet::default(), authority);
    let mut client = WorkloadClient::connect(gateway.port(), HOST, upstream.port());
    client.send_request("GET", "/exit", &[], b"");
    gateway.ended(client.read_response())
}

/// A plain-HTTP upstream on loopback that reads one request head, writes `reply`, and closes.
fn plain_upstream(reply: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut head = Vec::new();
        let mut byte = [0; 1];
        while !head.ends_with(b"\r\n\r\n") && matches!(stream.read(&mut byte), Ok(1)) {
            head.push(byte[0]);
        }
        let _ = stream.write_all(reply);
    });
    port
}

/// Send `GET /exit` over plain HTTP through a gateway to the upstream on `port`, and return what the
/// exchange left.
fn plain_get(port: u16, config: MitmConfig) -> Ended {
    let gateway = Gateway::start(config, CapabilitySet::default(), TestAuthority::default());
    let reply = plain_exchange(
        gateway.port(),
        &format!("GET http://{HOST}:{port}/exit HTTP/1.1\r\nHost: {HOST}:{port}\r\n\r\n"),
    );
    gateway.ended(reply)
}

/// Send `CONNECT` to a gateway for `port`, close, and return what the exchange left.
fn connect(port: u16, authority: TestAuthority) -> Ended {
    let gateway = Gateway::start(MitmConfig::default(), CapabilitySet::default(), authority);
    let mut client = WorkloadClient::connect_raw(gateway.port());
    let reply = client.raw_connect(HOST, port);
    drop(client);
    gateway.ended(reply)
}

/// Send `request` whole, in one write, through a gateway to a delivering upstream, and return what
/// the exchange left.
fn send(config: MitmConfig, request: impl Fn(u16) -> String) -> Ended {
    let upstream = TlsUpstream::start_with_response(HOST, OK_REPLY);
    let gateway = Gateway::start(
        trusting(&upstream, config),
        CapabilitySet::default(),
        TestAuthority::default(),
    );
    let mut client = WorkloadClient::connect(gateway.port(), HOST, upstream.port());
    client.send_raw(request(upstream.port()).as_bytes());
    gateway.ended(client.read_response())
}

/// A loopback port that refuses a connection.
fn closed_port() -> u16 {
    for _ in 0..8 {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        if matches!(
            TcpStream::connect_timeout(&address, Duration::from_secs(2)),
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused
        ) {
            return port;
        }
    }
    panic!("required setup: no loopback port refused a connection in 8 attempts");
}

/// Place `secret` in a uniquely-named environment variable and return its `env://` locator.
fn env_locator(secret: &str) -> Locator {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let name = format!(
        "EXIT_RECORDS_SECRET_{}",
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    // SAFETY: the name is unique to this call, so no other test reads or writes it.
    unsafe { std::env::set_var(&name, secret) };
    Locator::parse_uri(&format!("env://{name}")).unwrap()
}

/// One credential route on [`HOST`] at `port`, and the phantom that the workload sends for it.
fn credential(port: u16, placement: InjectMode, check: PhantomCheck) -> (CapabilitySet, String) {
    let destination = DestinationPattern::parse(&format!("{HOST}:{port}")).unwrap();
    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant").route(
        RouteSpec::opaque(destination.clone(), env_locator(SECRET), placement).phantom_check(check),
    ))
    .unwrap();
    let phantom = opened.phantoms()[0].token().to_string();
    let controls = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(
            destination,
            Arc::new(opened.into_vault()),
        ))
        .build();
    (controls, phantom)
}

/// The usual bearer route on [`HOST`] at `port`.
fn bearer(port: u16) -> (CapabilitySet, String) {
    credential(
        port,
        InjectMode::header("Bearer {}".to_string(), None).unwrap(),
        PhantomCheck::Strict,
    )
}

/// Send `request` to the gateway over plain TCP, and read its reply to the end.
fn plain_exchange(port: u16, request: &str) -> String {
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.write_all(request.as_bytes()).unwrap();
    let mut reply = Vec::new();
    let _ = tcp.read_to_end(&mut reply);
    String::from_utf8_lossy(&reply).into_owned()
}

/// One way that a permitted exchange ends.
#[derive(Debug, Clone, Copy)]
enum Fixture {
    /// The workload reads the governed response.
    Delivered,
    /// The upstream closes inside the body of its reply.
    UpstreamReset,
    /// The workload closes the tunnel before its TLS handshake.
    WorkloadClosed,
    ReplyOverLimit,
    /// The upstream never replies, and the upstream deadline passes.
    UpstreamDeadline,
    UpgradeReply,
    /// The workload sends a `Transfer-Encoding` that does not end in `chunked`.
    AmbiguousRequest,
    RequestOverLimit,
    /// The authority fails to record the outcome of the request.
    RequestOutcomeUnrecorded,
    /// The authority fails to record the outcome of the connection.
    ConnectOutcomeUnrecorded,
    /// The one permitted address refuses the connection.
    FailedDial,
    /// The gateway does not trust the certificate of the upstream.
    UntrustedUpstream,
    /// On plain HTTP, the upstream closes before the head of its reply.
    PlainUpstreamClosed,
    /// On plain HTTP, the reply body is larger than the limit.
    PlainReplyOverLimit,
}

impl Fixture {
    const ALL: [Self; 14] = [
        Self::Delivered,
        Self::UpstreamReset,
        Self::WorkloadClosed,
        Self::ReplyOverLimit,
        Self::UpstreamDeadline,
        Self::UpgradeReply,
        Self::AmbiguousRequest,
        Self::RequestOverLimit,
        Self::RequestOutcomeUnrecorded,
        Self::ConnectOutcomeUnrecorded,
        Self::FailedDial,
        Self::UntrustedUpstream,
        Self::PlainUpstreamClosed,
        Self::PlainReplyOverLimit,
    ];

    /// Whether the workload read the governed response, a peer ended the exchange, or the TLS setup
    /// failed.
    fn ends_with_a_permit(self) -> bool {
        matches!(
            self,
            Self::Delivered
                | Self::UpstreamReset
                | Self::WorkloadClosed
                | Self::UntrustedUpstream
                | Self::PlainUpstreamClosed
        )
    }

    fn run(self) -> Ended {
        let small_limit = MitmConfig {
            response_limits: ResponseLimits {
                max_body_bytes: SMALL_LIMIT,
            },
            ..MitmConfig::default()
        };
        match self {
            Self::Delivered => get(
                &TlsUpstream::start_with_response(HOST, OK_REPLY),
                MitmConfig::default(),
                TestAuthority::default(),
            ),
            Self::UpstreamReset => get(
                &TlsUpstream::start_with_response(HOST, CUT_REPLY),
                MitmConfig::default(),
                TestAuthority::default(),
            ),
            Self::WorkloadClosed => connect(
                TlsUpstream::start_with_response(HOST, OK_REPLY).port(),
                TestAuthority::default(),
            ),
            Self::ReplyOverLimit => get(
                &TlsUpstream::start_with_response(HOST, LONG_REPLY),
                small_limit,
                TestAuthority::default(),
            ),
            Self::UpstreamDeadline => get(
                &TlsUpstream::start_silent(HOST),
                MitmConfig {
                    upstream_read_deadline: Duration::from_millis(500),
                    ..MitmConfig::default()
                },
                TestAuthority::default(),
            ),
            Self::UpgradeReply => get(
                &TlsUpstream::start_with_response(HOST, UPGRADE_REPLY),
                MitmConfig::default(),
                TestAuthority::default(),
            ),
            Self::AmbiguousRequest => send(MitmConfig::default(), |port| {
                format!(
                    "POST /exit HTTP/1.1\r\nHost: {HOST}:{port}\r\n\
                     Transfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n"
                )
            }),
            Self::RequestOverLimit => send(small_limit, |port| {
                let body = "x".repeat(2 * SMALL_LIMIT);
                format!(
                    "POST /exit HTTP/1.1\r\nHost: {HOST}:{port}\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
            }),
            Self::RequestOutcomeUnrecorded => get(
                &TlsUpstream::start_with_response(HOST, OK_REPLY),
                MitmConfig::default(),
                TestAuthority::unrecording(Kind::HttpRequest),
            ),
            Self::ConnectOutcomeUnrecorded => connect(
                TlsUpstream::start_with_response(HOST, OK_REPLY).port(),
                TestAuthority::unrecording(Kind::Connect),
            ),
            Self::FailedDial => connect(closed_port(), TestAuthority::default()),
            Self::UntrustedUpstream => get_with(
                &TlsUpstream::start_with_response(HOST, OK_REPLY),
                MitmConfig::default(),
                TestAuthority::default(),
            ),
            Self::PlainUpstreamClosed => plain_get(plain_upstream(b""), MitmConfig::default()),
            Self::PlainReplyOverLimit => plain_get(plain_upstream(LONG_REPLY), small_limit),
        }
    }
}

/// **The last record of an exchange is a permit only when the workload read the governed response,
/// or a peer ended the exchange.** Each gateway bound adds exactly one denial, an end that a peer
/// causes adds none, and each exit pushes exactly one audit event.
#[test]
fn every_exchange_ends_with_a_permit_only_when_delivered() {
    for fixture in Fixture::ALL {
        let ended = fixture.run();
        let last = ended.records.last().expect("each exchange is recorded");
        assert_eq!(
            last.decision == AuditDecision::Allow,
            fixture.ends_with_a_permit(),
            "{fixture:?}: {:#?}",
            ended.records
        );
        assert_eq!(
            ended.denials().len(),
            usize::from(!fixture.ends_with_a_permit()),
            "{fixture:?}: {:#?}",
            ended.records
        );
        assert_eq!(ended.audit.len(), 1, "{fixture:?}: {:?}", ended.audit);
    }
}

/// **A reply over the body limit ends with one denial**, over TLS and over plain HTTP.
#[test]
fn a_reply_over_the_body_limit_ends_with_one_denial() {
    for fixture in [Fixture::ReplyOverLimit, Fixture::PlainReplyOverLimit] {
        let ended = fixture.run();
        assert_eq!(
            ended.reply, "",
            "{fixture:?}: no reply byte reaches the workload"
        );
        ended.assert_one_denial(
            "GET",
            "/exit",
            "the reply was refused: its body is larger than the limit",
        );
        ended.assert_handler_error();
    }
}

#[test]
fn an_upstream_deadline_ends_with_one_denial() {
    let ended = Fixture::UpstreamDeadline.run();
    assert_eq!(ended.reply, "", "no reply byte reaches the workload");
    ended.assert_one_denial("GET", "/exit", "the exchange passed the upstream deadline");
    ended.assert_handler_error();
}

#[test]
fn an_upstream_upgrade_reply_ends_with_one_denial() {
    let ended = Fixture::UpgradeReply.run();
    assert_eq!(ended.reply, "", "no reply byte reaches the workload");
    ended.assert_one_denial(
        "GET",
        "/exit",
        "the reply was refused: the gateway does not accept its head, framing, or upgrade",
    );
    ended.assert_handler_error();
}

/// **A dial that fails on every permitted address ends with one denial of the connection.** The
/// workload gets its 502, and the audit log keeps its one line.
#[test]
fn a_failed_dial_on_every_address_ends_with_one_denial() {
    let ended = Fixture::FailedDial.run();
    assert!(ended.reply.starts_with("HTTP/1.1 502 "), "{}", ended.reply);
    assert_eq!(
        ended
            .records
            .iter()
            .map(|record| record.decision)
            .collect::<Vec<_>>(),
        [AuditDecision::Allow, AuditDecision::Deny],
        "the permit of the one address, then the denial: {:#?}",
        ended.records
    );
    ended.assert_one_denial("", "/", "no permitted address accepted the connection");
    assert!(
        matches!(ended.audit.as_slice(), [event] if event.decision == AuditDecision::Deny),
        "{:?}",
        ended.audit
    );
}

/// **An inner request that the gateway refuses ends the connection with one denial.** The request
/// never reached a request decision, so the denial names the connection. hyper answers a head that
/// it refuses with its own `400`, which carries no refusal marker; a body over the limit gets no
/// reply.
#[test]
fn an_intercepted_request_that_the_gateway_refuses_ends_the_connection_with_one_denial() {
    for (fixture, reason, reply) in [
        (
            Fixture::AmbiguousRequest,
            "the request was refused: the gateway does not accept its head or framing",
            "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            Fixture::RequestOverLimit,
            "the request was refused: its body is larger than the limit",
            "",
        ),
    ] {
        let ended = fixture.run();
        assert_eq!(ended.reply, reply, "{fixture:?}: the reply to the workload");
        assert_eq!(ended.records.len(), 2, "{fixture:?}: {:#?}", ended.records);
        ended.assert_one_denial("", "/", reason);
        ended.assert_handler_error();
    }
}

/// **A permit whose outcome is not recorded ends with one denial on its own leg.**
#[test]
fn an_outcome_that_is_not_recorded_ends_with_one_denial() {
    let reason = "the outcome of the permitted effect was not recorded";

    let ended = Fixture::RequestOutcomeUnrecorded.run();
    assert_eq!(ended.reply, "", "no reply byte reaches the workload");
    ended.assert_one_denial("GET", "/exit", reason);
    ended.assert_handler_error();

    let ended = Fixture::ConnectOutcomeUnrecorded.run();
    assert!(ended.reply.starts_with("HTTP/1.1 502 "), "{}", ended.reply);
    ended.assert_one_denial("", "/", reason);
}

/// **An upstream that resets inside its reply is audited and records no denial.** A reset is an end
/// that a peer causes, not a policy denial, so the permit of the request stays the last record. On
/// plain HTTP, an upstream that closes before the head of its reply is the same end.
#[test]
fn an_upstream_reset_is_audited_and_records_no_denial() {
    for fixture in [Fixture::UpstreamReset, Fixture::PlainUpstreamClosed] {
        let ended = fixture.run();
        assert_eq!(ended.reply, "", "{fixture:?}: a torn reply is not released");
        ended.assert_ends_with_the_request_permit();
        ended.assert_handler_error();
    }
}

/// **An upstream certificate that the gateway does not trust records no denial.** A failed TLS
/// setup keeps only its audit line, so the permit of the request stays the last record.
#[test]
fn an_upstream_certificate_that_the_gateway_does_not_trust_records_no_denial() {
    let ended = Fixture::UntrustedUpstream.run();
    assert_eq!(ended.reply, "", "no reply byte reaches the workload");
    ended.assert_ends_with_the_request_permit();
    ended.assert_handler_error();
    assert!(
        ended.audit[0].reason.contains("certificate"),
        "the audit line names the certificate: {:?}",
        ended.audit
    );
}

/// One refusal that the gateway answers itself.
#[derive(Debug, Clone, Copy)]
enum Refusal {
    /// A path that is not RFC 3986.
    Path,
    /// A credential that would ride plain HTTP.
    PlaintextCredential,
    /// The credential fold refuses an absent phantom.
    CredentialFold,
    /// The request names another authority than the CONNECT.
    AuthorityBeforeMutation,
    /// The credential mutation makes `Host` name another authority.
    AuthorityAfterMutation,
    /// A remote MCP frame that is not JSON-RPC.
    McpFrame,
    /// The authority denies `http:request`.
    RequestDenied,
    /// The response fold blocks a reply in a coding that it cannot read.
    ResponseBlocked,
    /// The authority refuses the release of the reply.
    ReleaseRefused,
}

impl Refusal {
    const ALL: [Self; 9] = [
        Self::Path,
        Self::PlaintextCredential,
        Self::CredentialFold,
        Self::AuthorityBeforeMutation,
        Self::AuthorityAfterMutation,
        Self::McpFrame,
        Self::RequestDenied,
        Self::ResponseBlocked,
        Self::ReleaseRefused,
    ];

    fn run(self) -> Ended {
        if let Self::PlaintextCredential = self {
            let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = upstream.local_addr().unwrap().port();
            let (controls, _) = bearer(port);
            let gateway = Gateway::start(MitmConfig::default(), controls, TestAuthority::default());
            let reply = plain_exchange(
                gateway.port(),
                &format!("GET http://{HOST}:{port}/exit HTTP/1.1\r\nHost: {HOST}:{port}\r\n\r\n"),
            );
            return gateway.ended(reply);
        }
        let reply = match self {
            Self::ResponseBlocked => MARKED_REPLY,
            _ => OK_REPLY,
        };
        let upstream = TlsUpstream::start_with_response(HOST, reply);
        let port = upstream.port();
        let mut config = trusting(&upstream, MitmConfig::default());
        let mut controls = CapabilitySet::default();
        let mut authority = TestAuthority::default();
        let (mut method, mut path, mut body) = ("GET", "/exit", b"".as_slice());
        let mut request_authority = format!("{HOST}:{port}");
        let mut authorization = None;
        match self {
            Self::Path => path = "/%zz",
            Self::CredentialFold => controls = bearer(port).0,
            Self::AuthorityBeforeMutation => request_authority = format!("elsewhere.test:{port}"),
            Self::AuthorityAfterMutation => {
                controls = credential(
                    port,
                    InjectMode::header("{}".to_string(), Some("Host".to_string())).unwrap(),
                    PhantomCheck::Advisory,
                )
                .0;
            }
            Self::McpFrame => {
                config.mcp_servers = vec![(HOST.to_string(), "demo".to_string())];
                (method, path, body) = ("POST", "/mcp", b"not json".as_slice());
            }
            Self::RequestDenied => authority = TestAuthority::denying(Kind::HttpRequest),
            Self::ResponseBlocked => {
                let (bearer, phantom) = bearer(port);
                controls = bearer;
                authorization = Some(format!("Bearer {phantom}"));
            }
            Self::ReleaseRefused => authority = TestAuthority::denying(Kind::ResponseRelease),
            Self::PlaintextCredential => unreachable!("answered above"),
        }
        let gateway = Gateway::start(config, controls, authority);
        let mut client = WorkloadClient::connect(gateway.port(), HOST, port);
        let headers: Vec<(&str, &str)> = authorization
            .iter()
            .map(|value| ("Authorization", value.as_str()))
            .collect();
        client.send_request_with_authority(method, path, &request_authority, &headers, body);
        gateway.ended(client.read_response())
    }
}

/// **Each refusal is audited, emitted, and answered.** The audit log gets one denial, the records
/// end with one denial that carries the same correlation and reason, and the workload gets the
/// gateway's marked refusal.
#[test]
fn every_refusal_is_audited_emitted_and_answered() {
    for refusal in Refusal::ALL {
        let ended = refusal.run();
        assert!(
            ended
                .reply
                .to_ascii_lowercase()
                .contains("x-strands-box-egress: refused"),
            "{refusal:?}: {}",
            ended.reply
        );
        let [event] = ended.audit.as_slice() else {
            panic!("{refusal:?}: one audit event: {:?}", ended.audit);
        };
        assert_eq!(event.decision, AuditDecision::Deny, "{refusal:?}");
        let last = ended.records.last().expect("the refusal is recorded");
        assert_eq!(
            ended.denials().len(),
            1,
            "{refusal:?}: {:#?}",
            ended.records
        );
        assert_eq!(last.decision, AuditDecision::Deny, "{refusal:?}");
        assert_eq!(
            last.correlation.as_str(),
            event.correlation.as_str(),
            "{refusal:?}"
        );
        assert_eq!(last.reason, event.reason, "{refusal:?}");
        let text = format!("{:?}{:?}", ended.records, ended.audit);
        assert!(!text.contains(SECRET), "{refusal:?}: {text}");
    }
}

/// **A blocked response emits its refusal, and no record carries the upstream's bytes.** The
/// upstream names a coding of its own choice, and the reason names only the kind of refusal.
#[test]
fn a_blocked_response_emits_its_refusal_without_upstream_bytes() {
    let ended = Refusal::ResponseBlocked.run();
    assert!(ended.reply.starts_with("HTTP/1.1 403 "), "{}", ended.reply);
    ended.assert_one_denial(
        "GET",
        "/exit",
        "response blocked by egress control: credential denied",
    );
    assert!(
        matches!(ended.audit.as_slice(), [event]
            if event.reason == "response blocked by egress control: credential denied"),
        "{:?}",
        ended.audit
    );
    let text = format!("{:?}{:?}", ended.records, ended.audit);
    assert!(!text.contains(PLANTED_CODING), "{text}");
}

/// A short, unique AF_UNIX socket path under the temporary directory.
fn unique_socket_path() -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let next = NEXT.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("exit-{}-{next}.sock", std::process::id()))
}

/// **A refused proxy token is recorded on every transport.** The workload gets the 407, the audit
/// log gets one denial, and one record of the connection carries the same correlation.
#[test]
fn a_proxy_token_refusal_is_recorded() {
    let wrong_token = "Proxy-Authorization: Bearer wrong-token";
    for transport in ["tcp", "unix", "plain"] {
        let socket = unique_socket_path();
        let _ = std::fs::remove_file(&socket);
        let config = MitmConfig {
            expected_token: Some("right-token".to_string()),
            unix_socket_path: (transport == "unix").then(|| socket.clone()),
            ..MitmConfig::default()
        };
        let gateway = Gateway::start(config, CapabilitySet::default(), TestAuthority::default());
        let connect =
            format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n{wrong_token}\r\n\r\n");
        let reply = match transport {
            "unix" => {
                let mut stream = UnixStream::connect(&socket).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream.write_all(connect.as_bytes()).unwrap();
                let mut reply = Vec::new();
                let _ = stream.read_to_end(&mut reply);
                String::from_utf8_lossy(&reply).into_owned()
            }
            "plain" => plain_exchange(
                gateway.port(),
                &format!(
                    "GET http://{HOST}/exit HTTP/1.1\r\nHost: {HOST}\r\n{wrong_token}\r\n\r\n"
                ),
            ),
            _ => plain_exchange(gateway.port(), &connect),
        };
        let ended = gateway.ended(reply);
        // The shutdown of the gateway connects through the socket file, so the gateway stops first.
        drop(gateway);
        let _ = std::fs::remove_file(&socket);
        assert!(
            ended.reply.starts_with("HTTP/1.1 407 "),
            "{transport}: {}",
            ended.reply
        );
        let [event] = ended.audit.as_slice() else {
            panic!("{transport}: one audit event: {:?}", ended.audit);
        };
        assert_eq!(
            (event.decision, event.reason.as_str()),
            (AuditDecision::Deny, "proxy authentication required"),
            "{transport}"
        );
        ended.assert_one_denial("", "/", "proxy authentication required");
        assert_eq!(ended.records.len(), 1, "{transport}: {:#?}", ended.records);
        assert_eq!(
            ended.records[0].correlation.as_str(),
            event.correlation.as_str(),
            "{transport}"
        );
        assert!(
            !format!("{:?}{:?}", ended.records, ended.audit).contains("wrong-token"),
            "{transport}: no record carries the token"
        );
    }
}

/// **A host that does not resolve after its permit is audited as well as recorded.** The workload
/// gets its 502, and the audit event and the record name the resolve with one correlation.
#[test]
fn a_resolution_failure_is_audited() {
    let host = "resolution-failure.invalid";
    let gateway = Gateway::start(
        MitmConfig::default(),
        CapabilitySet::default(),
        TestAuthority::default(),
    );
    let mut client = WorkloadClient::connect_raw(gateway.port());
    let ended = gateway.ended(client.raw_connect(host, 443));
    assert!(ended.reply.starts_with("HTTP/1.1 502 "), "{}", ended.reply);
    let [event] = ended.audit.as_slice() else {
        panic!("one audit event: {:?}", ended.audit);
    };
    let [record] = ended.records.as_slice() else {
        panic!("one record: {:#?}", ended.records);
    };
    assert_eq!(
        (event.host.as_str(), event.port, event.decision),
        (host, 443, AuditDecision::Deny)
    );
    assert!(event.reason.contains("resolving"), "{}", event.reason);
    assert_eq!(record.decision, AuditDecision::Deny);
    assert_eq!(record.reason, event.reason);
    assert_eq!(record.correlation.as_str(), event.correlation.as_str());
}
