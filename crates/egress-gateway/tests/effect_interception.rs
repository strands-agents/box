//! End-to-end coverage for the egress-owned effect lifecycle.

#![cfg(feature = "tls-intercept")]

mod harness;

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use credentials::{
    Backend, DestinationPattern, InjectMode, Locator, RouteSpec, Vault, VaultConfig,
};
use egress_gateway::{
    AuditDecision, CapabilitySet, CredentialCapability, EffectAttempt, EffectInterceptor,
    EffectOutcome, EffectPermit, EgressDecision, Emitter, McpFrame, MitmConfig, MitmInterceptor,
    StubEmitter,
};

use harness::{TlsUpstream, WorkloadClient};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectKind {
    Resolve,
    Connect,
    HttpRequest,
    ResponseRelease,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AttemptSnapshot {
    Resolve {
        host: String,
        port: u16,
    },
    Connect {
        host: String,
        port: u16,
        address: SocketAddr,
        http_visibility: bool,
    },
    HttpRequest {
        host: String,
        port: u16,
        method: String,
        path: String,
        body_bytes: usize,
    },
    ResponseRelease {
        host: String,
        port: u16,
        method: String,
        path: String,
        status: u16,
        body_bytes: usize,
    },
}

impl AttemptSnapshot {
    fn capture(attempt: &EffectAttempt<'_>) -> Self {
        match attempt {
            EffectAttempt::Resolve { host, port } => Self::Resolve {
                host: (*host).to_string(),
                port: *port,
            },
            EffectAttempt::Connect {
                host,
                port,
                address,
                http_visibility,
            } => Self::Connect {
                host: (*host).to_string(),
                port: *port,
                address: *address,
                http_visibility: *http_visibility,
            },
            EffectAttempt::HttpRequest {
                host,
                port,
                method,
                path,
                body_bytes,
                intercepted: _,
                mcp: _,
            } => Self::HttpRequest {
                host: (*host).to_string(),
                port: *port,
                method: (*method).to_string(),
                path: (*path).to_string(),
                body_bytes: *body_bytes,
            },
            EffectAttempt::ResponseRelease {
                host,
                port,
                method,
                path,
                status,
                body_bytes,
            } => Self::ResponseRelease {
                host: (*host).to_string(),
                port: *port,
                method: (*method).to_string(),
                path: (*path).to_string(),
                status: *status,
                body_bytes: *body_bytes,
            },
            _ => panic!("unexpected future effect attempt"),
        }
    }

    fn kind(&self) -> EffectKind {
        match self {
            Self::Resolve { .. } => EffectKind::Resolve,
            Self::Connect { .. } => EffectKind::Connect,
            Self::HttpRequest { .. } => EffectKind::HttpRequest,
            Self::ResponseRelease { .. } => EffectKind::ResponseRelease,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Attempt(AttemptSnapshot),
    Outcome(EffectKind, EffectOutcome),
    MarkedIndeterminate(EffectKind),
}

#[derive(Clone)]
struct RecordingInterceptor {
    events: Arc<Mutex<Vec<Event>>>,
    deny: Option<EffectKind>,
    fail_recording: Option<EffectKind>,
}

impl RecordingInterceptor {
    fn allowing(events: Arc<Mutex<Vec<Event>>>) -> Self {
        Self {
            events,
            deny: None,
            fail_recording: None,
        }
    }

    fn denying(events: Arc<Mutex<Vec<Event>>>, kind: EffectKind) -> Self {
        Self {
            events,
            deny: Some(kind),
            fail_recording: None,
        }
    }

    fn failing_recording(events: Arc<Mutex<Vec<Event>>>, kind: EffectKind) -> Self {
        Self {
            events,
            deny: None,
            fail_recording: Some(kind),
        }
    }
}

impl EffectInterceptor for RecordingInterceptor {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        let snapshot = AttemptSnapshot::capture(attempt);
        let kind = snapshot.kind();
        self.events.lock().unwrap().push(Event::Attempt(snapshot));
        if self.deny == Some(kind) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "denied by test interceptor",
            ));
        }
        Ok(Box::new(RecordingPermit {
            events: self.events.clone(),
            kind,
            fail_recording: self.fail_recording == Some(kind),
        }))
    }
}

struct RecordingPermit {
    events: Arc<Mutex<Vec<Event>>>,
    kind: EffectKind,
    fail_recording: bool,
}

impl EffectPermit for RecordingPermit {
    fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
        self.events
            .lock()
            .unwrap()
            .push(Event::Outcome(self.kind, outcome));
        if self.fail_recording {
            Err(io::Error::other("test outcome sink failed"))
        } else {
            Ok(())
        }
    }

    fn mark_indeterminate(self: Box<Self>) {
        self.events
            .lock()
            .unwrap()
            .push(Event::MarkedIndeterminate(self.kind));
    }
}

/// Place `secret` in a uniquely-named environment variable and return its `env://` locator.
///
/// The vault's source set is sealed, so a test cannot inject a stub source
/// from outside the crate — it declares a real `env://` route instead, which is also what an operator
/// writes. The variable name is unique per call so concurrently-running tests cannot collide.
fn env_locator(secret: &str) -> Locator {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let name = format!(
        "EFFECT_INTERCEPTION_SECRET_{}",
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    // SAFETY: the name is unique to this call, so no other test reads or writes it. The variable
    // outlives the test deliberately — the vault resolves it once at open.
    unsafe { std::env::set_var(&name, secret) };
    Locator::parse_uri(&format!("env://{name}")).unwrap()
}

fn destination(host: &str, port: u16) -> DestinationPattern {
    DestinationPattern::parse(&format!("{host}:{port}")).unwrap()
}

fn config_for(host: &str, upstream: &TlsUpstream) -> MitmConfig {
    MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem()],
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        ..MitmConfig::default()
    }
}

fn proxy_port(handle: &egress_gateway::MitmHandle) -> u16 {
    handle.port().expect("test proxy uses TCP")
}

/// A capability set that injects nothing — the transport-only composition.
fn no_injection() -> CapabilitySet {
    CapabilitySet::builder().build()
}

fn event_names(events: &[Event]) -> Vec<&'static str> {
    events
        .iter()
        .map(|event| match event {
            Event::Attempt(snapshot) => match snapshot.kind() {
                EffectKind::Resolve => "attempt:resolve",
                EffectKind::Connect => "attempt:connect",
                EffectKind::HttpRequest => "attempt:request",
                EffectKind::ResponseRelease => "attempt:response",
            },
            Event::Outcome(kind, _) => match kind {
                EffectKind::Resolve => "outcome:resolve",
                EffectKind::Connect => "outcome:connect",
                EffectKind::HttpRequest => "outcome:request",
                EffectKind::ResponseRelease => "outcome:response",
            },
            Event::MarkedIndeterminate(kind) => match kind {
                EffectKind::Resolve => "indeterminate:resolve",
                EffectKind::Connect => "indeterminate:connect",
                EffectKind::HttpRequest => "indeterminate:request",
                EffectKind::ResponseRelease => "indeterminate:response",
            },
        })
        .collect()
}

fn wait_for_event_count(events: &Arc<Mutex<Vec<Event>>>, expected: usize) -> Vec<Event> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let snapshot = events.lock().unwrap().clone();
        if snapshot.len() >= expected {
            return snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {expected} lifecycle events; saw {:?}",
            event_names(&snapshot)
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn lifecycle_orders_real_effects_and_keeps_attempts_secret_free() {
    const SECRET: &str = "sk_live_lifecycle_secret";
    let host = "effects.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();
    let events = Arc::new(Mutex::new(Vec::new()));
    // The real credential capability, not a stub: this test is about the *ordering* of admitted
    // effects around an actual injection, and the shipped capability is what the box installs.
    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant").route(
        RouteSpec::opaque(
            destination(host, port),
            env_locator(SECRET),
            InjectMode::header("Bearer {}".to_string(), None).expect("a valid header placement"),
        ),
    ))
    .unwrap();
    let phantom = opened.phantoms()[0].token().to_string();
    let controls = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(
            destination(host, port),
            Arc::new(opened.into_vault()),
        ))
        .build();
    let handle = MitmInterceptor::start(
        config_for(host, &upstream),
        controls,
        Arc::new(RecordingInterceptor::allowing(events.clone())),
    )
    .unwrap();

    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request(
        "POST",
        "/v1/items?token=query-secret",
        &[("Authorization", &format!("Bearer {phantom}"))],
        b"body-secret",
    );
    assert_eq!(client.read_status(), 200);
    // The real capability swapped the phantom for the real secret on the way out.
    assert_eq!(
        upstream.last_request().header("authorization").as_deref(),
        Some(format!("Bearer {SECRET}").as_str())
    );

    // The client can read the flushed response before the proxy thread records its terminal
    // response outcome. Wait for that record instead of racing the exact-order assertion.
    let events = wait_for_event_count(&events, 7);
    assert_eq!(
        event_names(&events),
        vec![
            "attempt:resolve",
            "attempt:connect",
            "outcome:connect",
            "attempt:request",
            "outcome:request",
            "attempt:response",
            "outcome:response",
        ]
    );
    assert!(
        matches!(
            &events[0],
            Event::Attempt(AttemptSnapshot::Resolve { host: attempt_host, port: attempt_port })
                if attempt_host == host && *attempt_port == port
        ),
        "the host is decided before it is resolved: {events:?}"
    );
    assert!(matches!(
        &events[1],
        Event::Attempt(AttemptSnapshot::Connect {
            host: attempt_host,
            port: attempt_port,
            address,
            http_visibility: true,
        }) if attempt_host == host
            && *attempt_port == port
            && *address == SocketAddr::from(([127, 0, 0, 1], port))
    ));
    assert!(matches!(
        &events[3],
        Event::Attempt(AttemptSnapshot::HttpRequest {
            method,
            path,
            body_bytes,
            ..
        }) if method == "POST" && path == "/v1/items" && *body_bytes == 11
    ));
    // The request outcome is recorded at reply time and carries the reply's status.
    assert!(matches!(
        &events[4],
        Event::Outcome(
            EffectKind::HttpRequest,
            EffectOutcome::Replied {
                accepted_bytes,
                status: 200,
            }
        ) if *accepted_bytes > 0
    ));
    assert!(matches!(
        &events[5],
        Event::Attempt(AttemptSnapshot::ResponseRelease {
            status: 200,
            body_bytes: 2,
            ..
        })
    ));

    let rendered = format!("{events:?}");
    for secret in [SECRET, "query-secret", "body-secret", "authorization"] {
        assert!(!rendered.to_ascii_lowercase().contains(secret));
    }
}

#[test]
fn connect_denial_returns_403_without_opening_the_upstream_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let host = "connect-denied.test";
    let events = Arc::new(Mutex::new(Vec::new()));
    let config = MitmConfig {
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        ..MitmConfig::default()
    };
    let handle = MitmInterceptor::start(
        config,
        no_injection(),
        Arc::new(RecordingInterceptor::denying(
            events.clone(),
            EffectKind::Connect,
        )),
    )
    .unwrap();

    let mut client = WorkloadClient::connect_raw(proxy_port(&handle));
    let reply = client.raw_connect(host, port);

    assert!(reply.contains("403"));
    assert!(!reply.contains("200 Connection Established"));
    let error = listener.accept().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(
        event_names(&events.lock().unwrap()),
        vec!["attempt:resolve", "attempt:connect"]
    );
}

#[test]
fn request_denial_returns_trusted_diagnostic_without_response_release() {
    let host = "request-denied.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();
    let events = Arc::new(Mutex::new(Vec::new()));
    let handle = MitmInterceptor::start(
        config_for(host, &upstream),
        no_injection(),
        Arc::new(RecordingInterceptor::denying(
            events.clone(),
            EffectKind::HttpRequest,
        )),
    )
    .unwrap();

    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request("GET", "/blocked", &[], b"");

    assert_eq!(client.read_status(), 403);
    assert_eq!(upstream.request_count(), 0);
    assert_eq!(
        event_names(&events.lock().unwrap()),
        vec![
            "attempt:resolve",
            "attempt:connect",
            "outcome:connect",
            "attempt:request"
        ]
    );
}

#[test]
fn scrubbed_cross_host_redirect_crosses_response_release() {
    const SECRET: &str = "sk_live_redirect_secret";
    const RESPONSE: &[u8] = concat!(
        "HTTP/1.1 302 Found\r\n",
        "Location: https://other.test/next\r\n",
        "X-Echo: sk_live_redirect_secret\r\n",
        "Content-Length: 23\r\n",
        "Connection: close\r\n\r\n",
        "sk_live_redirect_secret"
    )
    .as_bytes();

    let host = "redirect.test";
    let upstream = TlsUpstream::start_with_response(host, RESPONSE);
    let port = upstream.port();
    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant").route(
        RouteSpec::opaque(
            destination(host, port),
            env_locator(SECRET),
            InjectMode::header("Bearer {}".to_string(), None).expect("a valid header placement"),
        ),
    ))
    .unwrap();
    let phantom = opened.phantoms()[0].token().to_string();
    let controls = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(
            destination(host, port),
            Arc::new(opened.into_vault()),
        ))
        .build();
    let events = Arc::new(Mutex::new(Vec::new()));
    let handle = MitmInterceptor::start(
        config_for(host, &upstream),
        controls,
        Arc::new(RecordingInterceptor::allowing(events.clone())),
    )
    .unwrap();

    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request(
        "GET",
        "/redirect",
        &[("Authorization", &format!("Bearer {phantom}"))],
        b"",
    );
    let response = client.read_response();

    assert!(response.starts_with("HTTP/1.1 302"));
    assert!(!response.contains(SECRET));
    assert!(response.contains("X-Echo: [REDACTED]"));
    assert!(response.ends_with("[REDACTED]"));
    assert!(events.lock().unwrap().iter().any(|event| matches!(
        event,
        Event::Attempt(AttemptSnapshot::ResponseRelease {
            status: 302,
            body_bytes: 10,
            ..
        })
    )));
}

#[test]
fn request_outcome_sink_failure_stops_after_the_request_effect() {
    let host = "request-outcome-failure.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();
    let events = Arc::new(Mutex::new(Vec::new()));
    let handle = MitmInterceptor::start(
        config_for(host, &upstream),
        no_injection(),
        Arc::new(RecordingInterceptor::failing_recording(
            events.clone(),
            EffectKind::HttpRequest,
        )),
    )
    .unwrap();

    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request("POST", "/committed", &[], b"effect");
    assert_eq!(
        client.read_response(),
        "",
        "a failed record at reply time refuses the workload the reply"
    );

    assert!(upstream.last_request().raw.contains("POST /committed"));
    std::thread::sleep(std::time::Duration::from_millis(50));
    let events = events.lock().unwrap().clone();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::Outcome(
            EffectKind::HttpRequest,
            EffectOutcome::Replied { accepted_bytes, status: 200 }
        ) if *accepted_bytes > 0
    )));
    assert!(!events.iter().any(|event| matches!(
        event,
        Event::Attempt(AttemptSnapshot::ResponseRelease { .. })
    )));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::MarkedIndeterminate(_)))
    );
}

/// An upstream that closes without a reply: the request outcome records the delivered bytes with
/// no status, exactly once, and no release follows.
#[test]
fn a_request_with_no_reply_records_its_delivery_without_a_status() {
    let host = "no-reply.test";
    let upstream = TlsUpstream::start_with_response(host, b"");
    let port = upstream.port();
    let shared = Arc::new(Mutex::new(Vec::new()));
    let handle = MitmInterceptor::start(
        config_for(host, &upstream),
        no_injection(),
        Arc::new(RecordingInterceptor::allowing(shared.clone())),
    )
    .unwrap();

    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request("POST", "/no-reply", &[], b"effect");
    assert_eq!(client.read_response(), "", "no reply reaches the workload");

    let events = wait_for_event_count(&shared, 5);
    assert_eq!(
        event_names(&events),
        vec![
            "attempt:resolve",
            "attempt:connect",
            "outcome:connect",
            "attempt:request",
            "outcome:request",
        ]
    );
    assert!(matches!(
        &events[4],
        Event::Outcome(EffectKind::HttpRequest, EffectOutcome::Completed(bytes)) if *bytes > 0
    ));
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(
        shared.lock().unwrap().len(),
        5,
        "one exchange is one request outcome, and no release follows a missing reply"
    );
}

/// A reply whose body is cut short after its head: the request outcome keeps the status the head
/// carried, so a rule counting 500 replies still sees it.
#[test]
fn a_reply_cut_short_after_its_head_records_its_status() {
    const RESPONSE: &[u8] =
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort";
    let host = "short-reply.test";
    let upstream = TlsUpstream::start_with_response(host, RESPONSE);
    let port = upstream.port();
    let shared = Arc::new(Mutex::new(Vec::new()));
    let handle = MitmInterceptor::start(
        config_for(host, &upstream),
        no_injection(),
        Arc::new(RecordingInterceptor::allowing(shared.clone())),
    )
    .unwrap();

    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request("GET", "/short", &[], b"");
    assert_eq!(client.read_response(), "", "a torn reply is not released");

    let events = wait_for_event_count(&shared, 5);
    assert!(
        matches!(
            &events[4],
            Event::Outcome(
                EffectKind::HttpRequest,
                EffectOutcome::Replied { status: 500, .. }
            )
        ),
        "{:?}",
        event_names(&events)
    );
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(
        shared.lock().unwrap().len(),
        5,
        "no release follows a torn reply"
    );
}

/// An upstream that never replies: the read deadline ends the exchange, the request outcome
/// records the delivered bytes with no status, and no release follows.
#[test]
fn an_upstream_that_never_replies_is_bounded_by_the_read_deadline() {
    let host = "silent.test";
    let upstream = TlsUpstream::start_silent(host);
    let port = upstream.port();
    let shared = Arc::new(Mutex::new(Vec::new()));
    let config = MitmConfig {
        upstream_read_deadline: Duration::from_millis(500),
        ..config_for(host, &upstream)
    };
    let handle = MitmInterceptor::start(
        config,
        no_injection(),
        Arc::new(RecordingInterceptor::allowing(shared.clone())),
    )
    .unwrap();

    let started = Instant::now();
    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request("POST", "/silent", &[], b"effect");
    assert_eq!(client.read_response(), "", "no reply reaches the workload");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the deadline bounds the wait: {:?}",
        started.elapsed()
    );

    let events = wait_for_event_count(&shared, 5);
    assert_eq!(
        event_names(&events),
        vec![
            "attempt:resolve",
            "attempt:connect",
            "outcome:connect",
            "attempt:request",
            "outcome:request",
        ]
    );
    assert!(matches!(
        &events[4],
        Event::Outcome(EffectKind::HttpRequest, EffectOutcome::Completed(bytes)) if *bytes > 0
    ));
}

/// An upstream that drips its reply one byte at a time, each under the per-read wait: the
/// deadline bounds the exchange as a whole, so the request outcome records with no status.
#[test]
fn an_upstream_that_drips_its_reply_is_bounded_by_the_read_deadline() {
    let host = "drip.test";
    let upstream = TlsUpstream::start_dripping(
        host,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        Duration::from_millis(200),
    );
    let port = upstream.port();
    let shared = Arc::new(Mutex::new(Vec::new()));
    let config = MitmConfig {
        upstream_read_deadline: Duration::from_millis(700),
        ..config_for(host, &upstream)
    };
    let handle = MitmInterceptor::start(
        config,
        no_injection(),
        Arc::new(RecordingInterceptor::allowing(shared.clone())),
    )
    .unwrap();

    let started = Instant::now();
    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request("GET", "/drip", &[], b"");
    assert_eq!(
        client.read_response(),
        "",
        "a dripped reply is not released"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the deadline bounds the exchange as a whole: {:?}",
        started.elapsed()
    );

    let events = wait_for_event_count(&shared, 5);
    assert!(
        matches!(
            &events[4],
            Event::Outcome(EffectKind::HttpRequest, EffectOutcome::Completed(bytes)) if *bytes > 0
        ),
        "{:?}",
        events[4]
    );
}

/// An upstream that never drains the request: the write deadline ends the exchange, the request
/// outcome records the bytes the socket accepted with no status, and no release follows.
#[test]
fn an_upstream_that_never_drains_the_request_is_bounded_by_the_write_deadline() {
    let host = "deaf.test";
    let upstream = TlsUpstream::start_deaf(host);
    let port = upstream.port();
    let shared = Arc::new(Mutex::new(Vec::new()));
    let config = MitmConfig {
        upstream_read_deadline: Duration::from_millis(500),
        ..config_for(host, &upstream)
    };
    let handle = MitmInterceptor::start(
        config,
        no_injection(),
        Arc::new(RecordingInterceptor::allowing(shared.clone())),
    )
    .unwrap();

    let started = Instant::now();
    let body = vec![b'x'; 12 << 20];
    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request("POST", "/deaf", &[], &body);
    assert_eq!(
        client.read_response(),
        "",
        "an undelivered request gets no reply"
    );
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the deadline bounds the write: {:?}",
        started.elapsed()
    );

    let events = wait_for_event_count(&shared, 5);
    assert!(
        matches!(
            &events[4],
            Event::Outcome(
                EffectKind::HttpRequest,
                EffectOutcome::Partial { .. } | EffectOutcome::Indeterminate { .. }
            )
        ),
        "{:?}",
        events[4]
    );
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(
        shared.lock().unwrap().len(),
        5,
        "no release follows an undelivered request"
    );
}

/// An upstream that accepts the request 64 KiB at a time, so every write progresses under the
/// per-write wait while the whole request outlasts the deadline: the exchange-wide check ends it,
/// and the request outcome records the partial delivery with no status.
#[test]
fn an_upstream_that_sips_the_request_is_bounded_by_the_write_deadline() {
    let host = "sip.test";
    let upstream = TlsUpstream::start_sipping(host, Duration::from_millis(10));
    let port = upstream.port();
    let shared = Arc::new(Mutex::new(Vec::new()));
    let config = MitmConfig {
        upstream_read_deadline: Duration::from_millis(700),
        ..config_for(host, &upstream)
    };
    let handle = MitmInterceptor::start(
        config,
        no_injection(),
        Arc::new(RecordingInterceptor::allowing(shared.clone())),
    )
    .unwrap();

    let started = Instant::now();
    let body = vec![b'x'; 12 << 20];
    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request("POST", "/sip", &[], &body);
    assert_eq!(
        client.read_response(),
        "",
        "an undelivered request gets no reply"
    );
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the deadline bounds the writes as a whole: {:?}",
        started.elapsed()
    );

    let events = wait_for_event_count(&shared, 5);
    assert!(
        matches!(
            &events[4],
            Event::Outcome(
                EffectKind::HttpRequest,
                EffectOutcome::Partial { .. } | EffectOutcome::Indeterminate { .. }
            )
        ),
        "{:?}",
        events[4]
    );
}

/// The plain-HTTP twin of the sipping case. No TLS layer reads during a write here, so only the
/// exchange-wide write check ends the exchange.
#[test]
fn an_upstream_that_sips_a_plain_request_is_bounded_by_the_write_deadline() {
    use std::io::{Read as _, Write as _};

    let host = "plain-sip.test";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut tcp) = incoming else { continue };
            std::thread::spawn(move || {
                let mut chunk = [0u8; 65536];
                loop {
                    let mut got = 0;
                    while got < chunk.len() {
                        match tcp.read(&mut chunk[got..]) {
                            Ok(n) if n > 0 => got += n,
                            _ => return,
                        }
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
        }
    });
    let shared = Arc::new(Mutex::new(Vec::new()));
    // Larger than any loopback buffer autotuning, so the write is still in progress at the deadline.
    let config = MitmConfig {
        upstream_read_deadline: Duration::from_millis(700),
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        response_limits: egress_gateway::ResponseLimits {
            max_body_bytes: 64 << 20,
        },
        ..MitmConfig::default()
    };
    let handle = MitmInterceptor::start(
        config,
        no_injection(),
        Arc::new(RecordingInterceptor::allowing(shared.clone())),
    )
    .unwrap();

    let started = Instant::now();
    let body = vec![b'x'; 48 << 20];
    let mut proxy =
        std::net::TcpStream::connect(("127.0.0.1", proxy_port(&handle))).expect("the proxy");
    proxy
        .write_all(
            format!(
                "POST http://{host}:{port}/sip HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .unwrap();
    proxy.write_all(&body).unwrap();
    let mut reply = Vec::new();
    let _ = proxy.read_to_end(&mut reply);
    assert!(reply.is_empty(), "an undelivered request gets no reply");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the deadline bounds the writes as a whole: {:?}",
        started.elapsed()
    );

    let events = wait_for_event_count(&shared, 5);
    assert!(
        matches!(
            &events[4],
            Event::Outcome(
                EffectKind::HttpRequest,
                EffectOutcome::Partial { .. } | EffectOutcome::Indeterminate { .. }
            )
        ),
        "{:?}",
        events[4]
    );
}

#[test]
fn connect_outcome_sink_failure_returns_502_after_opening_once() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let host = "connect-outcome-failure.test";
    let events = Arc::new(Mutex::new(Vec::new()));
    let config = MitmConfig {
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        ..MitmConfig::default()
    };
    let handle = MitmInterceptor::start(
        config,
        no_injection(),
        Arc::new(RecordingInterceptor::failing_recording(
            events.clone(),
            EffectKind::Connect,
        )),
    )
    .unwrap();

    let mut client = WorkloadClient::connect_raw(proxy_port(&handle));
    let reply = client.raw_connect(host, port);

    assert!(reply.contains("502"));
    assert!(!reply.contains("200 Connection Established"));
    let (_opened, _) = listener
        .accept()
        .expect("the socket effect occurred before its outcome sink failed");
    let events = events.lock().unwrap().clone();
    assert_eq!(
        event_names(&events),
        vec!["attempt:resolve", "attempt:connect", "outcome:connect"]
    );
    assert!(matches!(
        &events[2],
        Event::Outcome(EffectKind::Connect, EffectOutcome::Connected(peer))
            if peer.port() == port
    ));
}

/// Forwards to a shared [`StubEmitter`] so a test can read the records after the handle takes the
/// `Box<dyn Emitter>`.
struct SharedEmitter(Arc<StubEmitter>);

impl Emitter for SharedEmitter {
    fn emit(&self, decision: EgressDecision) {
        self.0.emit(decision);
    }
}

/// The effect attempts read the path the WORKLOAD sent, not the mutated one.
///
/// The wiring test the hand-built `attempt_schema_never_carries_body_or_header_content` below cannot
/// be: it constructs an attempt directly, so it proves the *schema* carries no secret and says nothing
/// about what the interceptor puts in it. This drives a real `url_path` credential through the real
/// capability, which is the only placement whose secret lands in `req.target.path` — and therefore the
/// only one that could put credential material into an authorization input.
///
/// `EffectAttempt`'s own doc promises attempts "contain no headers, credential material, or body
/// content", and `EgressDecision`'s promises it is secret-free. Both were false on this one placement
/// while true on every other, which is why the fix is a captured pre-mutation path rather than a
/// comment.
#[test]
fn attempts_carry_the_pre_mutation_path_for_a_path_spliced_credential() {
    const SECRET: &str = "sk_live_path_spliced_secret";
    let host = "pathsplice.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();
    let events = Arc::new(Mutex::new(Vec::new()));

    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant").route(
        RouteSpec::opaque(
            destination(host, port),
            env_locator(SECRET),
            InjectMode::url_path("/v1/{}/models").expect("a valid url-path placement"),
        ),
    ))
    .unwrap();
    let phantom = opened.phantoms()[0].token().to_string();
    let controls = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(
            destination(host, port),
            Arc::new(opened.into_vault()),
        ))
        .build();
    // A real emitter, so the durable record is observable — `start` installs a private stub whose
    // contents nothing can read, which is why sink 3 had no coverage.
    let emitter = Arc::new(StubEmitter::new());
    let handle = MitmInterceptor::start_with_emitter(
        config_for(host, &upstream),
        controls,
        Arc::new(RecordingInterceptor::allowing(events.clone())),
        Box::new(SharedEmitter(emitter.clone())),
    )
    .unwrap();

    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    // The workload presents the phantom spliced into the path, exactly where the secret will go.
    let workload_path = format!("/v1/{phantom}/models");
    client.send_request("GET", &workload_path, &[], b"");
    assert_eq!(client.read_status(), 200);

    // The secret DID reach the wire — the placement works.
    let seen = upstream.last_request().raw.clone();
    assert!(
        seen.contains(SECRET),
        "the upstream sees the real secret spliced into the path: {seen}"
    );

    // ...and did NOT reach any attempt the interceptor was shown.
    let captured = events.lock().unwrap().clone();
    assert!(
        !captured.is_empty(),
        "the interceptor saw at least one attempt"
    );
    let rendered = format!("{captured:?}");
    assert!(
        !rendered.contains(SECRET),
        "no attempt may carry the credential: {rendered}"
    );
    assert!(
        rendered.contains(&workload_path),
        "the attempts carry the path the workload sent: {rendered}"
    );

    // The emitter reports the two outbound enforcement points and no response-control result.
    let records = emitter.records();
    assert_eq!(records.len(), 2, "one connect and one request: {records:?}");
    assert!(
        records
            .iter()
            .any(|record| { record.method.is_empty() && record.decision == AuditDecision::Allow }),
        "the connection permit is emitted before the socket opens: {records:?}"
    );
    assert!(
        records.iter().any(|record| {
            record.method == "GET"
                && record.path == workload_path
                && record.decision == AuditDecision::Allow
        }),
        "the outbound request permit carries the workload path: {records:?}"
    );
    let rendered = format!("{records:?}");
    assert!(
        !rendered.contains(SECRET),
        "EgressDecision documents itself as secret-free: {rendered}"
    );
    assert!(
        rendered.contains(&workload_path),
        "the record carries the path the workload sent: {rendered}"
    );
}

#[test]
fn attempt_schema_never_carries_body_or_header_content() {
    let attempt = EffectAttempt::HttpRequest {
        host: "api.example",
        port: 443,
        method: "POST",
        path: "/v1",
        body_bytes: 42,
        intercepted: true,
        mcp: None,
    };

    let rendered = format!("{attempt:?}").to_ascii_lowercase();
    assert!(!rendered.contains("authorization"));
    assert!(!rendered.contains("secret"));
    assert!(!rendered.contains("body content"));

    // A frame's identity (`tool`) and its args are workload-controlled `params.*`, so a hostile
    // frame could put a forged header or a secret in either. The frame's Debug redacts both, so an
    // attempt carrying an `McpFrame` stays secret-free even for an adversarial tool and args.
    for tool in ["authorization: Bearer supersecret", "the-secret-value"] {
        let attempt = EffectAttempt::HttpRequest {
            host: "api.example",
            port: 443,
            method: "POST",
            path: "/mcp",
            body_bytes: 64,
            intercepted: false,
            mcp: Some(McpFrame::ToolCall {
                server: "prod",
                tool,
                arguments: r#"{"password":"the-secret-value"}"#,
            }),
        };
        let rendered = format!("{attempt:?}").to_ascii_lowercase();
        assert!(
            !rendered.contains("authorization"),
            "an adversarial tool must not reach the attempt's Debug: {rendered}"
        );
        assert!(
            !rendered.contains("secret"),
            "an adversarial tool or arg must not reach the attempt's Debug: {rendered}"
        );
        // The config-assigned server name and the protocol method are safe to show.
        assert!(
            rendered.contains("prod"),
            "the config-assigned server name is host-derived and stays visible: {rendered}"
        );
        assert!(
            rendered.contains("tools/call"),
            "the protocol method is a bounded verb and stays visible: {rendered}"
        );
    }
}
