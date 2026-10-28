//! The gateway pairs each decided effect attempt with the record of its decision.

#![cfg(feature = "tls-intercept")]

mod harness;

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;

use credentials::{
    Backend, DestinationPattern, InjectMode, Locator, RouteSpec, Vault, VaultConfig,
};
use egress_gateway::{
    AuditDecision, CapabilitySet, CredentialCapability, EffectAttempt, EffectInterceptor,
    EffectOutcome, EffectPermit, EgressDecision, Emitter, MitmConfig, MitmInterceptor,
};

use harness::{TlsUpstream, WorkloadClient};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Resolve,
    Connect,
    HttpRequest,
    ResponseRelease,
}

/// One call that the gateway made into the effect seam or the emitter seam, or the first byte of an
/// upstream connection.
#[derive(Debug, Clone)]
enum SeamCall {
    Intercept {
        kind: Kind,
        host: String,
        port: u16,
        method: String,
        path: String,
        permitted: bool,
        thread: ThreadId,
    },
    Emit {
        host: String,
        port: u16,
        method: String,
        path: String,
        decision: AuditDecision,
        thread: ThreadId,
    },
    UpstreamRead,
}

/// The reply of an upstream that accepts each request.
const OK_REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

/// The reply of an upstream that a credential route must block.
const ENCODED_REPLY: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

/// An authority that logs each attempt in the shared seam log, and refuses the `deny` kind.
struct LoggingInterceptor {
    calls: Arc<Mutex<Vec<SeamCall>>>,
    deny: Option<Kind>,
}

impl EffectInterceptor for LoggingInterceptor {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        let (kind, host, port, method, path) = match attempt {
            EffectAttempt::Resolve { host, port } => (Kind::Resolve, *host, *port, "", ""),
            EffectAttempt::Connect { host, port, .. } => (Kind::Connect, *host, *port, "", ""),
            EffectAttempt::HttpRequest {
                host,
                port,
                method,
                path,
                ..
            } => (Kind::HttpRequest, *host, *port, *method, *path),
            EffectAttempt::ResponseRelease {
                host,
                port,
                method,
                path,
                ..
            } => (Kind::ResponseRelease, *host, *port, *method, *path),
            _ => panic!("unexpected future effect attempt"),
        };
        let permitted = self.deny != Some(kind);
        self.calls.lock().unwrap().push(SeamCall::Intercept {
            kind,
            host: host.to_string(),
            port,
            method: method.to_string(),
            path: path.to_string(),
            permitted,
            thread: std::thread::current().id(),
        });
        if !permitted {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "denied by test interceptor",
            ));
        }
        Ok(Box::new(DiscardPermit))
    }
}

struct DiscardPermit;

impl EffectPermit for DiscardPermit {
    fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> io::Result<()> {
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

/// An emitter that logs each decision in the shared seam log.
struct LoggingEmitter(Arc<Mutex<Vec<SeamCall>>>);

impl Emitter for LoggingEmitter {
    fn emit(&self, decision: EgressDecision) {
        self.0.lock().unwrap().push(SeamCall::Emit {
            host: decision.host,
            port: decision.port,
            method: decision.method,
            path: decision.path,
            decision: decision.decision,
            thread: std::thread::current().id(),
        });
    }
}

/// A TLS upstream for `host` that returns `response`, and logs in `calls` when a connection sends its
/// first byte.
fn observed_upstream(
    host: &str,
    response: &'static [u8],
    calls: &Arc<Mutex<Vec<SeamCall>>>,
) -> TlsUpstream {
    let calls = calls.clone();
    TlsUpstream::start_observed(
        host,
        response,
        Arc::new(move || calls.lock().unwrap().push(SeamCall::UpstreamRead)),
    )
}

/// Place `secret` in a uniquely-named environment variable and return its `env://` locator.
fn env_locator(secret: &str) -> Locator {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let name = format!(
        "DECISION_PAIRING_SECRET_{}",
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    // SAFETY: the name is unique to this call, so no other test reads or writes it.
    unsafe { std::env::set_var(&name, secret) };
    Locator::parse_uri(&format!("env://{name}")).unwrap()
}

/// One credential route on `host:port`, and the phantom that the workload sends for it.
fn credential(host: &str, port: u16) -> (CapabilitySet, String) {
    let destination = DestinationPattern::parse(&format!("{host}:{port}")).unwrap();
    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant").route(
        RouteSpec::opaque(
            destination.clone(),
            env_locator("sk_live_pairing_secret"),
            InjectMode::header("Bearer {}".to_string(), None).expect("a valid header placement"),
        ),
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

/// Start a gateway in front of `upstream` that logs both seams in `calls`.
fn start(
    host: &str,
    upstream: &TlsUpstream,
    controls: CapabilitySet,
    deny: Option<Kind>,
    mcp: bool,
    calls: &Arc<Mutex<Vec<SeamCall>>>,
) -> egress_gateway::MitmHandle {
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem()],
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        mcp_servers: if mcp {
            vec![(host.to_string(), "demo".to_string())]
        } else {
            Vec::new()
        },
        ..MitmConfig::default()
    };
    MitmInterceptor::start_with_emitter(
        config,
        controls,
        Arc::new(LoggingInterceptor {
            calls: calls.clone(),
            deny,
        }),
        Box::new(LoggingEmitter(calls.clone())),
    )
    .unwrap()
}

/// Check that each decided attempt is followed at once by its decision, and count the pairs.
///
/// A decided attempt is a `Connect`, an `HttpRequest`, or a denied `Resolve`. Its decision is the
/// next entry in the log: an emit with the same identity and verdict, on the same thread, before an
/// upstream byte arrives.
fn decided_pairs(calls: &[SeamCall]) -> usize {
    let mut pairs = 0;
    for (index, call) in calls.iter().enumerate() {
        let SeamCall::Intercept {
            kind,
            host,
            port,
            method,
            path,
            permitted,
            thread,
        } = call
        else {
            continue;
        };
        let (method, path) = match kind {
            Kind::Connect => ("", "/"),
            Kind::Resolve if !permitted => ("", "/"),
            Kind::HttpRequest => (method.as_str(), path.as_str()),
            Kind::Resolve | Kind::ResponseRelease => continue,
        };
        let verdict = if *permitted {
            AuditDecision::Allow
        } else {
            AuditDecision::Deny
        };
        match calls.get(index + 1) {
            Some(SeamCall::Emit {
                host: emitted_host,
                port: emitted_port,
                method: emitted_method,
                path: emitted_path,
                decision,
                thread: emitted_thread,
            }) => assert!(
                emitted_host == host
                    && emitted_port == port
                    && emitted_method == method
                    && emitted_path == path
                    && *decision == verdict
                    && emitted_thread == thread,
                "the decision after {call:?} names another attempt: {calls:#?}"
            ),
            next => {
                panic!("the seam call after {call:?} is {next:?}, not its decision: {calls:#?}")
            }
        }
        pairs += 1;
    }
    pairs
}

/// **The next seam call after each decided attempt is its own decision, on the same thread, before
/// an upstream byte arrives.** Telemetry carries the policy verdict from `intercept` to `emit` in a
/// thread-local, so a seam call or socket I/O between the two can give one exchange the rule of
/// another, and a thread hop loses the rule.
#[test]
fn every_decided_attempt_is_followed_at_once_by_its_decision() {
    // A delivered exchange: the connection and the request each pair with their permit, and the
    // request reaches the upstream only after its permit is recorded.
    let host = "delivered.pairing.test";
    let calls = Arc::new(Mutex::new(Vec::new()));
    let upstream = observed_upstream(host, OK_REPLY, &calls);
    let handle = start(
        host,
        &upstream,
        CapabilitySet::default(),
        None,
        false,
        &calls,
    );
    let mut client = WorkloadClient::connect(handle.port().unwrap(), host, upstream.port());
    client.send_request("GET", "/delivered", &[], b"");
    assert_eq!(client.read_status(), 200);
    assert_eq!(decided_pairs(&calls.lock().unwrap()), 2);
    assert!(
        calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| matches!(call, SeamCall::UpstreamRead)),
        "the upstream got no request"
    );

    // A denied host and a denied address each pair with their denial before the 403.
    for (host, deny) in [
        ("resolve-denied.pairing.test", Kind::Resolve),
        ("connect-denied.pairing.test", Kind::Connect),
    ] {
        let upstream = TlsUpstream::start(host);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let handle = start(
            host,
            &upstream,
            CapabilitySet::default(),
            Some(deny),
            false,
            &calls,
        );
        let mut client = WorkloadClient::connect_raw(handle.port().unwrap());
        assert!(client.raw_connect(host, upstream.port()).contains("403"));
        assert_eq!(decided_pairs(&calls.lock().unwrap()), 1, "{deny:?}");
    }

    // A denied request pairs with its denial before the 403.
    let host = "request-denied.pairing.test";
    let upstream = TlsUpstream::start(host);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let handle = start(
        host,
        &upstream,
        CapabilitySet::default(),
        Some(Kind::HttpRequest),
        false,
        &calls,
    );
    let mut client = WorkloadClient::connect(handle.port().unwrap(), host, upstream.port());
    client.send_request("GET", "/denied", &[], b"");
    assert_eq!(client.read_status(), 403);
    assert_eq!(decided_pairs(&calls.lock().unwrap()), 2);

    // A response that the credential fold blocks: the request keeps its pair.
    let host = "response-blocked.pairing.test";
    let calls = Arc::new(Mutex::new(Vec::new()));
    let upstream = observed_upstream(host, ENCODED_REPLY, &calls);
    let (controls, phantom) = credential(host, upstream.port());
    let handle = start(host, &upstream, controls, None, false, &calls);
    let mut client = WorkloadClient::connect(handle.port().unwrap(), host, upstream.port());
    client.send_request(
        "GET",
        "/encoded",
        &[("Authorization", &format!("Bearer {phantom}"))],
        b"",
    );
    assert_eq!(client.read_status(), 403);
    assert_eq!(decided_pairs(&calls.lock().unwrap()), 2);

    // A refused MCP frame: no request is decided, and the connection keeps its pair.
    let host = "mcp.pairing.test";
    let upstream = TlsUpstream::start(host);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let handle = start(
        host,
        &upstream,
        CapabilitySet::default(),
        None,
        true,
        &calls,
    );
    let mut client = WorkloadClient::connect(handle.port().unwrap(), host, upstream.port());
    client.send_request("POST", "/mcp", &[], b"not json");
    assert_eq!(client.read_status(), 403);
    let calls = calls.lock().unwrap();
    assert_eq!(decided_pairs(&calls), 1);
    assert!(
        matches!(
            calls.last(),
            Some(SeamCall::Emit {
                decision: AuditDecision::Deny,
                ..
            })
        ),
        "the refused frame is recorded: {calls:#?}"
    );
}

/// **A reply that the gateway refuses after the request permit adds no decision.** The response fold
/// blocks an encoded reply, or the authority refuses the release of a plain one. The workload gets a
/// 403, the audit log gets one denial, and the request permit stays the last decision.
#[test]
fn a_reply_refused_after_the_request_permit_adds_no_decision() {
    for (host, reply, deny) in [
        ("response-blocked.refusal.test", ENCODED_REPLY, None),
        (
            "release-refused.refusal.test",
            OK_REPLY,
            Some(Kind::ResponseRelease),
        ),
    ] {
        let upstream = TlsUpstream::start_with_response(host, reply);
        let (controls, phantom) = credential(host, upstream.port());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let handle = start(host, &upstream, controls, deny, false, &calls);
        let mut client = WorkloadClient::connect(handle.port().unwrap(), host, upstream.port());
        client.send_request(
            "GET",
            "/refused",
            &[("Authorization", &format!("Bearer {phantom}"))],
            b"",
        );
        assert_eq!(client.read_status(), 403, "{host}");

        let calls = calls.lock().unwrap();
        let decisions: Vec<(&str, &str, AuditDecision)> = calls
            .iter()
            .filter_map(|call| match call {
                SeamCall::Emit {
                    method,
                    path,
                    decision,
                    ..
                } => Some((method.as_str(), path.as_str(), *decision)),
                _ => None,
            })
            .collect();
        assert_eq!(
            decisions,
            [
                ("", "/", AuditDecision::Allow),
                ("GET", "/refused", AuditDecision::Allow),
            ],
            "{host}: {calls:#?}"
        );
        let audit = handle.drain_audit_events();
        assert!(
            matches!(audit.as_slice(), [event] if event.decision == AuditDecision::Deny),
            "{host}: {audit:?}"
        );
    }
}
