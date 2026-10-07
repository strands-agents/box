//! Full end-to-end interception over real TLS (the goal test).
//!
//! Each scenario:
//! 1. **creates credentials** — a real `credentials::Vault` with an opaque phantom→real
//!    route and/or an AWS SigV4 route;
//! 2. **spins up the egress gateway** — a real `MitmInterceptor` bound to a localhost port, driving a
//!    `CapabilitySet` set and (where authorization matters) a `FixedPolicy` stand-in for the Cedar
//!    PDP wired through the `EffectInterceptor` seam, configured to trust a local TLS upstream's CA (the
//!    additive trust bundle);
//! 3. **sends a network request** — a real TLS workload client `CONNECT`s through the proxy, completes
//!    the TLS handshake against the proxy's ephemeral leaf, and sends an HTTPS request;
//! 4. **has it get intercepted** — TLS is terminated, the phantom is swapped for the real secret (or
//!    the request is SigV4-signed / policy-denied), and the (possibly rewritten)
//!    request reaches the upstream, which records exactly what it saw on the wire.
//!
//! **Who decides what.** Authorization is the PDP's alone, reached through `EffectInterceptor`; the
//! `FixedPolicy` below is the test's stand-in for it. `CapabilitySet` only mutates and may deny on a
//! credential **integrity** failure (phantom mismatch / missing phantom).
//!
//! Positive scenarios prove the swap/sign actually reach the upstream with the real secret and the
//! phantom gone; negative scenarios prove the fail-closed doors (policy deny, missing/mismatched
//! phantom deny) block before the upstream ever sees the request. The
//! real secret is asserted **absent** from the audit log throughout.
//!
//! Requires the default-on `tls-intercept` feature.

#![cfg(feature = "tls-intercept")]

mod harness;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use credentials::{
    Backend, DestinationPattern, InjectMode, Locator, PhantomCheck, RouteSpec, Vault, VaultConfig,
};
use egress_gateway::{
    AuditDecision, CapabilitySet, CredentialCapability, EffectAttempt, EffectInterceptor,
    EffectOutcome, EffectPermit, MitmConfig, MitmInterceptor, StubEmitter,
};

use harness::{TlsUpstream, WorkloadClient};

// ============================================================================================
// The PDP stand-in: authorization arrives ONLY through the EffectInterceptor seam
// ============================================================================================

/// A test stand-in for the Cedar PDP, reached through the one seam this crate uses for authorization.
///
/// `allowed_hosts` is the whole policy: a `Connect` attempt to a listed host is permitted, anything else
/// is `PermissionDenied` — which the adapter turns into a 403 without opening a socket. Request/response
/// effects are permitted, since these scenarios exercise host-level authorization. This mirrors how the
/// real `policy` crate plugs in (that crate depends on this one, never the reverse).
struct FixedPolicy {
    allowed_hosts: Vec<String>,
}

impl FixedPolicy {
    fn allowing(hosts: &[&str]) -> Arc<Self> {
        Arc::new(Self {
            allowed_hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
        })
    }

    /// Permit nothing, so an unauthorized host is refused.
    fn denying_all() -> Arc<Self> {
        Arc::new(Self {
            allowed_hosts: Vec::new(),
        })
    }
}

impl EffectInterceptor for FixedPolicy {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        if let EffectAttempt::Resolve { host, .. } | EffectAttempt::Connect { host, .. } = attempt
            && !self
                .allowed_hosts
                .iter()
                .any(|h| h.eq_ignore_ascii_case(host))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "denied by test policy",
            ));
        }
        Ok(Box::new(NoopPermit))
    }
}

struct NoopPermit;

impl EffectPermit for NoopPermit {
    fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> io::Result<()> {
        Ok(())
    }
    fn mark_indeterminate(self: Box<Self>) {}
}

// ============================================================================================
// Credential-store construction ("create credentials")
// ============================================================================================

/// Place `secret` in a uniquely-named environment variable and return its `env://` locator.
///
/// The vault's source set is sealed, so a test cannot inject a stub source
/// from outside the crate — it declares a real `env://` route instead, which is also what an operator
/// writes. The variable name is unique per call so concurrently-running tests cannot collide.
fn env_locator(secret: &str) -> Locator {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let name = format!(
        "EGRESS_PROXY_TEST_SECRET_{}",
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    // SAFETY: the name is unique to this call, so no other test reads or writes it. The variable
    // outlives the test deliberately — the vault resolves it once at open.
    unsafe { std::env::set_var(&name, secret) };
    Locator::parse_uri(&format!("env://{name}")).unwrap()
}

/// Build a store with one opaque header route for `host:port`; returns the store + the minted phantom.
fn opaque_store(host: &str, port: u16, secret: &'static str) -> (Arc<Vault>, String) {
    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant").route(
        RouteSpec::opaque(
            pat(host, port),
            env_locator(secret),
            InjectMode::header("Bearer {}".to_string(), None).expect("a valid header placement"),
        ),
    ))
    .unwrap();
    let phantom = opened.phantoms()[0].token().to_string();
    (Arc::new(opened.into_vault()), phantom)
}

/// An opaque store like [`opaque_store`], but with the route in `advisory` placeholder-check mode.
fn advisory_store(host: &str, port: u16, secret: &'static str) -> Arc<Vault> {
    let opened = Vault::open(
        VaultConfig::new(Backend::local(), "tenant").route(
            RouteSpec::opaque(
                pat(host, port),
                env_locator(secret),
                InjectMode::header("Bearer {}".to_string(), None)
                    .expect("a valid header placement"),
            )
            .phantom_check(PhantomCheck::Advisory),
        ),
    )
    .unwrap();
    Arc::new(opened.into_vault())
}

/// A `host:port` destination pattern (the test upstream is on an ephemeral port, so patterns must
/// carry the exact port — the matcher's default web-port inference only covers 443/80).
fn pat(host: &str, port: u16) -> DestinationPattern {
    DestinationPattern::parse(&format!("{host}:{port}")).unwrap()
}

/// The proxy's TCP port. Every scenario in this file drives the default TCP transport, so
/// `port()` (now `Option<u16>` after the AF_UNIX-pin migration) is always `Some` here; a `None`
/// would mean a test wired up the AF_UNIX pin by mistake, so unwrap with a pointed message.
fn proxy_port(handle: &egress_gateway::MitmHandle) -> u16 {
    handle.port().expect("TCP-mode test always has a port")
}

/// Start the gateway trusting `upstream`'s CA, pinning `host` to loopback so the workload can address
/// the upstream by name, with the given credential mutators and PDP. Returns the handle.
fn start_gateway(
    host: &str,
    upstream: &TlsUpstream,
    controls: CapabilitySet,
    policy: Arc<FixedPolicy>,
) -> egress_gateway::MitmHandle {
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem()],
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        ..MitmConfig::default()
    };
    MitmInterceptor::start(config, controls, policy).unwrap()
}

// ============================================================================================
// POSITIVE: opaque phantom→real swap reaches the upstream over TLS
// ============================================================================================

#[test]
fn opaque_swap_reaches_upstream_with_real_secret() {
    // (2) upstream first (its ephemeral port scopes the route patterns)
    let host = "api.stripe.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();

    // (1) credentials — an opaque phantom→real route for host:port
    let (store, phantom) = opaque_store(host, port, "sk_live_REALSECRET");

    // gateway: the PDP authorizes the host; the credential control performs the swap.
    let controls = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(pat(host, port), store))
        .build();
    let handle = start_gateway(host, &upstream, controls, FixedPolicy::allowing(&[host]));

    // (3) workload sends an HTTPS request carrying the PHANTOM token through the proxy
    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request(
        "GET",
        "/v1/charges",
        &[("Authorization", &format!("Bearer {phantom}"))],
        b"",
    );
    let status = client.read_status();

    // (4) interception: the upstream received the REAL secret, never the phantom
    let seen = upstream.last_request();
    assert_eq!(status, 200, "the swapped request succeeded end-to-end");
    assert_eq!(
        seen.header("authorization").as_deref(),
        Some("Bearer sk_live_REALSECRET"),
        "the upstream saw the real secret, injected at the boundary"
    );
    assert!(
        !seen.raw.contains(&phantom),
        "the phantom token must not survive to the upstream"
    );

    // The real secret must not appear anywhere in the audit log.
    for ev in handle.drain_audit_events() {
        assert!(!format!("{ev:?}").contains("sk_live_REALSECRET"));
    }
}

// ============================================================================================
// POSITIVE: chunked request and response bodies cross the real TLS interception path
// ============================================================================================

#[test]
fn chunked_http1_is_normalized_across_tls_interception() {
    let host = "stream.test";
    let upstream = TlsUpstream::start_chunked(host);
    let port = upstream.port();
    // An empty mutator set: nothing to inject. The PDP authorizes; installing an effect interceptor
    // forces HTTP visibility, so the L7 legs still run.
    let handle = start_gateway(
        host,
        &upstream,
        CapabilitySet::default(),
        FixedPolicy::allowing(&[host]),
    );

    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_chunked_request("POST", "/responses", b"chunked-request");
    let response = client.read_response();

    assert_eq!(
        response,
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 16\r\n\r\nmantle-stream-ok"
    );
    let seen = upstream.last_request();
    assert!(seen.raw.ends_with("chunked-request"));
    assert_eq!(seen.header("content-length").as_deref(), Some("15"));
    assert_eq!(seen.header("connection").as_deref(), Some("close"));
    for removed in ["transfer-encoding", "x-client-hop", "trailer"] {
        assert_eq!(
            seen.header(removed),
            None,
            "{removed} must not cross the client-to-upstream hop"
        );
    }
}

// ============================================================================================
// NEGATIVE: the inner HTTP authority cannot pivot away from the CONNECT-bound destination
// ============================================================================================

#[test]
fn mismatched_host_is_rejected_before_upstream_request_bytes() {
    let host = "bound-authority.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();
    let handle = start_gateway(
        host,
        &upstream,
        CapabilitySet::default(),
        FixedPolicy::allowing(&[host]),
    );

    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request_with_authority("GET", "/v1", "metadata.google.internal", &[], b"");

    assert_eq!(client.read_status(), 403);
    assert_eq!(
        upstream.request_count(),
        0,
        "a mismatched Host must not reach the CONNECT-bound upstream"
    );
}

#[test]
fn absolute_form_metadata_target_is_rejected_before_upstream_request_bytes() {
    let host = "bound-target.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();
    let handle = start_gateway(
        host,
        &upstream,
        CapabilitySet::default(),
        FixedPolicy::allowing(&[host]),
    );

    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request("GET", "http://169.254.169.254/latest/meta-data", &[], b"");

    assert_eq!(client.read_status(), 403);
    assert_eq!(
        upstream.request_count(),
        0,
        "an absolute-form metadata target must not reach an allowlisted upstream"
    );
}

// ============================================================================================
// POSITIVE: AWS SigV4 strip-then-sign reaches the upstream, host-derived scope
// ============================================================================================

#[test]
fn aws_sigv4_signs_and_reaches_upstream() {
    // AWS creds live in the ambient env for the v1 provider (serialized via the harness guard).
    let _env = harness::AwsEnvGuard::set(
        "AKIDEXAMPLE",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        None,
    );

    // (2) The upstream presents a cert for the amazonaws host; its ephemeral port scopes the route.
    let host = "execute-api.us-east-1.amazonaws.com";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();

    // (1) credentials — an AWS typed route (no phantom minted for AWS, R-7).
    let aws_auth = Locator::structured(
        [("source".to_string(), "aws".to_string())]
            .into_iter()
            .collect(),
    )
    .unwrap();
    let spec = RouteSpec::signed_aws(pat(host, port), aws_auth);
    // A signed route resolves nothing at open — its credentials are fetched per request, because
    // session credentials expire. So this opens cleanly with no secret anywhere in reach.
    let store = Arc::new(
        Vault::open(VaultConfig::new(Backend::local(), "t").route(spec))
            .unwrap()
            .into_vault(),
    );

    let controls = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(pat(host, port), store))
        .build();
    let handle = start_gateway(host, &upstream, controls, FixedPolicy::allowing(&[host]));

    // (3) workload sends an HTTPS request with a DUMMY inbound signature (as an SDK would).
    let mut client = WorkloadClient::connect_to_ip(proxy_port(&handle), host, port);
    client.send_request(
        "POST",
        "/prod/orders",
        &[
            (
                "Authorization",
                "AWS4-HMAC-SHA256 Credential=DUMMY/x, SignedHeaders=host, Signature=dead",
            ),
            ("X-Amz-Date", "19700101T000000Z"),
        ],
        b"{}",
    );
    let status = client.read_status();

    // (4) interception: the upstream saw a FRESH SigV4 signature with the host-derived scope, and the
    // dummy inbound artifacts were stripped and replaced.
    let seen = upstream.last_request();
    assert_eq!(status, 200);
    let authz = seen
        .header("authorization")
        .expect("re-signed Authorization");
    assert!(
        authz.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"),
        "re-signed with the vault creds: {authz}"
    );
    assert!(
        authz.contains("/us-east-1/execute-api/aws4_request"),
        "service/region derived from the host: {authz}"
    );
    assert!(
        !authz.contains("Signature=dead"),
        "the dummy inbound signature must not survive"
    );
    // The secret key never reaches the wire.
    assert!(
        !seen.raw.contains("wJalrXUtnFEMI"),
        "secret key leaked to upstream"
    );
}

/// The signature covers the `accept-encoding` the upstream receives, not the one the workload sent.
#[test]
fn aws_sigv4_signs_the_accept_encoding_that_reaches_upstream() {
    let _env = harness::AwsEnvGuard::set(
        "AKIDEXAMPLE",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        None,
    );
    let host = "bedrock-runtime.us-west-2.amazonaws.com";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();
    let aws_auth = Locator::structured(
        [("source".to_string(), "aws".to_string())]
            .into_iter()
            .collect(),
    )
    .unwrap();
    let store = Arc::new(
        Vault::open(
            VaultConfig::new(Backend::local(), "t")
                .route(RouteSpec::signed_aws(pat(host, port), aws_auth)),
        )
        .unwrap()
        .into_vault(),
    );
    let controls = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(pat(host, port), store))
        .build();
    let handle = start_gateway(host, &upstream, controls, FixedPolicy::allowing(&[host]));

    let signed_as = |headers: &[(&str, &str)]| {
        let mut client = WorkloadClient::connect_to_ip(proxy_port(&handle), host, port);
        client.send_request("POST", "/model/m/invoke", headers, b"{}");
        assert_eq!(client.read_status(), 200);
        let seen = upstream.last_request();
        assert_eq!(seen.header("accept-encoding").as_deref(), Some("identity"));
        let authz = seen.header("authorization").expect("a signed request");
        assert!(authz.contains("accept-encoding"), "{authz}");
        let date = seen.header("x-amz-date").expect("a signing date");
        let signature = authz.rsplit("Signature=").next().unwrap().to_string();
        (date, signature)
    };

    // Requests signed in the same second differ only in what the workload sent, so a signature over
    // the wire value is the same for each.
    for _ in 0..5 {
        let (date, identity) = signed_as(&[("Accept-Encoding", "identity")]);
        let (gzip_date, gzip) = signed_as(&[("Accept-Encoding", "gzip, br")]);
        let (split_date, split) =
            signed_as(&[("Accept-Encoding", "gzip"), ("Accept-Encoding", "br")]);
        let (absent_date, absent) = signed_as(&[]);
        if [&gzip_date, &split_date, &absent_date]
            .iter()
            .all(|d| **d == date)
        {
            assert_eq!(gzip, identity, "one encoding line");
            assert_eq!(split, identity, "two encoding lines");
            assert_eq!(absent, identity, "no encoding line");
            return;
        }
    }
    panic!("no two requests were signed in the same second");
}

// ============================================================================================
// NEGATIVE: the PDP governs — an unauthorized host is refused at CONNECT without opening a socket
// ============================================================================================

#[test]
fn policy_denied_host_is_refused_at_connect() {
    let host = "api.unauthorized.test";
    // The host resolves fine; only the PDP refuses it.
    let config = MitmConfig {
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        ..MitmConfig::default()
    };
    let handle =
        MitmInterceptor::start(config, CapabilitySet::default(), FixedPolicy::denying_all())
            .unwrap();

    let mut client = WorkloadClient::connect_raw(proxy_port(&handle));
    let reply = client.raw_connect(host, 443);
    assert!(
        reply.contains("403") && !reply.contains("200 Connection Established"),
        "a policy-denied host must be refused at the gate: {reply:?}"
    );

    let events = handle.drain_audit_events();
    assert!(events.iter().any(|e| e.decision == AuditDecision::Deny));
}

/// The PDP governs the L7 legs too: it sees the request effect for an authorized host, and its verdict
/// there decides whether the request bytes ever reach the upstream.
#[test]
fn policy_governs_the_request_leg_of_an_authorized_host() {
    /// Permits the connect but denies the HTTP request effect.
    struct ConnectOnly;
    impl EffectInterceptor for ConnectOnly {
        fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
            match attempt {
                EffectAttempt::HttpRequest { .. } => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "request denied by test policy",
                )),
                _ => Ok(Box::new(NoopPermit)),
            }
        }
    }

    let host = "api.l7-governed.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem()],
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        ..MitmConfig::default()
    };
    let handle =
        MitmInterceptor::start(config, CapabilitySet::default(), Arc::new(ConnectOnly)).unwrap();

    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request("GET", "/secret", &[], b"");

    assert_eq!(client.read_status(), 403, "the PDP denied the request leg");
    assert_eq!(
        upstream.request_count(),
        0,
        "a policy-denied request must never reach the upstream"
    );
}

// ============================================================================================
// NEGATIVE: a phantom mismatch fails closed (an INTEGRITY failure, not an authorization one)
// ============================================================================================

#[test]
fn phantom_mismatch_fails_closed() {
    let host = "api.mismatch.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();
    let (store, _real_phantom) = opaque_store(host, port, "sk_live_REALSECRET");
    let controls = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(pat(host, port), store))
        .build();
    // The PDP ALLOWS this host — the deny below comes purely from credential integrity.
    let handle = start_gateway(host, &upstream, controls, FixedPolicy::allowing(&[host]));

    // The workload presents a WRONG phantom → the credential control denies.
    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request(
        "GET",
        "/v1/charges",
        &[("Authorization", "Bearer slice_WRONGPHANTOM")],
        b"",
    );
    let status = client.read_status();

    assert_eq!(status, 403, "a phantom mismatch must fail closed");
    assert_eq!(
        upstream.request_count(),
        0,
        "a mismatched-phantom request must never reach the upstream"
    );
}

// ============================================================================================
// NEGATIVE: a missing phantom on a credential route fails closed
// ============================================================================================

#[test]
fn missing_phantom_fails_closed() {
    let host = "api.missing.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();
    let (store, _phantom) = opaque_store(host, port, "sk_live_REALSECRET");
    let controls = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(pat(host, port), store))
        .build();
    let handle = start_gateway(host, &upstream, controls, FixedPolicy::allowing(&[host]));

    // No Authorization header at all → no phantom found → deny (fail-closed).
    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request("GET", "/v1/charges", &[], b"");
    let status = client.read_status();

    assert_eq!(status, 403, "a missing phantom must fail closed");
    assert_eq!(upstream.request_count(), 0);
}

// ============================================================================================
// POSITIVE: an advisory route injects the real secret without a matching phantom
// ============================================================================================

#[test]
fn advisory_route_injects_without_a_matching_phantom() {
    let host = "api.advisory.test";
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();
    let store = advisory_store(host, port, "sk_live_REALSECRET");
    let controls = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(pat(host, port), store))
        .build();
    // Capture the decision journal so the advisory allow is asserted to be reconstructable.
    let emitter = StubEmitter::new();
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem()],
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        ..MitmConfig::default()
    };
    let handle = MitmInterceptor::start_with_emitter(
        config,
        controls,
        FixedPolicy::allowing(&[host]),
        Box::new(emitter.clone()),
    )
    .unwrap();

    // The workload presents a WRONG phantom, but the advisory route injects the real secret anyway.
    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request(
        "GET",
        "/v1/charges",
        &[("Authorization", "Bearer slice_WRONGPHANTOM")],
        b"",
    );
    let status = client.read_status();

    let seen = upstream.last_request();
    assert_eq!(status, 200, "advisory injects and forwards");
    assert_eq!(
        seen.header("authorization").as_deref(),
        Some("Bearer sk_live_REALSECRET"),
        "the upstream saw the real secret, injected despite the mismatch"
    );
    assert!(
        !seen.raw.contains("slice_WRONGPHANTOM"),
        "the foreign placeholder must be stripped, not carried upstream"
    );

    // The advisory injection is journalled as an allow decision naming the destination, carrying a
    // non-secret reason, and tying to the requester correlation — reconstructable, not stderr-only.
    let decisions = emitter.records();
    let advisory = decisions
        .iter()
        .find(|d| d.decision == AuditDecision::Allow && d.reason.contains("inject = always"))
        .expect("an advisory allow decision was journalled");
    assert_eq!(advisory.host, host, "the decision names the destination");
    assert!(
        !advisory.reason.contains("REALSECRET") && !advisory.reason.contains("WRONGPHANTOM"),
        "the journalled reason carries no secret or placeholder value: {}",
        advisory.reason
    );
    assert!(
        !advisory.correlation.as_str().is_empty(),
        "the decision ties to a requester correlation"
    );
}

// ============================================================================================
// NEGATIVE: config-load fail-closed — two credential controls on one pattern is a startup error
// ============================================================================================

#[test]
fn duplicate_credential_pattern_is_rejected_at_config_load() {
    let host = "api.dupe.test";
    let port = 443;
    let (store_a, _a) = opaque_store(host, port, "sk_live_A");
    let (store_b, _b) = opaque_store(host, port, "sk_live_B");
    let controls = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(pat(host, port), store_a))
        .add_credential(CredentialCapability::new(pat(host, port), store_b))
        .build();

    // start() runs CapabilitySet::validate against the adapter's max visibility; two controls on
    // one pattern would collide on `Authorization` for every request, so it is rejected before a socket
    // is bound. (MitmHandle is not Debug, so match rather than expect_err.)
    match MitmInterceptor::start(
        MitmConfig::default(),
        controls,
        FixedPolicy::allowing(&[host]),
    ) {
        Ok(_) => panic!("two credential controls on one pattern must fail config-load"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.to_lowercase().contains("pattern"),
                "the error must name the duplicated pattern: {msg:?}"
            );
        }
    }
}

// ============================================================================================
// NEGATIVE: a content-encoded echo of the real secret is refused, not delivered
// ============================================================================================

/// A gzip body whose plaintext is `{"echo":"Bearer sk_live_REALSECRET"}`. Compressed, the secret is
/// not present as bytes, so a scan of the raw response cannot see it.
const GZIP_ECHO_BODY: &[u8] = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xab\x56\x4a\x4d\xce\xc8\x57\xb2\x52\x72\x4a\x4d\x2c\x4a\x2d\x52\x28\xce\x8e\xcf\xc9\x2c\x4b\x8d\x0f\x72\x75\xf4\x09\x76\x75\x0e\x72\x0d\x51\xaa\x05\x00\x7e\x88\x7a\xda\x24\x00\x00\x00";

/// An upstream reply that echoes the real secret inside [`GZIP_ECHO_BODY`].
const GZIP_ECHO_RESPONSE: &[u8] = b"\x48\x54\x54\x50\x2f\x31\x2e\x31\x20\x32\x30\x30\x20\x4f\x4b\x0d\x0a\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x54\x79\x70\x65\x3a\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x6a\x73\x6f\x6e\x0d\x0a\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x45\x6e\x63\x6f\x64\x69\x6e\x67\x3a\x20\x67\x7a\x69\x70\x0d\x0a\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x4c\x65\x6e\x67\x74\x68\x3a\x20\x35\x36\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20\x63\x6c\x6f\x73\x65\x0d\x0a\x0d\x0a\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xab\x56\x4a\x4d\xce\xc8\x57\xb2\x52\x72\x4a\x4d\x2c\x4a\x2d\x52\x28\xce\x8e\xcf\xc9\x2c\x4b\x8d\x0f\x72\x75\xf4\x09\x76\x75\x0e\x72\x0d\x51\xaa\x05\x00\x7e\x88\x7a\xda\x24\x00\x00\x00";

/// An upstream reply that echoes the real secret in plain bytes.
const PLAIN_ECHO_RESPONSE: &[u8] = b"\x48\x54\x54\x50\x2f\x31\x2e\x31\x20\x32\x30\x30\x20\x4f\x4b\x0d\x0a\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x54\x79\x70\x65\x3a\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x6a\x73\x6f\x6e\x0d\x0a\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x4c\x65\x6e\x67\x74\x68\x3a\x20\x33\x36\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20\x63\x6c\x6f\x73\x65\x0d\x0a\x0d\x0a\x7b\x22\x65\x63\x68\x6f\x22\x3a\x22\x42\x65\x61\x72\x65\x72\x20\x73\x6b\x5f\x6c\x69\x76\x65\x5f\x52\x45\x41\x4c\x53\x45\x43\x52\x45\x54\x22\x7d";

#[test]
fn a_gzip_echo_of_the_real_secret_is_refused_not_delivered() {
    assert!(
        !GZIP_ECHO_BODY
            .windows(b"sk_live_REALSECRET".len())
            .any(|w| w == b"sk_live_REALSECRET"),
        "the fixture must hide the secret by compression, or the test proves nothing"
    );
    let host = "api.echo.test";
    let upstream = TlsUpstream::start_with_response(host, GZIP_ECHO_RESPONSE);
    let port = upstream.port();
    let (store, phantom) = opaque_store(host, port, "sk_live_REALSECRET");
    let controls = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(pat(host, port), store))
        .build();
    let handle = start_gateway(host, &upstream, controls, FixedPolicy::allowing(&[host]));

    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request(
        "GET",
        "/v1/echo",
        &[
            ("Authorization", &format!("Bearer {phantom}")),
            ("Accept-Encoding", "gzip"),
        ],
        b"",
    );
    let response = client.read_response();

    let seen = upstream.last_request();
    assert_eq!(
        seen.header("accept-encoding").as_deref(),
        Some("identity"),
        "a credentialed request must ask the origin for an unencoded response"
    );
    assert!(
        !response.starts_with("HTTP/1.1 200"),
        "the encoded echo must be refused, not delivered: {response:?}"
    );
    assert!(
        !response.contains("\u{1f}\u{8b}") && !response.contains("sk_live_REALSECRET"),
        "neither the encoded body nor the secret may reach the workload: {response:?}"
    );
}

#[test]
fn a_plain_echo_of_the_real_secret_is_redacted() {
    let host = "api.echo.test";
    let upstream = TlsUpstream::start_with_response(host, PLAIN_ECHO_RESPONSE);
    let port = upstream.port();
    let (store, phantom) = opaque_store(host, port, "sk_live_REALSECRET");
    let controls = CapabilitySet::builder()
        .add_credential(CredentialCapability::new(pat(host, port), store))
        .build();
    let handle = start_gateway(host, &upstream, controls, FixedPolicy::allowing(&[host]));

    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request(
        "GET",
        "/v1/echo",
        &[("Authorization", &format!("Bearer {phantom}"))],
        b"",
    );
    let response = client.read_response();

    assert!(response.starts_with("HTTP/1.1 200"), "{response:?}");
    assert!(
        !response.contains("sk_live_REALSECRET") && response.contains("[REDACTED]"),
        "the echoed secret must be redacted: {response:?}"
    );
}

// ============================================================================================
// NEGATIVE: a denied host is refused before it is resolved, so no DNS query leaves the box
// ============================================================================================

/// A name in the reserved `.invalid` TLD, which never resolves: a resolution attempt fails with 502.
const UNRESOLVABLE_HOST: &str = "no-such-host-dns-exfil.invalid";

#[test]
fn a_denied_host_is_refused_before_it_is_resolved() {
    let resolvable = "api.denied.test";
    let config = MitmConfig {
        dns_overrides: vec![(resolvable.to_string(), "127.0.0.1".parse().unwrap())],
        ..MitmConfig::default()
    };
    let handle =
        MitmInterceptor::start(config, CapabilitySet::default(), FixedPolicy::denying_all())
            .unwrap();

    let mut client = WorkloadClient::connect_raw(proxy_port(&handle));
    let unresolvable_reply = client.raw_connect(UNRESOLVABLE_HOST, 443);
    let mut client = WorkloadClient::connect_raw(proxy_port(&handle));
    let resolvable_reply = client.raw_connect(resolvable, 443);

    // A denied name gets the policy's 403 whether or not it would resolve. Before this check it got
    // 502, the resolver's failure, which proved the gateway had looked the denied name up.
    for (host, reply) in [
        (UNRESOLVABLE_HOST, &unresolvable_reply),
        (resolvable, &resolvable_reply),
    ] {
        assert!(
            reply.starts_with("HTTP/1.1 403") && !reply.contains("502"),
            "a denied {host} is refused by policy before resolution: {reply:?}"
        );
    }
    assert_eq!(
        unresolvable_reply.lines().next(),
        resolvable_reply.lines().next(),
        "the status must not reveal whether a denied name resolves"
    );
}

#[test]
fn a_permitted_host_is_still_resolved() {
    let handle = MitmInterceptor::start(
        MitmConfig::default(),
        CapabilitySet::default(),
        FixedPolicy::allowing(&[UNRESOLVABLE_HOST]),
    )
    .unwrap();

    let mut client = WorkloadClient::connect_raw(proxy_port(&handle));
    let reply = client.raw_connect(UNRESOLVABLE_HOST, 443);

    assert!(
        reply.starts_with("HTTP/1.1 502"),
        "a permitted host passes the pre-resolution check and reaches the resolver: {reply:?}"
    );
}

/// The first `python3` on `PATH` that the test can run, or `None` to skip.
fn python3() -> Option<std::path::PathBuf> {
    let output = std::process::Command::new("python3")
        .args(["-c", "import ssl, sys; print(sys.executable)"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().into())
}

/// CPython's strict verification, the default from Python 3.13, accepts the leaf the gateway mints.
#[test]
fn a_strict_python_client_accepts_the_minted_leaf() {
    let Some(python) = python3() else {
        eprintln!("skipping: no python3 with ssl on PATH");
        return;
    };
    let host = "strict.python.test";
    let upstream = TlsUpstream::start(host);
    let ca_dir = std::env::temp_dir().join(format!("box-ca-strict-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&ca_dir);
    let config = MitmConfig {
        intercept_ca_dir: Some(ca_dir.clone()),
        upstream_ca_pems: vec![upstream.ca_pem()],
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        ..MitmConfig::default()
    };
    let handle = MitmInterceptor::start(
        config,
        CapabilitySet::default(),
        FixedPolicy::allowing(&[host]),
    )
    .unwrap();
    let ca_path = handle
        .intercept_ca_path()
        .expect("the CA is written")
        .to_owned();

    let script = r#"
import http.client, ssl, sys
cafile, proxy_port, host, port = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
context = ssl.create_default_context(cafile=cafile)
context.verify_flags |= ssl.VERIFY_X509_STRICT
connection = http.client.HTTPSConnection("127.0.0.1", proxy_port, context=context, timeout=10)
connection.set_tunnel(host, port)
connection.request("GET", "/strict")
print(connection.getresponse().status)
"#;
    let output = std::process::Command::new(&python)
        .arg("-c")
        .arg(script)
        .arg(&ca_path)
        .arg(proxy_port(&handle).to_string())
        .arg(host)
        .arg(upstream.port().to_string())
        .output()
        .expect("run python3");
    let _ = std::fs::remove_dir_all(&ca_dir);

    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "200",
        "{} under strict verification: stderr={}",
        python.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}
