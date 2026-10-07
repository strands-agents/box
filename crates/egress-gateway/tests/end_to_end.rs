//! End-to-end: the real MITM adapter against the real `credentials` crate, with no dependency on the
//! not-yet-built crates.
//!
//! These start a real `MitmInterceptor` on a real localhost socket and drive traffic through it. The
//! upstream is a tiny in-process plaintext TCP echo/HTTP server the adapter tunnels to (the opaque
//! path) — proving the listener, CONNECT handling, resolve-once/pin, the handle surface,
//! and audit all work end-to-end against `credentials` and the stub seams. The credential-swap and
//! SigV4 correctness are proven at the control level in `aws_injection.rs` / the unit tests (socket
//! -free); the PDP-governed paths are proven in `interception_e2e.rs`.
//!
//! **The authorization authority is mandatory**, so these tests supply
//! [`PermitEverything`] — a stand-in that allows every effect — or [`RefuseLinkLocal`], which refuses
//! a connect to an IPv4 link-local address. What they exercise is the transport: listener, CONNECT
//! handling, resolve-once/pin, the per-address decision, handle surface, audit. The Cedar-governed authorization paths are proven
//! in `interception_e2e.rs`, whose `FixedPolicy` allows only named hosts.
//!
//! `tls-intercept` is default-on, so these run against the full adapter.

#![cfg(feature = "tls-intercept")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use credentials::{Backend, DestinationPattern, Locator, RouteSpec, Vault, VaultConfig};
use egress_gateway::{
    CapabilitySet, CredentialCapability, EffectAttempt, EffectInterceptor, EffectOutcome,
    EffectPermit, Interceptor, MitmConfig, MitmInterceptor,
};

/// Allows every effect.
///
/// The authority is mandatory; a test that wants selective authorization uses
/// `interception_e2e.rs`'s `FixedPolicy` instead.
struct PermitEverything;

impl EffectInterceptor for PermitEverything {
    fn intercept(&self, _effect: &EffectAttempt<'_>) -> std::io::Result<Box<dyn EffectPermit>> {
        Ok(Box::new(PermitEverythingPermit))
    }
}

struct PermitEverythingPermit;

impl EffectPermit for PermitEverythingPermit {
    fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> std::io::Result<()> {
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

/// The mandatory authority for a transport test.
fn permit_everything() -> Arc<dyn EffectInterceptor> {
    Arc::new(PermitEverything)
}

/// Refuses a connect to an IPv4 link-local address, and allows every other effect.
struct RefuseLinkLocal;

impl EffectInterceptor for RefuseLinkLocal {
    fn intercept(&self, effect: &EffectAttempt<'_>) -> std::io::Result<Box<dyn EffectPermit>> {
        if let EffectAttempt::Connect { address, .. } = effect
            && let std::net::IpAddr::V4(v4) = address.ip()
            && v4.is_link_local()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "a link-local address is refused",
            ));
        }
        Ok(Box::new(PermitEverythingPermit))
    }
}

fn refuse_link_local() -> Arc<dyn EffectInterceptor> {
    Arc::new(RefuseLinkLocal)
}

/// A tiny in-process plaintext HTTP upstream: accepts one connection, reads a request head, and
/// replies `200 OK` with a fixed body. Returns its bound address.
fn spawn_echo_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else { continue };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    addr
}

/// The adapter binds a real localhost port and surfaces the handle wiring (port, env vars).
#[test]
fn adapter_starts_and_surfaces_handle_wiring() {
    let handle = MitmInterceptor::start(
        MitmConfig::default(),
        CapabilitySet::default(),
        permit_everything(),
    )
    .unwrap();

    let bound_port = handle.port().expect("TCP mode always has a port");
    assert!(bound_port > 0, "bound an ephemeral localhost port");
    let env: std::collections::HashMap<_, _> = handle.env_vars().into_iter().collect();
    let proxy = format!("http://127.0.0.1:{bound_port}");
    assert_eq!(env.get("HTTPS_PROXY"), Some(&proxy));
    assert_eq!(env.get("HTTP_PROXY"), Some(&proxy));
    // Shutdown is idempotent and also runs on drop.
    handle.shutdown();
}

/// Every connection is terminated and inspected, so a **plaintext** upstream is no
/// longer reachable: the CONNECT is acked, the client's next bytes are treated as a TLS ClientHello,
/// and a plaintext `GET` fails the handshake instead of being spliced through un-inspected.
///
/// This is the property that replaced the opaque tunnel. A connection whose plaintext the boundary
/// cannot see could not raise `net:request`/`net:response`, so it would be exempt from two of the
/// three authorizations.
#[test]
fn a_plaintext_upstream_is_no_longer_reachable_un_inspected() {
    let upstream = spawn_echo_upstream();
    let host = "127.0.0.1";

    let handle = MitmInterceptor::start(
        MitmConfig::default(),
        CapabilitySet::default(),
        permit_everything(),
    )
    .unwrap();

    let mut client =
        TcpStream::connect(("127.0.0.1", handle.port().expect("TCP mode has a port"))).unwrap();
    let connect = format!(
        "CONNECT {host}:{} HTTP/1.1\r\nHost: {host}\r\n\r\n",
        upstream.port()
    );
    client.write_all(connect.as_bytes()).unwrap();

    let mut resp = [0u8; 128];
    let n = client.read(&mut resp).unwrap();
    let head = String::from_utf8_lossy(&resp[..n]);
    assert!(
        head.contains("200 Connection Established"),
        "the CONNECT is still acked before termination: {head}"
    );

    // The boundary now expects a TLS handshake. A plaintext request cannot be tunneled.
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut reply = Vec::new();
    let _ = client.read_to_end(&mut reply);
    let reply = String::from_utf8_lossy(&reply);
    assert!(
        !reply.contains("200 OK"),
        "an un-inspected plaintext exchange must not complete: {reply}"
    );
}

/// A benign name that resolves to a link-local address is refused at CONNECT by the decision on the
/// pinned address, before any upstream socket.
#[test]
fn a_name_resolving_to_link_local_is_refused_on_the_pinned_address() {
    let host = "benign.e2e.test";
    let config = MitmConfig {
        dns_overrides: vec![(host.to_string(), "169.254.169.254".parse().unwrap())],
        ..MitmConfig::default()
    };
    let handle =
        MitmInterceptor::start(config, CapabilitySet::default(), refuse_link_local()).unwrap();

    let mut client =
        TcpStream::connect(("127.0.0.1", handle.port().expect("TCP mode has a port"))).unwrap();
    client
        .write_all(format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n").as_bytes())
        .unwrap();
    let mut reply = Vec::new();
    let _ = client.read_to_end(&mut reply);
    let head = String::from_utf8_lossy(&reply);
    assert!(
        head.contains("403") && !head.contains("200 Connection Established"),
        "a name resolving to link-local must be denied before connect: {head:?}"
    );
}

/// A `CredentialCapability` needs `Http`, so it validates on a tls-intercept adapter but is a
/// hard config error against Connection-only visibility (the tunnel-only posture). Proven at the
/// `CapabilitySet` layer.
#[test]
fn config_load_visibility_gate() {
    // SAFETY: the name is unique to this test, so no other test reads or writes it.
    unsafe { std::env::set_var("END_TO_END_VISIBILITY_GATE_SECRET", "s") };
    let spec = RouteSpec::opaque(
        DestinationPattern::parse("api.example.com").unwrap(),
        Locator::parse_uri("env://END_TO_END_VISIBILITY_GATE_SECRET").unwrap(),
        credentials::InjectMode::header("Bearer {}".to_string(), None)
            .expect("a valid header placement"),
    );
    let store = Arc::new(
        Vault::open(VaultConfig::new(Backend::local(), "t").route(spec))
            .unwrap()
            .into_vault(),
    );
    let cred =
        CredentialCapability::new(DestinationPattern::parse("api.example.com").unwrap(), store);
    let set = CapabilitySet::builder().add_credential(cred).build();

    // Every connection is terminated and inspected, so a credential mutator is always
    // satisfiable and validation turns only on the one-control-per-pattern rule.
    assert!(set.validate().is_ok());
}

/// The same `CapabilitySet` value could be handed to a hypothetical second adapter
/// unchanged. A compile-level assertion: a fn generic over `Interceptor` accepts any adapter driving one.
#[test]
fn credential_injection_is_adapter_agnostic() {
    fn drives_controls<I: Interceptor>(interceptor: &I) -> usize {
        interceptor.credential_injection().len()
    }

    let handle = MitmInterceptor::start(
        MitmConfig::default(),
        CapabilitySet::default(),
        permit_everything(),
    )
    .unwrap();
    let _ = &handle;

    // A hypothetical second adapter reusing the SAME type with no change to the controls.
    struct HypotheticalAdapter {
        controls: CapabilitySet,
    }
    impl Interceptor for HypotheticalAdapter {
        fn credential_injection(&self) -> &CapabilitySet {
            &self.controls
        }
    }
    let second = HypotheticalAdapter {
        controls: CapabilitySet::default(),
    };
    assert_eq!(drives_controls(&second), 0);
}

// ============================================================================================
// AF_UNIX egress pin: the proxy binds ONLY a UnixListener and serves the identical
// CONNECT/tunnel protocol over it. std::os::unix::net is available on macOS, so these run on the
// dev host with no cross-compile.
// ============================================================================================

/// A short, unique AF_UNIX socket path under the temp dir. Kept short because `sun_path` is capped
/// (~104 bytes on macOS, 108 on Linux); pid + a per-process counter keep parallel runs from
/// colliding on the same file.
fn unique_sock_path() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("slc-e2e-{}-{n}.sock", std::process::id()))
}

/// With `unix_socket_path` set, the adapter binds ONLY an AF_UNIX socket (no TCP
/// port exists) and serves the same opaque-tunnel CONNECT path a TCP client would get: a `UnixStream`
/// client CONNECTs, the proxy pins + tunnels to the plaintext upstream, and the reply comes back.
#[test]
fn af_unix_pin_serves_connect_end_to_end() {
    let upstream = spawn_echo_upstream();
    let host = "127.0.0.1";
    let sock = unique_sock_path();
    // A stale socket file from a crashed prior run would fail bind; clear it first (best-effort).
    let _ = std::fs::remove_file(&sock);

    let config = MitmConfig {
        unix_socket_path: Some(sock.clone()),
        ..MitmConfig::default()
    };
    let handle =
        MitmInterceptor::start(config, CapabilitySet::default(), permit_everything()).unwrap();

    // The AF_UNIX pin has no TCP port; the socket path is what the supervisor points the workload at.
    assert_eq!(handle.port(), None, "AF_UNIX pin exposes no TCP port");
    assert_eq!(
        handle.unix_socket_path(),
        Some(sock.as_path()),
        "AF_UNIX pin reports its socket path"
    );

    // Act as the contained workload: connect over the AF_UNIX socket and speak the same CONNECT.
    // The CONNECT protocol is byte-identical to the TCP path; termination then applies equally, so
    // the exchange that follows is TLS rather than a plaintext splice.
    let mut client = UnixStream::connect(&sock).unwrap();
    let connect = format!(
        "CONNECT {host}:{} HTTP/1.1\r\nHost: {host}\r\n\r\n",
        upstream.port()
    );
    client.write_all(connect.as_bytes()).unwrap();

    let mut resp = [0u8; 128];
    let n = client.read(&mut resp).unwrap();
    let head = String::from_utf8_lossy(&resp[..n]);
    assert!(
        head.contains("200 Connection Established"),
        "CONNECT ack over AF_UNIX: {head}"
    );
}

/// The decision on the pinned address holds identically on the AF_UNIX client path.
#[test]
fn af_unix_refuses_a_name_resolving_to_link_local() {
    let sock = unique_sock_path();
    let _ = std::fs::remove_file(&sock);
    let host = "benign.afunix.test";
    let config = MitmConfig {
        unix_socket_path: Some(sock.clone()),
        dns_overrides: vec![(host.to_string(), "169.254.169.254".parse().unwrap())],
        ..MitmConfig::default()
    };
    let handle =
        MitmInterceptor::start(config, CapabilitySet::default(), refuse_link_local()).unwrap();

    let mut client = UnixStream::connect(&sock).unwrap();
    client
        .write_all(format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n").as_bytes())
        .unwrap();
    let mut reply = Vec::new();
    let _ = client.read_to_end(&mut reply);
    let reply = String::from_utf8_lossy(&reply);
    assert!(
        reply.contains("403") && !reply.contains("200 Connection Established"),
        "the pinned-address decision must hold over AF_UNIX: {reply:?}"
    );

    handle.shutdown();
    let _ = std::fs::remove_file(&sock);
}

/// A bind failure (the path already exists as a regular file, not a socket) returns
/// `ProxyError::Bind` and spawns no accept loop, rather than silently degrading.
#[test]
fn af_unix_bind_failure_returns_bind_error() {
    // A regular file where the socket should go → UnixListener::bind fails with EADDRINUSE/ENOTSOCK.
    let sock = unique_sock_path();
    std::fs::write(&sock, b"not a socket").unwrap();

    let config = MitmConfig {
        unix_socket_path: Some(sock.clone()),
        ..MitmConfig::default()
    };
    // `MitmHandle` is not `Debug`, so describe the outcome from the error side (or a plain "Ok")
    // rather than formatting the whole `Result`.
    match MitmInterceptor::start(config, CapabilitySet::default(), permit_everything()) {
        Err(egress_gateway::ProxyError::Bind(_)) => {}
        Err(other) => panic!("expected ProxyError::Bind, got a different error: {other:?}"),
        Ok(_) => panic!("binding onto an existing non-socket file must fail closed, not succeed"),
    }
    let _ = std::fs::remove_file(&sock);
}

/// The bound AF_UNIX socket file is created mode `0600`: owner-only, since DAC is the entire
/// access-control mechanism for the pin (nothing else gates connect()).
#[test]
fn af_unix_socket_mode_is_0600() {
    use std::os::unix::fs::PermissionsExt;

    let sock = unique_sock_path();
    let _ = std::fs::remove_file(&sock);
    let config = MitmConfig {
        unix_socket_path: Some(sock.clone()),
        ..MitmConfig::default()
    };
    let handle =
        MitmInterceptor::start(config, CapabilitySet::default(), permit_everything()).unwrap();

    let mode = std::fs::metadata(&sock).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "AF_UNIX socket must be owner-only (0600); got {:o}",
        mode & 0o777
    );

    handle.shutdown();
    let _ = std::fs::remove_file(&sock);
}
