//! The gateway's authorization seam fails closed on Linux.
//!
//! One question, asked of the route a contained workload's egress takes: when the authority holds
//! no permit covering the destination, does the request deny or tunnel? The seam here permits one
//! host and the test drives another, so the gate is reached with nothing matching.
//!
//! Harness-only. No containment applies, so this needs no real kernel and carries no `#[ignore]`.
//!
//! Linux only. On macOS this file compiles to nothing (`#![cfg]` below).

#![cfg(target_os = "linux")]
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use egress_gateway::{
    CapabilitySet, EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, MitmConfig,
    MitmInterceptor,
};

/// A tiny in-process plaintext HTTP upstream: for each connection, reads a
/// request head and replies `200 OK` with a fixed body. Returns its bound
/// loopback address. Copied from `egress-proxy`'s `end_to_end.rs` so this test
/// owns its fixtures (Test Isolation NFR).
fn spawn_echo_upstream() -> SocketAddr {
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

/// A short, unique AF_UNIX socket path under the temp dir. `sun_path` is capped
/// (108 bytes on Linux); pid + a per-process counter keep parallel runs from
/// colliding. Same pattern as `end_to_end.rs::unique_sock_path`.
fn unique_sock_path() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("slc-comp-{}-{n}.sock", std::process::id()))
}

/// Stands in for the `policy` crate at the gateway's authorization seam.
///
/// The proxy holds no allow/deny authority of its own, so a test that wants one host
/// reachable and another refused states that here. Only `Connect` is judged: this file
/// proves the *composition* of containment with a governed egress route, and the L4
/// connect is the decision that makes a destination reachable at all. Request and
/// response effects are admitted so an allowed host completes its exchange.
///
/// A denial is `PermissionDenied`, which the adapter turns into a 403 without opening a
/// socket — the same contract the real `EgressPolicyInterceptor` meets.
struct HostPolicy {
    allowed_hosts: Vec<String>,
}

impl HostPolicy {
    fn allowing(hosts: &[&str]) -> Arc<Self> {
        Arc::new(Self {
            allowed_hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
        })
    }
}

impl EffectInterceptor for HostPolicy {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        if let EffectAttempt::Connect { host, .. } = attempt
            && !self
                .allowed_hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(host))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "denied by composition-test policy",
            ));
        }
        Ok(Box::new(AcceptingPermit))
    }
}

/// Records nothing: this file asserts the kernel-visible deny surface, and the
/// outcome-recording contract is proven in `egress-gateway`'s own suite.
struct AcceptingPermit;

impl EffectPermit for AcceptingPermit {
    fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> io::Result<()> {
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

/// Map both demo names to loopback so the allowed one reaches the upstream and
/// the blocked one is refused before the override ever matters.
fn loopback_overrides() -> Vec<(String, std::net::IpAddr)> {
    vec![
        ("allowed.test".to_string(), "127.0.0.1".parse().unwrap()),
        ("blocked.test".to_string(), "127.0.0.1".parse().unwrap()),
    ]
}

/// A coverage hole fails closed rather than tunnelling.
///
/// This preserves the *property* an earlier version of this test guarded, not its
/// mechanism. Under the deleted `ControlSet` fold it was a false-green in a specific
/// way: an **unqualified** `*.test` pattern matched nothing at an ephemeral port, the
/// set folded empty, and the proxy default-ALLOWED — so `blocked.test` tunnelled. That
/// fold no longer exists, so the pattern-shaped version of this test cannot be written.
///
/// What survives is the question worth asking of any authorization seam: when the
/// authority has no permit covering the destination, does the request deny or tunnel?
/// Here the interceptor permits one host and the test drives a different one, so the
/// gate is reached with nothing matching — and must answer 403 without establishing a
/// tunnel. A `200 Connection Established` would mean the seam had failed open.
///
/// Harness-only: no containment and no probe — just the gateway's behaviour — so it runs on any
/// Linux host without the real-kernel floor, hence no `#[ignore]`.
#[test]
fn an_unauthorized_destination_denies_rather_than_tunnelling() {
    let upstream = spawn_echo_upstream();

    let sock = unique_sock_path();
    let _ = std::fs::remove_file(&sock);

    let config = MitmConfig {
        unix_socket_path: Some(sock.clone()),
        dns_overrides: loopback_overrides(),
        ..MitmConfig::default()
    };
    // Permits `allowed.test` only. The request below names `blocked.test`, so the seam
    // is consulted and nothing permits it.
    let handle = MitmInterceptor::start(
        config,
        CapabilitySet::default(),
        HostPolicy::allowing(&["allowed.test"]),
    )
    .expect("start AF_UNIX proxy");
    let proxy_sock = handle
        .unix_socket_path()
        .expect("socket path")
        .to_path_buf();

    // Drive blocked.test over the socket: the policy has no permit for it, so the
    // gateway must refuse with 403 rather than open a tunnel.
    let head = connect_over_unix(&proxy_sock, "blocked.test", upstream.port());

    handle.shutdown();
    let _ = std::fs::remove_file(&sock);

    assert!(
        head.contains("403") && !head.contains("200 Connection Established"),
        "a destination no permit covers must DENY rather than tunnel; got: {head:?}"
    );
}

/// Connect to the AF_UNIX proxy and send a `CONNECT <host>:<port>` head,
/// returning the proxy's response head. Mirrors the probe's `http-unix` client
/// and `end_to_end.rs`'s AF_UNIX leg — the only client shape that works through
/// an AF_UNIX forward proxy.
fn connect_over_unix(proxy_sock: &Path, host: &str, port: u16) -> String {
    let mut client = UnixStream::connect(proxy_sock).expect("connect AF_UNIX proxy");
    client.set_read_timeout(Some(Duration::from_secs(5))).ok();
    client
        .write_all(format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .expect("write CONNECT");
    let mut resp = [0u8; 128];
    let n = client.read(&mut resp).unwrap_or(0);
    String::from_utf8_lossy(&resp[..n]).into_owned()
}
