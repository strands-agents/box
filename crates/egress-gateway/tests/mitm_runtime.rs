//! The gateway's runtime and connection slots, seen from outside: the connection cap, `Drop`, and
//! the caller's runtime of each flavor.

#![cfg(feature = "tls-intercept")]

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use egress_gateway::{
    AuditDecision, CapabilitySet, EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit,
    EgressDecision, Emitter, MitmConfig, MitmHandle, MitmInterceptor,
};

/// An authority that refuses every effect.
struct RefuseEffects;

impl EffectInterceptor for RefuseEffects {
    fn intercept(&self, _: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refused by the runtime test",
        ))
    }
}

/// An authority that permits every effect and keeps the outcome of each request permit.
#[derive(Default)]
struct PermitAll {
    request_outcomes: Arc<Mutex<Vec<EffectOutcome>>>,
}

impl EffectInterceptor for PermitAll {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        let outcomes = matches!(attempt, EffectAttempt::HttpRequest { .. })
            .then(|| Arc::clone(&self.request_outcomes));
        Ok(Box::new(KeepOutcome(outcomes)))
    }
}

struct KeepOutcome(Option<Arc<Mutex<Vec<EffectOutcome>>>>);

impl EffectPermit for KeepOutcome {
    fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
        if let Some(outcomes) = self.0 {
            outcomes.lock().unwrap().push(outcome);
        }
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

fn start(config: MitmConfig, policy: Arc<dyn EffectInterceptor>) -> MitmHandle {
    MitmInterceptor::start(config, CapabilitySet::default(), policy).unwrap()
}

fn refusing(max_connections: usize) -> MitmHandle {
    start(
        MitmConfig {
            max_connections,
            ..MitmConfig::default()
        },
        Arc::new(RefuseEffects),
    )
}

fn proxy_addr(handle: &MitmHandle) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, handle.port().unwrap()))
}

/// A client whose reads give up after `wait`.
fn client(addr: SocketAddr, wait: Duration) -> TcpStream {
    let client = TcpStream::connect(addr).unwrap();
    client.set_read_timeout(Some(wait)).unwrap();
    client
}

const CONNECT: &[u8] = b"CONNECT refused.test:443 HTTP/1.1\r\nHost: refused.test:443\r\n\r\n";

/// Read until the peer closes, a read times out, or a read fails. Returns the bytes read.
fn read_reply(stream: &mut impl Read) -> Vec<u8> {
    let mut reply = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n @ 1..) = stream.read(&mut buf) {
        reply.extend_from_slice(&buf[..n]);
    }
    reply
}

/// Whether the gateway at `addr` answers one refused `CONNECT` with its `403` within 10 s.
fn serves(addr: SocketAddr) -> bool {
    let mut probe = client(addr, Duration::from_secs(10));
    probe.write_all(CONNECT).unwrap();
    read_reply(&mut probe).starts_with(b"HTTP/1.1 403 ")
}

/// A short, unique AF_UNIX socket path under the temp dir.
fn unique_sock_path() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("gwrt-{}-{n}.sock", std::process::id()))
}

/// Run `work` on its own thread, and fail when it takes 5 s or more.
fn within_5_s(what: &str, work: impl FnOnce() + Send + 'static) {
    let (done, finished) = mpsc::channel();
    thread::spawn(move || {
        work();
        let _ = done.send(());
    });
    assert!(
        finished.recv_timeout(Duration::from_secs(5)).is_ok(),
        "{what} did not return in 5 s"
    );
}

#[test]
fn the_connection_cap_holds_the_next_connection_until_a_slot_frees() {
    let handle = refusing(2);
    let addr = proxy_addr(&handle);
    let first = client(addr, Duration::from_secs(10));
    let _second = client(addr, Duration::from_secs(10));
    let mut third = client(addr, Duration::from_millis(300));
    third.write_all(CONNECT).unwrap();
    assert!(
        read_reply(&mut third).is_empty(),
        "two idle connections hold both slots, so the third gets no reply"
    );

    drop(first);
    third
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    assert!(
        read_reply(&mut third).starts_with(b"HTTP/1.1 403 "),
        "the third connection is served when a slot frees"
    );
}

#[test]
fn a_zero_connection_cap_serves_one_connection() {
    let handle = refusing(0);
    assert!(serves(proxy_addr(&handle)));
}

#[test]
fn an_unbounded_connection_cap_starts_and_serves() {
    let handle = refusing(usize::MAX);
    assert!(serves(proxy_addr(&handle)));
}

#[test]
fn drop_returns_while_every_slot_is_held() {
    let handle = refusing(1);
    let addr = proxy_addr(&handle);
    let _idle = client(addr, Duration::from_secs(10));
    let mut waiting = client(addr, Duration::from_secs(10));
    waiting.write_all(CONNECT).unwrap();
    within_5_s("drop with every slot held", move || drop(handle));
}

#[test]
fn drop_closes_the_listener_before_it_returns() {
    let handle = refusing(256);
    let addr = proxy_addr(&handle);
    drop(handle);
    assert!(TcpStream::connect(addr).is_err(), "the port refuses");
}

#[test]
fn drop_closes_the_af_unix_listener_before_it_returns() {
    let path = unique_sock_path();
    let _ = std::fs::remove_file(&path);
    let handle = start(
        MitmConfig {
            unix_socket_path: Some(path.clone()),
            ..MitmConfig::default()
        },
        Arc::new(RefuseEffects),
    );
    assert!(UnixStream::connect(&path).is_ok(), "the socket serves");
    drop(handle);
    assert!(UnixStream::connect(&path).is_err(), "the socket refuses");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_exchange_open_at_drop_runs_to_completion() {
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = origin.local_addr().unwrap().port();
    let (arrived, request_arrived) = mpsc::channel();
    let upstream = thread::spawn(move || {
        let (mut stream, _) = origin.accept().unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        arrived.send(()).unwrap();
        thread::sleep(Duration::from_millis(500));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });
    let policy = Arc::new(PermitAll::default());
    let outcomes = Arc::clone(&policy.request_outcomes);
    let handle = start(MitmConfig::default(), policy);
    let mut workload = client(proxy_addr(&handle), Duration::from_secs(10));
    workload
        .write_all(
            format!(
                "GET http://127.0.0.1:{port}/slow HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
    request_arrived
        .recv_timeout(Duration::from_secs(10))
        .unwrap();

    within_5_s("drop with an exchange open", move || drop(handle));
    let reply = read_reply(&mut workload);
    upstream.join().unwrap();

    assert!(
        reply.starts_with(b"HTTP/1.1 200 "),
        "the open exchange finishes after drop: {}",
        String::from_utf8_lossy(&reply)
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while outcomes.lock().unwrap().is_empty() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        matches!(
            outcomes.lock().unwrap().as_slice(),
            [EffectOutcome::Replied { status: 200, .. }]
        ),
        "the request permit records its reply: {:?}",
        outcomes.lock().unwrap()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_the_handle_inside_a_current_thread_runtime_does_not_panic() {
    let handle = refusing(256);
    let addr = proxy_addr(&handle);
    drop(handle);
    assert!(TcpStream::connect(addr).is_err(), "the port refuses");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_handle_inside_a_multi_thread_runtime_does_not_panic() {
    let handle = refusing(256);
    let addr = proxy_addr(&handle);
    drop(handle);
    assert!(TcpStream::connect(addr).is_err(), "the port refuses");
}

/// The test thread drives the caller's only worker and blocks it with a std exchange, so the
/// gateway answers only if it runs on a runtime of its own.
#[tokio::test(flavor = "current_thread")]
async fn the_gateway_serves_while_the_callers_runtime_is_blocked() {
    let handle = refusing(256);
    assert!(serves(proxy_addr(&handle)));
}

#[test]
fn the_handle_is_send_and_sync() {
    fn send_and_sync<T: Send + Sync>() {}
    send_and_sync::<MitmHandle>();
}

/// An authority that answers by host: `slow.test` waits 2 s and then refuses, `broken.test` fails,
/// and every other host is refused at once.
struct ByHost;

impl EffectInterceptor for ByHost {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        let EffectAttempt::Resolve { host, .. } = attempt else {
            return Ok(Box::new(KeepOutcome(None)));
        };
        match *host {
            "slow.test" => thread::sleep(Duration::from_secs(2)),
            "broken.test" => return Err(io::Error::other("the authority is unavailable")),
            "allowed.test" => return Ok(Box::new(KeepOutcome(None))),
            _ => {}
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refused by the runtime test",
        ))
    }
}

fn connect_head(host: &str, extra: &str) -> String {
    format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n{extra}\r\n")
}

#[test]
fn a_slow_decision_does_not_stall_another_connection() {
    let handle = start(MitmConfig::default(), Arc::new(ByHost));
    let addr = proxy_addr(&handle);
    let slow: Vec<_> = (0..16)
        .map(|_| {
            let mut client = client(addr, Duration::from_secs(10));
            client
                .write_all(connect_head("slow.test", "").as_bytes())
                .unwrap();
            client
        })
        .collect();
    // Let the slow decisions start on the gateway first.
    thread::sleep(Duration::from_millis(200));
    let started = Instant::now();
    let mut fast = client(addr, Duration::from_secs(10));
    fast.write_all(connect_head("fast.test", "").as_bytes())
        .unwrap();
    let reply = read_reply(&mut fast);
    let waited = started.elapsed();
    assert!(reply.starts_with(b"HTTP/1.1 403 "));
    assert!(
        waited < Duration::from_secs(1),
        "16 slow decisions stalled another connection for {waited:?}"
    );
    for mut client in slow {
        assert!(read_reply(&mut client).starts_with(b"HTTP/1.1 403 "));
    }
}

#[test]
fn refusals_before_the_ack_keep_their_bytes() {
    let handle = start(
        MitmConfig {
            expected_token: Some("secret-token".to_string()),
            ..MitmConfig::default()
        },
        Arc::new(ByHost),
    );
    let addr = proxy_addr(&handle);
    let token = "Proxy-Authorization: Bearer secret-token\r\n";
    let cases: [(String, &[u8]); 3] = [
        (
            connect_head("refused.test", "Proxy-Authorization: Bearer wrong\r\n"),
            b"HTTP/1.1 407 proxy authentication required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
        (
            connect_head("refused.test", token),
            b"HTTP/1.1 403 Forbidden\r\nx-strands-box-egress: refused\r\nConnection: close\r\nContent-Length: 27\r\n\r\nrefused by the runtime test",
        ),
        (
            connect_head("broken.test", token),
            b"HTTP/1.1 502 bad gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
    ];
    for (head, expected) in cases {
        let mut client = client(addr, Duration::from_secs(10));
        client.write_all(head.as_bytes()).unwrap();
        let reply = read_reply(&mut client);
        assert_eq!(
            String::from_utf8_lossy(&reply),
            String::from_utf8_lossy(expected),
            "{head:?}"
        );
    }
}

#[test]
fn af_unix_answers_a_plain_request_with_the_same_400() {
    let path = unique_sock_path();
    let _ = std::fs::remove_file(&path);
    let handle = start(
        MitmConfig {
            unix_socket_path: Some(path.clone()),
            ..MitmConfig::default()
        },
        Arc::new(RefuseEffects),
    );
    let mut client = UnixStream::connect(&path).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client
        .write_all(b"GET http://plain.test/ HTTP/1.1\r\nHost: plain.test\r\n\r\n")
        .unwrap();
    assert_eq!(
        read_reply(&mut client),
        b"HTTP/1.1 400 bad request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    drop(handle);
    let _ = std::fs::remove_file(&path);
}

/// Accept and hold every connection to a loopback origin, so a dial to it succeeds.
fn holding_origin() -> u16 {
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = origin.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut held = Vec::new();
        for stream in origin.incoming().flatten() {
            held.push(stream);
        }
    });
    port
}

/// Read one head, one byte for each read, so no byte after it leaves the socket.
fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
    }
    head
}

#[test]
fn a_client_hello_sent_with_the_connect_head_reaches_the_tls_acceptor() {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName};

    static N: AtomicU32 = AtomicU32::new(0);
    let port = holding_origin();
    let ca_dir = std::env::temp_dir().join(format!(
        "gwrt-ca-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let handle = start(
        MitmConfig {
            intercept_ca_dir: Some(ca_dir.clone()),
            dns_overrides: vec![("hello.test".to_string(), "127.0.0.1".parse().unwrap())],
            ..MitmConfig::default()
        },
        Arc::new(PermitAll::default()),
    );
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(handle.intercept_ca_path().unwrap()).unwrap())
        .unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut tls = rustls::ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("hello.test").unwrap(),
    )
    .unwrap();
    let mut first_write =
        format!("CONNECT hello.test:{port} HTTP/1.1\r\nHost: hello.test:{port}\r\n\r\n")
            .into_bytes();
    tls.write_tls(&mut first_write).unwrap();

    let mut tcp = client(proxy_addr(&handle), Duration::from_secs(10));
    tcp.write_all(&first_write).unwrap();
    assert_eq!(
        read_head(&mut tcp),
        b"HTTP/1.1 200 Connection Established\r\n\r\n"
    );
    while tls.is_handshaking() {
        tls.complete_io(&mut tcp).unwrap();
    }
    assert!(
        tls.peer_certificates().is_some(),
        "the gateway's leaf answered the early ClientHello"
    );
    drop(handle);
    let _ = std::fs::remove_dir_all(&ca_dir);
}

thread_local! {
    /// The destination of the last decision on this thread, as the box's telemetry decorator keeps
    /// the attributed decision for the emit that reports it.
    static PENDING: std::cell::RefCell<Option<(String, u16)>> = const { std::cell::RefCell::new(None) };
}

/// An authority that permits every effect and leaves the destination of each decision on the
/// thread that decided it.
struct LeavePending;

impl EffectInterceptor for LeavePending {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        let destination = match attempt {
            EffectAttempt::Resolve { host, port } | EffectAttempt::Connect { host, port, .. } => {
                Some((host.to_string(), *port))
            }
            _ => None,
        };
        PENDING.with(|pending| *pending.borrow_mut() = destination);
        Ok(Box::new(KeepOutcome(None)))
    }
}

/// An emitter that takes the pending decision on its own thread, and keeps each `Allow` that does
/// not find its own decision there.
#[derive(Default)]
struct TakePending {
    allows: Arc<AtomicU32>,
    unpaired: Arc<Mutex<Vec<String>>>,
}

impl Emitter for TakePending {
    fn emit(&self, record: EgressDecision) {
        let pending = PENDING.with(|pending| pending.borrow_mut().take());
        if record.decision == AuditDecision::Allow {
            self.allows.fetch_add(1, Ordering::SeqCst);
            if pending != Some((record.host.clone(), record.port)) {
                self.unpaired
                    .lock()
                    .unwrap()
                    .push(format!("{}:{} found {pending:?}", record.host, record.port));
            }
        }
    }
}

#[test]
fn intercept_and_emit_share_one_thread() {
    const EXCHANGES: u32 = 64;
    let port = holding_origin();
    let emitter = TakePending::default();
    let allows = Arc::clone(&emitter.allows);
    let unpaired = Arc::clone(&emitter.unpaired);
    let handle = MitmInterceptor::start_with_emitter(
        MitmConfig {
            dns_overrides: (0..EXCHANGES)
                .map(|i| (format!("h{i}.test"), "127.0.0.1".parse().unwrap()))
                .collect(),
            ..MitmConfig::default()
        },
        CapabilitySet::default(),
        Arc::new(LeavePending),
        Box::new(emitter),
    )
    .unwrap();
    let addr = proxy_addr(&handle);
    let clients: Vec<_> = (0..EXCHANGES)
        .map(|i| {
            thread::spawn(move || {
                let mut client = client(addr, Duration::from_secs(10));
                client
                    .write_all(
                        format!(
                            "CONNECT h{i}.test:{port} HTTP/1.1\r\nHost: h{i}.test:{port}\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                read_head(&mut client)
            })
        })
        .collect();
    for client in clients {
        assert_eq!(
            client.join().unwrap(),
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        );
    }
    assert_eq!(allows.load(Ordering::SeqCst), EXCHANGES);
    assert!(
        unpaired.lock().unwrap().is_empty(),
        "an emit ran on another thread than its decision: {:?}",
        unpaired.lock().unwrap()
    );
}
