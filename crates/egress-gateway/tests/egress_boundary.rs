//! Egress boundary evidence with independent recorders: the pinned address the authority
//! permitted is the one dialed, every spelling of an address reaches the authority as that address, and
//! a proxy fault (abort, framing ambiguity, a riding second request) delivers nothing upstream.
//!
//! Every negative assertion here stands beside three things: a recorder self-test (the observer
//! is proven live before it is trusted to report nothing), an allowed control through the same
//! gateway (the route works), and an outcome class that separates "the boundary refused" from
//! "the resolver could not answer". A 502 with a resolve failure is never counted as a refusal.
//!
//! This is controlled integration of the gateway process against loopback recorders. It is not
//! native evidence of the contained workload, the kernel, or the instance's resolver.

#![cfg(feature = "tls-intercept")]

mod harness;

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use egress_gateway::{
    AuditDecision, CapabilitySet, EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit,
    MitmConfig, MitmHandle, MitmInterceptor,
};

use harness::{TlsUpstream, WorkloadClient};

// ============================================================================================
// The authority stand-in: records every attempt it was asked about, permits by an address rule
// ============================================================================================

/// One attempt the authority saw, with its verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Connect {
        host: String,
        port: u16,
        address: SocketAddr,
        permitted: bool,
    },
    Request {
        method: String,
        path: String,
    },
}

type ConnectRule = dyn Fn(&str, SocketAddr) -> bool + Send + Sync;

/// A PDP stand-in reached only through `EffectInterceptor`. The connect rule is the whole policy;
/// request and release effects are permitted. Every `Connect` attempt is recorded with the exact
/// pinned address the gateway presented, so a test can assert which addresses were asked about.
struct RecordingPolicy {
    seen: Mutex<Vec<Seen>>,
    connect_rule: Box<ConnectRule>,
}

impl RecordingPolicy {
    fn with_rule(rule: impl Fn(&str, SocketAddr) -> bool + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(Vec::new()),
            connect_rule: Box::new(rule),
        })
    }

    /// Permit every connect.
    fn permit_all() -> Arc<Self> {
        Self::with_rule(|_, _| true)
    }

    /// Refuse every connect, so each one is a recorded attempt.
    fn refuse_all() -> Arc<Self> {
        Self::with_rule(|_, _| false)
    }

    /// Permit a connect only for `host` spelled exactly so, pinned at `ip`.
    fn permitting_host_at(host: &str, ip: IpAddr) -> Arc<Self> {
        let host = host.to_string();
        Self::with_rule(move |seen_host, address| seen_host == host && address.ip() == ip)
    }

    fn connects(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| matches!(s, Seen::Connect { .. }))
            .cloned()
            .collect()
    }

    fn requests(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| matches!(s, Seen::Request { .. }))
            .cloned()
            .collect()
    }

    fn clear(&self) {
        self.seen.lock().unwrap().clear();
    }
}

impl EffectInterceptor for RecordingPolicy {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        match attempt {
            EffectAttempt::Connect {
                host,
                port,
                address,
                ..
            } => {
                let permitted = (self.connect_rule)(host, *address);
                self.seen.lock().unwrap().push(Seen::Connect {
                    host: (*host).to_string(),
                    port: *port,
                    address: *address,
                    permitted,
                });
                if !permitted {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "denied by test policy",
                    ));
                }
            }
            EffectAttempt::HttpRequest { method, path, .. } => {
                self.seen.lock().unwrap().push(Seen::Request {
                    method: (*method).to_string(),
                    path: (*path).to_string(),
                });
            }
            _ => {}
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
// A plaintext recorder: the independent observer at a destination
// ============================================================================================

/// The total time one recorder connection has to deliver its request, from accept.
const CONNECTION_DEADLINE: Duration = Duration::from_secs(5);
/// How long a snapshot waits for the accept loop's acknowledgement and for in-flight connections.
const SNAPSHOT_DEADLINE: Duration = Duration::from_secs(10);
/// The most head bytes and body bytes the recorder reads before it records the connection as
/// incomplete.
const MAX_HEAD_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// One connection the recorder accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Observation {
    /// The request line, when a head arrived.
    request_line: Option<String>,
    /// Every byte actually read, head and body; never padding.
    raw: Vec<u8>,
    /// Whether the head and the declared body were read in full within the limits and deadline.
    complete: bool,
    /// Why the read stopped short, when it did.
    error: Option<String>,
}

/// What the recorder saw, taken behind a drain barrier: the accept loop swept its backlog after the
/// caller asked, and every accepted connection has finished.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot {
    observations: Vec<Observation>,
    accept_errors: Vec<String>,
}

impl Snapshot {
    fn request_lines(&self) -> Vec<String> {
        self.observations
            .iter()
            .filter(|o| o.complete)
            .filter_map(|o| o.request_line.clone())
            .collect()
    }

    fn requests(&self) -> Vec<String> {
        self.observations
            .iter()
            .filter(|o| o.complete)
            .map(|o| String::from_utf8_lossy(&o.raw).into_owned())
            .collect()
    }

    fn incomplete(&self) -> Vec<Observation> {
        self.observations
            .iter()
            .filter(|o| !o.complete)
            .cloned()
            .collect()
    }

    fn bytes(&self) -> usize {
        self.observations.iter().map(|o| o.raw.len()).sum()
    }
}

struct RecorderShared {
    observations: Mutex<Vec<Observation>>,
    accept_errors: Mutex<Vec<String>>,
    /// Streams still being read, so `stop` can shut them down.
    active: Mutex<Vec<(u64, TcpStream)>>,
    in_flight: AtomicUsize,
    stop: AtomicBool,
    /// Drain barrier: the caller bumps `requested`; the accept loop takes the ticket BEFORE a
    /// sweep and acknowledges only that ticket after a sweep that ended in "nothing pending".
    drain_requested: AtomicU64,
    drain_acknowledged: AtomicU64,
}

/// A loopback TCP listener that records every connection, every byte it actually read, and every
/// complete HTTP request, and answers a complete request `200 recorder-ok`. It stands where a
/// forbidden delivery would land, so "nothing arrived" is a measured, health-checked count and not
/// an absence of evidence: a truncated, oversized, timed-out or errored connection is an
/// incomplete observation with its reason, and an accept error fails the snapshot.
struct PlainRecorder {
    addr: SocketAddr,
    shared: Arc<RecorderShared>,
    accept_thread: Option<std::thread::JoinHandle<()>>,
    handlers: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
}

impl PlainRecorder {
    fn start() -> Self {
        Self::start_on(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap()
    }

    fn start_on(bind: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(bind)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let shared = Arc::new(RecorderShared {
            observations: Mutex::new(Vec::new()),
            accept_errors: Mutex::new(Vec::new()),
            active: Mutex::new(Vec::new()),
            in_flight: AtomicUsize::new(0),
            stop: AtomicBool::new(false),
            drain_requested: AtomicU64::new(0),
            drain_acknowledged: AtomicU64::new(0),
        });
        let handlers: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let (s, h) = (shared.clone(), handlers.clone());
        let accept_thread = std::thread::spawn(move || {
            let mut next_id = 0u64;
            loop {
                let ticket = s.drain_requested.load(Ordering::SeqCst);
                loop {
                    if s.stop.load(Ordering::SeqCst) {
                        break;
                    }
                    match listener.accept() {
                        Ok((tcp, _)) => {
                            // BSD and macOS hand an accepted socket the listener's O_NONBLOCK;
                            // Linux does not. The handler reads under timeouts, so the stream
                            // must block, or every read fails at once with WouldBlock.
                            if let Err(error) = tcp.set_nonblocking(false) {
                                s.accept_errors
                                    .lock()
                                    .unwrap()
                                    .push(format!("set accepted stream blocking: {error}"));
                                break;
                            }
                            let id = next_id;
                            next_id += 1;
                            s.in_flight.fetch_add(1, Ordering::SeqCst);
                            if let Ok(handle) = tcp.try_clone() {
                                s.active.lock().unwrap().push((id, handle));
                            }
                            let s = s.clone();
                            let handle = std::thread::spawn(move || {
                                let observation = observe(tcp);
                                s.observations.lock().unwrap().push(observation);
                                s.active.lock().unwrap().retain(|(i, _)| *i != id);
                                s.in_flight.fetch_sub(1, Ordering::SeqCst);
                            });
                            h.lock().unwrap().push(handle);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => {
                            s.accept_errors.lock().unwrap().push(error.to_string());
                            break;
                        }
                    }
                }
                if s.drain_acknowledged.load(Ordering::SeqCst) < ticket {
                    s.drain_acknowledged.store(ticket, Ordering::SeqCst);
                }
                if s.stop.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        Ok(Self {
            addr,
            shared,
            accept_thread: Some(accept_thread),
            handlers,
        })
    }

    fn port(&self) -> u16 {
        self.addr.port()
    }

    /// A snapshot behind the drain barrier. Panics if the accept loop does not acknowledge, if a
    /// connection is still being read after the deadline, or if the accept loop met an error, so
    /// an unhealthy observer can never report a clean zero.
    fn snapshot(&self) -> Snapshot {
        if !self.shared.stop.load(Ordering::SeqCst) {
            let wanted = self.shared.drain_requested.fetch_add(1, Ordering::SeqCst) + 1;
            let deadline = Instant::now() + SNAPSHOT_DEADLINE;
            while self.shared.drain_acknowledged.load(Ordering::SeqCst) < wanted {
                assert!(
                    Instant::now() < deadline,
                    "the recorder's accept loop did not acknowledge a drain within {SNAPSHOT_DEADLINE:?}"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        let deadline = Instant::now() + SNAPSHOT_DEADLINE;
        while self.shared.in_flight.load(Ordering::SeqCst) > 0 {
            assert!(
                Instant::now() < deadline,
                "a recorder connection is still being read after {SNAPSHOT_DEADLINE:?}"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        let snapshot = Snapshot {
            observations: self.shared.observations.lock().unwrap().clone(),
            accept_errors: self.shared.accept_errors.lock().unwrap().clone(),
        };
        assert!(
            snapshot.accept_errors.is_empty(),
            "the recorder's accept loop met errors; its counts are not evidence: {:?}",
            snapshot.accept_errors
        );
        snapshot
    }

    /// Connections accepted, complete or not.
    fn connections(&self) -> usize {
        self.snapshot().observations.len()
    }

    /// Bytes actually received over every connection.
    fn bytes(&self) -> usize {
        self.snapshot().bytes()
    }

    /// The request lines of the requests read to completion, in arrival order.
    fn request_lines(&self) -> Vec<String> {
        self.snapshot().request_lines()
    }

    /// Prove the observer is live: a direct host connection is counted, read whole and answered.
    /// The observations are then cleared so the test's own measurement starts at zero.
    fn self_test(&self) {
        let mut tcp = TcpStream::connect_timeout(&self.addr, CONNECTION_DEADLINE)
            .expect("recorder accepts a direct connection");
        tcp.set_read_timeout(Some(CONNECTION_DEADLINE)).unwrap();
        tcp.write_all(b"GET /self-test HTTP/1.1\r\nHost: recorder\r\n\r\n")
            .unwrap();
        let reply = read_head_and_body(&mut tcp, Instant::now() + CONNECTION_DEADLINE);
        assert!(
            reply.complete && reply.raw.starts_with(b"HTTP/1.1 200"),
            "the recorder must answer its own self-test whole: {reply:?}"
        );
        let seen = self.snapshot();
        assert_eq!(
            seen.request_lines(),
            vec!["GET /self-test HTTP/1.1".to_string()],
            "the recorder records a direct request whole: {seen:?}"
        );
        assert!(seen.incomplete().is_empty(), "{seen:?}");
        self.shared.observations.lock().unwrap().clear();
    }

    /// Stop accepting, join the accept loop, shut down every stream still being read, join the
    /// handlers. Bounded by the shutdown, not by a peer's pace.
    fn stop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.accept_thread.take() {
            let _ = thread.join();
        }
        for (_, stream) in self.shared.active.lock().unwrap().iter() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        let handlers: Vec<std::thread::JoinHandle<()>> =
            std::mem::take(&mut *self.handlers.lock().unwrap());
        for handle in handlers {
            let _ = handle.join();
        }
    }
}

impl Drop for PlainRecorder {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Read one connection's request within the limits and deadline, answer a complete one.
fn observe(mut tcp: TcpStream) -> Observation {
    let read = read_head_and_body(&mut tcp, Instant::now() + CONNECTION_DEADLINE);
    let request_line = read
        .raw
        .split(|b| *b == b'\n')
        .next()
        .map(|line| {
            String::from_utf8_lossy(line)
                .trim_end_matches('\r')
                .to_string()
        })
        .filter(|line| line.contains("HTTP/"));
    let complete = read.complete && request_line.is_some();
    if complete {
        let _ = tcp.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nrecorder-ok",
        );
        let _ = tcp.flush();
    }
    let error = match (read.error, request_line.is_some()) {
        (Some(error), _) => Some(error),
        (None, false) => Some("no request line".to_string()),
        (None, true) => None,
    };
    Observation {
        request_line,
        raw: read.raw,
        complete,
        error,
    }
}

/// The outcome of one bounded head-and-body read: the bytes actually read, never padding.
#[derive(Debug)]
struct BoundedRead {
    raw: Vec<u8>,
    complete: bool,
    error: Option<String>,
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Arm the read timeout with the time left to `deadline`, or say the deadline passed.
fn arm_deadline(stream: &TcpStream, deadline: Instant) -> Result<(), String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("deadline exceeded".to_string());
    }
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|error| format!("set read timeout: {error}"))
}

/// Read an HTTP head plus a `Content-Length` body within the limits and a total `deadline`, naming
/// why the read stopped short when it did. The returned bytes are exactly those read.
fn read_head_and_body(stream: &mut TcpStream, deadline: Instant) -> BoundedRead {
    let stop = |raw: Vec<u8>, error: String| BoundedRead {
        raw,
        complete: false,
        error: Some(error),
    };
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    let head_end = loop {
        if buf.len() >= MAX_HEAD_BYTES {
            return stop(buf, format!("head exceeds {MAX_HEAD_BYTES} bytes"));
        }
        if let Err(error) = arm_deadline(stream, deadline) {
            let n = buf.len();
            return stop(buf, format!("{error} after {n} head bytes"));
        }
        match stream.read(&mut byte) {
            Ok(1) => buf.push(byte[0]),
            Ok(_) => return stop(buf, "closed before the end of the head".to_string()),
            Err(error) if is_timeout(&error) => {
                let n = buf.len();
                return stop(buf, format!("deadline exceeded after {n} head bytes"));
            }
            Err(error) => {
                let n = buf.len();
                return stop(buf, format!("reading the head after {n} bytes: {error}"));
            }
        }
        if buf.ends_with(b"\r\n\r\n") {
            break buf.len();
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let declared: Vec<&str> = head
        .split("\r\n")
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim())
        })
        .collect();
    let len = match declared.as_slice() {
        [] => 0,
        [one] => match one.parse::<usize>() {
            Ok(len) => len,
            Err(_) => return stop(buf, "malformed Content-Length".to_string()),
        },
        _ => return stop(buf, "repeated Content-Length".to_string()),
    };
    if len > MAX_BODY_BYTES {
        return stop(
            buf,
            format!("declared body {len} exceeds {MAX_BODY_BYTES} bytes"),
        );
    }
    let mut chunk = [0u8; 8192];
    let mut filled = 0usize;
    while filled < len {
        if let Err(error) = arm_deadline(stream, deadline) {
            return stop(buf, format!("{error} after {filled} of {len} body bytes"));
        }
        let want = (len - filled).min(chunk.len());
        match stream.read(&mut chunk[..want]) {
            Ok(0) => return stop(buf, format!("closed after {filled} of {len} body bytes")),
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                filled += n;
            }
            Err(error) if is_timeout(&error) => {
                return stop(
                    buf,
                    format!("deadline exceeded after {filled} of {len} body bytes"),
                );
            }
            Err(error) => {
                return stop(
                    buf,
                    format!("reading the body after {filled} of {len} bytes: {error}"),
                );
            }
        }
    }
    BoundedRead {
        raw: buf,
        complete: true,
        error: None,
    }
}

// ============================================================================================
// Gateway drivers
// ============================================================================================

fn proxy_port(handle: &MitmHandle) -> u16 {
    handle.port().expect("TCP-mode test always has a port")
}

fn start(config: MitmConfig, policy: Arc<RecordingPolicy>) -> MitmHandle {
    MitmInterceptor::start(config, CapabilitySet::default(), policy).unwrap()
}

/// One plaintext proxy exchange: write `request` to the proxy and read its whole reply to close.
/// A read error or a read timeout fails the test by name; only a clean EOF is a reply.
fn plain_exchange(proxy: u16, request: &[u8]) -> String {
    let mut tcp = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.write_all(request).unwrap();
    let mut reply = Vec::new();
    if let Err(error) = tcp.read_to_end(&mut reply) {
        panic!(
            "the proxy did not close the exchange cleanly ({error}); partial reply: {:?}",
            String::from_utf8_lossy(&reply)
        );
    }
    String::from_utf8_lossy(&reply).into_owned()
}

/// Write `request` to the proxy, then drop the socket without reading: a client killed mid-upload.
fn plain_abort(proxy: u16, request: &[u8]) {
    let mut tcp = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    tcp.write_all(request).unwrap();
    let _ = tcp.shutdown(std::net::Shutdown::Both);
}

/// The proxy's answer to `CONNECT authority`, as the raw head.
fn raw_connect(proxy: u16, authority: &str) -> String {
    let mut client = WorkloadClient::connect_raw(proxy);
    client.raw_connect_authority(authority)
}

/// How one destination spelling fared at the gateway. The classes are disjoint and exhaustive
/// for the outcomes these tests accept; anything else fails the test by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The CONNECT was acknowledged: the destination resolved and the authority permitted it.
    Tunneled,
    /// The authority refused (403, a recorded and denied connect attempt).
    PolicyDenied,
    /// The resolver could not answer for this spelling on this host (502, audit reason names the
    /// resolve). This proves nothing about the authority and is reported as such.
    Unresolvable,
}

/// Classify the proxy's reply to a CONNECT for `authority`, cross-checked against the audit log and
/// the authority's recorded attempts, and require the evidence to be internally consistent.
fn classify_connect(
    handle: &MitmHandle,
    policy: &RecordingPolicy,
    authority: &str,
    reply: &str,
) -> Outcome {
    let events = handle.drain_audit_events();
    let denies: Vec<String> = events
        .iter()
        .filter(|e| e.decision == AuditDecision::Deny)
        .map(|e| e.reason.clone())
        .collect();
    let connects = policy.connects();
    if reply.contains("200 Connection Established") {
        assert!(
            connects.iter().any(|c| matches!(
                c,
                Seen::Connect {
                    permitted: true,
                    ..
                }
            )),
            "{authority}: a tunnel needs a permitted connect attempt; attempts: {connects:?}"
        );
        return Outcome::Tunneled;
    }
    if reply.contains(" 502 ") {
        assert!(
            denies.iter().any(|r| r.contains("resolving")),
            "{authority}: a 502 must be the resolver's failure, audited as such; denies: {denies:?}"
        );
        assert!(
            connects.is_empty(),
            "{authority}: an unresolvable destination raises no connect attempt; attempts: {connects:?}"
        );
        return Outcome::Unresolvable;
    }
    assert!(
        reply.contains(" 403 "),
        "{authority}: expected 200, 403 or 502 from the gateway, got {reply:?}"
    );
    assert!(
        connects.iter().any(|c| matches!(
            c,
            Seen::Connect {
                permitted: false,
                ..
            }
        )),
        "{authority}: a 403 must be a recorded, denied connect attempt; denies: {denies:?}, attempts: {connects:?}"
    );
    Outcome::PolicyDenied
}

/// Whether this build's libc is glibc, whose `getaddrinfo` applies `inet_aton` spellings.
fn resolver_is_glibc() -> bool {
    cfg!(all(target_os = "linux", target_env = "gnu"))
}

// ============================================================================================
// 1. Resolve/check/dial binding: the address the authority permitted is the address dialed
// ============================================================================================

/// A permitted name pinned at loopback reaches a recorder there. The same name and the same
/// address-bound authority, with the resolver answering `::1` instead, is refused at CONNECT and
/// the recorder at `::1` sees no connection. The authority saw the second address and refused it;
/// the gateway did not fall back to the address it had permitted before.
#[test]
fn a_rebound_answer_is_refused_by_the_address_bound_authority_and_never_dialed() {
    let host = "pinned.rebind.test";
    let permitted_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    // The permitted destination: a TLS upstream at 127.0.0.1.
    let upstream = TlsUpstream::start(host);
    let port = upstream.port();

    // The rebound destination: a recorder at [::1] on the SAME port, or 127.0.0.2 where IPv6
    // loopback is absent. It must be a distinct address the authority never permitted. Its absence
    // is a required-setup failure that names both bind errors; the test never returns without it.
    let (rebound_ip, rebound) = bind_rebound_recorder(port, REBOUND_CANDIDATES)
        .unwrap_or_else(|why| panic!("required setup: {why}"));
    rebound.self_test();

    // Run 1: the resolver answers the permitted address.
    let policy = RecordingPolicy::permitting_host_at(host, permitted_ip);
    let handle = start(
        MitmConfig {
            upstream_ca_pems: vec![upstream.ca_pem()],
            dns_overrides: vec![(host.to_string(), permitted_ip)],
            ..MitmConfig::default()
        },
        policy.clone(),
    );
    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_request("GET", "/pinned", &[], b"");
    assert_eq!(
        client.read_status(),
        200,
        "the permitted address is reached"
    );
    assert!(upstream.last_request().raw.starts_with("GET /pinned "));
    assert_eq!(
        policy.connects(),
        vec![Seen::Connect {
            host: host.to_string(),
            port,
            address: SocketAddr::new(permitted_ip, port),
            permitted: true,
        }],
        "exactly the permitted address was asked about and dialed"
    );
    drop(handle);

    // Run 2: the same name and policy, the resolver now answers the rebound address.
    let policy = RecordingPolicy::permitting_host_at(host, permitted_ip);
    let handle = start(
        MitmConfig {
            upstream_ca_pems: vec![upstream.ca_pem()],
            dns_overrides: vec![(host.to_string(), rebound_ip)],
            ..MitmConfig::default()
        },
        policy.clone(),
    );
    let authority = bracketed(host, port);
    let reply = raw_connect(proxy_port(&handle), &authority);
    assert_eq!(
        classify_connect(&handle, &policy, &authority, &reply),
        Outcome::PolicyDenied,
        "the rebound address is refused by the address-bound authority: {reply:?}"
    );
    assert_eq!(
        policy.connects(),
        vec![Seen::Connect {
            host: host.to_string(),
            port,
            address: SocketAddr::new(rebound_ip, port),
            permitted: false,
        }],
        "the authority was asked about the rebound address and nothing else"
    );
    assert_eq!(
        rebound.connections(),
        0,
        "the rebound destination was never contacted"
    );
    assert_eq!(
        upstream.request_count(),
        1,
        "the permitted upstream saw only run 1"
    );

    // Fault control: the same rebound answer under a permit-everything authority DOES reach the
    // recorder, so the zero above is the authority's refusal and not a dead observer or route.
    let permissive = RecordingPolicy::permit_all();
    let handle = start(
        MitmConfig {
            dns_overrides: vec![(host.to_string(), rebound_ip)],
            ..MitmConfig::default()
        },
        permissive.clone(),
    );
    let reply = raw_connect(proxy_port(&handle), &authority);
    assert_eq!(
        classify_connect(&handle, &permissive, &authority, &reply),
        Outcome::Tunneled,
        "under a permissive fault the rebound address is dialed"
    );
    assert_eq!(
        rebound.connections(),
        1,
        "the recorder at the rebound address observes the permissive delivery"
    );
}

/// The loopback addresses, other than `127.0.0.1`, a rebound recorder may stand on.
const REBOUND_CANDIDATES: &[IpAddr] = &[
    IpAddr::V6(Ipv6Addr::LOCALHOST),
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
];

/// Bind a recorder on `port` at the first of `candidates` that accepts it. When none does, the
/// error names every candidate with its own bind error, so a missing second loopback address is a
/// named setup failure and never a silent success.
fn bind_rebound_recorder(
    port: u16,
    candidates: &[IpAddr],
) -> Result<(IpAddr, PlainRecorder), String> {
    let mut errors = Vec::new();
    for ip in candidates {
        match PlainRecorder::start_on(SocketAddr::new(*ip, port)) {
            Ok(recorder) => return Ok((*ip, recorder)),
            Err(error) => errors.push(format!("{ip}:{port}: {error}")),
        }
    }
    Err(format!(
        "no second loopback address could bind the rebound recorder on port {port}: {errors:?}"
    ))
}

/// The setup path cannot succeed without a recorder: with every candidate unable to bind (one
/// port already held, one address not assigned to this host), the helper returns an error that
/// names both candidates and both bind errors, and the calling test panics on it by name.
#[test]
fn a_missing_rebound_loopback_address_is_a_named_setup_failure() {
    // Hold [::1]:P (or 127.0.0.2:P where IPv6 loopback is absent) so it cannot be bound again.
    let holder = REBOUND_CANDIDATES
        .iter()
        .find_map(|ip| TcpListener::bind(SocketAddr::new(*ip, 0)).ok())
        .expect("required setup: one rebound candidate binds on this host");
    let held = holder.local_addr().unwrap();
    // TEST-NET-1 is not assigned to any host interface, so a bind on it fails.
    let unassigned = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let candidates = [held.ip(), unassigned];
    let error = bind_rebound_recorder(held.port(), &candidates)
        .err()
        .expect("no candidate can bind: the helper must not hand back a recorder");
    for candidate in &candidates {
        assert!(
            error.contains(&format!("{candidate}:{}", held.port())),
            "the setup failure names {candidate}: {error}"
        );
    }
    assert!(
        error.matches(": ").count() >= 2 && error.contains("no second loopback address"),
        "the setup failure carries both bind errors: {error}"
    );
    // The positive shape: a free port binds the first candidate that this host offers.
    let (ip, recorder) = bind_rebound_recorder(0, REBOUND_CANDIDATES)
        .unwrap_or_else(|why| panic!("required setup: {why}"));
    assert!(REBOUND_CANDIDATES.contains(&ip));
    recorder.self_test();
}

/// An IPv6 host is spelled bracketed in an authority; a name or IPv4 literal is bare.
fn bracketed(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

// ============================================================================================
// 2. Address spellings through parser, resolver and authority
// ============================================================================================

/// Loopback spelled in each `inet_aton` form. Rust's `IpAddr` parser accepts none of them, so each
/// goes to the resolver as a name. The authority sees the spelling as the workload wrote it and the
/// resolved address beside it.
const LOOPBACK_SPELLINGS: &[&str] = &["2130706433", "0x7f000001", "0177.0.0.1", "127.1", "0x7f.1"];

/// The metadata address in every spelling a workload might try: literals the parser reads
/// directly, with the address each one denotes, and `inet_aton` forms only the resolver reads.
const METADATA_LITERALS: &[(&str, &str)] = &[
    ("169.254.169.254", "169.254.169.254"),
    ("169.254.169.254.", "169.254.169.254"),
    ("[::ffff:169.254.169.254]", "::ffff:169.254.169.254"),
    ("[::ffff:a9fe:a9fe]", "::ffff:169.254.169.254"),
    ("[::169.254.169.254]", "::169.254.169.254"),
    ("[2002:a9fe:a9fe::]", "2002:a9fe:a9fe::"),
    ("[2001:0:0:0:0:0:5601:5601]", "2001::5601:5601"),
];
const METADATA_RESOLVER_SPELLINGS: &[&str] = &[
    "2852039166",
    "0xa9fea9fe",
    "0251.0376.0251.0376",
    "169.254.43518",
    "0xa9.0xfe.0xa9.0xfe",
];

/// What this host's own resolver answers for a spelling, asked independently of the gateway with
/// the same `getaddrinfo` the gateway uses. Every expectation below follows this observation.
fn host_resolution(spelling: &str, port: u16) -> Option<Vec<IpAddr>> {
    (spelling, port)
        .to_socket_addrs()
        .ok()
        .map(|addresses| addresses.map(|a| a.ip()).collect::<Vec<_>>())
        .filter(|addresses| !addresses.is_empty())
}

/// A loopback destination in any numeric spelling reaches a recorder only when the authority
/// permits that spelling at that address, and the authority is asked about the resolved address
/// under the raw spelling. The expectation for each spelling follows the host resolver, observed
/// independently: a spelling the host resolves to loopback tunnels to the recorder; one the host
/// resolves elsewhere (macOS reads `0177.0.0.1` as `177.0.0.1`) is refused by the loopback-bound
/// authority at that address and nothing is dialed; one the host does not resolve is unresolvable.
/// The permit is never widened past the owned loopback recorder, and on glibc every spelling
/// resolves to loopback.
#[test]
fn loopback_respellings_reach_the_recorder_only_through_the_resolver_and_the_authority() {
    let recorder = PlainRecorder::start();
    recorder.self_test();
    let port = recorder.port();
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);

    // Control: the canonical literal, permitted at loopback, tunnels to the recorder.
    let policy = RecordingPolicy::permitting_host_at("127.0.0.1", loopback);
    let handle = start(MitmConfig::default(), policy.clone());
    let authority = format!("127.0.0.1:{port}");
    let reply = raw_connect(proxy_port(&handle), &authority);
    assert_eq!(
        classify_connect(&handle, &policy, &authority, &reply),
        Outcome::Tunneled
    );
    assert_eq!(
        recorder.connections(),
        1,
        "the canonical control reaches the recorder"
    );
    drop(handle);

    let mut to_loopback = Vec::new();
    let mut off_loopback = Vec::new();
    let mut unresolvable = Vec::new();
    for spelling in LOOPBACK_SPELLINGS {
        let observed = host_resolution(spelling, port);
        // Permitted in this spelling, and only at loopback: the authority sees the raw spelling as
        // `host` and the resolved address beside it.
        let policy = RecordingPolicy::permitting_host_at(spelling, loopback);
        let handle = start(MitmConfig::default(), policy.clone());
        let before = recorder.connections();
        let authority = format!("{spelling}:{port}");
        let reply = raw_connect(proxy_port(&handle), &authority);
        let outcome = classify_connect(&handle, &policy, &authority, &reply);
        match observed.as_deref() {
            None => {
                assert_eq!(
                    outcome,
                    Outcome::Unresolvable,
                    "{spelling}: the host resolver refuses it, so the gateway cannot resolve it either"
                );
                assert_eq!(
                    recorder.connections(),
                    before,
                    "{spelling}: nothing was dialed"
                );
                unresolvable.push(*spelling);
            }
            Some([first, ..]) if first.is_loopback() => {
                assert_eq!(
                    outcome,
                    Outcome::Tunneled,
                    "{spelling}: the host resolves it to {first}, permitted at loopback"
                );
                assert_eq!(
                    policy.connects(),
                    vec![Seen::Connect {
                        host: (*spelling).to_string(),
                        port,
                        address: SocketAddr::new(*first, port),
                        permitted: true,
                    }],
                    "{spelling}: the authority saw the raw spelling and the resolved loopback address"
                );
                assert_eq!(
                    recorder.connections(),
                    before + 1,
                    "{spelling}: the permitted spelling reached the recorder"
                );
                to_loopback.push((*spelling, *first));
            }
            Some([first, ..]) => {
                // The host reads the spelling as another address. The loopback-only authority
                // refuses that address, the gateway dials nothing, and the recorder is untouched.
                // The permit is not widened to make this pass.
                assert_eq!(
                    outcome,
                    Outcome::PolicyDenied,
                    "{spelling}: the host resolves it to {first}, which the loopback-only authority refuses"
                );
                assert_eq!(
                    policy.connects(),
                    vec![Seen::Connect {
                        host: (*spelling).to_string(),
                        port,
                        address: SocketAddr::new(*first, port),
                        permitted: false,
                    }],
                    "{spelling}: the authority refused exactly the address the host resolved, and no other address was asked about or dialed"
                );
                assert_eq!(
                    recorder.connections(),
                    before,
                    "{spelling}: the recorder saw no delivery for a refused address"
                );
                off_loopback.push((*spelling, *first));
            }
            Some([]) => unreachable!("host_resolution filters empty answers"),
        }
        drop(handle);

        // The same spelling, when the authority permits only the canonical literal, is refused
        // whatever it resolves to: the authority judges the spelling, and the recorder sees nothing.
        let policy = RecordingPolicy::permitting_host_at("127.0.0.1", loopback);
        let handle = start(MitmConfig::default(), policy.clone());
        let before = recorder.connections();
        let reply = raw_connect(proxy_port(&handle), &authority);
        let outcome = classify_connect(&handle, &policy, &authority, &reply);
        let expected = if observed.is_some() {
            Outcome::PolicyDenied
        } else {
            Outcome::Unresolvable
        };
        assert_eq!(
            outcome, expected,
            "{spelling}: a spelling the authority did not permit must not tunnel"
        );
        assert_eq!(
            recorder.connections(),
            before,
            "{spelling}: the recorder saw no delivery for a refused spelling"
        );
    }
    eprintln!(
        "loopback spellings to loopback: {to_loopback:?}; resolved off loopback and refused: {off_loopback:?}; unresolvable on this host: {unresolvable:?}"
    );
    if resolver_is_glibc() {
        assert!(
            unresolvable.is_empty() && off_loopback.is_empty(),
            "glibc getaddrinfo applies inet_aton, so every spelling resolves to loopback: unresolvable {unresolvable:?}, off loopback {off_loopback:?}"
        );
    }
}

/// The Mac's resolution of `0177.0.0.1`, reproduced on any host through the gateway's static
/// resolver override: the spelling answers `177.0.0.1`. The loopback-bound authority refuses that
/// address, the gateway dials nothing, and the recorder is untouched. The control is the same
/// spelling overridden to loopback, which tunnels. No permit is widened, and the off-loopback
/// address is never dialed: the authority refuses before any socket opens.
#[test]
fn a_spelling_the_resolver_reads_off_loopback_is_refused_before_any_dial() {
    let recorder = PlainRecorder::start();
    recorder.self_test();
    let port = recorder.port();
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let spelling = "0177.0.0.1";
    let elsewhere: IpAddr = "177.0.0.1".parse().unwrap();
    let authority = format!("{spelling}:{port}");

    let policy = RecordingPolicy::permitting_host_at(spelling, loopback);
    let handle = start(
        MitmConfig {
            dns_overrides: vec![(spelling.to_string(), elsewhere)],
            ..MitmConfig::default()
        },
        policy.clone(),
    );
    let reply = raw_connect(proxy_port(&handle), &authority);
    assert_eq!(
        classify_connect(&handle, &policy, &authority, &reply),
        Outcome::PolicyDenied,
        "{spelling} read as {elsewhere} is refused by the loopback-only authority: {reply:?}"
    );
    assert_eq!(
        policy.connects(),
        vec![Seen::Connect {
            host: spelling.to_string(),
            port,
            address: SocketAddr::new(elsewhere, port),
            permitted: false,
        }],
        "the authority refused exactly the off-loopback address, once, before any dial"
    );
    assert_eq!(recorder.connections(), 0, "nothing reached the recorder");
    drop(handle);

    // Control: the same spelling read as loopback tunnels to the recorder under the same policy.
    let policy = RecordingPolicy::permitting_host_at(spelling, loopback);
    let handle = start(
        MitmConfig {
            dns_overrides: vec![(spelling.to_string(), loopback)],
            ..MitmConfig::default()
        },
        policy.clone(),
    );
    let reply = raw_connect(proxy_port(&handle), &authority);
    assert_eq!(
        classify_connect(&handle, &policy, &authority, &reply),
        Outcome::Tunneled
    );
    assert_eq!(
        recorder.connections(),
        1,
        "the loopback reading reaches the recorder"
    );
}

/// Every spelling of the metadata address reaches the authority as a connect attempt for the
/// address it denotes, and nothing is dialed when the authority refuses it. Literal forms need no
/// resolver; `inet_aton` forms reach the authority only if the resolver reads them, and a resolver
/// refusal is reported as unresolvable.
#[test]
fn every_spelling_of_the_metadata_address_reaches_the_authority_as_that_address() {
    let policy = RecordingPolicy::refuse_all();
    let handle = start(MitmConfig::default(), policy.clone());
    let proxy = proxy_port(&handle);
    let metadata: IpAddr = "169.254.169.254".parse().unwrap();

    for (spelling, denoted) in METADATA_LITERALS {
        let authority = format!("{spelling}:80");
        let reply = raw_connect(proxy, &authority);
        let denoted: IpAddr = denoted.parse().unwrap();
        assert_eq!(
            classify_connect(&handle, &policy, &authority, &reply),
            Outcome::PolicyDenied,
            "{spelling}: a literal spelling needs no resolver and reaches the authority: {reply:?}"
        );
        assert!(
            policy
                .connects()
                .iter()
                .all(|c| matches!(c, Seen::Connect { address, .. } if address.ip() == denoted)),
            "{spelling}: the authority is asked about {denoted}: {:?}",
            policy.connects()
        );
        policy.clear();
    }

    let mut unresolvable = Vec::new();
    for spelling in METADATA_RESOLVER_SPELLINGS {
        let authority = format!("{spelling}:80");
        let reply = raw_connect(proxy, &authority);
        match classify_connect(&handle, &policy, &authority, &reply) {
            Outcome::PolicyDenied => assert!(
                policy.connects().iter().all(
                    |c| matches!(c, Seen::Connect { address, .. } if address.ip() == metadata)
                ),
                "{spelling}: the resolver reads it as the metadata address: {:?}",
                policy.connects()
            ),
            Outcome::Unresolvable => unresolvable.push(*spelling),
            other => panic!("{spelling}: refused or unresolvable, not {other:?}: {reply:?}"),
        }
        policy.clear();
    }
    eprintln!("metadata resolver spellings unresolvable on this host: {unresolvable:?}");
    if resolver_is_glibc() {
        assert!(
            unresolvable.is_empty(),
            "glibc getaddrinfo applies inet_aton, so every spelling reaches the authority: {unresolvable:?}"
        );
    }
}

/// The plain-HTTP absolute-form path converges on the same controls: a metadata spelling reaches
/// the authority as the metadata address and opens no upstream socket, and a permitted loopback
/// spelling reaches the recorder with a canonical `Host` rebuilt from the spelling the authority
/// judged.
#[test]
fn absolute_form_spellings_meet_the_same_authority() {
    let recorder = PlainRecorder::start();
    recorder.self_test();
    let port = recorder.port();
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);

    let policy = RecordingPolicy::with_rule(move |host, address| {
        (host == "2130706433" || host == "127.0.0.1") && address.ip() == loopback
    });
    let handle = start(MitmConfig::default(), policy.clone());
    let proxy = proxy_port(&handle);

    // The decimal spelling of the metadata address, absolute-form.
    let reply = plain_exchange(
        proxy,
        b"GET http://2852039166/latest/meta-data/ HTTP/1.1\r\nHost: 2852039166\r\nConnection: close\r\n\r\n",
    );
    let metadata: IpAddr = "169.254.169.254".parse().unwrap();
    let asked = policy.connects();
    if reply.starts_with("HTTP/1.1 502") && !resolver_is_glibc() {
        assert!(
            asked.is_empty(),
            "an unresolvable spelling asks nothing: {asked:?}"
        );
    } else {
        assert!(
            reply.starts_with("HTTP/1.1 403")
                && !asked.is_empty()
                && asked.iter().all(|c| matches!(
                    c,
                    Seen::Connect { address, permitted: false, .. } if address.ip() == metadata
                )),
            "the decimal metadata spelling is refused on the metadata address: {reply:?} {asked:?}"
        );
    }
    policy.clear();
    assert!(!reply.contains("200 OK"));

    // Control: a permitted decimal loopback spelling reaches the recorder, and the wire `Host` is
    // the authority the gateway judged.
    let reply = plain_exchange(
        proxy,
        format!("GET http://2130706433:{port}/spelled HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    );
    if reply.starts_with("HTTP/1.1 502") && !resolver_is_glibc() {
        eprintln!("skipping: this host's resolver does not read 2130706433");
        return;
    }
    assert!(
        reply.starts_with("HTTP/1.1 200") && reply.ends_with("recorder-ok"),
        "the permitted spelling reaches the recorder: {reply:?}"
    );
    let snapshot = recorder.snapshot();
    assert!(snapshot.incomplete().is_empty(), "{snapshot:?}");
    let seen = snapshot.requests();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].starts_with("GET /spelled HTTP/1.1"));
    assert!(
        seen[0].contains(&format!("\r\nHost: 2130706433:{port}\r\n")),
        "Host is rebuilt from the judged authority, not the workload's header: {}",
        seen[0]
    );
    assert_eq!(
        policy.requests(),
        vec![Seen::Request {
            method: "GET".to_string(),
            path: "/spelled".to_string(),
        }]
    );
}

// ============================================================================================
// 3. Proxy robustness: aborts and framing faults deliver nothing and leave the gateway serving
// ============================================================================================

/// Start a gateway that permits `host` pinned at loopback and trusts `upstream`.
fn gateway_for(host: &str, upstream: &TlsUpstream) -> (MitmHandle, Arc<RecordingPolicy>) {
    let policy = RecordingPolicy::permitting_host_at(host, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let handle = start(
        MitmConfig {
            upstream_ca_pems: vec![upstream.ca_pem()],
            dns_overrides: vec![(host.to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST))],
            ..MitmConfig::default()
        },
        policy.clone(),
    );
    (handle, policy)
}

/// The allowed control after a fault: a fresh complete request through the same gateway succeeds.
fn assert_still_serving(handle: &MitmHandle, host: &str, upstream: &TlsUpstream, path: &str) {
    let mut client = WorkloadClient::connect(proxy_port(handle), host, upstream.port());
    client.send_request("GET", path, &[], b"");
    assert_eq!(
        client.read_status(),
        200,
        "the gateway serves a complete request after the fault"
    );
    assert!(
        upstream
            .last_request()
            .raw
            .starts_with(&format!("GET {path} ")),
        "the control request reached the upstream"
    );
}

/// A client that sends a Content-Length head, part of the body, and dies. The gateway buffers the
/// whole request before it forwards, so the upstream receives zero request bytes, the fault is
/// audited, and the next request is served.
#[test]
fn an_upload_aborted_mid_body_delivers_nothing_and_the_gateway_keeps_serving() {
    let host = "abort.upload.test";
    // The upload's destination is a byte-counting recorder, so "nothing" is a count of zero bytes
    // and not only an absence of a parsed request.
    let recorder = PlainRecorder::start();
    recorder.self_test();
    let upstream = TlsUpstream::start(host);
    let (handle, policy) = gateway_for(host, &upstream);

    let mut client = WorkloadClient::connect(proxy_port(&handle), host, recorder.port());
    client.send_raw(
        format!(
            "POST /upload HTTP/1.1\r\nHost: {host}:{}\r\nContent-Length: 65536\r\n\r\n",
            recorder.port()
        )
        .as_bytes(),
    );
    client.send_raw(&[b'x'; 1024]);
    client.abort();

    // The upstream socket is opened at CONNECT (before the request is read), so one connection
    // exists; it carries no bytes and no request.
    assert_eq!(
        recorder.bytes(),
        0,
        "no upload byte reached the destination"
    );
    assert!(
        recorder.request_lines().is_empty(),
        "no request reached the destination"
    );
    assert!(
        policy.requests().is_empty(),
        "no request effect was raised for an incomplete upload"
    );
    let audited = wait_for_audit(&handle, "connection handler error");
    assert!(
        audited,
        "the aborted connection is audited, not silently swallowed"
    );

    assert_still_serving(&handle, host, &upstream, "/after-abort");
}

/// The chunked form of the same abort: one chunk, no terminator, then the client dies.
#[test]
fn a_chunked_upload_aborted_before_its_terminator_delivers_nothing() {
    let host = "abort.chunked.test";
    let recorder = PlainRecorder::start();
    recorder.self_test();
    let upstream = TlsUpstream::start(host);
    let (handle, policy) = gateway_for(host, &upstream);

    let mut client = WorkloadClient::connect(proxy_port(&handle), host, recorder.port());
    client.send_raw(
        format!(
            "POST /truncated HTTP/1.1\r\nHost: {host}:{}\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nchunk1\r\n",
            recorder.port()
        )
        .as_bytes(),
    );
    client.abort();

    assert_eq!(recorder.bytes(), 0, "no chunk reached the destination");
    assert!(policy.requests().is_empty());
    assert!(wait_for_audit(&handle, "connection handler error"));
    assert_still_serving(&handle, host, &upstream, "/after-chunked-abort");
}

/// On the plain-HTTP path the request is read before any upstream socket opens, so an aborted
/// upload opens nothing at all, and a completed one is served afterwards.
#[test]
fn a_plain_http_upload_aborted_mid_body_opens_no_upstream_socket() {
    let recorder = PlainRecorder::start();
    recorder.self_test();
    let port = recorder.port();
    let policy = RecordingPolicy::permitting_host_at("127.0.0.1", IpAddr::V4(Ipv4Addr::LOCALHOST));
    let handle = start(MitmConfig::default(), policy.clone());
    let proxy = proxy_port(&handle);

    plain_abort(
        proxy,
        format!("POST http://127.0.0.1:{port}/abort HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 9999999\r\n\r\npartial...")
            .as_bytes(),
    );
    assert_eq!(recorder.connections(), 0, "no upstream socket was opened");
    assert!(policy.connects().is_empty(), "no connect effect was raised");

    let reply = plain_exchange(
        proxy,
        format!("GET http://127.0.0.1:{port}/alive HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    );
    assert!(
        reply.starts_with("HTTP/1.1 200"),
        "served after the abort: {reply:?}"
    );
    assert_eq!(
        recorder.request_lines(),
        vec!["GET /alive HTTP/1.1".to_string()]
    );
}

/// Every framing ambiguity a smuggling attempt rides on is refused before any request effect and
/// before any upstream request: both lengths present (CL.TE and TE.CL), an obfuscated or repeated
/// transfer coding, and a repeated Content-Length. Over TLS the gateway drops the connection; the
/// client sees no 200, and the upstream sees no request.
#[test]
fn framing_ambiguity_is_refused_before_any_upstream_request() {
    let host = "framing.test";
    let upstream = TlsUpstream::start(host);
    let (handle, policy) = gateway_for(host, &upstream);
    let port = upstream.port();

    let cases: &[(&str, String)] = &[
        (
            "CL.TE",
            format!(
                "POST /legit HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
            ),
        ),
        (
            "TE.CL",
            format!(
                "POST /legit HTTP/1.1\r\nHost: {host}:{port}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGPOST /smuggled HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n"
            ),
        ),
        (
            "TE obfuscated",
            format!(
                "POST /legit HTTP/1.1\r\nHost: {host}:{port}\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n"
            ),
        ),
        (
            "TE list",
            format!(
                "POST /legit HTTP/1.1\r\nHost: {host}:{port}\r\nTransfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n"
            ),
        ),
        (
            "TE repeated",
            format!(
                "POST /legit HTTP/1.1\r\nHost: {host}:{port}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            ),
        ),
        (
            "CL repeated",
            format!(
                "POST /legit HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"
            ),
        ),
    ];
    for (name, request) in cases {
        let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
        client.send_raw(request.as_bytes());
        let status = client.read_status();
        assert_ne!(
            status, 200,
            "{name}: an ambiguous frame must not be answered 200"
        );
        assert_eq!(
            upstream.request_count(),
            0,
            "{name}: no request reached the upstream"
        );
        assert!(
            policy.requests().is_empty(),
            "{name}: no request effect was raised: {:?}",
            policy.requests()
        );
        assert!(
            wait_for_audit(&handle, "connection handler error"),
            "{name}: the refused frame is audited"
        );
    }

    assert_still_serving(&handle, host, &upstream, "/after-framing");
}

/// A second request riding a complete first one, in the same TLS connection, is never forwarded:
/// the gateway forwards exactly one request per connection, re-framed with its own Content-Length.
#[test]
fn a_second_request_riding_a_complete_first_one_is_not_forwarded() {
    let host = "pipeline.test";
    let upstream = TlsUpstream::start(host);
    let (handle, policy) = gateway_for(host, &upstream);
    let port = upstream.port();

    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_raw(
        format!(
            "POST /legit HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Length: 5\r\n\r\nhello\
             GET /admin HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(client.read_status(), 200, "the first request is served");

    let seen = upstream.last_request();
    assert!(seen.raw.starts_with("POST /legit "), "{}", seen.raw);
    assert_eq!(seen.header("content-length").as_deref(), Some("5"));
    assert!(seen.raw.ends_with("hello"), "{}", seen.raw);
    assert!(
        !seen.raw.contains("/admin"),
        "the riding request must not reach the upstream: {}",
        seen.raw
    );
    assert_eq!(
        upstream.request_count(),
        1,
        "exactly one request was forwarded"
    );
    assert_eq!(
        policy.requests(),
        vec![Seen::Request {
            method: "POST".to_string(),
            path: "/legit".to_string(),
        }],
        "exactly one request effect was raised"
    );
}

/// A chunked GET whose body is a second request is forwarded as ONE request whose body is that
/// text under a Content-Length, so the upstream cannot read it as a request.
#[test]
fn a_request_smuggled_inside_a_chunked_body_is_forwarded_as_body_bytes_only() {
    let host = "smuggle.test";
    let upstream = TlsUpstream::start(host);
    let (handle, policy) = gateway_for(host, &upstream);
    let port = upstream.port();

    let smuggled =
        format!("POST /admin HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Length: 0\r\n\r\n");
    let mut client = WorkloadClient::connect(proxy_port(&handle), host, port);
    client.send_raw(
        format!(
            "GET /legit HTTP/1.1\r\nHost: {host}:{port}\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{smuggled}\r\n0\r\n\r\n",
            smuggled.len()
        )
        .as_bytes(),
    );
    assert_eq!(client.read_status(), 200);

    let seen = upstream.last_request();
    assert!(seen.raw.starts_with("GET /legit "), "{}", seen.raw);
    assert_eq!(
        seen.header("content-length").as_deref(),
        Some(smuggled.len().to_string().as_str()),
        "the body is re-framed under one Content-Length"
    );
    assert_eq!(seen.header("transfer-encoding"), None);
    let (head, body) = seen.raw.split_once("\r\n\r\n").expect("one head, one body");
    assert!(
        !head.contains("/admin"),
        "the head names one request: {head}"
    );
    assert_eq!(body, smuggled, "the smuggled text arrives as body bytes");
    assert_eq!(upstream.request_count(), 1);
    assert_eq!(policy.requests().len(), 1);
}

/// A malformed request line on the plain path is answered 400 with no upstream socket; over TLS
/// the connection is dropped. Neither crashes the gateway.
#[test]
fn a_malformed_request_line_is_refused_without_an_upstream_socket() {
    let recorder = PlainRecorder::start();
    recorder.self_test();
    let port = recorder.port();
    let policy = RecordingPolicy::permitting_host_at("127.0.0.1", IpAddr::V4(Ipv4Addr::LOCALHOST));
    let handle = start(MitmConfig::default(), policy.clone());
    let proxy = proxy_port(&handle);

    let reply = plain_exchange(proxy, b"\x16\x03\x01 garbage that is not HTTP\r\n\r\n");
    assert!(
        reply.starts_with("HTTP/1.1 400") || reply.is_empty(),
        "garbage is a 400 or a close, never a tunnel: {reply:?}"
    );
    let reply = plain_exchange(
        proxy,
        format!("GET /origin-form-without-connect HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
            .as_bytes(),
    );
    assert!(
        reply.starts_with("HTTP/1.1 400"),
        "an origin-form target names no destination: {reply:?}"
    );
    assert_eq!(recorder.connections(), 0);
    assert!(policy.connects().is_empty());

    let reply = plain_exchange(
        proxy,
        format!("GET http://127.0.0.1:{port}/alive HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    );
    assert!(
        reply.starts_with("HTTP/1.1 200"),
        "served after the faults: {reply:?}"
    );
}

// ============================================================================================
// 4. The observer itself: what a zero from the recorder is allowed to mean
// ============================================================================================

/// A truncated body is an incomplete observation carrying exactly the bytes read (no padding), a
/// bare connect and a head-less connection are named, and the complete list stays empty.
#[test]
fn the_recorder_keeps_actual_bytes_and_names_incomplete_connections() {
    let recorder = PlainRecorder::start();
    recorder.self_test();
    let mut tcp = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
    tcp.write_all(b"POST /short HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\n\r\npartial")
        .unwrap();
    drop(tcp);
    drop(TcpStream::connect(("127.0.0.1", recorder.port())).unwrap());
    let mut tcp = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
    tcp.write_all(b"garbage\r\n\r\n").unwrap();
    drop(tcp);

    let snapshot = recorder.snapshot();
    assert_eq!(snapshot.observations.len(), 3, "{snapshot:?}");
    assert!(snapshot.request_lines().is_empty(), "{snapshot:?}");
    let incomplete = snapshot.incomplete();
    assert_eq!(incomplete.len(), 3);
    let short = incomplete
        .iter()
        .find(|o| o.request_line.as_deref() == Some("POST /short HTTP/1.1"))
        .expect("the truncated request is observed");
    assert!(
        short.raw.ends_with(b"partial"),
        "actual bytes, no padding: {:?}",
        short.raw
    );
    assert_eq!(
        short.raw.len(),
        b"POST /short HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\n\r\npartial".len()
    );
    assert!(
        short
            .error
            .as_deref()
            .is_some_and(|e| e.contains("closed after 7 of 100 body bytes")),
        "{:?}",
        short.error
    );
    assert!(incomplete.iter().any(|o| {
        o.raw.is_empty()
            && o.error
                .as_deref()
                .is_some_and(|e| e.contains("closed before the end of the head"))
    }));
    assert!(
        incomplete
            .iter()
            .any(|o| o.error.as_deref() == Some("no request line"))
    );
    assert_eq!(snapshot.bytes(), short.raw.len() + b"garbage\r\n\r\n".len());
}

/// A dribbling peer cannot hold `stop`: the accept loop is joined, the stream is shut down, and the
/// handler ends, well inside the connection deadline.
#[test]
fn the_recorder_stops_promptly_under_a_dribbling_peer() {
    let mut recorder = PlainRecorder::start();
    recorder.self_test();
    let mut peer = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
    peer.write_all(b"G").unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let dribbler = std::thread::spawn(move || {
        for _ in 0..10 {
            std::thread::sleep(Duration::from_millis(300));
            if peer.write_all(b"x").is_err() {
                break;
            }
        }
    });
    let started = Instant::now();
    recorder.stop();
    assert!(
        started.elapsed() < Duration::from_millis(1000),
        "stop waited on the shutdown, not the peer: {:?}",
        started.elapsed()
    );
    assert!(recorder.handlers.lock().unwrap().is_empty());
    let observations = recorder.shared.observations.lock().unwrap().clone();
    assert_eq!(observations.len(), 1, "{observations:?}");
    assert!(!observations[0].complete);
    let _ = dribbler.join();
}

/// A connection completed before a snapshot is asked for is in that snapshot, every time, with no
/// scheduling grace: the barrier ticket is taken before the sweep that answers it.
#[test]
fn the_recorder_snapshot_includes_every_connection_completed_before_it_was_asked() {
    let recorder = PlainRecorder::start();
    recorder.self_test();
    for i in 0..25 {
        let mut tcp = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
        tcp.set_read_timeout(Some(CONNECTION_DEADLINE)).unwrap();
        tcp.write_all(format!("GET /n{i} HTTP/1.1\r\nHost: h\r\n\r\n").as_bytes())
            .unwrap();
        let reply = read_head_and_body(&mut tcp, Instant::now() + CONNECTION_DEADLINE);
        assert!(reply.complete, "{reply:?}");
        let snapshot = recorder.snapshot();
        assert_eq!(snapshot.observations.len(), i + 1, "{snapshot:?}");
        assert!(snapshot.incomplete().is_empty(), "{snapshot:?}");
    }
}

/// A request that arrives in two parts after the accept is read whole under the connection
/// deadline: the accepted stream blocks. On BSD and macOS an accepted socket inherits the
/// listener's O_NONBLOCK, which made every read fail at once; Linux never inherited it, so this is
/// the control there and the regression on macOS.
#[test]
fn the_recorder_reads_a_delayed_request_whole_from_its_nonblocking_listener() {
    let recorder = PlainRecorder::start();
    recorder.self_test();
    let mut tcp = TcpStream::connect(("127.0.0.1", recorder.port())).unwrap();
    tcp.set_read_timeout(Some(CONNECTION_DEADLINE)).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    tcp.write_all(b"GET /late HTTP/1.1\r\nHost: h\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    tcp.write_all(b"\r\n").unwrap();
    let reply = read_head_and_body(&mut tcp, Instant::now() + CONNECTION_DEADLINE);
    assert!(
        reply.complete && reply.raw.starts_with(b"HTTP/1.1 200"),
        "{reply:?}"
    );
    let snapshot = recorder.snapshot();
    assert_eq!(
        snapshot.request_lines(),
        vec!["GET /late HTTP/1.1".to_string()]
    );
    assert!(snapshot.incomplete().is_empty(), "{snapshot:?}");
}

/// Poll the audit log for a deny whose reason contains `needle`; the handler thread audits after
/// the client has already gone.
fn wait_for_audit(handle: &MitmHandle, needle: &str) -> bool {
    for _ in 0..50 {
        if handle
            .drain_audit_events()
            .iter()
            .any(|e| e.decision == AuditDecision::Deny && e.reason.contains(needle))
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}
