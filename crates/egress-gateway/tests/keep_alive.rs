//! Client keep-alive: one client connection carries many requests in turn, in a CONNECT tunnel and
//! on a plain-HTTP connection.
//!
//! Each request still opens its own governed upstream socket, with its own `Resolve` and `Connect`
//! decisions, so a request on a kept-alive connection records the same attempts as the same request
//! on a connection of its own. Every reply that the gateway writes itself closes the connection, as
//! does a reply to an HTTP/1.0 request, to a request with `Connection: close`, and to a request that
//! names `Upgrade`. When a new connection finds no free slot, the oldest connection that waits
//! between requests gives its slot back.

#![cfg(feature = "tls-intercept")]

mod harness;

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use egress_gateway::{
    AuditDecision, CapabilitySet, EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit,
    MitmConfig, MitmHandle, MitmInterceptor, PROXY_ORIGIN_HEADER, PROXY_ORIGIN_VALUE, StubEmitter,
};

use harness::{TlsUpstream, WorkloadClient};

/// The reply of a fixture upstream that does not say `Connection: close`.
const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// How long a test waits for the gateway to end a connection.
const END_WAIT: Duration = Duration::from_secs(5);

/// An authority that keeps each attempt and each outcome, in order, and permits each attempt but
/// the `Connect` attempts after the first `connects`.
struct Log {
    attempts: Mutex<Vec<String>>,
    outcomes: Arc<Mutex<Vec<String>>>,
    connects: AtomicUsize,
}

impl Log {
    fn permit_all() -> Arc<Self> {
        Self::permitting_connects(usize::MAX)
    }

    fn permitting_connects(connects: usize) -> Arc<Self> {
        Arc::new(Self {
            attempts: Mutex::new(Vec::new()),
            outcomes: Arc::new(Mutex::new(Vec::new())),
            connects: AtomicUsize::new(connects),
        })
    }

    fn attempts(&self) -> Vec<String> {
        self.attempts.lock().unwrap().clone()
    }

    /// The attempts of one kind, by the start of their `Debug` text.
    fn of_kind(&self, kind: &str) -> Vec<String> {
        self.attempts()
            .into_iter()
            .filter(|attempt| attempt.starts_with(kind))
            .collect()
    }

    fn outcomes(&self) -> Vec<String> {
        self.outcomes.lock().unwrap().clone()
    }
}

struct LoggedPermit(Arc<Mutex<Vec<String>>>);

impl EffectPermit for LoggedPermit {
    fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
        self.0.lock().unwrap().push(format!("{outcome:?}"));
        Ok(())
    }
    fn mark_indeterminate(self: Box<Self>) {
        self.0.lock().unwrap().push("Indeterminate".to_string());
    }
}

impl EffectInterceptor for Log {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        self.attempts.lock().unwrap().push(format!("{attempt:?}"));
        if matches!(attempt, EffectAttempt::Connect { .. })
            && self
                .connects
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                })
                .is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "denied by test policy",
            ));
        }
        Ok(Box::new(LoggedPermit(Arc::clone(&self.outcomes))))
    }
}

/// A gateway that trusts each upstream and pins each of `hosts` to loopback.
fn gateway(
    upstreams: &[&TlsUpstream],
    hosts: &[&str],
    log: &Arc<Log>,
    tune: impl FnOnce(&mut MitmConfig),
) -> (MitmHandle, StubEmitter) {
    let mut config = MitmConfig {
        upstream_ca_pems: upstreams.iter().map(|upstream| upstream.ca_pem()).collect(),
        dns_overrides: hosts
            .iter()
            .map(|host| (host.to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST)))
            .collect(),
        ..MitmConfig::default()
    };
    tune(&mut config);
    let emitter = StubEmitter::new();
    let handle = MitmInterceptor::start_with_emitter(
        config,
        CapabilitySet::default(),
        log.clone(),
        Box::new(emitter.clone()),
    )
    .unwrap();
    (handle, emitter)
}

fn port(handle: &MitmHandle) -> u16 {
    handle.port().expect("a TCP gateway has a port")
}

/// A `GET` with no body and no `Connection` field, as a client that keeps its connection.
fn get(host: &str, port: u16, path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n")
}

/// Whether `reply` carries the refusal marker.
fn is_marked(reply: &str) -> bool {
    reply.to_ascii_lowercase().contains(&format!(
        "{}: {}",
        PROXY_ORIGIN_HEADER.to_ascii_lowercase(),
        PROXY_ORIGIN_VALUE
    ))
}

/// Whether `reply` says that the connection closes after it.
fn says_close(reply: &str) -> bool {
    reply
        .to_ascii_lowercase()
        .contains("\r\nconnection: close\r\n")
}

/// **One tunnel serves several requests in turn**, each on its own upstream socket. The fixture
/// upstream serves one request for each socket and says `Connection: close`, so the third reply
/// also shows that an upstream close does not close the client connection, and that a request with
/// no framing has no body: the next bytes are the next head.
#[test]
fn a_tunnel_serves_several_requests_in_turn() {
    let host = "turns.test";
    let upstream = TlsUpstream::start(host);
    let log = Log::permit_all();
    let (handle, _) = gateway(&[&upstream], &[host], &log, |_| {});
    let mut client = WorkloadClient::connect(port(&handle), host, upstream.port());
    for path in ["/one", "/two", "/three"] {
        client.send_raw(get(host, upstream.port(), path).as_bytes());
        let reply = client.read_response();
        assert_eq!(
            reply, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            "{path}"
        );
    }
    let paths: Vec<String> = upstream
        .requests()
        .iter()
        .map(|seen| seen.raw.lines().next().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        paths,
        [
            "GET /one HTTP/1.1",
            "GET /two HTTP/1.1",
            "GET /three HTTP/1.1"
        ]
    );
    assert_eq!(
        log.of_kind("Connect").len(),
        3,
        "one socket for each request"
    );
}

/// **A kept-alive tunnel records the same attempts as one tunnel for each request**: the same
/// kinds, hosts, ports, addresses, methods, paths, lengths, and `intercepted`, in the same order,
/// and the same outcomes.
#[test]
fn a_kept_alive_tunnel_records_the_same_attempts_as_one_tunnel_per_request() {
    let host = "same.test";
    let upstream = TlsUpstream::start_with_response(host, OK);
    let requests = |port: u16| {
        [
            get(host, port, "/a"),
            format!("POST /b HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Length: 3\r\n\r\nabc"),
        ]
    };

    let kept = Log::permit_all();
    let (handle, _) = gateway(&[&upstream], &[host], &kept, |_| {});
    let mut client = WorkloadClient::connect(port(&handle), host, upstream.port());
    for request in requests(upstream.port()) {
        client.send_raw(request.as_bytes());
        assert_eq!(client.read_status(), 200);
    }
    drop(client);

    let apart = Log::permit_all();
    let (handle, _) = gateway(&[&upstream], &[host], &apart, |_| {});
    for request in requests(upstream.port()) {
        let mut client = WorkloadClient::connect(port(&handle), host, upstream.port());
        client.send_raw(request.as_bytes());
        assert_eq!(client.read_status(), 200);
    }

    let attempts = kept.attempts();
    assert_eq!(attempts.len(), 8, "{attempts:#?}");
    assert_eq!(attempts, apart.attempts());
    let deadline = Instant::now() + END_WAIT;
    while apart.outcomes().len() < kept.outcomes().len() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let (mut kept, mut apart) = (kept.outcomes(), apart.outcomes());
    kept.sort();
    apart.sort();
    assert_eq!(kept, apart);
}

/// **Each request on a tunnel gets its own correlation**, which its connect decisions share.
#[test]
fn each_request_gets_its_own_correlation() {
    let host = "correlate.test";
    let upstream = TlsUpstream::start_with_response(host, OK);
    let log = Log::permit_all();
    let (handle, emitter) = gateway(&[&upstream], &[host], &log, |_| {});
    let mut client = WorkloadClient::connect(port(&handle), host, upstream.port());
    for path in ["/1", "/2", "/3"] {
        client.send_raw(get(host, upstream.port(), path).as_bytes());
        assert_eq!(client.read_status(), 200);
    }
    let records = emitter.records();
    let requests: Vec<_> = records.iter().filter(|r| !r.method.is_empty()).collect();
    assert_eq!(requests.len(), 3, "{records:#?}");
    let mut correlations: Vec<&str> = requests.iter().map(|r| r.correlation.as_str()).collect();
    correlations.dedup();
    assert_eq!(
        correlations.len(),
        3,
        "a distinct correlation each: {records:#?}"
    );
    for request in requests {
        assert!(
            records.iter().any(|record| record.method.is_empty()
                && record.correlation.as_str() == request.correlation.as_str()),
            "the connect decision of {} shares its correlation: {records:#?}",
            request.path
        );
    }
}

/// **The binding is checked on each request**: a later request that names another host gets the
/// refusal, the connection closes, and the upstream sees only the first request.
#[test]
fn a_request_naming_another_host_on_a_tunnel_is_refused_and_closes() {
    let host = "bound.test";
    let upstream = TlsUpstream::start_with_response(host, OK);
    let log = Log::permit_all();
    let (handle, _) = gateway(&[&upstream], &[host], &log, |_| {});
    let mut client = WorkloadClient::connect(port(&handle), host, upstream.port());
    client.send_raw(get(host, upstream.port(), "/first").as_bytes());
    assert_eq!(client.read_status(), 200);
    client.send_raw(get("other.test", upstream.port(), "/second").as_bytes());
    let refusal = client.read_response();
    assert!(
        refusal.ends_with("request authority rejected") && is_marked(&refusal),
        "{refusal}"
    );
    assert!(says_close(&refusal), "{refusal}");
    assert!(client.reads_end_within(END_WAIT), "the connection closes");
    let seen = upstream.requests();
    assert_eq!(seen.len(), 1, "{seen:?}");
}

/// **A client `Connection: close` ends the tunnel after its reply**, which says so.
#[test]
fn a_client_connection_close_ends_the_tunnel_after_the_reply() {
    let host = "close.test";
    let upstream = TlsUpstream::start_with_response(host, OK);
    let log = Log::permit_all();
    let (handle, _) = gateway(&[&upstream], &[host], &log, |_| {});
    let mut client = WorkloadClient::connect(port(&handle), host, upstream.port());
    client.send_request("GET", "/last", &[], b"");
    assert_eq!(
        client.read_response(),
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok"
    );
    assert!(client.reads_end_within(END_WAIT));
}

/// **An HTTP/1.0 request with `Connection: keep-alive` closes after its reply or its refusal**:
/// the reply is `HTTP/1.0` and says `Connection: close`, and the connection ends.
#[test]
fn an_http10_keep_alive_request_closes_after_its_reply_or_refusal() {
    let host = "ten.test";
    let upstream = TlsUpstream::start_with_response(host, OK);
    let log = Log::permit_all();
    let (handle, _) = gateway(&[&upstream], &[host], &log, |_| {});
    let port_up = upstream.port();
    for (authority, status) in [(host, 200), ("other.test", 403)] {
        let mut client = WorkloadClient::connect(port(&handle), host, port_up);
        client.send_raw(
            format!(
                "GET /ten HTTP/1.0\r\nHost: {authority}:{port_up}\r\nConnection: keep-alive\r\n\r\n"
            )
            .as_bytes(),
        );
        let reply = client.read_response();
        assert!(
            reply.starts_with(&format!("HTTP/1.0 {status} ")) && says_close(&reply),
            "{authority}: {reply}"
        );
        assert!(client.reads_end_within(END_WAIT), "{authority}");
    }
}

/// **A request that names `Upgrade` closes after its reply**: the gateway strips the field and
/// forwards a plain request, and the client's next bytes may not be an HTTP head.
#[test]
fn a_request_naming_upgrade_closes_after_its_reply() {
    let host = "lift.test";
    let upstream = TlsUpstream::start_with_response(host, OK);
    let log = Log::permit_all();
    let (handle, _) = gateway(&[&upstream], &[host], &log, |_| {});
    let mut client = WorkloadClient::connect(port(&handle), host, upstream.port());
    client.send_raw(
        format!(
            "GET /up HTTP/1.1\r\nHost: {host}:{}\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
            upstream.port()
        )
        .as_bytes(),
    );
    let reply = client.read_response();
    assert!(
        reply.starts_with("HTTP/1.1 200 ") && says_close(&reply),
        "{reply}"
    );
    assert!(client.reads_end_within(END_WAIT));
    assert!(
        !upstream
            .last_request()
            .raw
            .to_ascii_lowercase()
            .contains("upgrade"),
        "the upgrade fields are stripped"
    );
}

/// **A `HEAD`, `304`, or `204` reply keeps the next exchange aligned**: it carries no body, and
/// the next reply on the tunnel parses.
#[test]
fn a_head_304_or_204_reply_keeps_the_next_exchange_aligned() {
    let cases: [(&str, &'static [u8], &str); 3] = [
        (
            "HEAD",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
        ),
        (
            "GET",
            b"HTTP/1.1 304 Not Modified\r\nETag: \"e\"\r\n\r\n",
            "HTTP/1.1 304 Redirect\r\nEtag: \"e\"\r\n\r\n",
        ),
        (
            "GET",
            b"HTTP/1.1 204 No Content\r\n\r\n",
            "HTTP/1.1 204 OK\r\n\r\n",
        ),
    ];
    for (method, reply, head) in cases {
        let host = "aligned.test";
        let upstream = TlsUpstream::start_with_response(host, reply);
        let log = Log::permit_all();
        let (handle, _) = gateway(&[&upstream], &[host], &log, |_| {});
        let mut client = WorkloadClient::connect(port(&handle), host, upstream.port());
        let request = format!(
            "{method} /x HTTP/1.1\r\nHost: {host}:{}\r\n\r\n",
            upstream.port()
        );
        // Both requests in one write: a body after the first reply would misframe the second.
        client.send_raw(format!("{request}{request}").as_bytes());
        assert_eq!(client.read_head_only(), head, "{method} {head}");
        assert_eq!(
            client.read_head_only(),
            head,
            "{method} {head}: the next reply"
        );
    }
}

/// **A later request that ends mid-body delivers nothing**: no byte of it reaches the upstream and
/// it raises no request effect, while its socket is decided and opened, as on a tunnel of its own.
#[test]
fn an_upload_aborted_mid_body_on_a_later_request_delivers_nothing() {
    let host = "aborted.test";
    let upstream = TlsUpstream::start_with_response(host, OK);
    let log = Log::permit_all();
    let (handle, _) = gateway(&[&upstream], &[host], &log, |_| {});
    let port_up = upstream.port();
    let mut client = WorkloadClient::connect(port(&handle), host, port_up);
    client.send_raw(get(host, port_up, "/first").as_bytes());
    assert_eq!(client.read_status(), 200);
    client.send_raw(
        format!("POST /upload HTTP/1.1\r\nHost: {host}:{port_up}\r\nContent-Length: 10\r\n\r\nabc")
            .as_bytes(),
    );
    std::thread::sleep(Duration::from_millis(100));
    client.abort();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(upstream.requests().len(), 1);
    assert_eq!(log.of_kind("HttpRequest").len(), 1, "{:#?}", log.attempts());
    assert_eq!(log.of_kind("Connect").len(), 2, "{:#?}", log.attempts());
}

/// **A malformed pipelined request does not cancel the one before it**: the first reply arrives
/// whole, then hyper's `400`, then the end of the connection, and the malformed request raises
/// no effect.
#[test]
fn a_malformed_pipelined_request_does_not_cancel_the_one_before_it() {
    let host = "malformed.test";
    let upstream = TlsUpstream::start_with_response(host, OK);
    let log = Log::permit_all();
    let (handle, _) = gateway(&[&upstream], &[host], &log, |_| {});
    let mut client = WorkloadClient::connect(port(&handle), host, upstream.port());
    client
        .send_raw(format!("{}NOT A REQUEST\r\n\r\n", get(host, upstream.port(), "/ok")).as_bytes());
    assert_eq!(
        client.read_response(),
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    );
    let refusal = client.read_response();
    assert!(refusal.starts_with("HTTP/1.1 400 "), "{refusal}");
    assert!(client.reads_end_within(END_WAIT));
    assert_eq!(log.of_kind("Resolve").len(), 1, "{:#?}", log.attempts());
    assert_eq!(log.of_kind("HttpRequest").len(), 1, "{:#?}", log.attempts());
}

/// Assert that the end of a connection left no denial in the audit log, and that the release of
/// its last reply counted the bytes of that reply only.
fn assert_quiet_end(handle: &MitmHandle, log: &Log, case: &str) {
    // The connection task pushes its audit line after the end of the connection.
    std::thread::sleep(Duration::from_millis(200));
    let denials: Vec<String> = handle
        .drain_audit_events()
        .into_iter()
        .filter(|event| event.decision == AuditDecision::Deny)
        .map(|event| event.reason)
        .collect();
    assert!(denials.is_empty(), "{case}: {denials:?}");
    let outcomes = log.outcomes();
    assert_eq!(
        outcomes.last(),
        Some(&format!("Completed({})", OK.len())),
        "{case}: the release counts its own reply: {outcomes:#?}"
    );
}

/// **A later head that hyper refuses ends the connection quietly, however it arrives**: in one
/// write with the request before it, or in its own write after the reply. The earlier reply
/// arrives whole, then hyper's `400`, then the end. No audit line is a denial, and the release of
/// the earlier reply does not count the `400`.
#[test]
fn a_later_head_that_hyper_refuses_ends_quietly_however_it_arrives() {
    const BAD: &[u8] = b"NOT A REQUEST\r\n\r\n";
    let host = "later.test";
    let upstream = TlsUpstream::start_with_response(host, OK);
    let origin = PlainOrigin::start(OK.to_vec());
    let addr = origin.addr;
    for own_write in [false, true] {
        let case = format!("tunnel, own write {own_write}");
        let log = Log::permit_all();
        let (handle, _) = gateway(&[&upstream], &[host], &log, |_| {});
        let mut client = WorkloadClient::connect(port(&handle), host, upstream.port());
        let first = get(host, upstream.port(), "/ok");
        if own_write {
            client.send_raw(first.as_bytes());
            assert_eq!(client.read_response().as_bytes(), OK, "{case}");
            client.send_raw(BAD);
        } else {
            client.send_raw(&[first.as_bytes(), BAD].concat());
            assert_eq!(client.read_response().as_bytes(), OK, "{case}");
        }
        let refusal = client.read_response();
        assert!(refusal.starts_with("HTTP/1.1 400 "), "{case}: {refusal}");
        assert!(client.reads_end_within(END_WAIT), "{case}");
        assert_quiet_end(&handle, &log, &case);

        let case = format!("plain, own write {own_write}");
        let log = Log::permit_all();
        let (handle, _) = gateway(&[], &[], &log, |_| {});
        let mut client = plain_client(&handle);
        let first = format!("GET http://{addr}/ok HTTP/1.1\r\nHost: {addr}\r\n\r\n");
        if own_write {
            client.write_all(first.as_bytes()).unwrap();
            assert_eq!(read_reply(&mut client).as_bytes(), OK, "{case}");
            client.write_all(BAD).unwrap();
        } else {
            client.write_all(&[first.as_bytes(), BAD].concat()).unwrap();
            assert_eq!(read_reply(&mut client).as_bytes(), OK, "{case}");
        }
        let refusal = read_reply(&mut client);
        assert!(refusal.starts_with("HTTP/1.1 400 "), "{case}: {refusal}");
        assert!(plain_reads_end(&mut client), "{case}");
        assert_quiet_end(&handle, &log, &case);
    }
}

/// **An idle pause between two requests does not count on the upstream clock**: each request has
/// its own upstream socket and its own idle bound.
#[test]
fn an_idle_pause_between_requests_does_not_count_on_the_upstream_clock() {
    let host = "clock.test";
    let upstream = TlsUpstream::start_with_response(host, OK);
    let log = Log::permit_all();
    let (handle, _) = gateway(&[&upstream], &[host], &log, |config| {
        config.upstream_read_deadline = Duration::from_millis(500);
    });
    let mut client = WorkloadClient::connect(port(&handle), host, upstream.port());
    client.send_raw(get(host, upstream.port(), "/before").as_bytes());
    assert_eq!(client.read_status(), 200);
    std::thread::sleep(Duration::from_millis(800));
    client.send_raw(get(host, upstream.port(), "/after").as_bytes());
    assert_eq!(client.read_status(), 200);
}

// ============================================================================================
// Plain HTTP
// ============================================================================================

/// A plain-HTTP origin on loopback that answers the one request of each connection with `reply`
/// and closes, and keeps each request head.
struct PlainOrigin {
    addr: SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
}

impl PlainOrigin {
    fn start(reply: Vec<u8>) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&heads);
        let reply = Arc::new(reply);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (kept, reply) = (Arc::clone(&kept), Arc::clone(&reply));
                std::thread::spawn(move || {
                    let head = read_head(&mut stream);
                    if head.is_empty() {
                        return;
                    }
                    kept.lock().unwrap().push(head);
                    let _ = stream.write_all(&reply);
                });
            }
        });
        Self { addr, heads }
    }

    fn heads(&self) -> Vec<String> {
        std::thread::sleep(Duration::from_millis(50));
        self.heads.lock().unwrap().clone()
    }
}

/// A plain-HTTP client of the gateway, whose reads give up after [`END_WAIT`].
fn plain_client(handle: &MitmHandle) -> TcpStream {
    let client = TcpStream::connect(("127.0.0.1", port(handle))).unwrap();
    client.set_read_timeout(Some(END_WAIT)).unwrap();
    client
}

/// Read a head up to its blank line, one byte at a time.
fn read_head(stream: &mut impl Read) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// Read one reply, its head and the body that its `Content-Length` names.
fn read_reply(stream: &mut impl Read) -> String {
    let head = read_head(stream);
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).unwrap();
    format!("{head}{}", String::from_utf8_lossy(&body))
}

/// Whether the gateway ends `client` with no byte before its end.
fn plain_reads_end(client: &mut TcpStream) -> bool {
    let mut rest = Vec::new();
    match client.read_to_end(&mut rest) {
        Ok(_) => rest.is_empty(),
        Err(error) => error.kind() == io::ErrorKind::ConnectionReset && rest.is_empty(),
    }
}

/// **A reply that the upstream delimits by its close is re-framed for a kept-alive client**: it
/// carries the `Content-Length` of its body, and the next request on the connection parses.
#[test]
fn a_close_delimited_upstream_reply_is_reframed_for_a_kept_alive_client() {
    let origin = PlainOrigin::start(b"HTTP/1.1 200 OK\r\n\r\nuntil-close".to_vec());
    let log = Log::permit_all();
    let (handle, _) = gateway(&[], &[], &log, |_| {});
    let mut client = plain_client(&handle);
    let addr = origin.addr;
    for path in ["/first", "/second"] {
        write!(
            client,
            "GET http://{addr}{path} HTTP/1.1\r\nHost: {addr}\r\n\r\n"
        )
        .unwrap();
        assert_eq!(
            read_reply(&mut client),
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nuntil-close",
            "{path}"
        );
    }
    assert_eq!(origin.heads().len(), 2);
}

/// **One plain connection carries requests to different hosts**: each request is resolved and
/// connected for its own host, and its `Host` names the authority that the gateway judged.
#[test]
fn a_plain_connection_carries_requests_to_different_hosts() {
    let (one, two) = (
        PlainOrigin::start(OK.to_vec()),
        PlainOrigin::start(OK.to_vec()),
    );
    let log = Log::permit_all();
    let (handle, _) = gateway(&[], &["one.test", "two.test"], &log, |_| {});
    let mut client = plain_client(&handle);
    for (host, origin) in [("one.test", &one), ("two.test", &two)] {
        let authority = format!("{host}:{}", origin.addr.port());
        write!(
            client,
            "GET http://{authority}/x HTTP/1.1\r\nHost: forged.test\r\n\r\n"
        )
        .unwrap();
        assert!(
            read_reply(&mut client).starts_with("HTTP/1.1 200 "),
            "{host}"
        );
        let heads = origin.heads();
        assert!(
            heads.len() == 1 && heads[0].contains(&format!("\r\nHost: {authority}\r\n")),
            "{host}: {heads:?}"
        );
    }
    let resolves = log.of_kind("Resolve");
    assert!(
        resolves.len() == 2
            && resolves[0].contains("\"one.test\"")
            && resolves[1].contains("\"two.test\""),
        "{resolves:#?}"
    );
    assert_eq!(log.of_kind("Connect").len(), 2);
}

/// **A `CONNECT` after a plain request is refused after the whole earlier reply**: hyper writes
/// the `400` after that reply, the connection ends, and the `CONNECT` raises no decision.
#[test]
fn a_connect_after_a_plain_request_is_refused_after_the_complete_reply() {
    let origin = PlainOrigin::start(OK.to_vec());
    let log = Log::permit_all();
    let (handle, _) = gateway(&[], &[], &log, |_| {});
    let mut client = plain_client(&handle);
    let addr = origin.addr;
    write!(
        client,
        "GET http://{addr}/plain HTTP/1.1\r\nHost: {addr}\r\n\r\n"
    )
    .unwrap();
    assert_eq!(
        read_reply(&mut client),
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    );
    write!(client, "CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n\r\n").unwrap();
    let refusal = read_reply(&mut client);
    assert!(
        refusal.starts_with("HTTP/1.1 400 ") && says_close(&refusal),
        "{refusal}"
    );
    assert!(plain_reads_end(&mut client));
    assert_eq!(log.of_kind("Resolve").len(), 1, "{:#?}", log.attempts());
}

/// **Each plain request is checked for its own `Proxy-Authorization`.** On one kept-alive
/// connection, a request with the gateway's token is served, a request with no token is served
/// (the check is best effort, as on a connection of its own), and a request with another token gets
/// the `407` and the end of the connection, and opens no upstream socket.
#[test]
fn each_plain_request_is_checked_for_its_own_proxy_token() {
    let origin = PlainOrigin::start(OK.to_vec());
    let log = Log::permit_all();
    let (handle, _) = gateway(&[], &[], &log, |config| {
        config.expected_token = Some("the-token".to_string());
    });
    let mut client = plain_client(&handle);
    let addr = origin.addr;
    for (token, status) in [
        ("Proxy-Authorization: Bearer the-token\r\n", "200"),
        ("", "200"),
        ("Proxy-Authorization: Bearer another-token\r\n", "407"),
    ] {
        write!(
            client,
            "GET http://{addr}/token HTTP/1.1\r\nHost: {addr}\r\n{token}\r\n"
        )
        .unwrap();
        let reply = read_reply(&mut client);
        assert!(
            reply.starts_with(&format!("HTTP/1.1 {status} ")),
            "{token:?}: {reply}"
        );
    }
    assert!(plain_reads_end(&mut client), "the 407 closes the connection");
    assert_eq!(origin.heads().len(), 2, "the refused request opened no socket");
    assert_eq!(log.of_kind("Resolve").len(), 2, "{:#?}", log.attempts());
}

/// **A refused pipelined request does not enter a slow reply**: the first request gets a 4 MiB
/// reply that the client reads slowly, and the `CONNECT` that rides it is refused only after that
/// reply, whose body arrives exact.
#[test]
fn a_refused_pipelined_request_does_not_enter_a_slow_reply() {
    const LENGTH: usize = 4 * 1024 * 1024;
    let mut reply = format!("HTTP/1.1 200 OK\r\nContent-Length: {LENGTH}\r\n\r\n").into_bytes();
    reply.extend(std::iter::repeat_n(b'y', LENGTH));
    let origin = PlainOrigin::start(reply);
    let log = Log::permit_all();
    let (handle, _) = gateway(&[], &[], &log, |_| {});
    let mut client = plain_client(&handle);
    let addr = origin.addr;
    write!(
        client,
        "GET http://{addr}/large HTTP/1.1\r\nHost: {addr}\r\n\r\n\
         CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n\r\n"
    )
    .unwrap();
    let head = read_head(&mut client);
    assert_eq!(
        head,
        format!("HTTP/1.1 200 OK\r\nContent-Length: {LENGTH}\r\n\r\n")
    );
    let mut body = vec![0u8; LENGTH];
    for piece in body.chunks_mut(256 * 1024) {
        client.read_exact(piece).unwrap();
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(body.iter().all(|byte| *byte == b'y'), "the body is exact");
    let refusal = read_reply(&mut client);
    assert!(refusal.starts_with("HTTP/1.1 400 "), "{refusal}");
    assert!(plain_reads_end(&mut client));
}

// ============================================================================================
// Slots and shutdown
// ============================================================================================

/// **Slot pressure closes only the oldest idle connection.** With every slot held, two by idle
/// tunnels and one by a busy one, a new connection gets the slot of the older idle tunnel. The newer
/// idle tunnel and the busy one stay kept-alive.
#[test]
fn slot_pressure_closes_only_the_oldest_idle_connection() {
    let (idle_host, busy_host) = ("idle.test", "busy.test");
    let idle_upstream = TlsUpstream::start_with_response(idle_host, OK);
    let busy_upstream = TlsUpstream::start_dripping(busy_host, OK, Duration::from_millis(20));
    let log = Log::permit_all();
    let (handle, _) = gateway(
        &[&idle_upstream, &busy_upstream],
        &[idle_host, busy_host],
        &log,
        |config| config.max_connections = 3,
    );
    let (proxy, idle_port, busy_port) = (port(&handle), idle_upstream.port(), busy_upstream.port());
    let kept_alive = || {
        let mut client = WorkloadClient::connect(proxy, idle_host, idle_port);
        client.send_raw(get(idle_host, idle_port, "/idle").as_bytes());
        assert_eq!(client.read_status(), 200);
        client
    };
    let mut older = kept_alive();
    let mut newer = kept_alive();
    let mut busy = WorkloadClient::connect(proxy, busy_host, busy_port);
    busy.send_raw(get(busy_host, busy_port, "/busy").as_bytes());
    std::thread::sleep(Duration::from_millis(100));

    let started = Instant::now();
    let mut new = WorkloadClient::connect(proxy, idle_host, idle_port);
    new.send_raw(get(idle_host, idle_port, "/new").as_bytes());
    assert_eq!(new.read_status(), 200);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the new connection waited {:?}",
        started.elapsed()
    );
    assert!(
        older.reads_end_within(END_WAIT),
        "the oldest idle tunnel closed"
    );
    let reply = busy.read_response();
    assert!(
        reply.starts_with("HTTP/1.1 200 ") && !says_close(&reply),
        "the busy tunnel stays kept-alive: {reply}"
    );
    newer.send_raw(get(idle_host, idle_port, "/again").as_bytes());
    assert_eq!(newer.read_status(), 200, "the newer idle tunnel stays open");
}

/// **The stop ends idle kept-alive connections**: `shutdown` returns at once, and each client reads
/// the end of its tunnel.
#[test]
fn shutdown_ends_idle_kept_alive_connections() {
    let host = "stop.test";
    let upstream = TlsUpstream::start_with_response(host, OK);
    let log = Log::permit_all();
    let (handle, _) = gateway(&[&upstream], &[host], &log, |_| {});
    let mut clients: Vec<WorkloadClient> = (0..2)
        .map(|_| {
            let mut client = WorkloadClient::connect(port(&handle), host, upstream.port());
            client.send_raw(get(host, upstream.port(), "/idle").as_bytes());
            assert_eq!(client.read_status(), 200);
            client
        })
        .collect();
    let started = Instant::now();
    handle.shutdown();
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    for client in &mut clients {
        assert!(client.reads_end_within(END_WAIT));
    }
}

/// **At the stop, a connection inside an exchange delivers its whole reply, then closes.**
/// `shutdown` returns at once while the upstream drips its reply, and the reply says
/// `Connection: close`.
#[test]
fn shutdown_lets_a_busy_kept_alive_connection_finish_its_reply() {
    let host = "busy-stop.test";
    let upstream = TlsUpstream::start_dripping(host, OK, Duration::from_millis(10));
    let log = Log::permit_all();
    let (handle, _) = gateway(&[&upstream], &[host], &log, |_| {});
    let mut client = WorkloadClient::connect(port(&handle), host, upstream.port());
    client.send_raw(get(host, upstream.port(), "/busy").as_bytes());
    std::thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    handle.shutdown();
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    let reply = client.read_response();
    assert!(
        reply.starts_with("HTTP/1.1 200 ") && says_close(&reply) && reply.ends_with("\r\n\r\nok"),
        "{reply}"
    );
    assert!(client.reads_end_within(END_WAIT));
}
