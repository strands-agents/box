//! What the workload and the upstream see of the HTTP/1.1 exchange on hyper.
//!
//! hyper reads and writes the framing by RFC 9112, and the gateway re-frames every body under one
//! `Content-Length`. Each test pins one place where these bytes differ from the old hand-written
//! codec, so a later change is visible.

#![cfg(feature = "tls-intercept")]

mod harness;

use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use egress_gateway::{
    CapabilitySet, EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, MitmConfig,
    MitmHandle, MitmInterceptor,
};

use harness::{TlsUpstream, WorkloadClient};

/// The destination of every exchange in this file, pinned to loopback.
const HOST: &str = "wire.test";

/// A reply that the upstream gives to each request.
const OK_REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

/// One thing that the authority saw.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Request { method: String, path: String },
    RequestOutcome(EffectOutcome),
    Release { status: u16, body_bytes: usize },
    ReleaseOutcome(EffectOutcome),
}

/// An authority that permits each attempt and keeps each request and release, with its outcome.
#[derive(Default)]
struct Log(Shared);

impl Log {
    fn seen(&self) -> Vec<Seen> {
        self.0.lock().unwrap().clone()
    }

    /// What the authority saw once it holds `count` entries, or after 5 s.
    fn wait_for(&self, count: usize) -> Vec<Seen> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.0.lock().unwrap().len() < count && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(50));
        self.seen()
    }
}

/// The shared log of an authority.
type Shared = Arc<Mutex<Vec<Seen>>>;

/// A permit that keeps its outcome, when it has a way to name it.
struct Permit {
    log: Shared,
    seen: Option<fn(EffectOutcome) -> Seen>,
}

impl EffectPermit for Permit {
    fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
        if let Some(seen) = self.seen {
            self.log.lock().unwrap().push(seen(outcome));
        }
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

impl EffectInterceptor for Log {
    fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        let seen: Option<fn(EffectOutcome) -> Seen> = match attempt {
            EffectAttempt::HttpRequest { method, path, .. } => {
                self.0.lock().unwrap().push(Seen::Request {
                    method: method.to_string(),
                    path: path.to_string(),
                });
                Some(Seen::RequestOutcome)
            }
            EffectAttempt::ResponseRelease {
                status, body_bytes, ..
            } => {
                self.0.lock().unwrap().push(Seen::Release {
                    status: *status,
                    body_bytes: *body_bytes,
                });
                Some(Seen::ReleaseOutcome)
            }
            _ => None,
        };
        Ok(Box::new(Permit {
            log: Arc::clone(&self.0),
            seen,
        }))
    }
}

/// A gateway that trusts `upstream` (or not), with its log.
fn gateway(upstream: &TlsUpstream, trusted: bool) -> (MitmHandle, Arc<Log>) {
    let log = Arc::new(Log::default());
    let config = MitmConfig {
        upstream_ca_pems: if trusted {
            vec![upstream.ca_pem()]
        } else {
            Vec::new()
        },
        dns_overrides: vec![(HOST.to_string(), IpAddr::from([127, 0, 0, 1]))],
        ..MitmConfig::default()
    };
    let handle = MitmInterceptor::start(config, CapabilitySet::default(), log.clone()).unwrap();
    (handle, log)
}

/// Send `request` (with `{port}` in it for the upstream port) whole through a gateway to an
/// upstream that answers `reply`, and return the reply to the workload, the request that the
/// upstream saw, and the log once it holds `records` entries.
fn exchange(
    reply: &'static [u8],
    request: &str,
    records: usize,
) -> (String, Option<String>, Vec<Seen>) {
    let upstream = TlsUpstream::start_with_response(HOST, reply);
    let (handle, log) = gateway(&upstream, true);
    let port = upstream.port();
    let mut client = WorkloadClient::connect(handle.port().unwrap(), HOST, port);
    client.send_raw(request.replace("{port}", &port.to_string()).as_bytes());
    let response = client.read_response();
    let seen = (upstream.request_count() > 0).then(|| upstream.last_request().raw);
    (response, seen, log.wait_for(records))
}

/// **W1, W2: relayed header names are written in title case, and repeated names are grouped at
/// the first position of the name**, toward the workload and toward the upstream.
#[test]
fn relayed_header_names_are_title_case_and_grouped() {
    let (response, seen, _) = exchange(
        b"HTTP/1.1 200 OK\r\nx-lower: a\r\nSet-Cookie: 1\r\nX-Mid: m\r\nset-cookie: 2\r\n\
          Content-Length: 2\r\n\r\nok",
        "GET /w1 HTTP/1.1\r\nHost: wire.test:{port}\r\nx-lower-req: r\r\nAccept: 1\r\n\
         X-Mid: m\r\naccept: 2\r\n\r\n",
        4,
    );
    assert_eq!(
        response,
        "HTTP/1.1 200 OK\r\nX-Lower: a\r\nSet-Cookie: 1\r\nSet-Cookie: 2\r\nX-Mid: m\r\n\
         Connection: close\r\nContent-Length: 2\r\n\r\nok"
    );
    let seen = seen.expect("the upstream saw the request");
    assert!(
        seen.starts_with("GET /w1 HTTP/1.1\r\nHost: wire.test:")
            && seen.contains(
                "\r\nX-Lower-Req: r\r\nAccept: 1\r\nAccept: 2\r\nX-Mid: m\r\nConnection: close\r\n\
             Content-Length: 0\r\n\r\n"
            ),
        "{seen}"
    );
}

/// **W3: a 304 to the workload has no `Content-Length`.** hyper drops the length of a reply that
/// cannot carry a body.
#[test]
fn a_304_to_the_workload_has_no_content_length() {
    let (response, _, _) = exchange(
        b"HTTP/1.1 304 Not Modified\r\nETag: \"e\"\r\nContent-Length: 10\r\n\r\n",
        "GET /w3 HTTP/1.1\r\nHost: wire.test:{port}\r\n\r\n",
        4,
    );
    assert_eq!(
        response,
        "HTTP/1.1 304 Redirect\r\nEtag: \"e\"\r\nConnection: close\r\n\r\n"
    );
}

/// **W4: an HTTP/1.0 request gets an `HTTP/1.0` reply, and one exchange.** A `Connection:
/// keep-alive` from the client does not keep the connection open: the reply carries
/// `Connection: close`, the connection ends, and one request effect is raised.
#[test]
fn an_http10_keep_alive_request_gets_one_exchange() {
    let upstream = TlsUpstream::start_with_response(HOST, OK_REPLY);
    let (handle, log) = gateway(&upstream, true);
    let port = upstream.port();
    let mut client = WorkloadClient::connect(handle.port().unwrap(), HOST, port);
    client.send_raw(
        format!(
            "GET /w4 HTTP/1.0\r\nHost: {HOST}:{port}\r\nConnection: keep-alive\r\n\r\n\
             GET /second HTTP/1.0\r\nHost: {HOST}:{port}\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(
        client.read_response(),
        "HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok"
    );
    assert_eq!(client.read_response(), "", "the connection ends");
    let requests: Vec<Seen> = log
        .wait_for(4)
        .into_iter()
        .filter(|seen| matches!(seen, Seen::Request { .. }))
        .collect();
    assert_eq!(
        requests,
        [Seen::Request {
            method: "GET".to_string(),
            path: "/w4".to_string()
        }]
    );
    assert_eq!(upstream.request_count(), 1);
}

/// **W5: `Expect: 100-continue` gets an interim `100 Continue`** when the gateway reads the body.
/// The release still counts only the bytes of the final reply.
#[test]
fn expect_100_continue_gets_an_interim_reply() {
    let upstream = TlsUpstream::start_with_response(HOST, OK_REPLY);
    let (handle, log) = gateway(&upstream, true);
    let port = upstream.port();
    let mut client = WorkloadClient::connect(handle.port().unwrap(), HOST, port);
    client.send_raw(
        format!(
            "POST /w5 HTTP/1.1\r\nHost: {HOST}:{port}\r\nExpect: 100-continue\r\n\
             Content-Length: 5\r\n\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(client.read_response(), "HTTP/1.1 100 Continue\r\n\r\n");
    client.send_raw(b"hello");
    let reply = client.read_response();
    assert_eq!(
        reply,
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok"
    );
    assert!(upstream.last_request().raw.ends_with("\r\n\r\nhello"));
    assert!(
        log.wait_for(4)
            .contains(&Seen::ReleaseOutcome(EffectOutcome::Completed(reply.len()))),
        "{:?}",
        log.seen()
    );
}

/// **W7: an upstream status below 100 is refused.** No reply reaches the workload, and the request
/// outcome records no status.
#[test]
fn an_upstream_status_below_100_is_refused() {
    let (response, _, seen) = exchange(
        b"HTTP/1.1 099 Early\r\nContent-Length: 2\r\n\r\nok",
        "GET /w7 HTTP/1.1\r\nHost: wire.test:{port}\r\n\r\n",
        2,
    );
    assert_eq!(response, "");
    assert!(
        matches!(
            &seen[..],
            [
                Seen::Request { .. },
                Seen::RequestOutcome(EffectOutcome::Completed(_))
            ]
        ),
        "{seen:?}"
    );
}

/// **Chunk extensions follow hyper in both directions**: hyper skips them, whatever their
/// grammar, and the gateway re-frames the decoded body.
#[test]
fn chunk_extensions_follow_hyper_in_both_directions() {
    let (response, seen, _) = exchange(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;=bad\r\nok\r\n0\r\n\r\n",
        "POST /ext HTTP/1.1\r\nHost: wire.test:{port}\r\nTransfer-Encoding: chunked\r\n\r\n\
         2;name=\"open\r\nhi\r\n0\r\n\r\n",
        4,
    );
    assert_eq!(
        response,
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok"
    );
    let seen = seen.expect("the upstream saw the request");
    assert!(seen.contains("\r\nContent-Length: 2\r\n\r\nhi"), "{seen}");
    assert!(
        !seen.to_ascii_lowercase().contains("transfer-encoding"),
        "{seen}"
    );
}

/// **A trailer section is dropped in both directions.** hyper reads it, and the gateway forwards
/// the decoded body under one `Content-Length`, which carries no trailer.
#[test]
fn trailers_are_dropped_in_both_directions() {
    let (response, seen, _) = exchange(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Up\r\n\r\n\
          2\r\nok\r\n0\r\nX-Up: t\r\n\r\n",
        "POST /trailer HTTP/1.1\r\nHost: wire.test:{port}\r\nTransfer-Encoding: chunked\r\n\
         Trailer: X-Down\r\n\r\n2\r\nhi\r\n0\r\nX-Down: t\r\n\r\n",
        4,
    );
    assert_eq!(
        response,
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok"
    );
    let seen = seen.expect("the upstream saw the request");
    assert!(seen.ends_with("\r\nContent-Length: 2\r\n\r\nhi"), "{seen}");
    assert!(!seen.contains("X-Down"), "{seen}");
}

/// **Informational replies are skipped with no count.** Seventeen `100` replies, more than the old
/// cap, then the final reply, which is released.
#[test]
fn informational_replies_are_skipped_with_no_count() {
    let reply: &'static [u8] = Box::leak(
        format!(
            "{}HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            "HTTP/1.1 100 Continue\r\n\r\n".repeat(17)
        )
        .into_bytes()
        .into_boxed_slice(),
    );
    let (response, _, seen) = exchange(
        reply,
        "GET /1xx HTTP/1.1\r\nHost: wire.test:{port}\r\n\r\n",
        4,
    );
    assert_eq!(
        response,
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok"
    );
    assert!(
        seen.iter().any(|seen| matches!(
            seen,
            Seen::RequestOutcome(EffectOutcome::Replied { status: 200, .. })
        )),
        "{seen:?}"
    );
}

/// **A reply with both lengths, or with a repeated equal length, is decoded by RFC 9112** and
/// released under one `Content-Length`: `Transfer-Encoding: chunked` wins over `Content-Length`.
#[test]
fn a_reply_with_two_lengths_is_decoded_and_reframed() {
    for reply in [
        &b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\nTransfer-Encoding: chunked\r\n\r\n\
           2\r\nok\r\n0\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok"[..],
    ] {
        let (response, _, _) = exchange(
            reply,
            "GET /two HTTP/1.1\r\nHost: wire.test:{port}\r\n\r\n",
            4,
        );
        assert_eq!(
            response,
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok"
        );
    }
}

/// **A target byte that `http::Uri` refuses gets hyper's own `400`**, with no refusal marker, and
/// no request effect: `<` in the path, and `"` in the query.
#[test]
fn a_target_byte_that_http_uri_refuses_gets_hyper_400() {
    for target in ["/a<b", "/s?filter={\"a\":1}"] {
        let (response, seen, log) = exchange(
            OK_REPLY,
            &format!("GET {target} HTTP/1.1\r\nHost: wire.test:{{port}}\r\n\r\n"),
            0,
        );
        assert_eq!(
            response, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            "{target}"
        );
        assert_eq!(seen, None, "{target}: no request reached the upstream");
        assert!(log.is_empty(), "{target}: no request effect: {log:?}");
    }
}

/// **A fragment in the target is dropped before the request is judged**: `http::Uri` keeps no
/// fragment, so the judged path and the forwarded path are both the path before `#`.
#[test]
fn a_fragment_in_the_target_is_dropped_before_the_request_is_judged() {
    let (response, seen, log) = exchange(
        OK_REPLY,
        "GET /a#b HTTP/1.1\r\nHost: wire.test:{port}\r\n\r\n",
        4,
    );
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(seen.expect("forwarded").starts_with("GET /a HTTP/1.1\r\n"));
    assert_eq!(
        log[0],
        Seen::Request {
            method: "GET".to_string(),
            path: "/a".to_string()
        }
    );
}

/// **A client that half-closes after its request still gets the reply**, and the release records
/// its delivery.
#[test]
fn a_client_half_close_still_gets_the_reply() {
    let upstream = TlsUpstream::start_with_response(HOST, OK_REPLY);
    let (handle, log) = gateway(&upstream, true);
    let port = upstream.port();
    let mut client = WorkloadClient::connect(handle.port().unwrap(), HOST, port);
    client.send_raw(format!("GET /half HTTP/1.1\r\nHost: {HOST}:{port}\r\n\r\n").as_bytes());
    client.close_write();
    let reply = client.read_response();
    assert_eq!(
        reply,
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok"
    );
    let seen = log.wait_for(4);
    assert!(
        seen.contains(&Seen::ReleaseOutcome(EffectOutcome::Completed(reply.len()))),
        "{seen:?}"
    );
}

/// **The upstream TLS handshake follows the request decision.** An upstream whose certificate the
/// gateway does not trust gets the request decision first, and then a request outcome of no byte
/// with the certificate error.
#[test]
fn the_upstream_tls_handshake_follows_the_request_decision() {
    let upstream = TlsUpstream::start_with_response(HOST, OK_REPLY);
    let (handle, log) = gateway(&upstream, false);
    let port = upstream.port();
    let mut client = WorkloadClient::connect(handle.port().unwrap(), HOST, port);
    client.send_request("GET", "/untrusted", &[], b"");
    assert_eq!(client.read_response(), "");
    assert_eq!(
        log.wait_for(2),
        [
            Seen::Request {
                method: "GET".to_string(),
                path: "/untrusted".to_string()
            },
            Seen::RequestOutcome(EffectOutcome::Failed {
                accepted_bytes: 0,
                error_kind: io::ErrorKind::InvalidData
            }),
        ]
    );
}

/// **An early reply to a large upload is released after the body is sent.** The upstream answers
/// `413` as soon as it has the head, then reads the whole body: the workload gets the `413`, and
/// the request outcome counts every byte of the request.
#[test]
fn an_early_reply_to_a_large_upload_is_released_after_the_body_is_sent() {
    const BODY: usize = 4 << 20;
    let upstream = TlsUpstream::start_answering_early(
        HOST,
        b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let (handle, log) = gateway(&upstream, true);
    let port = upstream.port();
    let mut client = WorkloadClient::connect(handle.port().unwrap(), HOST, port);
    client.send_request("POST", "/upload", &[], &vec![b'x'; BODY]);
    assert_eq!(
        client.read_response(),
        "HTTP/1.1 413 Client Error\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    let seen = upstream.last_request().raw;
    let (_, body) = seen.split_once("\r\n\r\n").unwrap();
    assert_eq!(body.len(), BODY, "the upstream read the whole body");
    let log = log.wait_for(4);
    assert!(
        log.iter().any(|seen| matches!(
            seen,
            Seen::RequestOutcome(EffectOutcome::Replied { accepted_bytes, status: 413 })
                if *accepted_bytes > BODY
        )),
        "{log:?}"
    );
    assert!(
        log.iter()
            .any(|seen| matches!(seen, Seen::Release { status: 413, .. })),
        "{log:?}"
    );
}

/// **A head over the 64 KiB limit gets hyper's own `431`**, with no refusal marker and no request
/// effect, and a long head under the limit still passes whole.
#[test]
fn a_head_over_the_limit_gets_hyper_431() {
    let long = "b".repeat(70 * 1024);
    let (response, seen, log) = exchange(
        OK_REPLY,
        &format!("GET /long HTTP/1.1\r\nHost: wire.test:{{port}}\r\nX-Long: {long}\r\n\r\n"),
        0,
    );
    assert_eq!(
        response,
        "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    assert_eq!(seen, None);
    assert!(log.is_empty(), "{log:?}");

    let legal = "b".repeat(4096);
    let (response, seen, _) = exchange(
        OK_REPLY,
        &format!("GET /legal HTTP/1.1\r\nHost: wire.test:{{port}}\r\nX-Long: {legal}\r\n\r\n"),
        4,
    );
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(
        seen.expect("forwarded")
            .contains(&format!("\r\nX-Long: {legal}\r\n"))
    );
}

/// **A nested `CONNECT` inside a tunnel is refused**: the connection closes with no reply and no
/// request effect.
#[test]
fn a_nested_connect_is_refused() {
    let (response, seen, log) = exchange(
        OK_REPLY,
        "CONNECT other.test:443 HTTP/1.1\r\nHost: other.test:443\r\n\r\n",
        0,
    );
    assert_eq!(response, "");
    assert_eq!(seen, None);
    assert!(log.is_empty(), "{log:?}");
}

/// A plain-HTTP origin on loopback that reads one request head and answers `reply`, then closes.
/// Its thread returns the head that it read.
fn plain_origin(reply: &'static [u8]) -> (u16, std::thread::JoinHandle<String>) {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut head = Vec::new();
        let mut byte = [0; 1];
        while !head.ends_with(b"\r\n\r\n") && matches!(stream.read(&mut byte), Ok(1)) {
            head.push(byte[0]);
        }
        let _ = stream.write_all(reply);
        String::from_utf8_lossy(&head).into_owned()
    });
    (port, thread)
}

/// Send `request` whole to a gateway on plain HTTP, and read until the gateway closes.
fn plain_exchange(handle: &MitmHandle, request: &str) -> String {
    use std::io::{Read, Write};

    let mut client = std::net::TcpStream::connect(("127.0.0.1", handle.port().unwrap())).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client.write_all(request.as_bytes()).unwrap();
    let mut reply = Vec::new();
    let _ = client.read_to_end(&mut reply);
    String::from_utf8_lossy(&reply).into_owned()
}

/// A gateway that permits loopback on plain HTTP, with an expected proxy token.
fn plain_gateway() -> (MitmHandle, Arc<Log>) {
    let log = Arc::new(Log::default());
    let config = MitmConfig {
        expected_token: Some("token".to_string()),
        ..MitmConfig::default()
    };
    let handle = MitmInterceptor::start(config, CapabilitySet::default(), log.clone()).unwrap();
    (handle, log)
}

/// **On plain HTTP, the gateway's static replies keep their bytes**: a target that names no
/// destination, a wrong proxy token, and a body whose chunk framing is broken each get the same
/// reply as before, with no request effect.
#[test]
fn plain_refusals_keep_their_bytes() {
    let (handle, log) = plain_gateway();
    let cases = [
        (
            "GET /origin-form HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n",
            "HTTP/1.1 400 bad request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
        (
            "GET http://127.0.0.1:9/token HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\
             Proxy-Authorization: Bearer wrong\r\n\r\n",
            "HTTP/1.1 407 proxy authentication required\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n",
        ),
        (
            "POST http://127.0.0.1:9/chunks HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\
             Transfer-Encoding: chunked\r\n\r\nzz\r\n",
            "HTTP/1.1 400 bad request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
    ];
    for (request, reply) in cases {
        assert_eq!(plain_exchange(&handle, request), reply, "{request:?}");
    }
    assert!(log.seen().is_empty(), "{:?}", log.seen());
}

/// **On plain HTTP, a target byte that `http::Uri` refuses gets hyper's own `400`**, with no
/// refusal marker, before any decision and before any upstream socket opens.
#[test]
fn a_target_byte_that_http_uri_refuses_gets_hyper_400_on_plain_http() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (handle, log) = plain_gateway();
    let reply = plain_exchange(
        &handle,
        &format!("GET http://127.0.0.1:{port}/a<b HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
    );
    assert_eq!(
        reply,
        "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    assert!(log.seen().is_empty(), "{:?}", log.seen());
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
        "no upstream socket opened"
    );
}

/// **On plain HTTP, a reply with no length is read to its close** and released under one
/// `Content-Length`, and an HTTP/1.0 request gets an `HTTP/1.0` reply (W4).
#[test]
fn a_plain_reply_with_no_length_is_read_to_its_close() {
    let (port, origin) = plain_origin(b"HTTP/1.1 200 OK\r\n\r\nuntil-close");
    let (handle, log) = plain_gateway();
    let reply = plain_exchange(
        &handle,
        &format!("GET http://127.0.0.1:{port}/close HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
    );
    assert_eq!(
        reply,
        "HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Length: 11\r\n\r\nuntil-close"
    );
    let head = origin.join().unwrap();
    assert!(
        head.starts_with("GET /close HTTP/1.1\r\n") && head.contains("\r\nHost: 127.0.0.1:"),
        "{head}"
    );
    assert!(
        log.wait_for(4)
            .contains(&Seen::ReleaseOutcome(EffectOutcome::Completed(reply.len()))),
        "{:?}",
        log.seen()
    );
}
