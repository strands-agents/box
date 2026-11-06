//! A reply from a site with no credential and no MCP server streams to the workload as it arrives,
//! so a body over the 16 MiB limit gets through (strands-agents/box#171).
//!
//! Each test starts a real `MitmInterceptor` that trusts a local TLS upstream, sends an HTTPS
//! request through it, and reads what the workload receives.
//!
//! Requires the default-on `tls-intercept` feature.

#![cfg(feature = "tls-intercept")]

mod harness;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use egress_gateway::{
    CapabilitySet, EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, MitmConfig,
    MitmHandle, MitmInterceptor,
};

use harness::{TlsUpstream, WorkloadClient, decode_chunked, header_value};

/// The gateway's default body limit, `ResponseLimits::default().max_body_bytes`.
const LIMIT: usize = 16 * 1024 * 1024;

/// Permits every effect, and notes when the gateway asks to release a reply, with the size it
/// gives.
#[derive(Default)]
struct Releases {
    asked_at: Mutex<Vec<Instant>>,
    sizes: Mutex<Vec<Option<usize>>>,
}

impl EffectInterceptor for Releases {
    fn intercept(&self, effect: &EffectAttempt<'_>) -> std::io::Result<Box<dyn EffectPermit>> {
        if let EffectAttempt::ResponseRelease { body_bytes, .. } = effect {
            self.asked_at.lock().unwrap().push(Instant::now());
            self.sizes.lock().unwrap().push(*body_bytes);
        }
        Ok(Box::new(Permit))
    }
}

struct Permit;

impl EffectPermit for Permit {
    fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> std::io::Result<()> {
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

/// Start a gateway with no credential and no MCP server, trusting `upstream` and pinning `host`
/// to loopback.
fn start_gateway(host: &str, upstream: &TlsUpstream, policy: Arc<Releases>) -> MitmHandle {
    let config = MitmConfig {
        upstream_ca_pems: vec![upstream.ca_pem()],
        dns_overrides: vec![(host.to_string(), "127.0.0.1".parse().unwrap())],
        ..MitmConfig::default()
    };
    MitmInterceptor::start(config, CapabilitySet::default(), policy).unwrap()
}

fn proxy_port(handle: &MitmHandle) -> u16 {
    handle.port().expect("TCP-mode test always has a port")
}

/// `len` bytes repeating a 251-byte cycle, so a dropped or repeated piece shows up.
fn body_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// A `200` reply that states its size in `Content-Length`.
fn sized_reply(body: &[u8]) -> Vec<u8> {
    let mut reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    reply.extend_from_slice(body);
    reply
}

/// A chunked `200` reply that states no size, in 1 MiB chunks, as a Git server sends a pack.
fn chunked_reply(body: &[u8]) -> Vec<u8> {
    let mut reply =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    for chunk in body.chunks(1024 * 1024) {
        reply.extend_from_slice(format!("{:X}\r\n", chunk.len()).as_bytes());
        reply.extend_from_slice(chunk);
        reply.extend_from_slice(b"\r\n");
    }
    reply.extend_from_slice(b"0\r\n\r\n");
    reply
}

/// GET through the gateway, and return the head and the decoded body the workload received.
fn fetch(host: &str, upstream: &TlsUpstream) -> (String, Vec<u8>) {
    let handle = start_gateway(host, upstream, Arc::default());
    let mut client = WorkloadClient::connect(proxy_port(&handle), host, upstream.port());
    client.send_request("GET", "/package.tgz", &[], b"");
    let head = client.read_head();
    let raw = client.read_to_close();
    let chunked = header_value(&head, "transfer-encoding")
        .is_some_and(|coding| coding.eq_ignore_ascii_case("chunked"));
    let body = if chunked {
        decode_chunked(&raw).expect("the chunked body ends with its last chunk")
    } else {
        raw
    };
    (head, body)
}

fn assert_whole(head: &str, body: &[u8], expected: &[u8]) {
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "the workload got no 200 reply, so the gateway refused it; head: {head:?}"
    );
    assert_eq!(
        body.len(),
        expected.len(),
        "the workload got {} of the {} body bytes",
        body.len(),
        expected.len()
    );
    assert!(body == expected, "the body reached the workload changed");
}

#[test]
fn a_reply_one_byte_over_the_limit_reaches_the_workload_whole() {
    let host = "registry.stream.test";
    let body = body_of(LIMIT + 1);
    let upstream = TlsUpstream::start_with_bytes(host, sized_reply(&body));

    let (head, received) = fetch(host, &upstream);

    assert_whole(&head, &received, &body);
}

#[test]
fn a_40_mib_reply_reaches_the_workload_whole() {
    let host = "media.stream.test";
    let body = body_of(40 * 1024 * 1024);
    let upstream = TlsUpstream::start_with_bytes(host, sized_reply(&body));

    let (head, received) = fetch(host, &upstream);

    assert_whole(&head, &received, &body);
}

#[test]
fn a_chunked_reply_over_the_limit_reaches_the_workload_whole() {
    let host = "git.stream.test";
    let body = body_of(LIMIT + 1024 * 1024);
    let upstream = TlsUpstream::start_with_bytes(host, chunked_reply(&body));

    let (head, received) = fetch(host, &upstream);

    assert_whole(&head, &received, &body);
}

/// box#171's own check: an origin that sends part of a reply and finishes later. The workload
/// gets the first piece, and the gateway asks for the go-ahead, before the origin finishes.
#[test]
fn the_first_piece_reaches_the_workload_before_the_reply_ends() {
    let host = "events.stream.test";
    let gap = Duration::from_secs(2);
    let first =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nfirst\r\n";
    let rest = b"4\r\nlast\r\n0\r\n\r\n";
    let upstream = TlsUpstream::start_in_pieces(host, vec![first.to_vec(), rest.to_vec()], gap);
    let policy = Arc::new(Releases::default());
    let handle = start_gateway(host, &upstream, policy.clone());
    let mut client = WorkloadClient::connect(proxy_port(&handle), host, upstream.port());

    let sent = Instant::now();
    client.send_request("GET", "/events", &[], b"");
    let head = client.read_head();
    let first_piece = client.time_until(b"first", sent);
    let asked = policy.asked_at.lock().unwrap().first().copied();

    assert!(
        head.starts_with("HTTP/1.1 200"),
        "no 200 reply; head: {head:?}"
    );
    let first_piece = first_piece.expect("the first piece reached the workload");
    assert!(
        first_piece < gap / 2,
        "the first piece arrived {first_piece:?} after the request, so the gateway waited for \
         the origin to finish"
    );
    let asked = asked
        .expect("the gateway asked for the go-ahead")
        .duration_since(sent);
    assert!(
        asked < gap / 2,
        "the gateway asked for the go-ahead {asked:?} after the request, so it waited for the \
         origin to finish"
    );
}

/// The gateway asks for the go-ahead before it reads the body, so it gives the length the
/// upstream declared, and no length for a chunked reply.
#[test]
fn the_go_ahead_carries_the_declared_length() {
    let body = body_of(1024);
    for (host, reply, expected) in [
        ("sized.stream.test", sized_reply(&body), Some(1024)),
        ("chunked.stream.test", chunked_reply(&body), None),
    ] {
        let upstream = TlsUpstream::start_with_bytes(host, reply);
        let policy = Arc::new(Releases::default());
        let handle = start_gateway(host, &upstream, policy.clone());
        let mut client = WorkloadClient::connect(proxy_port(&handle), host, upstream.port());
        client.send_request("GET", "/package.tgz", &[], b"");
        let head = client.read_head();
        let _ = client.read_to_close();

        assert!(head.starts_with("HTTP/1.1 200"), "{host}: {head:?}");
        assert_eq!(*policy.sizes.lock().unwrap(), vec![expected], "{host}");
    }
}
