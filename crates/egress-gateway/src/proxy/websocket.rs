//! WebSocket: the RFC 6455 handshake checks, and a relay that reads each frame header and forwards
//! the frame as it came. Before more of the workload's bytes leave, the relay asks policy again.

use std::cell::RefCell;

use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hyper::header::HeaderMap;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use ring::rand::SecureRandom as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use crate::audit::RequestId;
use crate::boundary::{BodyRef, InterceptedResponse, Target, Verdict};
use crate::capability::CapabilityContext;
use crate::effect::{ClaimedEffectPermit, EffectAttempt, EffectOutcome};
use crate::intercept::mitm::SharedState;
use crate::intercept::mitm::connect::ConnectRequest;
use crate::intercept::mitm::l7;

/// What a request asks for in its `Upgrade` field.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Handshake {
    /// No `websocket` token: an ordinary request.
    None,
    /// A valid handshake, with its `Sec-WebSocket-Key`.
    WebSocket(String),
    /// A request that names `websocket` and is not a valid handshake, and why.
    Malformed(&'static str),
}

/// Classify a request head as hyper parsed it.
pub(crate) fn classify<B: hyper::body::Body>(request: &hyper::Request<B>) -> Handshake {
    let headers = request.headers();
    if !tokens(headers, "upgrade").any(|token| token.eq_ignore_ascii_case("websocket")) {
        return Handshake::None;
    }
    let key = one(headers, "sec-websocket-key")
        .filter(|key| STANDARD.decode(key).is_ok_and(|bytes| bytes.len() == 16));
    Handshake::Malformed(if request.method() != hyper::Method::GET {
        "websocket: handshake method is not GET"
    } else if request.version() != hyper::Version::HTTP_11 {
        "websocket: handshake is not HTTP/1.1"
    } else if !tokens(headers, "connection").any(|token| token.eq_ignore_ascii_case("upgrade")) {
        "websocket: handshake lacks Connection: upgrade"
    } else if one(headers, "sec-websocket-version") != Some("13") {
        "websocket: handshake version is not 13"
    } else if !request.body().is_end_stream() {
        "websocket: handshake carries a body"
    } else if let Some(key) = key {
        return Handshake::WebSocket(key.to_string());
    } else {
        "websocket: handshake key is not 16 bytes of base64"
    })
}

/// The `Sec-WebSocket-Accept` value that answers `key`.
pub(crate) fn accept(key: &str) -> String {
    let mut digest = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    digest.update(key.as_bytes());
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    STANDARD.encode(digest.finish())
}

/// Check that a `101` answers the handshake whose accept value is `accept`. hyper's client takes
/// every `101` as an upgrade, so the gateway checks it.
pub(crate) fn check_101(headers: &HeaderMap, accept: &str) -> Result<(), &'static str> {
    if !one(headers, "upgrade").is_some_and(|value| value.eq_ignore_ascii_case("websocket")) {
        Err("websocket: 101 does not name Upgrade: websocket")
    } else if !tokens(headers, "connection").any(|token| token.eq_ignore_ascii_case("upgrade")) {
        Err("websocket: 101 lacks Connection: upgrade")
    } else if one(headers, "sec-websocket-accept") != Some(accept) {
        Err("websocket: 101 carries a wrong Sec-WebSocket-Accept")
    } else if headers.contains_key("sec-websocket-extensions") {
        Err("websocket: 101 negotiates an extension")
    } else {
        Ok(())
    }
}

/// Every comma-separated token of every `name` field.
fn tokens<'a>(headers: &'a HeaderMap, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    headers
        .get_all(name)
        .iter()
        .flat_map(|value| value.to_str().unwrap_or("").split(','))
        .map(str::trim)
}

/// The value of the one `name` field, or `None` when it is absent or repeated.
fn one<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok().map(str::trim),
        _ => None,
    }
}

/// The status, the reason, and the response body of a refusal.
type Refusal = (u16, &'static str, &'static [u8]);

/// The refusals before policy, then one of the WebSocket slots. Returns the accept value and the
/// slot.
pub(crate) fn admit(
    handshake: Handshake,
    state: &SharedState,
    host: &str,
) -> Result<Option<(String, Slot)>, Refusal> {
    match handshake {
        Handshake::None => Ok(None),
        Handshake::Malformed(why) => Err((400, why, b"malformed WebSocket handshake")),
        Handshake::WebSocket(_) if state.mcp_server_for(host).is_some() => Err((
            403,
            "websocket: upgrade to a remote MCP server",
            b"WebSocket refused for an MCP server",
        )),
        Handshake::WebSocket(key) => Slot::take(state)
            .map(|slot| Some((accept(&key), slot)))
            .ok_or((
                503,
                "websocket: the open WebSockets hold their share of the connection slots",
                b"WebSocket session limit reached",
            )),
    }
}

/// One of the open WebSockets, at most three quarters of the connection slots, so plain requests
/// always find a slot.
pub(crate) struct Slot(Arc<AtomicUsize>);

impl Slot {
    pub(crate) fn take(state: &SharedState) -> Option<Self> {
        let cap = (state.config.max_connections * 3 / 4).max(1);
        let open = state.websockets.clone();
        open.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < cap).then_some(n + 1)
        })
        .ok()
        .map(|_| Self(open))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// An upgraded upstream, waiting for the workload's side of the upgrade.
pub(crate) struct Relay {
    pub(crate) upstream: Upgraded,
    /// The target of the handshake, when a credential applies to it and server messages are
    /// scrubbed.
    pub(crate) scrub: Option<Target>,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) correlation: RequestId,
    /// Held until the relay ends.
    pub(crate) _slot: Slot,
}

/// Relay frames between the workload and the upstream until both close, and record a close that
/// the gateway makes.
pub(crate) async fn run(
    workload: Upgraded,
    relay: Relay,
    state: &SharedState,
    connect: &ConnectRequest,
) {
    let (mut from_workload, mut to_workload) = tokio::io::split(TokioIo::new(workload));
    let (mut from_upstream, mut to_upstream) = tokio::io::split(TokioIo::new(relay.upstream));
    let limits = Limits {
        max: state.config.response_limits.max_body_bytes,
        active: Cell::new(Instant::now()),
    };
    let (upstream_clean, workload_clean) = (Cell::new(true), Cell::new(true));
    let ping = RefCell::new(None);
    let mut lease = Lease {
        state,
        connect,
        request: (&relay.method, &relay.path),
        correlation: &relay.correlation,
        open: None,
        asked: (Instant::now(), 0),
    };
    let correlation = &relay.correlation;
    let scrub = relay.scrub.as_ref().map(|target| {
        move |payload| {
            scrub(state, target, correlation, payload).map_err(|why| -> Fault { (1014, 1008, why) })
        }
    });
    let fault = tokio::select! {
        end = async {
            tokio::try_join!(
                pump(
                    &mut from_workload,
                    &mut to_upstream,
                    Side::Client { lease: &mut lease, ping: &ping },
                    &limits,
                    &upstream_clean,
                ),
                pump(
                    &mut from_upstream,
                    &mut to_workload,
                    Side::Server {
                        scrub: scrub.as_ref().map(|scrub| scrub as &Scrub),
                        ping: &ping,
                    },
                    &limits,
                    &workload_clean,
                ),
            )
        } => end.err(),
        () = idle(&limits.active, state.config.upstream_read_deadline) => {
            Some((1001, 1001, "websocket: idle".to_string()))
        }
    };
    if let Some((to_client, to_server, reason)) = &fault {
        if workload_clean.get() {
            let _ = to_workload
                .write_all(&encode(8, &to_client.to_be_bytes(), false))
                .await;
        }
        if upstream_clean.get() {
            let _ = to_upstream
                .write_all(&encode(8, &to_server.to_be_bytes(), true))
                .await;
        }
        let request = (relay.method.as_str(), relay.path.as_str());
        l7::record_deny(state, connect, request, reason, relay.correlation.clone());
    }
    let _ = to_workload.shutdown().await;
    let _ = to_upstream.shutdown().await;
}

/// The close codes to the workload and to the upstream, and why the gateway closes.
type Fault = (u16, u16, String);

/// The scrub of one server message.
type Scrub<'a> = dyn Fn(Vec<u8>) -> Result<Vec<u8>, Fault> + 'a;

/// The message cap, and when a byte last moved in either direction.
struct Limits {
    max: usize,
    active: Cell<Instant>,
}

/// What a pump adds to the frame rules, and the server's ping that has no pong yet.
enum Side<'a, 'b> {
    /// The workload's frames, each sent inside a lease that policy allowed.
    Client {
        lease: &'a mut Lease<'b>,
        ping: &'a RefCell<Option<Vec<u8>>>,
    },
    /// The server's frames, scrubbed when a credential applies.
    Server {
        scrub: Option<&'a Scrub<'b>>,
        ping: &'a RefCell<Option<Vec<u8>>>,
    },
}

/// Bytes the workload may send before the relay asks policy again.
const LEASE_BYTES: usize = 64 * 1024;
/// How long a lease lasts.
const LEASE_TIME: Duration = Duration::from_secs(30);

/// The workload's bytes that one `http:request` decision allows. The relay asks again when they
/// are used up, when the lease is old, or when the policy history has changed.
struct Lease<'a> {
    state: &'a SharedState,
    connect: &'a ConnectRequest,
    /// The handshake's method and path.
    request: (&'a str, &'a str),
    correlation: &'a RequestId,
    /// The open lease: its permit, the bytes it allows, and the bytes sent.
    open: Option<(ClaimedEffectPermit, usize, usize)>,
    /// When the open lease was decided, and the history version then.
    asked: (Instant, u64),
}

impl Lease<'_> {
    /// Make room for one frame of `size` bytes, or refuse it with the policy's reason.
    fn admit(&mut self, size: usize) -> Result<(), Fault> {
        let version = self.state.effect_interceptor.history_version();
        let current = self.asked.1 == version && self.asked.0.elapsed() < LEASE_TIME;
        if let Some((_, allowed, sent)) = &mut self.open
            && current
            && *sent + size <= *allowed
        {
            *sent += size;
            return Ok(());
        }
        self.end();
        let allowed = size.max(LEASE_BYTES);
        let attempt = EffectAttempt::HttpRequest {
            host: &self.connect.host,
            port: self.connect.port,
            method: self.request.0,
            path: self.request.1,
            body_bytes: allowed,
            intercepted: true,
            mcp: None,
            upgrade: Some("websocket"),
        };
        match l7::claim_effect(self.state, &attempt) {
            Ok(permit) => {
                l7::record_allow(
                    self.state,
                    self.connect,
                    self.request,
                    self.correlation.clone(),
                );
                self.open = Some((permit, allowed, size));
                self.asked = (Instant::now(), version);
                Ok(())
            }
            Err(error) => {
                let code = if error.kind() == std::io::ErrorKind::PermissionDenied {
                    1008
                } else {
                    1011
                };
                Err((
                    code,
                    1001,
                    format!("request effect interception failed: {error}"),
                ))
            }
        }
    }

    /// Record the bytes the open lease sent.
    fn end(&mut self) {
        if let Some((permit, _, sent)) = self.open.take() {
            let outcome = EffectOutcome::Replied {
                accepted_bytes: sent,
                status: 101,
            };
            let _ = permit.record_outcome(outcome);
        }
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.end();
    }
}

/// Forward frames from `from` to `to` until a Close or the end of the stream. Each frame is
/// checked by its header and forwarded as it came, except a server frame that `scrub` must read.
/// Frames from the client are masked, and frames from the server are not.
async fn pump<R, W>(
    from: &mut R,
    to: &mut W,
    mut direction: Side<'_, '_>,
    limits: &Limits,
    clean: &Cell<bool>,
) -> Result<(), Fault>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (from_client, scrub) = match &direction {
        Side::Client { .. } => (true, None),
        Side::Server { scrub, .. } => (false, *scrub),
    };
    let side = if from_client { "client" } else { "server" };
    // The side that breaks a rule gets its code. The other side gets 1001 after a workload fault,
    // and 1014 (bad gateway) after a server fault.
    let fault = |code, why: &str| {
        let why = format!("websocket: {side} {why}");
        if from_client {
            (code, 1001, why)
        } else {
            (1014, code, why)
        }
    };
    let protocol = |why: &str| fault(1002, why);
    let too_big = || fault(1009, "message exceeds the size limit");
    let mut buffer = Vec::new();
    // The opcode and length so far of a message whose last frame has not come, and its payload
    // when it is scrubbed.
    let mut message: Option<(u8, usize, Vec<u8>)> = None;
    let mut chunk = vec![0; 16 * 1024];
    loop {
        while let Some(frame) = header(&buffer).map_err(protocol)? {
            if frame.masked != from_client {
                return Err(protocol(if from_client {
                    "frame not masked"
                } else {
                    "frame masked"
                }));
            }
            if frame.len > limits.max {
                return Err(too_big());
            }
            if buffer.len() < frame.size + frame.len {
                break;
            }
            let bytes: Vec<u8> = buffer.drain(..frame.size + frame.len).collect();
            let payload = &bytes[frame.size..];
            let data = frame.opcode < 8;
            if data {
                let (opcode, len, held) = match (frame.opcode, message.take()) {
                    (0, Some((opcode, len, held))) => (opcode, len + frame.len, held),
                    (1 | 2, None) => (frame.opcode, frame.len, Vec::new()),
                    _ => return Err(protocol("frame breaks the message order")),
                };
                if len > limits.max {
                    return Err(too_big());
                }
                message = (!frame.fin || scrub.is_some()).then_some((opcode, len, held));
            }
            // A frame with no check goes out under the gateway's key, not the workload's.
            let mut exempt = None;
            match &mut direction {
                // No check for a Close with only its code, or one pong for each ping.
                Side::Client { lease, ping } if !data => {
                    let key = &bytes[frame.size - 4..frame.size];
                    let plain: Vec<u8> = payload
                        .iter()
                        .zip(key.iter().cycle())
                        .map(|(b, k)| b ^ k)
                        .collect();
                    let free = match frame.opcode {
                        8 => matches!(frame.len, 0 | 2),
                        10 => ping.borrow_mut().take_if(|ping| *ping == plain).is_some(),
                        _ => false,
                    };
                    if free {
                        exempt = Some(encode(frame.opcode, &plain, true));
                    } else {
                        lease.admit(bytes.len())?;
                    }
                }
                Side::Client { lease, .. } => lease.admit(bytes.len())?,
                Side::Server { ping, .. } if frame.opcode == 9 => {
                    *ping.borrow_mut() = Some(payload.to_vec())
                }
                Side::Server { .. } => {}
            }
            let out = match scrub {
                Some(scrub) if data => {
                    let (opcode, len, mut held) = message.take().unwrap_or_default();
                    held.extend_from_slice(payload);
                    if !frame.fin {
                        message = Some((opcode, len, held));
                        continue;
                    }
                    encode(opcode, &scrub(held)?, false)
                }
                // A control payload that held the secret goes empty; a Close keeps its code.
                Some(scrub) if scrub(payload.to_vec())? != payload => {
                    let kept = if frame.opcode == 8 {
                        frame.len.min(2)
                    } else {
                        0
                    };
                    encode(frame.opcode, &payload[..kept], false)
                }
                _ => exempt.unwrap_or(bytes),
            };
            clean.set(false);
            if to.write_all(&out).await.is_err() {
                return Ok(());
            }
            clean.set(true);
            if frame.opcode == 8 {
                return Ok(());
            }
        }
        match from.read(&mut chunk).await {
            Ok(0) | Err(_) => {
                let _ = to.shutdown().await;
                return Ok(());
            }
            Ok(read) => {
                limits.active.set(Instant::now());
                buffer.extend_from_slice(&chunk[..read]);
            }
        }
    }
}

/// A frame header.
struct Header {
    fin: bool,
    opcode: u8,
    masked: bool,
    /// The payload length.
    len: usize,
    /// The header length.
    size: usize,
}

/// The header at the start of `buffer`, once it is whole.
fn header(buffer: &[u8]) -> Result<Option<Header>, &'static str> {
    let [first, second, ..] = *buffer else {
        return Ok(None);
    };
    if first & 0x70 != 0 {
        return Err("frame sets a reserved bit");
    }
    let (opcode, fin, masked) = (first & 0x0f, first & 0x80 != 0, second & 0x80 != 0);
    let (len, size) = match second & 0x7f {
        126 if buffer.len() >= 4 => (u64::from(u16::from_be_bytes([buffer[2], buffer[3]])), 4),
        127 if buffer.len() >= 10 => (
            u64::from_be_bytes(buffer[2..10].try_into().unwrap_or_default()),
            10,
        ),
        126 | 127 => return Ok(None),
        len => (u64::from(len), 2),
    };
    match opcode {
        0..=2 => {}
        8..=10 if fin && len <= 125 => {}
        8..=10 => return Err("control frame is fragmented or too long"),
        _ => return Err("frame has an unknown opcode"),
    }
    let size = size + if masked { 4 } else { 0 };
    let len = usize::try_from(len).map_err(|_| "frame is too long")?;
    Ok((buffer.len() >= size).then_some(Header {
        fin,
        opcode,
        masked,
        len,
        size,
    }))
}

/// One whole frame. A frame toward the server is masked with a fresh key.
fn encode(opcode: u8, payload: &[u8], mask: bool) -> Vec<u8> {
    let bit = if mask { 0x80 } else { 0 };
    let mut out = vec![0x80 | opcode];
    match payload.len() {
        len @ 0..=125 => out.push(bit | len as u8),
        len @ 126..=0xffff => {
            out.push(bit | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        len => {
            out.push(bit | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    if mask {
        let mut key = [0; 4];
        let _ = ring::rand::SystemRandom::new().fill(&mut key);
        out.extend_from_slice(&key);
        out.extend(
            payload
                .iter()
                .zip(key.iter().cycle())
                .map(|(byte, k)| byte ^ k),
        );
    } else {
        out.extend_from_slice(payload);
    }
    out
}

/// Remove a credential that `target`'s route attached from one server message.
fn scrub(
    state: &SharedState,
    target: &Target,
    correlation: &RequestId,
    payload: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let mut message = InterceptedResponse::http(200, Default::default(), BodyRef::Bytes(payload));
    let cx = CapabilityContext::new(correlation.clone(), state.now_unix_secs(), target.clone());
    match state.controls.evaluate_response(&mut message, &cx) {
        Verdict::Allow { .. } => Ok(match message.body {
            BodyRef::Bytes(body) => body,
            BodyRef::Empty => Vec::new(),
        }),
        Verdict::Deny { reason } => Err(format!("websocket: {reason}")),
    }
}

/// Wait until no byte has moved in either direction for `limit`.
async fn idle(active: &Cell<Instant>, limit: Duration) {
    while Instant::now() < active.get() + limit {
        tokio::time::sleep_until(active.get() + limit).await;
    }
}
