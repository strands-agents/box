use std::cell::{Cell, RefCell};
use std::io;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use credentials::ResponseRedactor;
use hyper::header::HeaderMap as WireHeaders;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use ring::rand::SecureRandom as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use crate::audit::{Decision as AuditDecision, RequestId};
use crate::boundary::{HeaderMap, Target};
use crate::effect::{ClaimedEffectPermit, EffectAttempt, EffectOutcome, WebSocketOpcode};
use crate::intercept::mitm::SharedState;
use crate::intercept::mitm::connect::ConnectRequest;
use crate::intercept::mitm::l7;

const CONTINUATION: u8 = 0x0;
const TEXT: u8 = 0x1;
const BINARY: u8 = 0x2;
const CLOSE: u8 = 0x8;
const PING: u8 = 0x9;
const PONG: u8 = 0xA;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Handshake {
    None,
    WebSocket { accept: String },
    Malformed(&'static str),
}

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
        return Handshake::WebSocket {
            accept: accept(key),
        };
    } else {
        "websocket: handshake key is not 16 bytes of base64"
    })
}

fn accept(key: &str) -> String {
    let mut digest = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    digest.update(key.as_bytes());
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    STANDARD.encode(digest.finish())
}

pub(crate) fn check_101(headers: &WireHeaders, accept: &str) -> Result<(), &'static str> {
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

fn tokens<'a>(headers: &'a WireHeaders, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    headers
        .get_all(name)
        .iter()
        .flat_map(|value| value.to_str().unwrap_or("").split(','))
        .map(str::trim)
}

fn one<'a>(headers: &'a WireHeaders, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok().map(str::trim),
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Header {
    fin: bool,
    opcode: u8,
    key: Option<[u8; 4]>,
    len: usize,
    size: usize,
}

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
        127 if buffer.len() >= 10 => {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(&buffer[2..10]);
            if bytes[0] & 0x80 != 0 {
                return Err("frame length sets the most significant bit");
            }
            (u64::from_be_bytes(bytes), 10)
        }
        126 | 127 => return Ok(None),
        len => (u64::from(len), 2),
    };
    match opcode {
        CONTINUATION | TEXT | BINARY => {}
        CLOSE | PING | PONG if fin && len <= 125 => {}
        CLOSE | PING | PONG => return Err("control frame is fragmented or too long"),
        _ => return Err("frame has an unknown opcode"),
    }
    let len = usize::try_from(len).map_err(|_| "frame is too long")?;
    if !masked {
        return Ok((buffer.len() >= size).then_some(Header {
            fin,
            opcode,
            key: None,
            len,
            size,
        }));
    }
    Ok(buffer.get(size..size + 4).map(|key| Header {
        fin,
        opcode,
        key: key.try_into().ok(),
        len,
        size: size + 4,
    }))
}

fn mask(payload: &mut [u8], key: Option<[u8; 4]>) {
    if let Some(key) = key {
        for (byte, k) in payload.iter_mut().zip(key.iter().cycle()) {
            *byte ^= k;
        }
    }
}

fn mask_key() -> Option<[u8; 4]> {
    let mut key = [0; 4];
    ring::rand::SystemRandom::new().fill(&mut key).ok()?;
    Some(key)
}

fn encode(opcode: u8, payload: &[u8], key: Option<[u8; 4]>) -> Vec<u8> {
    let mut frame = encode_head(opcode, payload.len(), key);
    frame.reserve(payload.len());
    let start = frame.len();
    frame.extend_from_slice(payload);
    mask(&mut frame[start..], key);
    frame
}

fn encode_head(opcode: u8, len: usize, key: Option<[u8; 4]>) -> Vec<u8> {
    let bit = if key.is_some() { 0x80 } else { 0 };
    let mut frame = Vec::with_capacity(14);
    frame.push(0x80 | opcode);
    match len {
        len @ 0..=125 => frame.push(bit | len as u8),
        len @ 126..=0xffff => {
            frame.push(bit | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        }
        len => {
            frame.push(bit | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    frame.extend(key.into_iter().flatten());
    frame
}

fn check_message(opcode: u8, payload: &[u8]) -> Result<(), (u16, &'static str)> {
    let utf8 = |bytes| std::str::from_utf8(bytes).is_ok();
    match (opcode, payload) {
        (TEXT, text) if !utf8(text) => Err((1007, "text is not UTF-8")),
        (CLOSE, [_]) => Err((1002, "close payload is one byte")),
        (CLOSE, [high, low, reason @ ..]) => {
            if !matches!(
                u16::from_be_bytes([*high, *low]),
                1000..=1003 | 1007..=1014 | 3000..=4999
            ) {
                Err((1002, "close code is not valid"))
            } else if !utf8(reason) {
                Err((1007, "close reason is not UTF-8"))
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

fn effect_opcode(opcode: u8) -> Option<WebSocketOpcode> {
    match opcode {
        TEXT => Some(WebSocketOpcode::Text),
        BINARY => Some(WebSocketOpcode::Binary),
        CLOSE => Some(WebSocketOpcode::Close),
        PING => Some(WebSocketOpcode::Ping),
        PONG => Some(WebSocketOpcode::Pong),
        _ => None,
    }
}

pub(crate) struct Relay {
    pub(crate) upstream: Upgraded,
    pub(crate) path: String,
    pub(crate) scrub: Option<Target>,
    pub(crate) correlation: RequestId,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Workload,
    Server,
}

struct Fault {
    workload: u16,
    server: u16,
    refusal: Option<String>,
}

impl Fault {
    fn refused(reason: String) -> Self {
        Self {
            workload: 1008,
            server: 1001,
            refusal: Some(reason),
        }
    }

    fn protocol(side: Side, code: u16, why: &str) -> Self {
        let (workload, server, sender) = match side {
            Side::Workload => (code, 1001, "workload"),
            Side::Server => (1014, code, "server"),
        };
        Self {
            workload,
            server,
            refusal: Some(format!("websocket: {sender} {why}")),
        }
    }

    fn dropped(side: Side) -> Self {
        let code = match side {
            Side::Workload => 1001,
            Side::Server => 1014,
        };
        Self {
            workload: code,
            server: code,
            refusal: None,
        }
    }

    fn internal(refusal: Option<String>) -> Self {
        Self {
            workload: 1011,
            server: 1001,
            refusal,
        }
    }
}

struct InFlight {
    permit: ClaimedEffectPermit,
    header: usize,
    payload: usize,
    written: usize,
}

impl InFlight {
    fn record(self, error: Option<io::ErrorKind>) -> io::Result<()> {
        let delivered = self.written.saturating_sub(self.header);
        let outcome = match error {
            None => EffectOutcome::Completed(self.payload),
            Some(error_kind) if delivered == 0 => EffectOutcome::Failed {
                accepted_bytes: 0,
                error_kind,
            },
            Some(error_kind) => EffectOutcome::Partial {
                accepted_bytes: delivered,
                error_kind,
            },
        };
        self.permit.record_outcome(outcome)
    }
}

#[derive(Default)]
struct Leg {
    closed: Cell<bool>,
    in_flight: RefCell<Option<InFlight>>,
}

impl Leg {
    fn begin(&self, permit: ClaimedEffectPermit, header: usize, payload: usize) {
        *self.in_flight.borrow_mut() = Some(InFlight {
            permit,
            header,
            payload,
            written: 0,
        });
    }

    fn end(&self, side: Side, error: Option<io::ErrorKind>) -> Result<(), Fault> {
        self.closed.set(error.is_some());
        if let Some(in_flight) = self.in_flight.take() {
            in_flight.record(error).map_err(|_| Fault::internal(None))?;
        }
        match (error, side) {
            (None, _) => Ok(()),
            (Some(_), Side::Workload) => Err(Fault::dropped(Side::Server)),
            (Some(_), Side::Server) => Err(Fault::dropped(Side::Workload)),
        }
    }
}

fn out_key(side: Side) -> Result<Option<[u8; 4]>, Fault> {
    match side {
        Side::Server => Ok(None),
        Side::Workload => mask_key()
            .map(Some)
            .ok_or_else(|| Fault::internal(Some("websocket: no mask key".into()))),
    }
}

struct Session<'a> {
    state: &'a SharedState,
    connect: &'a ConnectRequest,
    path: &'a str,
    scrub: Option<&'a Target>,
    active: Cell<Instant>,
}

pub(crate) async fn run(
    workload: Upgraded,
    relay: Relay,
    state: &SharedState,
    connect: &ConnectRequest,
) {
    let (mut from_workload, mut to_workload) = tokio::io::split(TokioIo::new(workload));
    let (mut from_server, mut to_server) = tokio::io::split(TokioIo::new(relay.upstream));
    let session = Session {
        state,
        connect,
        path: &relay.path,
        scrub: relay.scrub.as_ref(),
        active: Cell::new(Instant::now()),
    };
    let (workload_leg, server_leg) = (Leg::default(), Leg::default());
    let fault = tokio::select! {
        ended = async {
            tokio::try_join!(
                session.pump(Side::Workload, &mut from_workload, &mut to_server, &server_leg),
                session.pump(Side::Server, &mut from_server, &mut to_workload, &workload_leg),
            )
        } => ended.err(),
        () = idle(&session.active, state.config.upstream_read_deadline) => Some(Fault {
            workload: 1001,
            server: 1001,
            refusal: None,
        }),
    };
    for leg in [&workload_leg, &server_leg] {
        if let Some(in_flight) = leg.in_flight.take() {
            leg.closed.set(true);
            let _ = in_flight.record(Some(io::ErrorKind::ConnectionAborted));
        }
    }
    if let Some(reason) = fault.as_ref().and_then(|fault| fault.refusal.as_deref()) {
        let request = ("GET", relay.path.as_str());
        let correlation = relay.correlation.clone();
        l7::emit_decision(
            state,
            connect,
            request,
            AuditDecision::Deny,
            reason,
            correlation,
        );
    }
    let closing = async {
        if let Some(fault) = &fault {
            if !workload_leg.closed.get() {
                let close = encode(CLOSE, &fault.workload.to_be_bytes(), None);
                let _ = to_workload.write_all(&close).await;
            }
            if !server_leg.closed.get() {
                match mask_key() {
                    Some(key) => {
                        let close = encode(CLOSE, &fault.server.to_be_bytes(), Some(key));
                        let _ = to_server.write_all(&close).await;
                    }
                    None => eprintln!(
                        "strands-box: warning: no mask key for the WebSocket Close to {}",
                        connect.host
                    ),
                }
            }
        }
        let _ = to_workload.shutdown().await;
        let _ = to_server.shutdown().await;
    };
    let _ = tokio::time::timeout(state.config.upstream_read_deadline, closing).await;
}

impl Session<'_> {
    async fn pump<R, W>(&self, side: Side, from: &mut R, to: &mut W, leg: &Leg) -> Result<(), Fault>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let limit = self.state.config.response_limits.max_body_bytes;
        let fault = |code, why| Fault::protocol(side, code, why);
        let mut buffer = Vec::new();
        let mut message: Option<(u8, Vec<u8>)> = None;
        loop {
            while let Some(frame) = header(&buffer).map_err(|why| fault(1002, why))? {
                if frame.key.is_some() != (side == Side::Workload) {
                    return Err(fault(1002, "frame masking does not match its sender"));
                }
                if frame.opcode == BINARY
                    && frame.fin
                    && message.is_none()
                    && side == Side::Server
                    && self.scrub.is_none()
                {
                    buffer.drain(..frame.size);
                    self.stream(frame.len, &mut buffer, from, to, leg).await?;
                    continue;
                }
                let held = match &message {
                    Some((_, payload)) if frame.opcode < CLOSE => payload.len(),
                    _ => 0,
                };
                if frame.len > limit.saturating_sub(held) {
                    return Err(fault(1009, "message exceeds the size limit"));
                }
                if buffer.len() < frame.size + frame.len {
                    break;
                }
                let rest = buffer.split_off(frame.size + frame.len);
                let mut payload = std::mem::replace(&mut buffer, rest);
                payload.drain(..frame.size);
                mask(&mut payload, frame.key);
                let whole = match (frame.opcode, message.take()) {
                    (CLOSE | PING | PONG, held) => {
                        message = held;
                        Some((frame.opcode, payload))
                    }
                    (TEXT | BINARY, None) => Some((frame.opcode, payload)),
                    (CONTINUATION, Some((opcode, mut held))) => {
                        held.extend_from_slice(&payload);
                        Some((opcode, held))
                    }
                    _ => return Err(fault(1002, "frame breaks the message order")),
                };
                match whole {
                    Some((opcode, payload)) if frame.fin || opcode >= CLOSE => {
                        self.deliver(side, opcode, payload, to, leg).await?;
                        if opcode == CLOSE {
                            leg.closed.set(true);
                            return Ok(());
                        }
                    }
                    held => message = held,
                }
            }
            self.read(side, from, &mut buffer).await?;
        }
    }

    async fn deliver<W: AsyncWrite + Unpin>(
        &self,
        side: Side,
        opcode: u8,
        payload: Vec<u8>,
        to: &mut W,
        leg: &Leg,
    ) -> Result<(), Fault> {
        check_message(opcode, &payload).map_err(|(code, why)| Fault::protocol(side, code, why))?;
        let redactors = self
            .scrub_for(side)
            .map(|target| redactors(self.state, target));
        let redactors = redactors.transpose()?;
        let key = out_key(side)?;
        let permit = self.decide(side, opcode, payload.len())?;
        let mut payload = match redactors {
            Some(redactors) => scrub(opcode, payload, redactors),
            None => payload,
        };
        let head = encode_head(opcode, payload.len(), key);
        mask(&mut payload, key);
        leg.begin(permit, head.len(), payload.len());
        let error = self.write(to, &[&head, &payload], leg).await;
        leg.end(side, error)
    }

    async fn stream<R, W>(
        &self,
        len: usize,
        buffer: &mut Vec<u8>,
        from: &mut R,
        to: &mut W,
        leg: &Leg,
    ) -> Result<(), Fault>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let permit = self.decide(Side::Server, BINARY, len)?;
        let head = encode_head(BINARY, len, None);
        leg.begin(permit, head.len(), len);
        let mut sent = buffer.len().min(len);
        let mut error = self.write(to, &[&head, &buffer[..sent]], leg).await;
        buffer.drain(..sent);
        while error.is_none() && sent < len {
            self.read(Side::Server, from, buffer).await?;
            let piece = buffer.len().min(len - sent);
            error = self.write(to, &[&buffer[..piece]], leg).await;
            buffer.drain(..piece);
            sent += piece;
        }
        leg.end(Side::Server, error)
    }

    async fn read<R: AsyncRead + Unpin>(
        &self,
        side: Side,
        from: &mut R,
        buffer: &mut Vec<u8>,
    ) -> Result<(), Fault> {
        buffer.reserve(16 * 1024);
        match from.read_buf(buffer).await {
            Ok(0) | Err(_) => Err(Fault::dropped(side)),
            Ok(_) => {
                self.active.set(Instant::now());
                Ok(())
            }
        }
    }

    fn scrub_for(&self, side: Side) -> Option<&Target> {
        self.scrub.filter(|_| side == Side::Server)
    }

    fn decide(
        &self,
        side: Side,
        opcode: u8,
        payload_bytes: usize,
    ) -> Result<ClaimedEffectPermit, Fault> {
        let opcode = effect_opcode(opcode)
            .ok_or_else(|| Fault::protocol(side, 1002, "frame has an unknown opcode"))?;
        let (host, port, path) = (self.connect.host.as_str(), self.connect.port, self.path);
        let attempt = match side {
            Side::Workload => EffectAttempt::WebSocketSend {
                host,
                port,
                path,
                opcode,
                payload_bytes,
            },
            Side::Server => EffectAttempt::WebSocketReceive {
                host,
                port,
                path,
                opcode,
                payload_bytes,
            },
        };
        l7::claim_effect(self.state, &attempt).map_err(|error| {
            let reason = format!("message effect interception failed: {error}");
            if error.kind() == io::ErrorKind::PermissionDenied {
                Fault::refused(reason)
            } else {
                Fault::internal(Some(reason))
            }
        })
    }

    async fn write<W: AsyncWrite + Unpin>(
        &self,
        to: &mut W,
        parts: &[&[u8]],
        leg: &Leg,
    ) -> Option<io::ErrorKind> {
        for part in parts {
            let mut written = 0;
            while written < part.len() {
                match to.write(&part[written..]).await {
                    Ok(0) => return Some(io::ErrorKind::WriteZero),
                    Ok(count) => {
                        written += count;
                        self.active.set(Instant::now());
                        if let Some(in_flight) = leg.in_flight.borrow_mut().as_mut() {
                            in_flight.written += count;
                        }
                    }
                    Err(error) => return Some(error.kind()),
                }
            }
        }
        to.flush().await.err().map(|error| error.kind())
    }
}

fn redactors(state: &SharedState, target: &Target) -> Result<Vec<ResponseRedactor>, Fault> {
    let controls = state
        .controls
        .response_controls(&mut HeaderMap::new(), target)
        .map_err(Fault::refused)?;
    Ok(controls.redactors)
}

fn scrub(opcode: u8, payload: Vec<u8>, redactors: Vec<ResponseRedactor>) -> Vec<u8> {
    let control = (opcode >= CLOSE).then(|| payload.clone());
    let mut scrubbed = payload;
    for mut redactor in redactors {
        let mut out = redactor.push(&scrubbed);
        out.extend(redactor.finish());
        scrubbed = out;
    }
    match control {
        Some(mut original) if original != scrubbed => {
            original.truncate(if opcode == CLOSE { 2 } else { 0 });
            original
        }
        _ => scrubbed,
    }
}

async fn idle(active: &Cell<Instant>, limit: Duration) {
    while Instant::now() < active.get() + limit {
        tokio::time::sleep_until(active.get() + limit).await;
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::{Empty, Full};
    use hyper::body::Bytes;

    use super::*;

    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
    const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    fn handshake(
        edit: impl FnOnce(hyper::http::request::Builder) -> hyper::http::request::Builder,
    ) -> Handshake {
        let request = edit(
            hyper::Request::get("/chat")
                .header("Upgrade", "websocket")
                .header("Connection", "keep-alive, Upgrade")
                .header("Sec-WebSocket-Version", "13")
                .header("Sec-WebSocket-Key", KEY),
        );
        classify(&request.body(Empty::<Bytes>::new()).unwrap())
    }

    #[test]
    fn a_valid_handshake_is_classified_with_its_accept_value() {
        assert_eq!(
            handshake(|request| request),
            Handshake::WebSocket {
                accept: ACCEPT.to_string()
            }
        );
        let plain = hyper::Request::get("/")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert_eq!(classify(&plain), Handshake::None);
    }

    #[test]
    fn each_broken_handshake_rule_is_malformed() {
        let malformed = |handshake| matches!(handshake, Handshake::Malformed(_));
        assert!(malformed(handshake(|request| request.method("POST"))));
        assert!(malformed(handshake(
            |request| request.version(hyper::Version::HTTP_10)
        )));
        assert!(malformed(handshake(
            |request| request.header("Sec-WebSocket-Version", "8")
        )));
        assert!(malformed(handshake(
            |request| request.header("Sec-WebSocket-Key", "c2hvcnQ=")
        )));
        let without_connection = hyper::Request::get("/")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", KEY)
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert!(malformed(classify(&without_connection)));
        let with_body = hyper::Request::get("/")
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", KEY)
            .body(Full::new(Bytes::from_static(b"x")))
            .unwrap();
        assert!(malformed(classify(&with_body)));
    }

    #[test]
    fn a_101_must_answer_the_handshake_and_negotiate_no_extension() {
        let answer = |extra: &[(&'static str, &'static str)]| {
            let mut headers = WireHeaders::new();
            for (name, value) in [("upgrade", "websocket"), ("connection", "Upgrade")]
                .iter()
                .chain(extra)
            {
                headers.append(*name, value.parse().unwrap());
            }
            check_101(&headers, ACCEPT)
        };
        assert_eq!(answer(&[("sec-websocket-accept", ACCEPT)]), Ok(()));
        assert!(answer(&[("sec-websocket-accept", KEY)]).is_err());
        assert!(answer(&[]).is_err());
        let deflate = [
            ("sec-websocket-accept", ACCEPT),
            ("sec-websocket-extensions", "permessage-deflate"),
        ];
        assert!(answer(&deflate).is_err());
    }

    #[test]
    fn a_frame_round_trips_and_each_header_rule_is_checked() {
        for (len, mask) in [(5, true), (300, false), (70_000, true)] {
            let payload = vec![7; len];
            let frame = encode(BINARY, &payload, mask.then_some([9, 8, 7, 6]));
            let parsed = header(&frame).unwrap().unwrap();
            assert_eq!(
                (parsed.fin, parsed.opcode, parsed.key.is_some(), parsed.len),
                (true, BINARY, mask, len)
            );
            assert_eq!(parsed.size + len, frame.len());
            assert_eq!(header(&frame[..parsed.size - 1]), Ok(None));
            if mask {
                let key = &frame[parsed.size - 4..parsed.size];
                assert_ne!(&frame[parsed.size..parsed.size + 4], &payload[..4]);
                assert_eq!(frame[parsed.size] ^ key[0], 7);
            }
        }
        assert!(header(&[0xC1, 0]).is_err(), "a reserved bit");
        assert!(header(&[0x83, 0]).is_err(), "an unknown opcode");
        assert!(header(&[0x09, 0]).is_err(), "a fragmented Ping");
        assert!(
            header(&[0x89, 126, 0, 126]).is_err(),
            "a Ping over 125 bytes"
        );
    }

    #[test]
    fn a_message_must_be_utf8_text_or_a_valid_close() {
        assert_eq!(check_message(TEXT, "hé".as_bytes()), Ok(()));
        assert_eq!(check_message(TEXT, &[0xff]).unwrap_err().0, 1007);
        assert_eq!(check_message(BINARY, &[0xff]), Ok(()));
        assert_eq!(check_message(CLOSE, &[]), Ok(()));
        assert_eq!(check_message(CLOSE, b"\x03\xe8done"), Ok(()));
        assert_eq!(check_message(CLOSE, &[3]).unwrap_err().0, 1002);
        assert_eq!(
            check_message(CLOSE, b"\x03\xed").unwrap_err().0,
            1002,
            "1005"
        );
        assert_eq!(check_message(CLOSE, b"\x03\xe8\xff").unwrap_err().0, 1007);
    }
}
