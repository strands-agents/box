//! WebSocket (RFC 6455) through an intercepted TLS connection: the handshake checks and the relay.
//!
//! | Part | Role |
//! |---|---|
//! | [`classify`] | Finds a WebSocket handshake in a request, or the reason it is malformed. |
//! | [`check_switching_protocols`] | Accepts a `101` only when it answers the forwarded handshake. |
//! | [`relay`] | Reads, checks, and re-frames every frame in both directions after the `101`. |

mod frame;

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::Connection;

use self::frame::{Decoder, Event};
use super::connect::ConnectRequest;
use super::l7::{DecisionSubject, emit_decision};
use super::response_leg::{self, ResponseDecision};
use super::{SharedState, http1};
use crate::audit::Decision as AuditDecision;
use crate::audit::{NetworkAuditEvent, RequestId};
use crate::boundary::{BodyRef, HeaderMap, InterceptedResponse};
use crate::capability::CapabilityContext;
use crate::error::{ProxyError, Result};

/// The `Upgrade` token of a WebSocket handshake.
pub(super) const PROTOCOL: &str = "websocket";

/// The GUID RFC 6455 appends to the handshake key to derive `Sec-WebSocket-Accept`.
const ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The bytes queued for one peer above which the relay stops reading the other peer.
const PENDING_LIMIT: usize = 256 * 1024;

/// The smallest fragment the relay writes when it splits a message.
const MIN_FRAGMENT: usize = 1024;

/// How long the relay drops what a peer still sends after the relay's last bytes, so that a close
/// it sent is not lost to a reset.
const LINGER: Duration = Duration::from_secs(2);

/// What a request asks for in its `Upgrade` field.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum UpgradeRequest {
    /// No WebSocket upgrade.
    None,
    /// A WebSocket handshake, with its `Sec-WebSocket-Key`.
    WebSocket(String),
    /// A request that names `websocket` but is not a valid handshake, and why.
    Malformed(&'static str),
}

/// Classify a request as it arrived, before its hop-by-hop fields are removed.
pub(super) fn classify(
    method: &str,
    version: Option<u8>,
    headers: &HeaderMap,
    body: &[u8],
) -> UpgradeRequest {
    if !tokens(headers, "upgrade").any(|token| token.eq_ignore_ascii_case(PROTOCOL)) {
        return UpgradeRequest::None;
    }
    let refusal = if method != "GET" {
        "handshake method is not GET"
    } else if version != Some(1) {
        "handshake is not HTTP/1.1"
    } else if !tokens(headers, "connection").any(|token| token.eq_ignore_ascii_case("upgrade")) {
        "handshake lacks Connection: upgrade"
    } else if single(headers, "sec-websocket-version") != Some("13") {
        "handshake version is not 13"
    } else if !body.is_empty() {
        "handshake carries a body"
    } else {
        match single(headers, "sec-websocket-key").filter(|key| is_valid_key(key)) {
            Some(key) => return UpgradeRequest::WebSocket(key.to_string()),
            None => "handshake key is not 16 bytes of base64",
        }
    };
    UpgradeRequest::Malformed(refusal)
}

/// Whether `key` is the base64 of 16 bytes.
fn is_valid_key(key: &str) -> bool {
    STANDARD.decode(key).is_ok_and(|bytes| bytes.len() == 16)
}

/// The value of each `name` field, without its optional whitespace.
fn values<'a>(headers: &'a HeaderMap, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    headers
        .iter()
        .filter(move |(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| http1::trim_ows(value))
}

/// Every comma-separated token of every `name` field.
fn tokens<'a>(headers: &'a HeaderMap, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    values(headers, name)
        .flat_map(|value| value.split(','))
        .map(http1::trim_ows)
        .filter(|token| !token.is_empty())
}

/// How many `name` fields a head carries.
enum Field<'a> {
    Absent,
    One(&'a str),
    Repeated,
}

impl<'a> Field<'a> {
    fn of(headers: &'a HeaderMap, name: &'a str) -> Self {
        let mut found = values(headers, name);
        match (found.next(), found.next()) {
            (None, _) => Self::Absent,
            (Some(value), None) => Self::One(value),
            (Some(_), Some(_)) => Self::Repeated,
        }
    }
}

/// The value of the one `name` field, or `None` when it is absent or repeated.
fn single<'a>(headers: &'a HeaderMap, name: &'a str) -> Option<&'a str> {
    match Field::of(headers, name) {
        Field::One(value) => Some(value),
        Field::Absent | Field::Repeated => None,
    }
}

/// What a `101` must carry to answer one forwarded handshake.
pub(super) struct Expected {
    accept: String,
    protocols: Vec<String>,
}

impl Expected {
    /// The answer to the handshake with `key` whose forwarded headers are `headers`.
    pub(super) fn new(key: &str, headers: &HeaderMap) -> Self {
        Self {
            accept: accept_value(key),
            protocols: tokens(headers, "sec-websocket-protocol")
                .map(str::to_string)
                .collect(),
        }
    }
}

/// The `Sec-WebSocket-Accept` value for `key`.
fn accept_value(key: &str) -> String {
    let mut digest = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    digest.update(key.as_bytes());
    digest.update(ACCEPT_GUID.as_bytes());
    STANDARD.encode(digest.finish())
}

/// Check a `101` head against the handshake it answers, before its hop-by-hop fields are removed.
pub(super) fn check_switching_protocols(
    headers: &HeaderMap,
    expected: &Expected,
) -> std::result::Result<(), &'static str> {
    if !single(headers, "upgrade").is_some_and(|value| value.eq_ignore_ascii_case(PROTOCOL)) {
        return Err("101 does not name Upgrade: websocket");
    }
    if !tokens(headers, "connection").any(|token| token.eq_ignore_ascii_case("upgrade")) {
        return Err("101 lacks Connection: upgrade");
    }
    if single(headers, "sec-websocket-accept") != Some(expected.accept.as_str()) {
        return Err("101 carries a wrong Sec-WebSocket-Accept");
    }
    if headers.contains("sec-websocket-extensions") {
        return Err("101 negotiates an extension");
    }
    match Field::of(headers, "sec-websocket-protocol") {
        Field::Absent => Ok(()),
        Field::One(protocol) if expected.protocols.iter().any(|offered| offered == protocol) => {
            Ok(())
        }
        Field::One(_) | Field::Repeated => {
            Err("101 selects a subprotocol the request did not offer")
        }
    }
}

/// What the relay needs from the exchange that opened it.
pub(super) struct Upgraded {
    /// The handshake's capability context; its target selects the binding the leak scrub reads.
    pub(super) cx: CapabilityContext,
    /// Whether the request leg attached a credential to the handshake.
    pub(super) credentialed: bool,
    /// The handshake's correlation.
    pub(super) correlation: RequestId,
    /// The handshake's path as the workload sent it, before any credential mutation.
    pub(super) path: String,
}

/// One side of an upgraded connection, as the handshake left it.
pub(super) struct Peer<S> {
    tls: Connection,
    socket: S,
    /// Plaintext the handshake read past its head.
    carried: Vec<u8>,
}

impl<S> Peer<S> {
    pub(super) fn new(tls: impl Into<Connection>, socket: S, carried: Vec<u8>) -> Self {
        Self {
            tls: tls.into(),
            socket,
            carried,
        }
    }
}

/// Relay frames between the workload and the upstream until either side ends the connection.
pub(super) fn relay<C, U>(
    client: Peer<C>,
    upstream: Peer<U>,
    connect: &ConnectRequest,
    upgraded: Upgraded,
    state: &SharedState,
) -> Result<()>
where
    C: Read + Write + AsRawFd,
    U: Read + Write + AsRawFd,
{
    let max_message = state.config.response_limits.max_body_bytes;
    let mut client = Side::new(Role::Workload, client, max_message)?;
    let mut upstream = Side::new(Role::Upstream, upstream, max_message)?;
    let relay = Relay {
        state,
        connect,
        upgraded,
        random: SystemRandom::new(),
    };
    let idle = state.config.upstream_read_deadline;
    let mut progressed = Instant::now();
    let mut finishing = false;
    loop {
        if !finishing {
            finishing = client.over()
                || upstream.over()
                || relay.pump(&mut client, &mut upstream)?
                || relay.pump(&mut upstream, &mut client)?;
        }
        if finishing {
            client.finishing = true;
            upstream.finishing = true;
        }
        if client.flush() | upstream.flush() {
            progressed = Instant::now();
        }
        if finishing && client.drained() && upstream.drained() {
            break;
        }
        let left = idle.saturating_sub(progressed.elapsed());
        if left.is_zero() {
            if finishing {
                break;
            }
            client.queue_close(frame::GOING_AWAY, &relay.random)?;
            upstream.queue_close(frame::GOING_AWAY, &relay.random)?;
            finishing = true;
            progressed = Instant::now();
            continue;
        }
        let client_may_read = !finishing && upstream.has_room();
        let upstream_may_read = !finishing && client.has_room();
        // Input held back for a queue that has drained since is decoded without a wait.
        let held = !finishing
            && ((client.backed_up && upstream.has_room())
                || (upstream.backed_up && client.has_room()));
        let mut entries = [
            client.poll_entry(client_may_read),
            upstream.poll_entry(upstream_may_read),
        ];
        wait(&mut entries, if held { Duration::ZERO } else { left })?;
        if client.on_ready(&entries[0]) | upstream.on_ready(&entries[1]) {
            progressed = Instant::now();
        }
    }
    linger(&mut client, &mut upstream)?;
    match client.tls_error.take().or(upstream.tls_error.take()) {
        Some(error) => Err(ProxyError::Intercept(format!("websocket TLS: {error}"))),
        None => Ok(()),
    }
}

/// Which peer a side is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The workload, which masks its frames.
    Workload,
    /// The upstream, which does not.
    Upstream,
}

impl Role {
    /// The peer's name in an audit reason.
    fn name(self) -> &'static str {
        match self {
            Self::Workload => "client",
            Self::Upstream => "server",
        }
    }
}

/// The exchange-wide parts of a relay.
struct Relay<'a> {
    state: &'a SharedState,
    connect: &'a ConnectRequest,
    upgraded: Upgraded,
    random: SystemRandom,
}

impl Relay<'_> {
    /// Decode what `from` sent and queue it for `to`; returns whether the relay must finish.
    fn pump<A, B>(&self, from: &mut Side<A>, to: &mut Side<B>) -> Result<bool> {
        loop {
            while to.has_room() && !from.closed_by_peer {
                match from.decoder.next_event() {
                    Ok(Some(event)) => {
                        if self.forward(event, from, to)? {
                            return Ok(true);
                        }
                    }
                    Ok(None) => break,
                    Err(fault) => {
                        let reason = format!("websocket: {} {}", from.role.name(), fault.reason);
                        self.refuse(from, to, fault.code, reason)?;
                        return Ok(true);
                    }
                }
            }
            if !to.has_room() {
                from.backed_up = true;
                return Ok(false);
            }
            match from.take_plaintext() {
                Input::Moved => {}
                Input::Empty => {
                    from.backed_up = false;
                    return Ok(false);
                }
                Input::Ended => {
                    from.ended = true;
                    return Ok(true);
                }
            }
        }
    }

    /// Queue one event from `from` for `to`; returns whether the relay must finish, because both
    /// peers have sent Close or the event was refused.
    fn forward<A, B>(&self, event: Event, from: &mut Side<A>, to: &mut Side<B>) -> Result<bool> {
        let event = if from.role == Role::Upstream && self.upgraded.credentialed {
            match self.scrub(event) {
                Ok(event) => event,
                Err(reason) => {
                    let reason = format!("websocket: server message refused: {reason}");
                    self.refuse(from, to, frame::POLICY_VIOLATION, reason)?;
                    return Ok(true);
                }
            }
        } else {
            event
        };
        match event {
            Event::Message {
                text,
                payload,
                fragment,
            } => {
                let opcode = if text { frame::TEXT } else { frame::BINARY };
                to.queue_message(opcode, &payload, fragment, &self.random)?;
            }
            Event::Ping(payload) => to.queue(frame::PING, &payload, &self.random)?,
            Event::Pong(payload) => to.queue(frame::PONG, &payload, &self.random)?,
            Event::Close(payload) => {
                if !to.close_queued {
                    to.close_queued = true;
                    to.queue(frame::CLOSE, &payload, &self.random)?;
                }
                from.closed_by_peer = true;
                return Ok(to.closed_by_peer);
            }
        }
        Ok(false)
    }

    /// Close `from` with `code`, and `to` with 1014 when `from` is the upstream or 1001 when it is
    /// the workload, and record the secret-free `reason` in the audit log and as a deny decision.
    fn refuse<A, B>(
        &self,
        from: &mut Side<A>,
        to: &mut Side<B>,
        code: u16,
        reason: String,
    ) -> Result<()> {
        from.queue_close(code, &self.random)?;
        let peer_code = match from.role {
            Role::Upstream => frame::BAD_GATEWAY,
            Role::Workload => frame::GOING_AWAY,
        };
        to.queue_close(peer_code, &self.random)?;
        self.state.audit.push(NetworkAuditEvent::deny(
            &self.connect.host,
            self.connect.port,
            reason.clone(),
            self.upgraded.correlation.clone(),
        ));
        // The handshake's allow is already recorded, so a close the gateway makes is its own deny.
        emit_decision(
            self.state,
            DecisionSubject {
                host: &self.connect.host,
                port: self.connect.port,
                method: "GET",
                path: &self.upgraded.path,
            },
            AuditDecision::Deny,
            &reason,
            self.upgraded.correlation.clone(),
        );
        Ok(())
    }

    /// `event` with every copy of the attached secret redacted, or why the response controls refuse it.
    fn scrub(&self, event: Event) -> std::result::Result<Event, String> {
        Ok(match event {
            Event::Message {
                text,
                payload,
                fragment,
            } => Event::Message {
                text,
                payload: self.redact(payload)?,
                fragment,
            },
            Event::Ping(payload) => Event::Ping(self.redact_control(payload, 0)?),
            Event::Pong(payload) => Event::Pong(self.redact_control(payload, 0)?),
            Event::Close(payload) => Event::Close(self.redact_control(payload, 2)?),
        })
    }

    /// A control payload, cut to its first `keep` bytes when it carried the secret, so it stays a
    /// valid control frame.
    fn redact_control(
        &self,
        payload: Vec<u8>,
        keep: usize,
    ) -> std::result::Result<Vec<u8>, String> {
        let redacted = self.redact(payload.clone())?;
        Ok(if redacted == payload {
            payload
        } else {
            payload[..keep.min(payload.len())].to_vec()
        })
    }

    /// Run the response leg over `payload` as a body, which redacts the secret it echoes.
    fn redact(&self, payload: Vec<u8>) -> std::result::Result<Vec<u8>, String> {
        let mut message = InterceptedResponse::http(101, HeaderMap::new(), BodyRef::Bytes(payload));
        match response_leg::evaluate_and_apply(
            &self.state.controls,
            &mut message,
            &self.upgraded.cx,
        ) {
            ResponseDecision::Block(reason) => Err(reason.to_string()),
            ResponseDecision::Return | ResponseDecision::RedirectReentry(_) => {
                Ok(match message.body {
                    BodyRef::Bytes(bytes) => bytes,
                    BodyRef::Empty => Vec::new(),
                })
            }
        }
    }
}

/// What one attempt to move plaintext out of TLS found.
enum Input {
    /// Plaintext moved into the decoder.
    Moved,
    /// No plaintext is available yet.
    Empty,
    /// The peer's stream has ended.
    Ended,
}

/// Frames queued for one peer that its TLS connection has not taken yet.
#[derive(Default)]
struct Outbox {
    bytes: Vec<u8>,
    sent: usize,
}

impl Outbox {
    fn pending(&self) -> usize {
        self.bytes.len() - self.sent
    }

    fn unsent(&self) -> &[u8] {
        &self.bytes[self.sent..]
    }

    fn advance(&mut self, count: usize) {
        self.sent += count;
        if self.sent == self.bytes.len() {
            frame::empty(&mut self.bytes);
            self.sent = 0;
        }
    }

    /// The buffer to append a frame to.
    fn buffer(&mut self) -> &mut Vec<u8> {
        if self.sent > 0 && self.sent >= self.bytes.len() / 2 {
            self.bytes.drain(..self.sent);
            self.sent = 0;
        }
        &mut self.bytes
    }
}

/// One peer of the relay: its TLS connection, its socket, and what the relay knows of its state.
struct Side<S> {
    role: Role,
    tls: Connection,
    socket: S,
    decoder: Decoder,
    outbox: Outbox,
    /// TLS may hold plaintext the decoder has not taken.
    plaintext_ready: bool,
    /// The relay holds back the peer's input until the other peer's queue drains.
    backed_up: bool,
    /// The peer sent a Close frame; the relay drops what it sends after it.
    closed_by_peer: bool,
    /// The relay queued a Close frame for the peer.
    close_queued: bool,
    /// The socket reported a hang-up or an error.
    hung_up: bool,
    /// The socket read reached its end.
    eof: bool,
    /// The peer's stream has ended: its plaintext ran out after EOF, or its TLS failed.
    ended: bool,
    /// A write to the peer failed.
    broken: bool,
    /// The relay is closing; the peer gets TLS close_notify once its frames are out.
    finishing: bool,
    /// The relay queued TLS close_notify for the peer.
    notified: bool,
    /// Whether the last poll asked to read this socket.
    reading: bool,
    tls_error: Option<rustls::Error>,
}

impl<S: AsRawFd> Side<S> {
    fn new(role: Role, peer: Peer<S>, max_message: usize) -> Result<Self> {
        prepare_socket(peer.socket.as_raw_fd())
            .map_err(|error| ProxyError::Io(format!("websocket socket: {error}")))?;
        let mut decoder = Decoder::new(role == Role::Workload, max_message);
        decoder.feed(&peer.carried);
        Ok(Self {
            role,
            tls: peer.tls,
            socket: peer.socket,
            decoder,
            outbox: Outbox::default(),
            plaintext_ready: true,
            backed_up: false,
            closed_by_peer: false,
            close_queued: false,
            hung_up: false,
            eof: false,
            ended: false,
            broken: false,
            finishing: false,
            notified: false,
            reading: false,
            tls_error: None,
        })
    }
}

impl<S> Side<S> {
    /// Whether the peer's stream has ended or can no longer be written.
    fn over(&self) -> bool {
        self.ended || self.broken
    }

    /// Whether the relay may queue more for this peer.
    fn has_room(&self) -> bool {
        self.outbox.pending() <= PENDING_LIMIT
    }

    /// Queue one unfragmented frame.
    fn queue(&mut self, opcode: u8, payload: &[u8], random: &SystemRandom) -> Result<()> {
        self.queue_frame(opcode, true, payload, random)
    }

    /// Queue a data message in frames of at most `fragment` bytes and at least [`MIN_FRAGMENT`], or
    /// in one frame when it has no `fragment`.
    fn queue_message(
        &mut self,
        opcode: u8,
        payload: &[u8],
        fragment: Option<usize>,
        random: &SystemRandom,
    ) -> Result<()> {
        let size = fragment.map_or(payload.len(), |size| size.max(MIN_FRAGMENT));
        if payload.len() <= size {
            return self.queue_frame(opcode, true, payload, random);
        }
        let count = payload.len().div_ceil(size);
        for (index, chunk) in payload.chunks(size).enumerate() {
            let opcode = if index == 0 {
                opcode
            } else {
                frame::CONTINUATION
            };
            self.queue_frame(opcode, index + 1 == count, chunk, random)?;
        }
        Ok(())
    }

    /// Queue one frame, masked when it goes to the upstream.
    fn queue_frame(
        &mut self,
        opcode: u8,
        fin: bool,
        payload: &[u8],
        random: &SystemRandom,
    ) -> Result<()> {
        let mask = match self.role {
            Role::Workload => None,
            Role::Upstream => {
                let mut key = [0u8; 4];
                random
                    .fill(&mut key)
                    .map_err(|_| ProxyError::Intercept("websocket mask key".to_string()))?;
                Some(key)
            }
        };
        frame::encode(self.outbox.buffer(), opcode, fin, payload, mask);
        Ok(())
    }

    /// Queue a Close frame with `code`, unless one is already queued.
    fn queue_close(&mut self, code: u16, random: &SystemRandom) -> Result<()> {
        if self.close_queued {
            return Ok(());
        }
        self.close_queued = true;
        self.queue(frame::CLOSE, &code.to_be_bytes(), random)
    }

    /// Move the plaintext TLS holds into the decoder; after a Close from the peer, drop it.
    fn take_plaintext(&mut self) -> Input {
        let mut reader = self.tls.reader();
        match io::BufRead::fill_buf(&mut reader) {
            Ok([]) => Input::Ended,
            Ok(chunk) => {
                let count = chunk.len();
                if !self.closed_by_peer {
                    self.decoder.feed(chunk);
                }
                io::BufRead::consume(&mut reader, count);
                Input::Moved
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                self.plaintext_ready = false;
                Input::Empty
            }
            Err(_) => Input::Ended,
        }
    }
}

impl<S: Read + Write + AsRawFd> Side<S> {
    /// Read TLS records from the socket; returns whether the socket gave any.
    fn read(&mut self) -> bool {
        loop {
            match self.tls.read_tls(&mut self.socket) {
                Ok(0) => self.eof = true,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return false,
                Err(_) => {
                    self.eof = true;
                    self.ended = true;
                    return true;
                }
            }
            match self.tls.process_new_packets() {
                Ok(io_state) => self.plaintext_ready = io_state.plaintext_bytes_to_read() > 0,
                Err(error) => {
                    self.ended = true;
                    self.tls_error = Some(error);
                }
            }
            return true;
        }
    }

    /// Hand queued frames to TLS and TLS records to the socket; returns whether the socket took any.
    fn flush(&mut self) -> bool {
        let mut progress = false;
        while !self.broken {
            while self.outbox.pending() > 0 {
                match self.tls.writer().write(self.outbox.unsent()) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => self.outbox.advance(count),
                }
            }
            if self.finishing && !self.notified && self.outbox.pending() == 0 {
                self.tls.send_close_notify();
                self.notified = true;
            }
            if !self.tls.wants_write() {
                break;
            }
            match self.tls.write_tls(&mut self.socket) {
                Ok(0) => self.broken = true,
                Ok(_) => progress = true,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => self.broken = true,
            }
        }
        progress
    }

    /// Whether everything the relay owes this peer is out, close_notify included.
    fn drained(&self) -> bool {
        self.broken || (self.notified && !self.tls.wants_write())
    }

    /// The poll entry for this socket; `may_read` is false while the other peer's queue is full.
    fn poll_entry(&mut self, may_read: bool) -> libc::pollfd {
        self.reading = may_read && !self.eof && !self.plaintext_ready;
        let mut events = 0;
        if self.reading {
            events |= libc::POLLIN;
        }
        if !self.broken && self.tls.wants_write() {
            events |= libc::POLLOUT;
        }
        // A hung-up socket stays ready, so it is left out while the relay has nothing to do with it.
        let fd = if events == 0 && self.hung_up {
            -1
        } else {
            self.socket.as_raw_fd()
        };
        libc::pollfd {
            fd,
            events,
            revents: 0,
        }
    }

    /// Act on what poll reported; returns whether the socket gave any bytes.
    fn on_ready(&mut self, entry: &libc::pollfd) -> bool {
        let gone = entry.revents & (libc::POLLHUP | libc::POLLERR) != 0;
        if gone {
            self.hung_up = true;
        }
        self.reading && (gone || entry.revents & libc::POLLIN != 0) && self.read()
    }

    /// Whether the socket has nothing more to give the linger.
    fn quiet(&self) -> bool {
        self.eof || self.broken
    }

    /// The poll entry for the linger.
    fn linger_entry(&self) -> libc::pollfd {
        libc::pollfd {
            fd: if self.quiet() {
                -1
            } else {
                self.socket.as_raw_fd()
            },
            events: libc::POLLIN,
            revents: 0,
        }
    }

    /// Read and drop the bytes the socket holds.
    fn discard(&mut self, entry: &libc::pollfd) {
        if self.quiet() || entry.revents == 0 {
            return;
        }
        let mut scratch = [0u8; 16 * 1024];
        loop {
            match self.socket.read(&mut scratch) {
                Ok(0) => {}
                Ok(_) => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(_) => {}
            }
            self.eof = true;
            return;
        }
    }
}

/// End the write half of both sockets, then drop what the peers still send until each reaches
/// EOF or [`LINGER`] passes.
fn linger<C, U>(client: &mut Side<C>, upstream: &mut Side<U>) -> Result<()>
where
    C: Read + Write + AsRawFd,
    U: Read + Write + AsRawFd,
{
    for fd in [client.socket.as_raw_fd(), upstream.socket.as_raw_fd()] {
        // SAFETY: shutdown takes a descriptor the relay owns; a failure leaves it to the close.
        unsafe { libc::shutdown(fd, libc::SHUT_WR) };
    }
    let until = Instant::now() + LINGER;
    while !(client.quiet() && upstream.quiet()) {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let mut entries = [client.linger_entry(), upstream.linger_entry()];
        wait(&mut entries, left)?;
        client.discard(&entries[0]);
        upstream.discard(&entries[1]);
    }
    Ok(())
}

/// Put a relay socket in nonblocking mode, and make a TCP socket send each write at once.
fn prepare_socket(fd: RawFd) -> io::Result<()> {
    set_nonblocking(fd)?;
    let on: libc::c_int = 1;
    // SAFETY: setsockopt reads one c_int from `on` for a descriptor the caller owns. It fails on a
    // socket that is not TCP, which keeps its default.
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            (&raw const on).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    Ok(())
}

/// Put a socket in nonblocking mode.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl reads the status flags of a descriptor the caller owns.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl sets the status flags of a descriptor the caller owns.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Wait until a socket in `entries` is ready, or `timeout` passes.
fn wait(entries: &mut [libc::pollfd; 2], timeout: Duration) -> Result<()> {
    let millis = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: `entries` is a valid array of two pollfd records for the length of the call.
    let ready = unsafe { libc::poll(entries.as_mut_ptr(), entries.len() as libc::nfds_t, millis) };
    if ready < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(ProxyError::Io(format!("websocket poll: {error}")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        HeaderMap::from_pairs(
            pairs
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string())),
        )
    }

    fn handshake(extra: &[(&str, &str)]) -> HeaderMap {
        let mut pairs = vec![
            ("Host", "echo.example"),
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Version", "13"),
            ("Sec-WebSocket-Key", KEY),
        ];
        pairs.extend_from_slice(extra);
        headers(&pairs)
    }

    #[test]
    fn the_accept_value_matches_the_rfc_6455_example() {
        assert_eq!(accept_value(KEY), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn a_valid_handshake_is_found_in_any_case() {
        assert_eq!(
            classify("GET", Some(1), &handshake(&[]), b""),
            UpgradeRequest::WebSocket(KEY.to_string())
        );
        let spelled = headers(&[
            ("upgrade", "h2c, WebSocket"),
            ("connection", "keep-alive, UPGRADE"),
            ("sec-websocket-version", " 13 "),
            ("sec-websocket-key", KEY),
        ]);
        assert_eq!(
            classify("GET", Some(1), &spelled, b""),
            UpgradeRequest::WebSocket(KEY.to_string())
        );
    }

    #[test]
    fn another_upgrade_token_is_not_a_websocket() {
        let h2c = headers(&[
            ("Upgrade", "h2c"),
            ("Connection", "Upgrade, HTTP2-Settings"),
        ]);
        assert_eq!(classify("GET", Some(1), &h2c, b""), UpgradeRequest::None);
        assert_eq!(
            classify("POST", Some(1), &HeaderMap::new(), b"x"),
            UpgradeRequest::None
        );
    }

    #[test]
    fn an_invalid_handshake_names_its_fault() {
        let without = |name: &str| {
            let mut headers = handshake(&[]);
            headers.remove(name);
            headers
        };
        let with = |name: &str, value: &str| {
            let mut headers = handshake(&[]);
            headers.set(name, value.to_string());
            headers
        };
        for (method, version, headers, body, reason) in [
            (
                "POST",
                Some(1),
                handshake(&[]),
                &b""[..],
                "handshake method is not GET",
            ),
            (
                "get",
                Some(1),
                handshake(&[]),
                b"",
                "handshake method is not GET",
            ),
            (
                "GET",
                Some(0),
                handshake(&[]),
                b"",
                "handshake is not HTTP/1.1",
            ),
            (
                "GET",
                Some(1),
                without("connection"),
                b"",
                "handshake lacks Connection: upgrade",
            ),
            (
                "GET",
                Some(1),
                with("connection", "keep-alive"),
                b"",
                "handshake lacks Connection: upgrade",
            ),
            (
                "GET",
                Some(1),
                with("sec-websocket-version", "8"),
                b"",
                "handshake version is not 13",
            ),
            (
                "GET",
                Some(1),
                without("sec-websocket-version"),
                b"",
                "handshake version is not 13",
            ),
            (
                "GET",
                Some(1),
                handshake(&[]),
                b"body",
                "handshake carries a body",
            ),
            (
                "GET",
                Some(1),
                without("sec-websocket-key"),
                b"",
                "handshake key is not 16 bytes of base64",
            ),
            (
                "GET",
                Some(1),
                with("sec-websocket-key", "dG9vIHNob3J0"),
                b"",
                "handshake key is not 16 bytes of base64",
            ),
            (
                "GET",
                Some(1),
                with("sec-websocket-key", "not base64!!!!!!!!!!!!=="),
                b"",
                "handshake key is not 16 bytes of base64",
            ),
            (
                "GET",
                Some(1),
                handshake(&[("Sec-WebSocket-Key", KEY)]),
                b"",
                "handshake key is not 16 bytes of base64",
            ),
        ] {
            assert_eq!(
                classify(method, version, &headers, body),
                UpgradeRequest::Malformed(reason),
                "{reason}"
            );
        }
    }

    fn switching(extra: &[(&str, &str)]) -> HeaderMap {
        let mut pairs = vec![
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        ];
        pairs.extend_from_slice(extra);
        headers(&pairs)
    }

    #[test]
    fn a_101_that_answers_the_handshake_is_accepted() {
        let expected = Expected::new(KEY, &handshake(&[]));
        assert_eq!(
            check_switching_protocols(&switching(&[]), &expected),
            Ok(())
        );

        let offered = Expected::new(KEY, &handshake(&[("Sec-WebSocket-Protocol", "chat, v2")]));
        assert_eq!(
            check_switching_protocols(&switching(&[("Sec-WebSocket-Protocol", "v2")]), &offered),
            Ok(())
        );
    }

    #[test]
    fn a_101_that_does_not_answer_the_handshake_is_refused() {
        let expected = Expected::new(KEY, &handshake(&[("Sec-WebSocket-Protocol", "chat")]));
        let mut wrong_upgrade = switching(&[]);
        wrong_upgrade.set("Upgrade", "h2c".to_string());
        let mut no_connection = switching(&[]);
        no_connection.remove("connection");
        let mut wrong_accept = switching(&[]);
        wrong_accept.set(
            "Sec-WebSocket-Accept",
            accept_value("AAAAAAAAAAAAAAAAAAAAAA=="),
        );
        for (headers, reason) in [
            (wrong_upgrade, "101 does not name Upgrade: websocket"),
            (no_connection, "101 lacks Connection: upgrade"),
            (wrong_accept, "101 carries a wrong Sec-WebSocket-Accept"),
            (
                switching(&[("Sec-WebSocket-Extensions", "permessage-deflate")]),
                "101 negotiates an extension",
            ),
            (
                switching(&[("Sec-WebSocket-Protocol", "superchat")]),
                "101 selects a subprotocol the request did not offer",
            ),
            (
                switching(&[("Sec-WebSocket-Protocol", "chat, chat")]),
                "101 selects a subprotocol the request did not offer",
            ),
        ] {
            assert_eq!(
                check_switching_protocols(&headers, &expected),
                Err(reason),
                "{reason}"
            );
        }
        let none_offered = Expected::new(KEY, &handshake(&[]));
        assert!(
            check_switching_protocols(
                &switching(&[("Sec-WebSocket-Protocol", "chat")]),
                &none_offered
            )
            .is_err()
        );
    }

    #[test]
    fn an_outbox_compacts_and_counts_what_is_unsent() {
        let mut outbox = Outbox::default();
        outbox.buffer().extend_from_slice(b"abcdef");
        outbox.advance(4);
        assert_eq!(outbox.unsent(), b"ef");
        outbox.buffer().extend_from_slice(b"gh");
        assert_eq!(outbox.unsent(), b"efgh");
        assert_eq!(outbox.pending(), 4);
        outbox.advance(4);
        assert_eq!(outbox.pending(), 0);
        assert!(outbox.bytes.is_empty());
    }

    #[test]
    fn a_drained_outbox_frees_a_large_buffer_and_keeps_a_small_one() {
        let mut outbox = Outbox::default();
        outbox.buffer().extend_from_slice(&[0u8; 1000]);
        outbox.advance(1000);
        assert!(outbox.bytes.capacity() >= 1000);

        outbox.buffer().extend_from_slice(&vec![0u8; 4 << 20]);
        outbox.advance(4 << 20);
        assert_eq!(outbox.pending(), 0);
        assert!(
            outbox.bytes.capacity() <= frame::KEEP_CAPACITY,
            "{}",
            outbox.bytes.capacity()
        );
    }

    #[test]
    fn a_relay_socket_is_nonblocking_and_sends_tcp_writes_at_once() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        prepare_socket(tcp.as_raw_fd()).unwrap();
        assert!(tcp.nodelay().unwrap());
        let mut byte = [0u8; 1];
        assert_eq!(
            (&tcp).read(&mut byte).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        let (unix, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        prepare_socket(unix.as_raw_fd()).unwrap();
        assert_eq!(
            (&unix).read(&mut byte).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
