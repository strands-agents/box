//! The relay of one WebSocket after its `101`.
//!
//! One async function runs in the connection task, which holds the connection slot and the
//! session slot until the relay ends. Two forwarders (read, decode, check, scrub, frame again) race
//! in one `select!` with an idle arm and a stop arm. Two writers drain one outbox each, so a peer
//! that stops reading stalls only the direction toward it. No frame passes undecoded: the relay
//! never copies bytes from one stream to the other.
//!
//! When a credential route matches the destination, the response fold scrubs each server message
//! and control frame for the injected secret, in `off_worker`, before the relay frames it again.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::time::Instant;

use super::super::SharedState;
use super::super::exchange::{Subject, record_refusal, refusal_kind};
use super::super::response_leg::{self, ResponseDecision};
use super::Pending;
use super::frame::{self, Decoder, Event};
use crate::boundary::{BodyRef, HeaderMap, InterceptedResponse};
use crate::capability::{CapabilityContext, CapabilitySet};
use crate::effect::off_worker;
use crate::error::{ProxyError, Result};

/// The bytes queued for one peer above which a forwarder waits; one larger message goes alone.
const PENDING_LIMIT: usize = 256 * 1024;

/// The smallest fragment that the relay writes when it splits a message.
const MIN_FRAGMENT: usize = 1024;

/// How long the relay reads and drops after its last bytes, so that a close is not lost to a
/// reset.
const LINGER: Duration = Duration::from_secs(2);

/// One read from a peer.
const READ_CHUNK: usize = 64 * 1024;

/// Relay one WebSocket from the `101` to its end: `client` is the workload after its `101`, with
/// the bytes that it sent after its handshake first.
///
/// The session ends when both peers have sent Close, when a peer breaks a rule (one `Deny`), when
/// no byte moves in either direction for `upstream_read_deadline` (1001 to both), when the
/// gateway stops (1001 to both), or when a peer ends its stream. There is no limit on the life of
/// a session that moves.
pub(in super::super) async fn run<C>(
    pending: Pending,
    client: C,
    state: &SharedState,
    mut stop: watch::Receiver<bool>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    let Pending {
        host,
        port,
        path,
        correlation,
        scrub,
        upstream,
        slot: _slot,
    } = pending;
    let idle = state.config.upstream_read_deadline;
    let max_message = state.config.response_limits.max_body_bytes;
    let relay = Relay {
        state,
        subject: Subject {
            host: &host,
            port,
            method: "GET",
            path: &path,
            correlation: &correlation,
        },
        scrub,
        random: SystemRandom::new(),
        closed_by: [AtomicBool::new(false), AtomicBool::new(false)],
        close_sent: [AtomicBool::new(false), AtomicBool::new(false)],
        activity: Activity::new(),
        reading_ended: Notify::new(),
    };
    let (mut client_reads, client_writes) = tokio::io::split(client);
    let (mut upstream_reads, upstream_writes) = tokio::io::split(upstream);
    let (to_client, client_queue, client_room) = Outbox::new();
    let (to_upstream, upstream_queue, upstream_room) = Outbox::new();
    let mut client_decoder = Decoder::new(true, max_message);
    let mut upstream_decoder = Decoder::new(false, max_message);

    let reading = async {
        let end = tokio::select! {
            end = relay.forward(
                Role::Workload,
                &mut client_reads,
                &mut client_decoder,
                &to_client,
                &to_upstream,
            ) => end,
            end = relay.forward(
                Role::Upstream,
                &mut upstream_reads,
                &mut upstream_decoder,
                &to_upstream,
                &to_client,
            ) => end,
            () = relay.activity.idle(idle) => {
                relay.close_both(frame::GOING_AWAY, &to_client, &to_upstream);
                End::Closed
            }
            _ = stop.wait_for(|stop| *stop) => {
                relay.close_both(frame::GOING_AWAY, &to_client, &to_upstream);
                End::Closed
            }
        };
        // The writers send what is queued, then TLS close_notify and FIN.
        drop((to_client, to_upstream));
        relay.activity.touch();
        relay.reading_ended.notify_one();
        end
    };
    let writing = async {
        tokio::join!(
            write_peer(client_writes, client_queue, client_room, &relay.activity),
            write_peer(
                upstream_writes,
                upstream_queue,
                upstream_room,
                &relay.activity
            ),
        )
    };
    // Once reading has ended, a writer that moves no byte for the idle limit ends the session.
    let finish_bound = async {
        relay.reading_ended.notified().await;
        relay.activity.idle(idle).await;
    };
    let end = tokio::select! {
        biased;
        (end, _) = async { tokio::join!(reading, writing) } => end,
        () = finish_bound => End::Stuck,
    };
    linger(&mut client_reads, &mut upstream_reads).await;
    match end {
        End::Closed | End::Eof => Ok(()),
        End::Broken(why) => Err(ProxyError::Io(format!("websocket: {why}"))),
        End::Stuck => Err(ProxyError::Io(
            "websocket: a peer stopped reading during the close".to_string(),
        )),
    }
}

/// Which peer a frame comes from or goes to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The workload, which masks its frames.
    Workload,
    /// The upstream, which does not.
    Upstream,
}

impl Role {
    /// The peer's name in a record.
    fn name(self) -> &'static str {
        match self {
            Self::Workload => "client",
            Self::Upstream => "server",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Workload => 0,
            Self::Upstream => 1,
        }
    }

    fn other(self) -> Self {
        match self {
            Self::Workload => Self::Upstream,
            Self::Upstream => Self::Workload,
        }
    }
}

/// Why the reading half of a relay ended.
enum End {
    /// Both peers sent Close, or the gateway closed both.
    Closed,
    /// A peer ended its stream with no Close. The other peer gets TLS close_notify and FIN.
    Eof,
    /// A read failed, or a peer stopped taking frames; the secret-free reason.
    Broken(String),
    /// A writer moved no byte for the idle limit after reading ended.
    Stuck,
}

/// The state of one session that both forwarders share. Atomics, not cells: the connection task
/// runs on a multi-thread runtime, so its future is `Send`.
struct Relay<'a> {
    state: &'a SharedState,
    /// The identity that each record of this session names: the handshake's.
    subject: Subject<'a>,
    /// The handshake's capability context when the relay scrubs each server message.
    scrub: Option<CapabilityContext>,
    random: SystemRandom,
    /// A Close frame came from this peer; the relay drops what it sends after it.
    closed_by: [AtomicBool; 2],
    /// The relay queued a Close frame for this peer; it sends no second one.
    close_sent: [AtomicBool; 2],
    activity: Activity,
    /// Reading has ended, so the finish bound starts.
    reading_ended: Notify,
}

impl Relay<'_> {
    /// Read `from`, decode its frames, and queue each one for the other peer, until an end.
    async fn forward<R: AsyncRead + Unpin>(
        &self,
        from: Role,
        reader: &mut R,
        decoder: &mut Decoder,
        own: &Outbox,
        other: &Outbox,
    ) -> End {
        let mut buffer = vec![0u8; READ_CHUNK];
        loop {
            while !self.closed_by[from.index()].load(Ordering::Relaxed) {
                match decoder.next_event() {
                    Ok(Some(event)) => {
                        if let Some(end) = self.pass(from, event, own, other).await {
                            return end;
                        }
                    }
                    Ok(None) => break,
                    Err(fault) => {
                        self.refuse(from, fault.code, fault.reason, own, other);
                        return End::Closed;
                    }
                }
            }
            match reader.read(&mut buffer).await {
                Ok(0) => return End::Eof,
                Ok(count) => {
                    self.activity.touch();
                    // After its Close, a peer may send no more frames (RFC 6455 section 5.5.1).
                    if !self.closed_by[from.index()].load(Ordering::Relaxed) {
                        decoder.feed(&buffer[..count]);
                    }
                }
                Err(error) => return End::Broken(format!("{} read: {error}", from.name())),
            }
        }
    }

    /// Scrub one event from `from` when it comes from the server of a credentialed handshake, then
    /// queue it for the other peer; `Some` ends the session.
    async fn pass(&self, from: Role, event: Event, own: &Outbox, other: &Outbox) -> Option<End> {
        let event = match (&self.scrub, from) {
            // The fold is synchronous seam work, so it runs where it may block.
            (Some(context), Role::Upstream) => {
                match off_worker(|| scrub(&self.state.controls, context, event)) {
                    Ok(event) => event,
                    Err(kind) => {
                        let reason = format!("message refused: {kind}");
                        self.refuse(from, frame::POLICY_VIOLATION, &reason, own, other);
                        return Some(End::Closed);
                    }
                }
            }
            _ => event,
        };
        let to = from.other();
        let mask = self.mask(to);
        let framed = match event {
            Event::Message {
                text,
                payload,
                fragment,
            } => {
                let opcode = if text { frame::TEXT } else { frame::BINARY };
                encode_message(opcode, &payload, fragment, mask)
            }
            Event::Ping(payload) => encode_message(frame::PING, &payload, None, mask),
            Event::Pong(payload) => encode_message(frame::PONG, &payload, None, mask),
            Event::Close(payload) => {
                // The Close passes with its code and reason as the peer sent them.
                if !self.close_sent[to.index()].swap(true, Ordering::Relaxed)
                    && let Ok(close) = encode_message(frame::CLOSE, &payload, None, mask)
                {
                    other.close(close);
                }
                self.closed_by[from.index()].store(true, Ordering::Relaxed);
                return self.closed_by[to.index()]
                    .load(Ordering::Relaxed)
                    .then_some(End::Closed);
            }
        };
        let Ok(framed) = framed else {
            return Some(End::Broken("no mask key for a frame".to_string()));
        };
        other
            .send(framed)
            .await
            .err()
            .map(|Gone| End::Broken(format!("the {} stopped taking frames", to.name())))
    }

    /// Close `from`, the peer at fault, with `code`, and the other peer with 1014 when the server is
    /// at fault or 1001 when the client is; record one `Deny` with the secret-free `why`.
    fn refuse(&self, from: Role, code: u16, why: &str, own: &Outbox, other: &Outbox) {
        let other_code = match from {
            Role::Upstream => frame::BAD_GATEWAY,
            Role::Workload => frame::GOING_AWAY,
        };
        self.close(from, code, own);
        self.close(from.other(), other_code, other);
        let reason = format!("websocket: {} {why}", from.name());
        // The handshake's allow is recorded already, so a close that the gateway makes is its own
        // `Deny`. The reason is static text, with no payload byte.
        off_worker(|| record_refusal(self.state, &self.subject, &reason));
    }

    /// Close both peers with `code`.
    fn close_both(&self, code: u16, to_client: &Outbox, to_upstream: &Outbox) {
        self.close(Role::Workload, code, to_client);
        self.close(Role::Upstream, code, to_upstream);
    }

    /// Queue a Close frame with `code` for `to`, unless one is queued already. It never waits for
    /// room, so a peer that stops reading cannot hold a close back.
    fn close(&self, to: Role, code: u16, outbox: &Outbox) {
        if self.close_sent[to.index()].swap(true, Ordering::Relaxed) {
            return;
        }
        if let Ok(close) = encode_message(frame::CLOSE, &code.to_be_bytes(), None, self.mask(to)) {
            outbox.close(close);
        }
    }

    /// The source of mask keys for frames to `to`: only frames to the upstream are masked.
    fn mask(&self, to: Role) -> Option<&SystemRandom> {
        (to == Role::Upstream).then_some(&self.random)
    }
}

/// `event` with each copy of the injected secret redacted by the response fold, or the kind of the
/// fold's refusal. A control frame that carried the secret keeps only the bytes that hold no secret:
/// none for a ping or a pong, the two code bytes for a close. A data message keeps its fragment
/// size, so the relay frames the redacted message as the server framed it.
fn scrub(
    controls: &CapabilitySet,
    context: &CapabilityContext,
    event: Event,
) -> std::result::Result<Event, &'static str> {
    Ok(match event {
        Event::Message {
            text,
            payload,
            fragment,
        } => Event::Message {
            text,
            payload: redact(controls, context, payload)?,
            fragment,
        },
        Event::Ping(payload) => Event::Ping(redact_control(controls, context, payload, 0)?),
        Event::Pong(payload) => Event::Pong(redact_control(controls, context, payload, 0)?),
        Event::Close(payload) => Event::Close(redact_control(controls, context, payload, 2)?),
    })
}

/// A control payload, cut to its first `keep` bytes when it carried the secret, so that it stays a
/// valid control frame.
fn redact_control(
    controls: &CapabilitySet,
    context: &CapabilityContext,
    payload: Vec<u8>,
    keep: usize,
) -> std::result::Result<Vec<u8>, &'static str> {
    let redacted = redact(controls, context, payload.clone())?;
    Ok(if redacted == payload {
        payload
    } else {
        payload[..keep.min(payload.len())].to_vec()
    })
}

/// Run the response fold over `payload` as the body of the `101`, which redacts each copy of the
/// secret that the server echoes.
fn redact(
    controls: &CapabilitySet,
    context: &CapabilityContext,
    payload: Vec<u8>,
) -> std::result::Result<Vec<u8>, &'static str> {
    let mut message = InterceptedResponse::http(101, HeaderMap::new(), BodyRef::Bytes(payload));
    match response_leg::evaluate_and_apply(controls, &mut message, context) {
        ResponseDecision::Block(reason) => Err(refusal_kind(&reason)),
        ResponseDecision::Return | ResponseDecision::RedirectReentry(_) => Ok(match message.body {
            BodyRef::Bytes(bytes) => bytes,
            BodyRef::Empty => Vec::new(),
        }),
    }
}

/// A data message as frames of at most `fragment` bytes and at least [`MIN_FRAGMENT`], or as one
/// frame when it has no `fragment`. With `mask`, each frame gets its own fresh mask key, so the
/// upstream never sees a key that the workload chose.
fn encode_message(
    opcode: u8,
    payload: &[u8],
    fragment: Option<usize>,
    mask: Option<&SystemRandom>,
) -> std::result::Result<Vec<u8>, ring::error::Unspecified> {
    let size = fragment.map_or(payload.len(), |size| size.max(MIN_FRAGMENT));
    let mut out = Vec::new();
    if payload.len() <= size {
        frame::encode(&mut out, opcode, true, payload, key(mask)?);
        return Ok(out);
    }
    let count = payload.len().div_ceil(size);
    for (index, chunk) in payload.chunks(size).enumerate() {
        let opcode = if index == 0 {
            opcode
        } else {
            frame::CONTINUATION
        };
        frame::encode(&mut out, opcode, index + 1 == count, chunk, key(mask)?);
    }
    Ok(out)
}

/// A fresh mask key from `random`, or `None` for a frame that is not masked.
fn key(
    random: Option<&SystemRandom>,
) -> std::result::Result<Option<[u8; 4]>, ring::error::Unspecified> {
    let Some(random) = random else {
        return Ok(None);
    };
    let mut key = [0u8; 4];
    random.fill(&mut key)?;
    Ok(Some(key))
}

/// When a byte last moved, in either direction toward either peer.
struct Activity {
    start: Instant,
    /// Milliseconds from `start` to the last byte.
    last: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last: AtomicU64::new(0),
        }
    }

    /// A byte moved now.
    fn touch(&self) {
        let elapsed = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last.store(elapsed, Ordering::Relaxed);
    }

    /// Return once no byte has moved for `idle`.
    async fn idle(&self, idle: Duration) {
        loop {
            let last = self.start + Duration::from_millis(self.last.load(Ordering::Relaxed));
            let deadline = last + idle;
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    }
}

/// The frames queued for one peer. A forwarder waits for room when [`PENDING_LIMIT`] bytes wait,
/// so a peer that stops reading stalls only the direction toward it, and memory stays bounded.
struct Outbox {
    queue: mpsc::UnboundedSender<Queued>,
    room: Arc<Semaphore>,
}

/// Frames waiting for one writer, and the room that they hold.
struct Queued {
    bytes: Vec<u8>,
    _room: Option<OwnedSemaphorePermit>,
}

/// The writer of an outbox has ended.
struct Gone;

impl Outbox {
    fn new() -> (Self, mpsc::UnboundedReceiver<Queued>, Arc<Semaphore>) {
        let (queue, queued) = mpsc::unbounded_channel();
        let room = Arc::new(Semaphore::new(PENDING_LIMIT));
        let outbox = Self {
            queue,
            room: Arc::clone(&room),
        };
        (outbox, queued, room)
    }

    /// Queue frames once there is room for them. One message above the limit takes all of the room
    /// and goes alone.
    async fn send(&self, bytes: Vec<u8>) -> std::result::Result<(), Gone> {
        // `PENDING_LIMIT` is far below `u32::MAX`.
        let wanted = bytes.len().clamp(1, PENDING_LIMIT) as u32;
        let room = Arc::clone(&self.room)
            .acquire_many_owned(wanted)
            .await
            .map_err(|_| Gone)?;
        self.queue
            .send(Queued {
                bytes,
                _room: Some(room),
            })
            .map_err(|_| Gone)
    }

    /// Queue a Close frame. It takes no room, so it never waits.
    fn close(&self, bytes: Vec<u8>) {
        let _ = self.queue.send(Queued { bytes, _room: None });
    }
}

/// Drain one peer's outbox to its write half, then send TLS close_notify and FIN. When the writer
/// ends, a forwarder that waits for room learns that the peer is gone.
async fn write_peer<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut queued: mpsc::UnboundedReceiver<Queued>,
    room: Arc<Semaphore>,
    activity: &Activity,
) -> io::Result<()> {
    let written = async {
        while let Some(frames) = queued.recv().await {
            writer.write_all(&frames.bytes).await?;
            if queued.is_empty() {
                writer.flush().await?;
            }
            activity.touch();
        }
        writer.shutdown().await
    }
    .await;
    room.close();
    written
}

/// Read and drop from both peers until each has ended its stream, or for [`LINGER`].
async fn linger<A: AsyncRead + Unpin, B: AsyncRead + Unpin>(a: &mut A, b: &mut B) {
    let _ = tokio::time::timeout(LINGER, async { tokio::join!(drain(a), drain(b)) }).await;
}

/// Read and drop until the end of the stream or an error.
async fn drain<R: AsyncRead + Unpin>(reader: &mut R) {
    let mut buffer = [0u8; 4096];
    while matches!(reader.read(&mut buffer).await, Ok(count) if count > 0) {}
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use credentials::DestinationPattern;

    use super::*;
    use crate::audit::{Decision as AuditDecision, RequestId, SharedAuditLog};
    use crate::boundary::{InterceptedRequest, Target};
    use crate::capability::{CapabilityOutcome, EgressCapability};
    use crate::effect::{EffectAttempt, EffectInterceptor, EffectPermit};
    use crate::intercept::mitm::{ClientLimits, MitmConfig, tls};
    use crate::seams::StubEmitter;

    /// One frame on the wire: its opcode, fin bit, mask key, and unmasked payload.
    type Wire = (u8, bool, Option<[u8; 4]>, Vec<u8>);

    /// The frames of `wire`.
    fn frames(wire: &[u8]) -> Vec<Wire> {
        let mut out = Vec::new();
        let mut rest = wire;
        while !rest.is_empty() {
            let (fin, opcode) = (rest[0] & 0x80 != 0, rest[0] & 0x0F);
            let masked = rest[1] & 0x80 != 0;
            let (length, mut start) = match rest[1] & 0x7F {
                126 => (usize::from(u16::from_be_bytes([rest[2], rest[3]])), 4),
                127 => (
                    usize::try_from(u64::from_be_bytes(rest[2..10].try_into().unwrap())).unwrap(),
                    10,
                ),
                short => (usize::from(short), 2),
            };
            let key = masked.then(|| {
                let key: [u8; 4] = rest[start..start + 4].try_into().unwrap();
                start += 4;
                key
            });
            let mut payload = rest[start..start + length].to_vec();
            if let Some(key) = key {
                frame::apply_mask(&mut payload, key);
            }
            out.push((opcode, fin, key, payload));
            rest = &rest[start + length..];
        }
        out
    }

    /// **A message goes on in the sender's largest fragment, never below 1 KiB**, and in one frame
    /// when the sender sent one.
    #[test]
    fn encode_message_splits_at_the_senders_fragment_and_never_below_one_kib() {
        let payload: Vec<u8> = (0..5000).map(|index| (index % 251) as u8).collect();
        let sizes = |fragment| {
            frames(&encode_message(frame::BINARY, &payload, fragment, None).unwrap())
                .into_iter()
                .map(|(opcode, fin, _, payload)| (opcode, fin, payload.len()))
                .collect::<Vec<_>>()
        };
        assert_eq!(sizes(None), [(frame::BINARY, true, 5000)]);
        assert_eq!(
            sizes(Some(2048)),
            [
                (frame::BINARY, false, 2048),
                (frame::CONTINUATION, false, 2048),
                (frame::CONTINUATION, true, 904),
            ]
        );
        assert_eq!(sizes(Some(16)).len(), 5, "16-byte fragments go on as 1 KiB");
        assert!(
            sizes(Some(16))[..4]
                .iter()
                .all(|(_, _, size)| *size == 1024)
        );
        assert_eq!(sizes(Some(8000)), [(frame::BINARY, true, 5000)]);
        let joined: Vec<u8> =
            frames(&encode_message(frame::BINARY, &payload, Some(16), None).unwrap())
                .into_iter()
                .flat_map(|(_, _, _, payload)| payload)
                .collect();
        assert_eq!(joined, payload);
    }

    /// **Each frame toward the server gets its own fresh mask key**; frames toward the client are
    /// not masked.
    #[test]
    fn encode_message_masks_each_frame_with_its_own_key() {
        let random = SystemRandom::new();
        let payload = vec![7u8; 4096];
        let masked =
            frames(&encode_message(frame::TEXT, &payload, Some(1024), Some(&random)).unwrap());
        let keys: Vec<[u8; 4]> = masked.iter().map(|(_, _, key, _)| key.unwrap()).collect();
        assert_eq!(keys.len(), 4);
        for (index, key) in keys.iter().enumerate() {
            assert!(!keys[index + 1..].contains(key), "{keys:?}");
        }
        assert!(
            masked
                .iter()
                .all(|(_, _, _, part)| part == &vec![7u8; 1024])
        );
        let plain = frames(&encode_message(frame::TEXT, &payload, None, None).unwrap());
        assert_eq!(plain[0].2, None);
    }

    /// Run `future` on a current-thread runtime with timers.
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(future)
    }

    /// **One message above the limit goes alone**: it takes all of the room, and the next message
    /// waits until the writer takes it.
    #[test]
    fn an_outbox_admits_one_oversized_message_alone() {
        block_on(async {
            let (outbox, mut queued, _room) = Outbox::new();
            outbox
                .send(vec![0u8; PENDING_LIMIT * 4])
                .await
                .ok()
                .unwrap();
            let waits = tokio::time::timeout(Duration::from_millis(50), outbox.send(vec![1u8]));
            assert!(waits.await.is_err(), "the next message waits for room");
            let first = queued.recv().await.unwrap();
            assert_eq!(first.bytes.len(), PENDING_LIMIT * 4);
            drop(first);
            outbox.send(vec![1u8]).await.ok().unwrap();
            assert_eq!(queued.recv().await.unwrap().bytes, [1u8]);
        });
    }

    /// **A close never waits for room**, and a forwarder that waits for room learns that the
    /// writer is gone.
    #[test]
    fn a_close_never_waits_for_room() {
        block_on(async {
            let (outbox, mut queued, room) = Outbox::new();
            outbox.send(vec![0u8; PENDING_LIMIT]).await.ok().unwrap();
            outbox.close(vec![0x88, 0x00]);
            let _message = queued.recv().await.unwrap();
            assert_eq!(queued.recv().await.unwrap().bytes, [0x88, 0x00]);
            let waiting = outbox.send(vec![1u8]);
            room.close();
            assert!(
                waiting.await.is_err(),
                "a closed room refuses the forwarder"
            );
        });
    }

    /// A credential control on `ws.example.com` whose response fold redacts `secret` and refuses a
    /// body that holds `refuse`.
    struct Fold;

    impl EgressCapability for Fold {
        fn pattern(&self) -> &DestinationPattern {
            static PATTERN: OnceLock<DestinationPattern> = OnceLock::new();
            PATTERN.get_or_init(|| DestinationPattern::parse("ws.example.com").unwrap())
        }

        fn on_request(
            &self,
            _request: &mut InterceptedRequest,
            _context: &CapabilityContext,
        ) -> CapabilityOutcome {
            CapabilityOutcome::none()
        }

        fn on_response(
            &self,
            response: &mut InterceptedResponse,
            _context: &CapabilityContext,
        ) -> CapabilityOutcome {
            let body = String::from_utf8_lossy(response.body.as_bytes()).into_owned();
            if body.contains("refuse") {
                return CapabilityOutcome::unavailable("the fold refuses this body");
            }
            response.body = BodyRef::Bytes(body.replace("secret", "[REDACTED]").into_bytes());
            CapabilityOutcome::none()
        }
    }

    /// An authority that the relay never consults.
    struct Unconsulted;

    impl EffectInterceptor for Unconsulted {
        fn intercept(&self, _attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
            panic!("the relay claims no effect")
        }
    }

    fn state(emitter: &StubEmitter) -> SharedState {
        SharedState {
            controls: CapabilitySet::from_parts(vec![Box::new(Fold)]),
            config: MitmConfig::default(),
            ca: None,
            upstream_config: Arc::new(tls::upstream_client_config(&[]).unwrap()),
            audit: SharedAuditLog::new(),
            emitter: Box::new(emitter.clone()),
            effect_interceptor: Arc::new(Unconsulted),
            expected_token: None,
            client_limits: ClientLimits::default(),
            sessions: Arc::new(Semaphore::new(1)),
        }
    }

    /// **The fold scrubs each server message and control frame, and a server message that it
    /// refuses closes the server with 1008 and the workload with 1014.** A redacted message keeps
    /// its fragment size, a ping that carried the secret loses its payload, the refused message
    /// never reaches the workload, and one `Deny` names the fault with no payload byte.
    #[test]
    fn the_fold_scrubs_server_messages_and_a_refused_one_closes_with_1008_and_1014() {
        let emitter = StubEmitter::new();
        let state = state(&emitter);
        let (client, mut workload) = tokio::io::duplex(64 * 1024);
        let (upstream, mut server) = tokio::io::duplex(64 * 1024);
        let correlation = RequestId::new("relay");
        let pending = Pending {
            host: "ws.example.com".to_string(),
            port: 443,
            path: "/chat".to_string(),
            correlation: correlation.clone(),
            scrub: Some(CapabilityContext::new(
                correlation,
                0,
                Target::new("ws.example.com", 443),
            )),
            upstream: Box::new(upstream),
            slot: Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
        };
        let (_stop, stop) = watch::channel(false);
        let lead = format!("{}you sent secret", "x".repeat(1500));
        let mut sent = Vec::new();
        frame::encode(&mut sent, frame::TEXT, false, lead.as_bytes(), None);
        frame::encode(&mut sent, frame::CONTINUATION, true, &[b'y'; 1500], None);
        frame::encode(&mut sent, frame::PING, true, b"secret", None);
        frame::encode(&mut sent, frame::TEXT, true, b"refuse secret", None);
        let (ended, to_workload, to_server) = block_on(async {
            // The peers end their streams when they have read to the end, so the linger ends.
            let peers = async move {
                server.write_all(&sent).await.unwrap();
                let (mut to_workload, mut to_server) = (Vec::new(), Vec::new());
                workload.read_to_end(&mut to_workload).await.unwrap();
                server.read_to_end(&mut to_server).await.unwrap();
                (to_workload, to_server)
            };
            let (ended, (to_workload, to_server)) =
                tokio::join!(run(pending, client, &state, stop), peers);
            (ended, to_workload, to_server)
        });
        assert!(ended.is_ok(), "a refusal ends the session cleanly");

        let expected = format!(
            "{}you sent [REDACTED]{}",
            "x".repeat(1500),
            "y".repeat(1500)
        );
        let workload_frames = frames(&to_workload);
        let shapes: Vec<(u8, bool, usize)> = workload_frames
            .iter()
            .map(|(opcode, fin, _, payload)| (*opcode, *fin, payload.len()))
            .collect();
        assert_eq!(
            shapes,
            [
                (frame::TEXT, false, lead.len()),
                (frame::CONTINUATION, true, expected.len() - lead.len()),
                (frame::PING, true, 0),
                (frame::CLOSE, true, 2),
            ],
            "the message goes on in the server's largest fragment, then an empty ping, then the close"
        );
        let joined: Vec<u8> = workload_frames[..2]
            .iter()
            .flat_map(|(_, _, _, payload)| payload.clone())
            .collect();
        assert_eq!(String::from_utf8(joined).unwrap(), expected);
        assert_eq!(workload_frames[3].3, frame::BAD_GATEWAY.to_be_bytes());

        let server_frames = frames(&to_server);
        assert_eq!(server_frames.len(), 1, "only the close goes to the server");
        assert_eq!(server_frames[0].0, frame::CLOSE);
        assert!(
            server_frames[0].2.is_some(),
            "a frame to the server is masked"
        );
        assert_eq!(server_frames[0].3, frame::POLICY_VIOLATION.to_be_bytes());

        let reason = "websocket: server message refused: credential denied";
        let audit: Vec<String> = state
            .audit
            .drain()
            .into_iter()
            .map(|event| event.reason)
            .collect();
        assert_eq!(audit, [reason]);
        let denials: Vec<(String, String, String)> = emitter
            .records()
            .into_iter()
            .filter(|record| record.decision == AuditDecision::Deny)
            .map(|record| (record.method, record.path, record.reason))
            .collect();
        assert_eq!(
            denials,
            [("GET".to_string(), "/chat".to_string(), reason.to_string())]
        );
    }

    /// **The idle wait restarts on activity**: a byte that moves before the limit moves the end
    /// of the wait.
    #[test]
    fn the_idle_wait_restarts_on_activity() {
        block_on(async {
            let activity = Activity::new();
            let idle = Duration::from_millis(200);
            let started = Instant::now();
            let touching = async {
                for _ in 0..3 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    activity.touch();
                }
            };
            tokio::join!(activity.idle(idle), touching);
            assert!(
                started.elapsed() >= Duration::from_millis(500),
                "{:?}",
                started.elapsed()
            );
        });
    }
}
