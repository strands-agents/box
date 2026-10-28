//! The accept loop and per-connection handler.

use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::Response;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

use crate::audit::RequestId;

use super::SharedState;
use super::connect::{self, ConnectRequest};
use super::convert::{self, Whole};
use super::exchange::{Subject, Unfinished, emit_decision, record_refusal, record_unfinished};
use super::resolve::PinnedDestination;
use super::serve::{PlainSession, TlsSession, serve_plain, serve_tls};
use crate::audit::{Decision as AuditDecision, NetworkAuditEvent};
use crate::effect::{ClaimedEffectPermit, EffectAttempt, EffectOutcome, off_worker};
use crate::error::ProxyError;

/// The one listener that `start` bound, before the gateway runtime registers it.
pub(super) enum BoundListener {
    /// A TCP listener on loopback.
    Tcp(std::net::TcpListener),
    /// An AF_UNIX listener (the pin mode).
    Unix(std::os::unix::net::UnixListener),
}

impl BoundListener {
    /// Make accepts non-blocking, as the runtime requires before it registers the listener.
    pub(super) fn set_nonblocking(&self) -> io::Result<()> {
        match self {
            Self::Tcp(listener) => listener.set_nonblocking(true),
            Self::Unix(listener) => listener.set_nonblocking(true),
        }
    }

    /// Register the listener with the current runtime.
    pub(super) fn into_tokio(self) -> io::Result<Listening> {
        Ok(match self {
            Self::Tcp(listener) => Listening::Tcp(tokio::net::TcpListener::from_std(listener)?),
            Self::Unix(listener) => Listening::Unix(tokio::net::UnixListener::from_std(listener)?),
        })
    }
}

/// The listener, registered with the gateway runtime.
pub(super) enum Listening {
    Tcp(tokio::net::TcpListener),
    Unix(tokio::net::UnixListener),
}

impl Listening {
    async fn accept(&self) -> io::Result<Accepted> {
        Ok(match self {
            Self::Tcp(listener) => Accepted::Tcp(listener.accept().await?.0),
            Self::Unix(listener) => Accepted::Unix(listener.accept().await?.0),
        })
    }
}

/// One accepted client connection.
enum Accepted {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
}

/// One held connection slot. The slot frees when this value drops: at the end of the connection,
/// on any error, or in a panic unwind.
struct Slot {
    _permit: OwnedSemaphorePermit,
}

/// Run the accept loop until `stopping` turns `true` or its sender drops. Each connection holds one
/// of the `slots`, which `config.max_connections` sizes: the loop accepts, then waits for a free
/// slot before it accepts more, so an untrusted workload cannot make the gateway serve without bound
/// (backpressure, not an optimization). Both waits watch the stop, so a full slot set cannot hold
/// the stop back.
pub(super) async fn accept_loop(
    listener: Listening,
    state: Arc<SharedState>,
    slots: Arc<Semaphore>,
    mut stopping: watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            biased;
            _ = stopping.wait_for(|stop| *stop) => break,
            accepted = listener.accept() => accepted,
        };
        let Ok(client) = accepted else { continue };
        let slot = tokio::select! {
            biased;
            _ = stopping.wait_for(|stop| *stop) => break,
            permit = Arc::clone(&slots).acquire_owned() => match permit {
                Ok(permit) => Slot { _permit: permit },
                Err(_) => break,
            },
        };
        // The first head must be complete a fixed time after the connection takes its slot.
        let head_deadline = Instant::now() + state.client_limits.first_head;
        tokio::spawn(serve_connection(
            client,
            Arc::clone(&state),
            slot,
            head_deadline,
            stopping.clone(),
        ));
    }
    // The listener and the state drop before the caller reports the end of the loop.
    drop(listener);
    drop(state);
}

/// Serve one connection: read its first head, then route it. The task holds the slot until the
/// connection ends, also while it relays a WebSocket. `stop` ends a relay.
async fn serve_connection(
    client: Accepted,
    state: Arc<SharedState>,
    slot: Slot,
    head_deadline: Instant,
    stop: watch::Receiver<bool>,
) {
    let handled = match client {
        Accepted::Tcp(stream) => {
            // Small writes, such as a WebSocket frame, leave at once.
            let _ = stream.set_nodelay(true);
            route(stream, &state, slot, head_deadline, stop).await
        }
        Accepted::Unix(stream) => route(stream, &state, slot, head_deadline, stop).await,
    };
    if let Err(err) = handled {
        // Never silently swallow a handler failure — record it (secret-free) so a broken
        // connection is observable rather than a mystery. `host`/`port` are unknown this
        // early, so the audit line names the failure with a placeholder target.
        state.audit.push(NetworkAuditEvent::deny(
            "-",
            0,
            format!("connection handler error: {err}"),
            RequestId::new("egress-connection-error"),
        ));
    }
}

/// A client socket of one transport, as the async front reads it.
trait Client: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    /// Whether a first head that is not a `CONNECT` is served as a plain-HTTP absolute-form
    /// request. The AF_UNIX transport stays CONNECT-only: the AF_UNIX pin has no plain-HTTP client,
    /// so such a head gets a 400.
    const PLAIN_HTTP: bool;
}

impl Client for tokio::net::TcpStream {
    /// Not a CONNECT. Treat it as a plain-HTTP absolute-form request — the same controls apply
    /// (net:connect and the L7 legs), over plaintext with no CONNECT ack. The CONNECT-only
    /// v1 used to 400 here.
    const PLAIN_HTTP: bool = true;
}

impl Client for tokio::net::UnixStream {
    const PLAIN_HTTP: bool = false;
}

/// Route one client connection by request shape, after reading its head.
///
/// A CONNECT opens the TLS interception path ([`tls_path`]); anything else is a plain-HTTP request
/// on TCP ([`serve_plain`]) and a 400 on AF_UNIX. Reading the head is the only work shared before
/// the split. A failed or late read of the head is a silent drop.
async fn route<C: Client>(
    mut client: C,
    state: &Arc<SharedState>,
    slot: Slot,
    head_deadline: Instant,
    stop: watch::Receiver<bool>,
) -> Result<(), ProxyError> {
    let idle = state.client_limits.idle;
    let head = match read_until_headers_end(&mut client, idle, head_deadline).await {
        Ok(head) => head,
        Err(_) => return Ok(()),
    };
    match connect::parse_connect(&head) {
        // HTTPS via CONNECT: terminate TLS and inspect.
        Some(connect) => tls_path(client, connect, state, slot, stop).await,
        None if C::PLAIN_HTTP => {
            let _slot = slot;
            let session = PlainSession {
                client,
                proxy_authorization: connect::proxy_authorization_from_head(&head),
                head: head.into_bytes(),
                stop,
            };
            serve_plain(Arc::clone(state), session).await
        }
        None => {
            let _ = write_client(
                &mut client,
                status_reply(400, "bad request").as_bytes(),
                idle,
            )
            .await;
            Ok(())
        }
    }
}

/// The CONNECT acknowledgement, written once the upstream is open and its outcome is recorded.
const CONNECT_ACK: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

/// Handle one CONNECT (HTTPS) connection: run the shared L4 controls, acknowledge, then terminate
/// TLS and serve the exchange on hyper.
async fn tls_path<C: Client>(
    mut client: C,
    connect: ConnectRequest,
    state: &Arc<SharedState>,
    slot: Slot,
    stop: watch::Receiver<bool>,
) -> Result<(), ProxyError> {
    let idle = state.client_limits.idle;
    let correlation = RequestId::unique();

    // Best-effort token check — never the primary defense.
    if !connect::token_ok(
        state.expected_token.as_deref(),
        connect.proxy_authorization.as_deref(),
    ) {
        let reply = off_worker(|| refuse_proxy_token(state, &connect, &correlation));
        let _ = write_client(&mut client, reply.as_bytes(), idle).await;
        return Ok(());
    }

    // Shared L4: the pre-resolution `net:connect`, resolve-once/pin, and the per-address
    // `net:connect` effect. Claimed and opened BEFORE the CONNECT ack, so a denial returns 403 without
    // creating a socket or exposing a false tunnel. The whole sequence is synchronous and runs in
    // one `off_worker` call, so each decision and its emit share one thread, and a slow decision
    // stalls only this connection.
    let upstream = match off_worker(|| open_governed_upstream(state, &connect, &correlation)) {
        Ok(upstream) => upstream,
        Err(error) => {
            let _ = write_client(&mut client, &error.response_bytes("CONNECT"), idle).await;
            return Ok(());
        }
    };

    // The upstream is open and its outcome was recorded; now let the client proceed.
    write_client(&mut client, CONNECT_ACK, idle)
        .await
        .map_err(|e| ProxyError::Io(format!("writing CONNECT ack: {e}")))?;

    // Every connection is terminated and inspected. There is no un-inspected path: a
    // connection whose plaintext the boundary cannot see could not raise `http:request`, so it would
    // be exempt from the request authorization and would carry no credential decision either.
    //
    // **Two decisions, not three, and the actions are `net:connect` and `http:request`.** This named
    // `net:request` and `net:response` and called them two of three authorizations. Neither action
    // exists.
    //
    // The response leg takes **no decision**. `policy`'s egress adapter matches `ResponseRelease`
    // and returns `Ok(())`, so a rule cannot refuse a release or budget on a response size. The
    // reply reaches history once, on the request permit, as `output.status` of the one
    // `http:request::response` an exchange records.
    //
    // The gateway would honour a refusal on that leg: `serve::serve_tls` emits a deny event and
    // withholds the bytes. The shipped interceptor never issues one.
    //
    // A handshake or pin failure hard-fails (drop), never a downgrade; the connection task
    // audits the error. This task holds the slot until the exchange ends.
    let _slot = slot;
    let session = TlsSession {
        client,
        upstream,
        connect,
        correlation,
        stop,
    };
    serve_tls(Arc::clone(state), session).await
}

/// A failure before CONNECT can be acknowledged.
pub(super) enum OpenUpstreamError {
    /// The effect interceptor explicitly denied the socket open.
    Denied(io::Error),
    /// The interceptor, socket open, peer lookup, or outcome sink failed.
    Failed,
}

impl OpenUpstreamError {
    /// The refusal that the gateway writes on the raw socket before the CONNECT acknowledgement.
    fn response_bytes(&self, method: &str) -> Vec<u8> {
        match self {
            Self::Denied(error) => {
                let mut bytes = Vec::new();
                super::l7::write_interceptor_error(&mut bytes, method, error, None);
                bytes
            }
            Self::Failed => status_reply(502, "bad gateway").into_bytes(),
        }
    }

    /// The same refusal as a hyper reply, for a plain-HTTP request of `version`.
    pub(super) fn response(&self, method: &str, version: http::Version) -> Response<Whole> {
        match self {
            Self::Denied(error) => convert::interceptor_response(method, version, error, None),
            Self::Failed => convert::status_response(version, 502, "bad gateway"),
        }
    }

    fn audit_reason(&self) -> &'static str {
        match self {
            Self::Denied(_) => "connect effect denied",
            Self::Failed => "connect effect or outcome recording failed",
        }
    }
}

/// Run the shared L4 controls for one destination and open the governed upstream.
///
/// The pre-resolution `net:connect`, resolve-once/pin, and the per-address `net:connect`
/// effect ([`open_upstream`]) are identical for every transport (TCP, AF_UNIX) and every request
/// shape (CONNECT, plain HTTP), so all three handlers converge here. On refusal it pushes the audit
/// event and returns the refusal the caller writes to its own client stream; on success
/// it returns the open upstream socket. The caller owns acknowledging CONNECT (or not) and running
/// the L7 legs.
pub(super) fn open_governed_upstream(
    state: &SharedState,
    connect: &ConnectRequest,
    correlation: &RequestId,
) -> std::result::Result<TcpStream, OpenUpstreamError> {
    // Policy decides the host before it is resolved, so a denied destination sends no DNS query: a
    // workload cannot carry data out in the labels of a name the gateway looks up and then refuses.
    // The per-address `net:connect` below still decides every resolved address.
    let resolve = EffectAttempt::Resolve {
        host: &connect.host,
        port: connect.port,
    };
    match state.effect_interceptor.intercept(&resolve) {
        Ok(_decided) => {}
        Err(error) => {
            emit_decision(
                state,
                &Subject::connection(connect, correlation),
                AuditDecision::Deny,
                &error.to_string(),
            );
            let refusal = if error.kind() == io::ErrorKind::PermissionDenied {
                OpenUpstreamError::Denied(error)
            } else {
                OpenUpstreamError::Failed
            };
            state.audit.push(NetworkAuditEvent::deny(
                &connect.host,
                connect.port,
                refusal.audit_reason().to_string(),
                correlation.clone(),
            ));
            return Err(refusal);
        }
    }

    // Resolve-once + pin, honoring any supervisor DNS override. A resolution failure
    // is a hard 502, never a retry.
    let override_ip = state.dns_override(&connect.host);
    let pinned =
        match PinnedDestination::resolve_with_override(&connect.host, connect.port, override_ip) {
            Ok(pinned) => pinned,
            Err(error) => {
                record_refusal(
                    state,
                    &Subject::connection(connect, correlation),
                    &error.to_string(),
                );
                return Err(OpenUpstreamError::Failed);
            }
        };

    // Authorization is the authored policy's, enforced inside `open_upstream` through the
    // `EffectInterceptor` seam (`EffectAttempt::Connect`) before the socket opens — there is no
    // allow/deny authority in this crate. Every connection is terminated and inspected; see
    // `open_upstream`'s `http_visibility` for why no route is an opaque tunnel.
    match open_upstream(state, connect, &pinned, correlation) {
        Ok(upstream) => Ok(upstream),
        Err(error) => {
            state.audit.push(NetworkAuditEvent::deny(
                &connect.host,
                connect.port,
                error.audit_reason().to_string(),
                correlation.clone(),
            ));
            Err(error)
        }
    }
}

/// Claim and perform pinned upstream socket attempts shared by TLS and opaque paths.
fn open_upstream(
    state: &SharedState,
    connect: &ConnectRequest,
    pinned: &PinnedDestination,
    correlation: &RequestId,
) -> std::result::Result<TcpStream, OpenUpstreamError> {
    let subject = Subject::connection(connect, correlation);
    let unfinished = |why| {
        record_unfinished(state, &subject, why);
        OpenUpstreamError::Failed
    };
    for address in pinned.pinned_addrs() {
        // Each pinned address is its own authorization: the address authorized is the address
        // dialed, so a fallback cannot ride the first address's permit.
        let attempt = EffectAttempt::Connect {
            host: &connect.host,
            port: connect.port,
            address,
            // **Unconditionally true, so TLS termination is never selective.** Every connection is
            // terminated and inspected; no opaque-tunnel path exists.
            //
            // This arrived through three layers — a `SharedState::route_needs_http` that returned
            // `true` for every route, a `needs_http` local at each caller, and a parameter on this
            // function. All three are gone. A maintainer reading them went looking for the selective
            // path they implied, and there was none to find.
            //
            // The field stays because `EffectAttempt` is in this crate's frozen `lib.rs` `pub use`
            // set, and it is an attribute a policy adapter could expose to a rule. Its one production
            // consumer, `policy`'s egress adapter, discards it today.
            http_visibility: true,
        };
        let permit = match state.effect_interceptor.intercept(&attempt) {
            Ok(permit) => ClaimedEffectPermit::new(permit),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                emit_decision(state, &subject, AuditDecision::Deny, &error.to_string());
                return Err(OpenUpstreamError::Denied(error));
            }
            Err(error) => {
                emit_decision(state, &subject, AuditDecision::Deny, &error.to_string());
                return Err(OpenUpstreamError::Failed);
            }
        };
        emit_decision(state, &subject, AuditDecision::Allow, "");

        let upstream = match TcpStream::connect(address) {
            Ok(upstream) => upstream,
            Err(error) => {
                permit
                    .record_outcome(EffectOutcome::ConnectFailed(error.kind()))
                    .map_err(|_| unfinished(Unfinished::OutcomeUnrecorded))?;
                continue;
            }
        };

        let peer = upstream
            .peer_addr()
            .map_err(|_| unfinished(Unfinished::SocketUnprepared))?;
        permit
            .record_outcome(EffectOutcome::Connected(peer))
            .map_err(|_| unfinished(Unfinished::OutcomeUnrecorded))?;
        // The gateway runtime registers the socket, and its idle bound replaces socket timeouts.
        // Small writes, such as a WebSocket frame, leave at once.
        upstream
            .set_nonblocking(true)
            .and_then(|()| upstream.set_nodelay(true))
            .map_err(|_| unfinished(Unfinished::SocketUnprepared))?;
        return Ok(upstream);
    }

    Err(unfinished(Unfinished::NoAddressConnected))
}

/// The reason and the status message of a refused proxy token.
pub(super) const PROXY_AUTHENTICATION_REQUIRED: &str = "proxy authentication required";

/// Record a refused proxy token, and return the `407` to write.
fn refuse_proxy_token(
    state: &SharedState,
    connect: &ConnectRequest,
    correlation: &RequestId,
) -> String {
    record_refusal(
        state,
        &Subject::connection(connect, correlation),
        PROXY_AUTHENTICATION_REQUIRED,
    );
    status_reply(407, PROXY_AUTHENTICATION_REQUIRED)
}

/// Read the first head from `stream` up to the `\r\n\r\n` terminator (bounded), as a string. Each
/// read waits at most `idle`, and a read that ends at or after `deadline` fails.
///
/// One byte for each read, on an unbuffered stream: every byte after the head, such as a
/// `ClientHello` sent with the `CONNECT`, stays in the socket for the next reader.
async fn read_until_headers_end<S: AsyncRead + Unpin>(
    stream: &mut S,
    idle: Duration,
    deadline: Instant,
) -> io::Result<String> {
    use tokio::io::AsyncReadExt;

    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = tokio::time::timeout(idle, stream.read(&mut byte))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client idle bound passed"))??;
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "client head deadline passed",
            ));
        }
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") || buf.len() > 64 * 1024 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Write `bytes` to an async client stream, and fail when the write waits `idle`.
async fn write_client<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
    idle: Duration,
) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;

    tokio::time::timeout(idle, stream.write_all(bytes))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client idle bound passed"))?
}

/// A minimal status line + empty body (for a proxy-level refusal).
fn status_reply(status: u16, msg: &str) -> String {
    format!("HTTP/1.1 {status} {msg}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
    use std::os::unix::net::UnixListener;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::super::runtime::GatewayThread;

    use crate::capability::CapabilitySet;
    use crate::effect::{EffectAttempt, EffectInterceptor, EffectPermit};
    use crate::seams::StubEmitter;

    /// An authority that permits one address and refuses every other, recording what it saw.
    struct AddressPolicy {
        permitted: Option<IpAddr>,
        seen: Mutex<Vec<(SocketAddr, bool)>>,
    }

    impl AddressPolicy {
        fn permitting(ip: IpAddr) -> Arc<Self> {
            Arc::new(Self {
                permitted: Some(ip),
                seen: Mutex::new(Vec::new()),
            })
        }
        fn permit_all() -> Arc<Self> {
            Arc::new(Self {
                permitted: None,
                seen: Mutex::new(Vec::new()),
            })
        }
        fn seen(&self) -> Vec<(SocketAddr, bool)> {
            self.seen.lock().unwrap().clone()
        }
    }

    struct NoopPermit;
    impl EffectPermit for NoopPermit {
        fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> io::Result<()> {
            Ok(())
        }
        fn mark_indeterminate(self: Box<Self>) {}
    }

    impl EffectInterceptor for AddressPolicy {
        fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
            if let EffectAttempt::Connect { address, .. } = attempt {
                let permitted = self.permitted.is_none_or(|ip| address.ip() == ip);
                self.seen.lock().unwrap().push((*address, permitted));
                if !permitted {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "address refused by test policy",
                    ));
                }
            }
            Ok(Box::new(NoopPermit))
        }
    }

    /// A loopback listener counting the connections it accepts, measured behind a drain barrier
    /// (ticket taken before the sweep, acknowledged after it) and stopped by joining.
    struct Recorder {
        addr: SocketAddr,
        accepted: Arc<AtomicUsize>,
        accept_error: Arc<Mutex<Option<String>>>,
        drain_requested: Arc<std::sync::atomic::AtomicU64>,
        drain_acknowledged: Arc<std::sync::atomic::AtomicU64>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Recorder {
        fn bind(addr: SocketAddr) -> io::Result<Self> {
            let listener = TcpListener::bind(addr)?;
            listener.set_nonblocking(true)?;
            let addr = listener.local_addr()?;
            Ok(Self::from_accept(addr, move || listener.accept()))
        }

        fn from_accept(
            addr: SocketAddr,
            mut accept: impl FnMut() -> io::Result<(TcpStream, SocketAddr)> + Send + 'static,
        ) -> Self {
            let accepted = Arc::new(AtomicUsize::new(0));
            let accept_error = Arc::new(Mutex::new(None));
            let drain_requested = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let drain_acknowledged = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let (count, failure, requested, acknowledged, stopping) = (
                accepted.clone(),
                accept_error.clone(),
                drain_requested.clone(),
                drain_acknowledged.clone(),
                stop.clone(),
            );
            let thread = std::thread::spawn(move || {
                while !stopping.load(Ordering::SeqCst) {
                    let ticket = requested.load(Ordering::SeqCst);
                    while !stopping.load(Ordering::SeqCst) {
                        match accept() {
                            Ok((stream, _)) => {
                                count.fetch_add(1, Ordering::SeqCst);
                                drop(stream);
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(error) => {
                                *failure.lock().unwrap() = Some(error.to_string());
                                return;
                            }
                        }
                    }
                    if acknowledged.load(Ordering::SeqCst) < ticket {
                        acknowledged.store(ticket, Ordering::SeqCst);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            });
            Self {
                addr,
                accepted,
                accept_error,
                drain_requested,
                drain_acknowledged,
                stop,
                thread: Some(thread),
            }
        }

        /// The accept count after the loop has swept every connection queued before this call.
        fn accepted(&self) -> usize {
            let wanted = self.drain_requested.fetch_add(1, Ordering::SeqCst) + 1;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while self.drain_acknowledged.load(Ordering::SeqCst) < wanted {
                self.assert_healthy();
                assert!(
                    std::time::Instant::now() < deadline,
                    "the recorder's accept loop did not acknowledge a drain"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            self.assert_healthy();
            self.accepted.load(Ordering::SeqCst)
        }

        /// The accept count once it reaches `expected`, or after 2 s.
        fn await_accepted(&self, expected: usize) -> usize {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                let accepted = self.accepted();
                if accepted >= expected || std::time::Instant::now() >= deadline {
                    return accepted;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }

        fn assert_healthy(&self) {
            let error = self.accept_error.lock().unwrap().clone();
            if let Some(error) = error {
                panic!("the recorder's accept failed: {error}");
            }
        }

        /// Independent endpoint control: the host itself reaches this recorder and is counted.
        fn assert_live(&self) {
            let before = self.accepted();
            drop(
                TcpStream::connect_timeout(&self.addr, std::time::Duration::from_secs(2))
                    .expect("the host reaches the recorder"),
            );
            assert_eq!(
                self.await_accepted(before + 1),
                before + 1,
                "the recorder counts a direct connection"
            );
        }
    }

    impl Drop for Recorder {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    #[test]
    #[should_panic(expected = "accept failed: injected accept failure")]
    fn an_accept_error_cannot_be_read_as_a_clean_zero() {
        let recorder =
            Recorder::from_accept(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), || {
                Err(io::Error::other("injected accept failure"))
            });
        recorder.accepted();
    }

    /// A second loopback address on `port`, distinct from `127.0.0.1`. Required setup: its absence
    /// fails the test by name rather than skipping the body.
    fn second_loopback_recorder(port: u16) -> Recorder {
        let candidates = [
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        ];
        let mut errors = Vec::new();
        for ip in candidates {
            match Recorder::bind(SocketAddr::new(ip, port)) {
                Ok(recorder) => return recorder,
                Err(error) => errors.push(format!("{ip}: {error}")),
            }
        }
        panic!(
            "required setup: no second loopback address could be bound on port {port}: {errors:?}"
        );
    }

    fn state(policy: Arc<dyn EffectInterceptor>) -> SharedState {
        SharedState {
            controls: CapabilitySet::default(),
            config: super::super::MitmConfig::default(),
            ca: None,
            upstream_config: Arc::new(super::super::tls::upstream_client_config(&[]).unwrap()),
            audit: crate::audit::SharedAuditLog::new(),
            emitter: Box::new(StubEmitter::new()),
            effect_interceptor: policy,
            expected_token: None,
            client_limits: ClientLimits::default(),
            sessions: Arc::new(Semaphore::new(0)),
        }
    }

    fn connect_to(host: &str, port: u16) -> ConnectRequest {
        ConnectRequest {
            host: host.to_string(),
            port,
            proxy_authorization: None,
        }
    }

    /// A resolver answer of two addresses, one the authority permits and one it refuses, against
    /// live recorders at both: the refused address is never dialed whatever its position, and a
    /// refusal aborts the connect rather than falling through to the permitted one.
    #[test]
    fn a_pinned_address_the_authority_refused_is_never_dialed_whatever_its_position() {
        let permitted =
            Recorder::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let port = permitted.addr.port();
        let refused = second_loopback_recorder(port);
        permitted.assert_live();
        refused.assert_live();
        let (permitted_before, refused_before) = (permitted.accepted(), refused.accepted());
        let (a, b) = (permitted.addr.ip(), refused.addr.ip());
        let host = "two-answers.test";
        let correlation = RequestId::new("test");

        // Refused address first: the connect is refused outright; neither recorder is contacted.
        let policy = AddressPolicy::permitting(a);
        let shared = state(policy.clone());
        let pinned = PinnedDestination::from_ips(port, vec![b, a]);
        assert!(
            matches!(
                open_upstream(&shared, &connect_to(host, port), &pinned, &correlation),
                Err(OpenUpstreamError::Denied(_))
            ),
            "a refused first address aborts the connect"
        );
        assert_eq!(policy.seen(), vec![(SocketAddr::new(b, port), false)]);
        assert_eq!(
            refused.accepted(),
            refused_before,
            "the refused address was never dialed"
        );
        assert_eq!(
            permitted.accepted(),
            permitted_before,
            "the permitted address does not ride the refusal as a fallback"
        );

        // Permitted address first: it is dialed, and the refused one is never asked about.
        let policy = AddressPolicy::permitting(a);
        let shared = state(policy.clone());
        let pinned = PinnedDestination::from_ips(port, vec![a, b]);
        let upstream = open_upstream(&shared, &connect_to(host, port), &pinned, &correlation)
            .ok()
            .expect("the permitted address connects");
        assert_eq!(upstream.peer_addr().unwrap(), SocketAddr::new(a, port));
        assert_eq!(policy.seen(), vec![(SocketAddr::new(a, port), true)]);
        assert_eq!(
            permitted.await_accepted(permitted_before + 1),
            permitted_before + 1
        );
        assert_eq!(refused.accepted(), refused_before);
        drop(upstream);
    }

    /// **The dialed socket sends small writes at once** (`TCP_NODELAY`), so a WebSocket frame does
    /// not wait for the next one.
    #[test]
    fn the_dialed_socket_sends_small_writes_at_once() {
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = origin.local_addr().unwrap().port();
        let shared = state(AddressPolicy::permit_all());
        let pinned = PinnedDestination::from_ips(port, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        let upstream = open_upstream(
            &shared,
            &connect_to("nodelay.test", port),
            &pinned,
            &RequestId::new("test"),
        )
        .ok()
        .expect("the permitted address connects");
        assert!(upstream.nodelay().unwrap());
    }

    /// A dead endpoint plus a live refused recorder that share one port, on two loopback addresses
    /// every supported host has: the recorder on a second loopback address (`[::1]`, or `127.0.0.2`
    /// where IPv6 loopback is absent) chooses an ephemeral port, and `127.0.0.1` on that same port
    /// is left unbound. No port is bound and released, so no freed port can be reused; the dead
    /// endpoint is confirmed closed from the host by a bounded connect before it is trusted, and a
    /// port that is already in use on `127.0.0.1` is retried with a fresh recorder.
    struct DeadAndRefused {
        dead: SocketAddr,
        refused: Recorder,
    }

    const DEAD_ENDPOINT_ATTEMPTS: usize = 8;

    fn dead_and_refused_endpoints() -> Result<DeadAndRefused, Vec<String>> {
        let mut rejected = Vec::new();
        for _ in 0..DEAD_ENDPOINT_ATTEMPTS {
            let refused = second_loopback_recorder(0);
            let dead = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), refused.addr.port());
            match confirm_closed(dead) {
                Ok(()) => return Ok(DeadAndRefused { dead, refused }),
                Err(error) => rejected.push(error),
            }
        }
        Err(rejected)
    }

    /// The host-side control: a bounded connect to `endpoint` must be refused at once. Anything
    /// else (an accepted connection, a timeout, another error) is reported by name so the endpoint
    /// is never trusted as dead.
    fn confirm_closed(endpoint: SocketAddr) -> Result<(), String> {
        match TcpStream::connect_timeout(&endpoint, std::time::Duration::from_secs(2)) {
            Ok(_) => Err(format!("{endpoint}: something accepted the connection")),
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => Ok(()),
            Err(error) => Err(format!(
                "{endpoint}: {error} ({:?}), not ConnectionRefused",
                error.kind()
            )),
        }
    }

    /// The fall-through exists only across permitted addresses: a permitted address that is dead
    /// moves on to the next answer, and a refused next answer still stops it. `dead` must already
    /// be confirmed closed and `refused` live; both halves run against the same pinned order.
    fn assert_dead_permitted_address_does_not_open_refused(dead: SocketAddr, refused: &Recorder) {
        let port = dead.port();
        assert_eq!(refused.addr.port(), port, "both endpoints share the port");
        refused.assert_live();
        let refused_before = refused.accepted();
        let b = refused.addr.ip();
        let host = "two-answers.test";
        let correlation = RequestId::new("test");

        // Positive control: with every address permitted the dial falls through to the live
        // recorder, so the refusal below is the authority's and not a dead dial path.
        let permissive = AddressPolicy::permit_all();
        let shared = state(permissive.clone());
        let pinned = PinnedDestination::from_ips(port, vec![dead.ip(), b]);
        let upstream = open_upstream(&shared, &connect_to(host, port), &pinned, &correlation)
            .ok()
            .expect("a permissive authority lets the dial fall through to the second answer");
        assert_eq!(upstream.peer_addr().unwrap(), SocketAddr::new(b, port));
        assert_eq!(
            permissive.seen(),
            vec![(dead, true), (SocketAddr::new(b, port), true)]
        );
        assert_eq!(
            refused.await_accepted(refused_before + 1),
            refused_before + 1,
            "the recorder at the second answer is live"
        );
        drop(upstream);

        let policy = AddressPolicy::permitting(dead.ip());
        let shared = state(policy.clone());
        let pinned = PinnedDestination::from_ips(port, vec![dead.ip(), b]);
        assert!(
            matches!(
                open_upstream(&shared, &connect_to(host, port), &pinned, &correlation),
                Err(OpenUpstreamError::Denied(_))
            ),
            "a dead permitted address does not open the refused one"
        );
        assert_eq!(
            policy.seen(),
            vec![(dead, true), (SocketAddr::new(b, port), false)]
        );
        assert_eq!(
            refused.accepted(),
            refused_before + 1,
            "the refused address saw no second connection"
        );
        // The dead endpoint stayed closed across both dials: nothing else bound it meanwhile.
        confirm_closed(dead).expect("required setup held: the dead endpoint is still closed");
    }

    /// Portable form of the no-fallthrough regression: the dead permitted endpoint is `127.0.0.1`
    /// on the port the refused recorder holds at a second loopback address, so it needs no third
    /// loopback address and runs on Linux and macOS alike.
    #[test]
    fn a_dead_permitted_address_does_not_open_a_refused_one() {
        let fixture = dead_and_refused_endpoints().unwrap_or_else(|rejected| {
            panic!(
                "required setup: no port was closed on 127.0.0.1 in {DEAD_ENDPOINT_ATTEMPTS} \
                 attempts: {rejected:?}"
            )
        });
        assert_dead_permitted_address_does_not_open_refused(fixture.dead, &fixture.refused);
    }

    /// Same-family variant kept where the host provides a third loopback address: the dead
    /// endpoint `127.0.0.3` has no socket of this process on any port and the live recorder is
    /// IPv4 as well, so the fall-through is exercised between two IPv4 answers.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_dead_third_loopback_address_does_not_open_a_refused_one() {
        let refused = Recorder::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let dead = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), refused.addr.port());
        confirm_closed(dead).unwrap_or_else(|error| panic!("required setup: {error}"));
        assert_dead_permitted_address_does_not_open_refused(dead, &refused);
    }

    /// Setup-failure control: an endpoint something listens at is rejected by name, so the fixture
    /// cannot hand out a live address as the dead one.
    #[test]
    fn a_live_endpoint_is_not_accepted_as_dead() {
        let live = Recorder::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let error = confirm_closed(live.addr).expect_err("a listening endpoint is not closed");
        assert!(
            error.contains("accepted the connection"),
            "the rejection names the live endpoint: {error}"
        );
        assert_eq!(
            live.await_accepted(1),
            1,
            "the recorder counts the rejected probe"
        );
        live.assert_live();
    }

    /// The fixture's dead endpoint is closed from the host and its recorder is live on the same
    /// port at another loopback address.
    #[test]
    fn the_dead_and_refused_fixture_shares_one_port_across_two_loopback_addresses() {
        let fixture = dead_and_refused_endpoints()
            .unwrap_or_else(|rejected| panic!("required setup: {rejected:?}"));
        assert_eq!(fixture.dead.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(fixture.refused.addr.ip(), fixture.dead.ip());
        assert_eq!(fixture.refused.addr.port(), fixture.dead.port());
        confirm_closed(fixture.dead).unwrap();
        fixture.refused.assert_live();
    }

    use std::io::{BufRead, BufReader};
    use std::time::Duration;

    use super::super::ClientLimits;
    use crate::audit::SharedAuditLog;

    /// The client limits of a test, in milliseconds.
    fn limits(idle_ms: u64, first_head_ms: u64) -> ClientLimits {
        ClientLimits {
            idle: Duration::from_millis(idle_ms),
            first_head: Duration::from_millis(first_head_ms),
        }
    }

    /// A gateway on TCP loopback with one slot, told to stop on drop and never joined, so a slot
    /// that does not free fails a test instead of hanging it.
    struct Gateway {
        addr: SocketAddr,
        _gateway: GatewayThread,
    }

    impl Gateway {
        fn start(policy: Arc<dyn EffectInterceptor>, limits: ClientLimits) -> Self {
            let mut shared = state(policy);
            shared.client_limits = limits;
            Self::serve(shared)
        }

        /// Serve `shared` with one slot.
        fn serve(mut shared: SharedState) -> Self {
            shared.config.max_connections = 1;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let addr = listener.local_addr().unwrap();
            Self {
                addr,
                _gateway: serve_listener(BoundListener::Tcp(listener), shared),
            }
        }

        /// A client whose reads give up after 10 s.
        fn connect(&self) -> TcpStream {
            let client = TcpStream::connect(self.addr).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            client
        }

        /// Whether the one slot is free: another client gets the 400 for a request that names no
        /// destination.
        fn serves_another_client(&self) -> bool {
            let mut probe = self.connect();
            probe.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
            let mut reply = Vec::new();
            probe.read_to_end(&mut reply).is_ok() && reply.starts_with(b"HTTP/1.1 400 ")
        }
    }

    /// Serve `listener` on a gateway runtime. Dropping the returned thread value stops its accept
    /// loop and does not wait for it.
    fn serve_listener(listener: BoundListener, shared: SharedState) -> GatewayThread {
        listener.set_nonblocking().unwrap();
        GatewayThread::start(listener, Arc::new(shared)).unwrap()
    }

    /// A plain-HTTP origin on loopback that reads one request and answers with `reply` of the
    /// length of its body. Its thread returns that length.
    fn plain_origin(
        reply: impl FnOnce(usize) -> Vec<u8> + Send + 'static,
    ) -> (SocketAddr, std::thread::JoinHandle<usize>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            write_reply_paced(reader.get_mut(), &reply(length));
            length
        });
        (addr, thread)
    }

    /// The host that a tunnel test names in its `CONNECT`. The gateway resolves it to loopback.
    const TUNNEL_HOST: &str = "tunnel.test";

    /// A TLS origin for [`TUNNEL_HOST`] on loopback that reads one request head and answers with a
    /// body of `length` bytes. Its thread ends when it has written the reply.
    fn tls_origin(
        config: Arc<rustls::ServerConfig>,
        length: usize,
    ) -> (SocketAddr, std::thread::JoinHandle<()>) {
        tls_origin_after(config, length, Duration::ZERO)
    }

    /// [`tls_origin`], which waits `delay` after the request head before it answers.
    fn tls_origin_after(
        config: Arc<rustls::ServerConfig>,
        length: usize,
        delay: Duration,
    ) -> (SocketAddr, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let connection = rustls::ServerConnection::new(config).unwrap();
            let mut reader = BufReader::new(rustls::StreamOwned::new(connection, stream));
            let mut line = String::new();
            while line != "\r\n" {
                line.clear();
                reader.read_line(&mut line).unwrap();
            }
            std::thread::sleep(delay);
            let stream = reader.get_mut();
            write_reply_paced(stream, &vec![b'y'; length]);
            let _ = stream.flush();
        });
        (addr, thread)
    }

    /// Write a `200` with `body`, in 64 KiB pieces 2 ms apart, until the gateway stops taking them.
    fn write_reply_paced(stream: &mut impl Write, body: &[u8]) {
        // The pieces are paced, because a burst of loopback bytes delays the handshakes that
        // `Recorder` counts in other tests.
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
        if stream.write_all(head.as_bytes()).is_err() {
            return;
        }
        for piece in body.chunks(64 * 1024) {
            if stream.write_all(piece).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Read until the gateway ends the connection, and return what arrived.
    fn read_until_closed(client: &mut impl Read) -> Vec<u8> {
        let mut reply = Vec::new();
        match client.read_to_end(&mut reply) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Err(error) => panic!("the gateway did not end the connection: {error}"),
        }
        reply
    }

    /// A CONNECT head that takes more than 5 s to [`drip`].
    const DRIPPED_HEAD: &[u8] = b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\
        User-Agent: a-client-that-sends-one-byte-each-fifty-ms\r\n\r\n";

    /// Write `bytes` one at a time, 50 ms apart, until the peer stops taking them.
    fn drip(writer: &mut impl Write, bytes: &[u8]) {
        for byte in bytes {
            if writer.write_all(std::slice::from_ref(byte)).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// A reader that gives one byte for each read, and waits before it gives its last byte.
    struct LateLastByte<'a> {
        bytes: &'a [u8],
        wait: Duration,
    }

    impl tokio::io::AsyncRead for LateLastByte<'_> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            out: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            if self.bytes.len() == 1 {
                std::thread::sleep(self.wait);
            }
            if let Some((first, rest)) = self.bytes.split_first() {
                out.put_slice(&[*first]);
                self.bytes = rest;
            }
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Run `future` to its end on a current-thread runtime with timers and I/O.
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    /// **A head whose last byte arrives after its deadline is refused**, also when the read of that
    /// byte started before the deadline.
    #[test]
    fn a_head_that_ends_after_its_deadline_is_refused() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let idle = Duration::from_secs(60);
        let later = Instant::now() + Duration::from_secs(60);
        assert_eq!(
            block_on(read_until_headers_end(&mut &head[..], idle, later))
                .unwrap()
                .as_bytes(),
            head
        );
        let mut late = LateLastByte {
            bytes: head,
            wait: Duration::from_millis(600),
        };
        let deadline = Instant::now() + Duration::from_millis(300);
        let error = block_on(read_until_headers_end(&mut late, idle, deadline)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    /// The head read takes no byte after the head, so a `ClientHello` sent with the `CONNECT` stays
    /// in the socket for the TLS acceptor.
    #[test]
    fn the_connect_head_read_leaves_the_next_bytes_in_the_stream() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (rest, read) = block_on(async {
            let (mut gateway, mut client) = tokio::net::UnixStream::pair().unwrap();
            client.write_all(head).await.unwrap();
            client.write_all(b"\x16\x03\x01hello").await.unwrap();
            drop(client);
            let deadline = Instant::now() + Duration::from_secs(60);
            let read = read_until_headers_end(&mut gateway, Duration::from_secs(60), deadline)
                .await
                .unwrap();
            let mut rest = Vec::new();
            gateway.read_to_end(&mut rest).await.unwrap();
            (rest, read)
        });
        assert_eq!(read.as_bytes(), head);
        assert_eq!(rest, b"\x16\x03\x01hello");
    }

    /// **A client that sends nothing is cut at the idle bound, and its slot frees.**
    #[test]
    fn an_idle_client_is_cut_and_frees_its_slot() {
        let gateway = Gateway::start(AddressPolicy::permit_all(), limits(200, 60_000));
        let mut client = gateway.connect();
        let started = Instant::now();
        assert!(read_until_closed(&mut client).is_empty());
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(150),
            "the idle bound cut the client, not a failure at once: {waited:?}"
        );
        assert!(gateway.serves_another_client(), "the slot is free");
    }

    /// **A client that drips its first head is cut at the head deadline, before any decision**, with
    /// an idle bound that no pause of the drip reaches.
    #[test]
    fn a_client_that_drips_its_head_is_cut_at_the_deadline() {
        let policy = AddressPolicy::permit_all();
        let gateway = Gateway::start(policy.clone(), limits(60_000, 300));
        let mut client = gateway.connect();
        let mut writer = client.try_clone().unwrap();
        let started = Instant::now();
        let dripper = std::thread::spawn(move || drip(&mut writer, DRIPPED_HEAD));
        let reply = read_until_closed(&mut client);
        let waited = started.elapsed();
        dripper.join().unwrap();
        assert!(reply.is_empty(), "{}", String::from_utf8_lossy(&reply));
        assert!(
            waited >= Duration::from_millis(250) && waited < Duration::from_secs(3),
            "the head deadline cut the client before its head ended: {waited:?}"
        );
        assert!(policy.seen().is_empty(), "no decision was asked for");
        assert!(gateway.serves_another_client(), "the slot is free");
    }

    /// **A large plain-HTTP body that keeps moving passes, whatever its total time.** The body takes
    /// longer than the head deadline and the idle bound together, and no pause reaches the idle bound.
    #[test]
    fn a_slow_but_moving_large_plain_body_passes() {
        const BODY: usize = 4 * 1024 * 1024;
        const PIECE: usize = 128 * 1024;
        let (origin, received) = plain_origin(|length| length.to_string().into_bytes());
        let gateway = Gateway::start(AddressPolicy::permit_all(), limits(1_000, 300));
        let mut client = gateway.connect();
        let started = Instant::now();
        write!(
            client,
            "POST http://{origin}/upload HTTP/1.1\r\nHost: {origin}\r\nContent-Length: {BODY}\r\n\r\n"
        )
        .unwrap();
        let piece = vec![b'x'; PIECE];
        for _ in 0..BODY / PIECE {
            client.write_all(&piece).unwrap();
            std::thread::sleep(Duration::from_millis(50));
        }
        let reply = String::from_utf8(read_until_closed(&mut client)).unwrap();
        let took = started.elapsed();
        assert!(
            took > Duration::from_millis(1_300),
            "the body took longer than both bounds together: {took:?}"
        );
        assert_eq!(received.join().unwrap(), BODY, "the origin read each byte");
        assert!(reply.starts_with("HTTP/1.1 200 "), "{reply}");
        assert!(reply.ends_with(&format!("\r\n\r\n{BODY}")), "{reply}");
    }

    /// **A plain-HTTP body that stops is cut at the idle bound with a 400**, before any decision and
    /// before any upstream socket opens.
    #[test]
    fn a_plain_body_that_stops_is_cut_before_any_upstream_socket() {
        let origin = Recorder::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        origin.assert_live();
        let before = origin.accepted();
        let policy = AddressPolicy::permit_all();
        let gateway = Gateway::start(policy.clone(), limits(200, 60_000));
        let mut client = gateway.connect();
        let address = origin.addr;
        write!(
            client,
            "POST http://{address}/upload HTTP/1.1\r\nHost: {address}\r\nContent-Length: 1000\r\n\r\n\
             only-ten-b"
        )
        .unwrap();
        let reply = read_until_closed(&mut client);
        assert!(
            reply.starts_with(b"HTTP/1.1 400 "),
            "{}",
            String::from_utf8_lossy(&reply)
        );
        assert!(policy.seen().is_empty(), "no decision was asked for");
        assert_eq!(origin.accepted(), before, "no upstream socket opened");
        assert!(gateway.serves_another_client(), "the slot is free");
    }

    /// The reply of a never-reads test, larger than the socket buffers at both ends of a tuned host.
    const LARGE_REPLY: usize = 64 * 1024 * 1024;

    /// An authority that permits each attempt, and keeps the outcome of each response release.
    #[derive(Default)]
    struct ReleaseLog {
        outcomes: Arc<Mutex<Vec<EffectOutcome>>>,
    }

    /// A permit that adds its outcome to a log, when it has one.
    struct LoggedPermit(Option<Arc<Mutex<Vec<EffectOutcome>>>>);

    impl EffectPermit for LoggedPermit {
        fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
            if let Some(outcomes) = &self.0 {
                outcomes.lock().unwrap().push(outcome);
            }
            Ok(())
        }
        fn mark_indeterminate(self: Box<Self>) {}
    }

    impl EffectInterceptor for ReleaseLog {
        fn intercept(&self, attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
            let log = matches!(attempt, EffectAttempt::ResponseRelease { .. })
                .then(|| self.outcomes.clone());
            Ok(Box::new(LoggedPermit(log)))
        }
    }

    impl ReleaseLog {
        /// Assert that the one release failed at the client idle bound.
        fn assert_cut_at_the_idle_bound(&self) {
            let outcomes = self.outcomes.lock().unwrap().clone();
            assert!(
                matches!(
                    outcomes[..],
                    [EffectOutcome::Partial {
                        error_kind: io::ErrorKind::TimedOut,
                        ..
                    } | EffectOutcome::Failed {
                        error_kind: io::ErrorKind::TimedOut,
                        ..
                    }]
                ),
                "the release records the idle bound: {outcomes:?}"
            );
        }
    }

    /// Assert that a connection ended at the client idle bound: one audit denial, the handler error
    /// that names the bound, and no `Deny` record.
    fn assert_ended_at_the_idle_bound(emitter: &StubEmitter, audit: &SharedAuditLog, case: &str) {
        let denials: Vec<String> = audit
            .drain()
            .into_iter()
            .filter(|event| event.decision == AuditDecision::Deny)
            .map(|event| event.reason)
            .collect();
        assert!(
            matches!(
                &denials[..],
                [reason] if reason.starts_with("connection handler error: ")
                    && reason.contains("client idle bound passed")
            ),
            "{case}: {denials:?}"
        );
        assert!(
            emitter
                .records()
                .iter()
                .all(|record| record.decision != AuditDecision::Deny),
            "{case}: no Deny record"
        );
    }

    /// **A client that never reads its reply is cut within two idle waits after the reply arrives,
    /// and its slot frees.** One write can copy a part of the reply and then wait the idle bound.
    #[test]
    fn a_client_that_never_reads_its_reply_is_cut_and_frees_its_slot() {
        const IDLE: Duration = Duration::from_secs(1);
        let (origin, replied) = plain_origin(|_| vec![b'y'; LARGE_REPLY]);
        let releases = Arc::new(ReleaseLog::default());
        let emitter = StubEmitter::new();
        let mut shared = state(releases.clone());
        shared.client_limits = ClientLimits {
            idle: IDLE,
            first_head: Duration::from_secs(60),
        };
        shared.config.response_limits.max_body_bytes = 2 * LARGE_REPLY;
        shared.emitter = Box::new(emitter.clone());
        let audit = shared.audit.clone();
        let gateway = Gateway::serve(shared);
        let mut client = gateway.connect();
        write!(
            client,
            "GET http://{origin}/large HTTP/1.1\r\nHost: {origin}\r\n\r\n"
        )
        .unwrap();
        replied.join().unwrap();
        let arrived = Instant::now();
        assert!(
            gateway.serves_another_client(),
            "the slot frees while the client reads nothing"
        );
        let waited = arrived.elapsed();
        assert!(
            waited >= IDLE * 4 / 5 && waited < IDLE * 5 / 2,
            "one or two idle waits: {waited:?}"
        );
        releases.assert_cut_at_the_idle_bound();
        assert_ended_at_the_idle_bound(&emitter, &audit, "plain");
        let reply = read_until_closed(&mut client);
        assert!(reply.starts_with(b"HTTP/1.1 200 "));
        assert!(
            reply.len() < LARGE_REPLY,
            "the gateway ended the reply after {} bytes",
            reply.len()
        );
    }

    /// A gateway on an AF_UNIX socket with one slot, stopped on drop and never joined.
    struct UnixGateway {
        path: std::path::PathBuf,
        _gateway: GatewayThread,
    }

    impl UnixGateway {
        /// Serve `shared` with one slot, on a socket that `name` makes unique.
        fn serve(mut shared: SharedState, name: &str) -> Self {
            shared.config.max_connections = 1;
            let path =
                std::env::temp_dir().join(format!("gwcl-{}-{name}.sock", std::process::id()));
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).unwrap();
            Self {
                _gateway: serve_listener(BoundListener::Unix(listener), shared),
                path,
            }
        }

        /// A client whose reads give up after 10 s.
        fn connect(&self) -> UnixStream {
            let client = UnixStream::connect(&self.path).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            client
        }

        /// Whether the one slot is free: another client gets the 400 for a head that is not a
        /// `CONNECT`.
        fn serves_another_client(&self) -> bool {
            let mut probe = self.connect();
            probe.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
            let mut reply = Vec::new();
            probe.read_to_end(&mut reply).is_ok() && reply.starts_with(b"HTTP/1.1 400 ")
        }
    }

    impl Drop for UnixGateway {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// **An AF_UNIX client has the same bounds.** A client that sends nothing is cut at the idle
    /// bound, and a client that drips its head is cut at the head deadline.
    #[test]
    fn an_af_unix_client_is_cut_at_the_idle_bound_and_at_the_head_deadline() {
        for (name, limits) in [("idle", limits(200, 60_000)), ("drip", limits(60_000, 300))] {
            let policy = AddressPolicy::permit_all();
            let mut shared = state(policy.clone());
            shared.client_limits = limits;
            let gateway = UnixGateway::serve(shared, name);
            let mut client = gateway.connect();
            let mut writer = client.try_clone().unwrap();
            let started = Instant::now();
            let dripper = std::thread::spawn(move || {
                if name == "drip" {
                    drip(&mut writer, DRIPPED_HEAD);
                }
            });
            let reply = read_until_closed(&mut client);
            let waited = started.elapsed();
            dripper.join().unwrap();

            assert!(
                reply.is_empty(),
                "{name}: {}",
                String::from_utf8_lossy(&reply)
            );
            assert!(
                waited >= Duration::from_millis(150) && waited < Duration::from_secs(3),
                "{name}: cut at its bound: {waited:?}"
            );
            assert!(
                policy.seen().is_empty(),
                "{name}: no decision was asked for"
            );
            assert!(gateway.serves_another_client(), "{name}: the slot is free");
        }
    }

    /// A state that terminates TLS for [`TUNNEL_HOST`], with the parts that a tunnel test reads.
    struct Tunnel {
        state: SharedState,
        /// The config of a workload that trusts the gateway's leaf.
        workload: Arc<rustls::ClientConfig>,
        /// The config of an origin for [`TUNNEL_HOST`] that the gateway trusts.
        origin: Arc<rustls::ServerConfig>,
        emitter: StubEmitter,
        audit: SharedAuditLog,
    }

    impl Tunnel {
        fn new(policy: Arc<dyn EffectInterceptor>, idle: Duration) -> Self {
            let ca = super::super::ca::EphemeralCa::generate(None, None).unwrap();
            let trust = Arc::new(
                super::super::tls::upstream_client_config(&[ca.ca_cert_pem().to_string()]).unwrap(),
            );
            let origin =
                Arc::new(super::super::tls::server_config_for_host(&ca, TUNNEL_HOST).unwrap());
            let emitter = StubEmitter::new();
            let mut state = state(policy);
            state.ca = Some(ca);
            state.upstream_config = trust.clone();
            state.config.dns_overrides =
                vec![(TUNNEL_HOST.to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST))];
            state.client_limits = ClientLimits {
                idle,
                first_head: Duration::from_secs(60),
            };
            state.emitter = Box::new(emitter.clone());
            let audit = state.audit.clone();
            Self {
                state,
                workload: trust,
                origin,
                emitter,
                audit,
            }
        }
    }

    /// Send a `CONNECT` for [`TUNNEL_HOST`] on `port`, and read its `200`.
    fn open_tunnel(client: &mut (impl Read + Write), port: u16) {
        write!(
            client,
            "CONNECT {TUNNEL_HOST}:{port} HTTP/1.1\r\nHost: {TUNNEL_HOST}:{port}\r\n\r\n"
        )
        .unwrap();
        // One byte for each read, so the TLS bytes after the ack stay in the socket.
        let mut ack = Vec::new();
        let mut byte = [0u8; 1];
        while !ack.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte).unwrap();
            ack.push(byte[0]);
        }
        let ack = String::from_utf8_lossy(&ack);
        assert!(ack.starts_with("HTTP/1.1 200 "), "{ack}");
    }

    /// A TLS client of the gateway for [`TUNNEL_HOST`].
    fn workload_tls(workload: &Arc<rustls::ClientConfig>) -> rustls::ClientConnection {
        let name = rustls::pki_types::ServerName::try_from(TUNNEL_HOST).unwrap();
        rustls::ClientConnection::new(workload.clone(), name).unwrap()
    }

    /// Where a tunnel client stops sending.
    #[derive(Clone, Copy, Debug)]
    enum Stop {
        /// After the `CONNECT` reply, before the TLS handshake.
        BeforeHandshake,
        /// After the first half of its `ClientHello`.
        InsideHandshake,
        /// After the TLS handshake and a part of its request head.
        InsideRequest,
    }

    /// Open a tunnel on `client`, stop as `stop` says, and return the time from the stop to the end
    /// of the connection.
    fn stop_in_a_tunnel(
        mut client: impl Read + Write,
        port: u16,
        stop: Stop,
        workload: &Arc<rustls::ClientConfig>,
    ) -> Duration {
        open_tunnel(&mut client, port);
        let mut tls = workload_tls(workload);
        match stop {
            Stop::BeforeHandshake => {}
            Stop::InsideHandshake => {
                let mut hello = Vec::new();
                tls.write_tls(&mut hello).unwrap();
                client.write_all(&hello[..hello.len() / 2]).unwrap();
            }
            Stop::InsideRequest => {
                let mut stream = rustls::Stream::new(&mut tls, &mut client);
                write!(stream, "GET / HTTP/1.1\r\nHost: {TUNNEL_HOST}:{port}\r\n").unwrap();
                stream.flush().unwrap();
            }
        }
        let stopped = Instant::now();
        read_until_closed(&mut client);
        stopped.elapsed()
    }

    /// **A tunnel client that stops sending is cut at one idle wait, and its slot frees**, also
    /// when it stops inside a TLS record. It stops before the TLS handshake, inside it, or inside its
    /// request, on TCP, and inside the handshake on AF_UNIX.
    #[test]
    fn a_tunnel_client_that_stops_sending_is_cut_at_one_idle_wait() {
        const IDLE: Duration = Duration::from_secs(1);
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = origin.local_addr().unwrap().port();
        let one_wait = |case: &str, waited: Duration| {
            assert!(
                waited >= IDLE * 4 / 5 && waited < IDLE * 3 / 2,
                "{case}: one idle wait: {waited:?}"
            );
        };

        let tunnel = Tunnel::new(AddressPolicy::permit_all(), IDLE);
        let (workload, emitter, audit) = (tunnel.workload, tunnel.emitter, tunnel.audit);
        let gateway = Gateway::serve(tunnel.state);
        for stop in [
            Stop::BeforeHandshake,
            Stop::InsideHandshake,
            Stop::InsideRequest,
        ] {
            let case = format!("tcp {stop:?}");
            one_wait(
                &case,
                stop_in_a_tunnel(gateway.connect(), port, stop, &workload),
            );
            assert!(gateway.serves_another_client(), "{case}: the slot is free");
            assert_ended_at_the_idle_bound(&emitter, &audit, &case);
        }

        let tunnel = Tunnel::new(AddressPolicy::permit_all(), IDLE);
        let (workload, emitter, audit) = (tunnel.workload, tunnel.emitter, tunnel.audit);
        let gateway = UnixGateway::serve(tunnel.state, "tunnel");
        let waited = stop_in_a_tunnel(gateway.connect(), port, Stop::InsideHandshake, &workload);
        one_wait("unix InsideHandshake", waited);
        assert!(gateway.serves_another_client(), "unix: the slot is free");
        assert_ended_at_the_idle_bound(&emitter, &audit, "unix InsideHandshake");
    }

    /// **A tunnel client that never reads its reply is cut within two idle waits after the reply
    /// arrives, and its slot frees.** The release records the idle bound as its error.
    #[test]
    fn a_tunnel_client_that_never_reads_its_reply_is_cut_and_frees_its_slot() {
        const IDLE: Duration = Duration::from_secs(1);
        let releases = Arc::new(ReleaseLog::default());
        let mut tunnel = Tunnel::new(releases.clone(), IDLE);
        tunnel.state.config.response_limits.max_body_bytes = 2 * LARGE_REPLY;
        let (origin, replied) = tls_origin(tunnel.origin, LARGE_REPLY);
        let gateway = Gateway::serve(tunnel.state);
        let mut client = gateway.connect();
        open_tunnel(&mut client, origin.port());
        let mut tls = workload_tls(&tunnel.workload);
        let mut stream = rustls::Stream::new(&mut tls, &mut client);
        write!(
            stream,
            "GET /large HTTP/1.1\r\nHost: {TUNNEL_HOST}:{}\r\n\r\n",
            origin.port()
        )
        .unwrap();
        stream.flush().unwrap();
        replied.join().unwrap();
        let arrived = Instant::now();
        assert!(
            gateway.serves_another_client(),
            "the slot frees while the client reads nothing"
        );
        let waited = arrived.elapsed();
        assert!(
            waited >= IDLE * 4 / 5 && waited < IDLE * 5 / 2,
            "one or two idle waits: {waited:?}"
        );
        releases.assert_cut_at_the_idle_bound();
        assert_ended_at_the_idle_bound(&tunnel.emitter, &tunnel.audit, "tunnel");
    }

    /// **A slow upstream reply outlasts the client idle bound.** The workload waits in silence for
    /// longer than its idle bound while the upstream prepares its reply, and still gets the reply:
    /// with half-close on, hyper reads no client byte while the exchange waits, so no client read
    /// waits the bound.
    #[test]
    fn a_slow_upstream_reply_outlasts_the_client_idle_bound() {
        const IDLE: Duration = Duration::from_millis(300);
        let tunnel = Tunnel::new(AddressPolicy::permit_all(), IDLE);
        let (origin, replied) = tls_origin_after(tunnel.origin, 2, IDLE * 3);
        let gateway = Gateway::serve(tunnel.state);
        let mut client = gateway.connect();
        open_tunnel(&mut client, origin.port());
        let mut tls = workload_tls(&tunnel.workload);
        let mut stream = rustls::Stream::new(&mut tls, &mut client);
        write!(
            stream,
            "GET /slow HTTP/1.1\r\nHost: {TUNNEL_HOST}:{}\r\n\r\n",
            origin.port()
        )
        .unwrap();
        stream.flush().unwrap();
        let reply = String::from_utf8(read_until_closed(&mut stream)).unwrap();
        replied.join().unwrap();
        assert_eq!(
            reply,
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nyy"
        );
    }

    /// **W8: the inner head has one total bound.** A workload that drips its request head inside
    /// the tunnel, each byte under the idle bound, is cut when the head bound passes, with no reply
    /// and no request decision.
    #[test]
    fn an_inner_head_that_drips_past_its_bound_is_cut() {
        let policy = AddressPolicy::permit_all();
        let mut tunnel = Tunnel::new(policy.clone(), Duration::from_secs(60));
        tunnel.state.client_limits.first_head = Duration::from_millis(500);
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = origin.local_addr().unwrap().port();
        let gateway = Gateway::serve(tunnel.state);
        let mut client = gateway.connect();
        open_tunnel(&mut client, port);
        let mut tls = workload_tls(&tunnel.workload);
        let mut stream = rustls::Stream::new(&mut tls, &mut client);
        let head = format!("GET /drip HTTP/1.1\r\nHost: {TUNNEL_HOST}:{port}\r\n\r\n");
        let started = Instant::now();
        let mut cut = false;
        for byte in head.as_bytes() {
            if stream
                .write_all(std::slice::from_ref(byte))
                .and_then(|()| stream.flush())
                .is_err()
            {
                cut = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // A write after the cut fails; a drip that ended first reads the close.
        let reply = if cut {
            Vec::new()
        } else {
            read_until_closed(&mut stream)
        };
        let waited = started.elapsed();
        assert!(reply.is_empty(), "{}", String::from_utf8_lossy(&reply));
        assert!(
            cut && waited < Duration::from_millis(50) * head.len() as u32,
            "the head bound cut the drip before its end: {waited:?}"
        );
        assert_eq!(
            policy.seen().len(),
            1,
            "only the connection was decided: {:?}",
            policy.seen()
        );
        assert!(gateway.serves_another_client(), "the slot is free");
    }
}
