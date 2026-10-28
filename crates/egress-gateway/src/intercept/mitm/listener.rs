//! The accept loop and per-connection handler.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use crate::audit::RequestId;

use super::SharedState;
use super::connect::{self, ConnectRequest};
use super::exchange::{Subject, Unfinished, emit_decision, record_refusal, record_unfinished};
use super::resolve::PinnedDestination;
use crate::audit::{Decision as AuditDecision, NetworkAuditEvent};
use crate::effect::{ClaimedEffectPermit, EffectAttempt, EffectOutcome};
use crate::error::ProxyError;

/// A counting semaphore bounding the number of in-flight connection threads, with no external
/// dependency. `acquire` blocks the accept loop until a slot frees, so
/// an untrusted workload cannot make the adapter spawn unbounded OS threads (backpressure, not an
/// optimization). Each [`Permit`] releases its slot on drop.
struct ConnectionLimiter {
    available: Mutex<usize>,
    freed: Condvar,
}

impl ConnectionLimiter {
    fn new(max: usize) -> Self {
        Self {
            // A zero cap would deadlock the accept loop; clamp to at least one slot.
            available: Mutex::new(max.max(1)),
            freed: Condvar::new(),
        }
    }

    /// Block until a slot is free, then take it. Returns a [`Permit`] that releases on drop.
    fn acquire(self: &Arc<Self>) -> Permit {
        let mut available = self.available.lock().unwrap_or_else(|e| e.into_inner());
        while *available == 0 {
            available = self
                .freed
                .wait(available)
                .unwrap_or_else(|e| e.into_inner());
        }
        *available -= 1;
        Permit {
            limiter: self.clone(),
        }
    }
}

/// A held connection slot; returns it to the [`ConnectionLimiter`] on drop.
struct Permit {
    limiter: Arc<ConnectionLimiter>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut available = self
            .limiter
            .available
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *available += 1;
        self.limiter.freed.notify_one();
    }
}

/// Run the accept loop until `stop` is set. Each connection is handled on its own thread,
/// **bounded** by `config.max_connections`: the loop blocks on a free slot before accepting more, so
/// an untrusted workload cannot exhaust the host with unbounded threads.
pub(super) fn accept_loop(listener: TcpListener, state: Arc<SharedState>, stop: Arc<AtomicBool>) {
    let limiter = Arc::new(ConnectionLimiter::new(state.config.max_connections));
    for incoming in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let stream = match incoming {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Block here until a connection slot is free (backpressure), then hand the permit to the
        // worker thread so the slot is released when the connection finishes.
        let permit = limiter.acquire();
        let head_deadline = Instant::now() + state.client_limits.first_head;
        let state = state.clone();
        std::thread::spawn(move || {
            // The permit lives for the duration of the connection; dropping it frees the slot.
            let _permit = permit;
            if let Err(err) = dispatch_connection(stream, head_deadline, &state) {
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
        });
    }
}

/// Route one client connection by request shape, after reading its head.
///
/// A CONNECT opens the TLS interception path ([`handle_tls_connect`]); anything else is treated as a
/// plain-HTTP absolute-form request ([`handle_plain_http`]). Setting the client bounds and reading the
/// head are the only work shared before the split, so they live here and each handler owns its
/// transport and L7 path from there.
fn dispatch_connection(
    mut client: TcpStream,
    head_deadline: Instant,
    state: &SharedState,
) -> Result<(), ProxyError> {
    // A socket that takes no bound, or a failed or late read, is a silent drop.
    let idle = Some(state.client_limits.idle);
    if client
        .set_read_timeout(idle)
        .and_then(|()| client.set_write_timeout(idle))
        .is_err()
    {
        return Ok(());
    }
    let head = match read_until_headers_end(&mut client, head_deadline) {
        Ok(head) => head,
        Err(_) => return Ok(()),
    };
    match connect::parse_connect(&head) {
        // HTTPS via CONNECT: terminate TLS and inspect.
        Some(connect) => handle_tls_connect(client, connect, state),
        // Not a CONNECT. Treat it as a plain-HTTP absolute-form request — the same controls apply
        // (net:connect and the L7 legs), over plaintext with no CONNECT ack. The CONNECT-only
        // v1 used to 400 here.
        None => handle_plain_http(client, head, state),
    }
}

/// Handle one CONNECT (HTTPS) connection: run the shared L4 controls, terminate TLS, run the L7 legs.
fn handle_tls_connect(
    mut client: TcpStream,
    connect: ConnectRequest,
    state: &SharedState,
) -> Result<(), ProxyError> {
    let correlation = RequestId::unique();

    // Best-effort token check — never the primary defense.
    if !connect::token_ok(
        state.expected_token.as_deref(),
        connect.proxy_authorization.as_deref(),
    ) {
        refuse_proxy_token(state, &connect, &correlation, &mut client);
        return Ok(());
    }

    // Shared L4: the pre-resolution `net:connect`, resolve-once/pin, and the per-address
    // `net:connect` effect. Claimed and opened BEFORE the CONNECT ack, so a denial returns 403 without
    // creating a socket or exposing a false tunnel.
    let upstream = match open_governed_upstream(state, &connect, &correlation) {
        Ok(upstream) => upstream,
        Err(error) => {
            error.write_response(&mut client, "CONNECT");
            return Ok(());
        }
    };

    // The upstream is open and its outcome was recorded; now let the client proceed.
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
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
    // The gateway would honour a refusal on that leg: `l7::intercept_tls` emits a deny event and
    // withholds the bytes. The shipped interceptor never issues one.
    //
    // A handshake or pin failure hard-fails (drop), never a downgrade; the accept loop
    // audits the error.
    super::l7::intercept_tls(client, upstream, &connect, state, correlation)?;
    Ok(())
}

/// Handle one plain-HTTP (non-CONNECT, absolute-form) client request end-to-end.
///
/// A workload dialing an `http://` URL through the proxy sends an absolute-form request rather than a
/// CONNECT. This runs the identical controls as the CONNECT path — `net:connect`, and
/// then the L7 request/response legs over plaintext (`http:request` + credential injection) — reusing
/// [`open_governed_upstream`] and [`super::l7::forward_plain`]. There is no TLS termination and no
/// CONNECT ack.
fn handle_plain_http(
    client: TcpStream,
    head: String,
    state: &SharedState,
) -> Result<(), ProxyError> {
    // A second handle on the same socket for writing responses; the original is consumed by the reader.
    let mut writer = match client.try_clone() {
        Ok(writer) => writer,
        Err(_) => return Ok(()),
    };
    // Read the proxy token from the RAW head now: `read_request` below strips `Proxy-Authorization`
    // (a hop-by-hop header), so reading it from the parsed request would always see nothing and the
    // token check would silently accept every request.
    let proxy_authorization = connect::proxy_authorization_from_head(&head);
    // Re-feed the already-read head, so the hardened `read_request` parses head+body from one stream
    // rather than a second HTTP parser.
    let reader = std::io::Cursor::new(head.into_bytes()).chain(client);
    let mut client_buf = std::io::BufReader::new(reader);
    let parsed = match super::http1::read_request(
        &mut client_buf,
        state.config.response_limits.max_body_bytes,
    ) {
        Ok(parsed) => parsed,
        Err(_) => {
            let _ = write_status(&mut writer, 400, "bad request");
            return Ok(());
        }
    };
    // Absolute-form only: a plain-HTTP proxy request names the full URL. An origin-form target with no
    // CONNECT has no destination and is refused.
    let Some((host, port, origin_target)) = connect::parse_absolute_target(&parsed.target) else {
        let _ = write_status(&mut writer, 400, "bad request");
        return Ok(());
    };
    // A plain-HTTP proxy request may carry `Proxy-Authorization` too (RFC 7235), so the token check
    // runs on this transport as well — using the value read from the raw head above.
    let connect = ConnectRequest {
        host,
        port,
        proxy_authorization,
    };
    let correlation = RequestId::unique().with_headers(&parsed.headers);
    // Best-effort token check — never the primary defense. Run here so the
    // plain-HTTP path matches `handle_tls_connect` and `handle_connection_unix` rather than skipping
    // the defense-in-depth layer silently.
    if !connect::token_ok(
        state.expected_token.as_deref(),
        connect.proxy_authorization.as_deref(),
    ) {
        refuse_proxy_token(state, &connect, &correlation, &mut writer);
        return Ok(());
    }

    // Shared L4: the pre-resolution `net:connect`, resolve-once/pin, and the per-address
    // `net:connect` effect — identical to the CONNECT path. No CONNECT ack for a plain-HTTP request.
    let upstream = match open_governed_upstream(state, &connect, &correlation) {
        Ok(upstream) => upstream,
        Err(error) => {
            error.write_response(&mut writer, &parsed.method);
            return Ok(());
        }
    };
    // Run the L7 legs over plaintext, reusing request_leg/response_leg/effects.
    super::l7::forward_plain(
        &mut writer,
        upstream,
        &connect,
        parsed,
        origin_target,
        state,
        correlation,
    )
}

/// Run the AF_UNIX accept loop until `stop` is set. A near-duplicate of
/// [`accept_loop`] with `UnixStream` in place of `TcpStream`: same [`ConnectionLimiter`] backpressure,
/// same per-connection thread model, same audit-on-handler-error. It exists because the workload under
/// the AF_UNIX egress pin cannot create an `AF_INET` socket at all — a TCP listener would serve no one —
/// so the proxy binds only the AF_UNIX socket and speaks the identical CONNECT/TLS/L7 protocol over it.
/// It duplicates rather than adds a `TcpStream`/`UnixStream` trait, to keep the change local and
/// the diff small (revisit if a third transport ever appears).
pub(super) fn accept_loop_unix(
    listener: UnixListener,
    state: Arc<SharedState>,
    stop: Arc<AtomicBool>,
) {
    let limiter = Arc::new(ConnectionLimiter::new(state.config.max_connections));
    for incoming in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let stream = match incoming {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Same backpressure as the TCP loop: block on a free slot before accepting more.
        let permit = limiter.acquire();
        let head_deadline = Instant::now() + state.client_limits.first_head;
        let state = state.clone();
        std::thread::spawn(move || {
            let _permit = permit;
            if let Err(err) = handle_connection_unix(stream, head_deadline, &state) {
                state.audit.push(NetworkAuditEvent::deny(
                    "-",
                    0,
                    format!("connection handler error: {err}"),
                    RequestId::new("egress-connection-error"),
                ));
            }
        });
    }
}

/// Handle one AF_UNIX client connection end-to-end. Mirrors [`handle_tls_connect`]
/// step for step — read CONNECT head, best-effort token check, the shared L4 controls, then the L7
/// legs — differing only in the client leg's type (`UnixStream`). It stays CONNECT-only: a non-CONNECT
/// head is a 400, because the AF_UNIX pin has no plain-HTTP client. The shared L4 controls
/// ([`open_governed_upstream`]) and the L7 path ([`super::l7::intercept_tls`]) are reused unchanged.
fn handle_connection_unix(
    mut client: UnixStream,
    head_deadline: Instant,
    state: &SharedState,
) -> Result<(), ProxyError> {
    // 1. Read the CONNECT head. Same byte-exact protocol and bounds as the TCP path.
    let idle = Some(state.client_limits.idle);
    if client
        .set_read_timeout(idle)
        .and_then(|()| client.set_write_timeout(idle))
        .is_err()
    {
        return Ok(());
    }
    let head = match read_until_headers_end(&mut client, head_deadline) {
        Ok(head) => head,
        Err(_) => return Ok(()),
    };
    let connect = match connect::parse_connect(&head) {
        Some(c) => c,
        None => {
            let _ = write_status(&mut client, 400, "bad request");
            return Ok(());
        }
    };

    let correlation = RequestId::unique();

    // 2. Best-effort token check — never the primary defense.
    if !connect::token_ok(
        state.expected_token.as_deref(),
        connect.proxy_authorization.as_deref(),
    ) {
        refuse_proxy_token(state, &connect, &correlation, &mut client);
        return Ok(());
    }

    // Shared L4: the pre-resolution `net:connect`, resolve-once/pin, and the per-address
    // `net:connect` effect — transport-agnostic, so the AF_UNIX path reuses it unchanged. Opened
    // before the CONNECT ack, exactly as on the TCP client path.
    let upstream = match open_governed_upstream(state, &connect, &correlation) {
        Ok(upstream) => upstream,
        Err(error) => {
            error.write_response(&mut client, "CONNECT");
            return Ok(());
        }
    };

    // The upstream is open and its outcome was recorded; now let the client proceed.
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|e| ProxyError::Io(format!("writing CONNECT ack: {e}")))?;

    // Same generic L7 interception as the TCP path — `intercept_tls` is generic over the client
    // stream, so the `UnixStream` client flows through unchanged. Termination is
    // unconditional here for the same reason as the TCP path.
    super::l7::intercept_tls(client, upstream, &connect, state, correlation)?;
    Ok(())
}

/// A failure before CONNECT can be acknowledged.
enum OpenUpstreamError {
    /// The effect interceptor explicitly denied the socket open.
    Denied(io::Error),
    /// The interceptor, socket open, peer lookup, or outcome sink failed.
    Failed,
}

impl OpenUpstreamError {
    fn write_response(&self, stream: &mut impl Write, method: &str) {
        match self {
            Self::Denied(error) => super::l7::write_interceptor_error(stream, method, error, None),
            Self::Failed => {
                let _ = write_status(stream, 502, "bad gateway");
            }
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
fn open_governed_upstream(
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
        upstream
            .set_read_timeout(Some(state.config.upstream_read_deadline))
            .and_then(|()| upstream.set_write_timeout(Some(state.config.upstream_read_deadline)))
            .map_err(|_| unfinished(Unfinished::SocketUnprepared))?;
        return Ok(upstream);
    }

    Err(unfinished(Unfinished::NoAddressConnected))
}

/// Record a refused proxy token, then answer `407`.
fn refuse_proxy_token(
    state: &SharedState,
    connect: &ConnectRequest,
    correlation: &RequestId,
    client: &mut impl Write,
) {
    record_refusal(
        state,
        &Subject::connection(connect, correlation),
        "proxy authentication required",
    );
    let _ = write_status(client, 407, "proxy authentication required");
}

/// Read the first head from `stream` up to the `\r\n\r\n` terminator (bounded), as a string, and
/// fail when a read ends at or after `deadline`.
fn read_until_headers_end<S: Read>(stream: &mut S, deadline: Instant) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
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

/// Write a minimal status line + empty body to the client (for a proxy-level refusal). Generic over
/// any [`Write`] for the same reason as [`read_until_headers_end`].
fn write_status<S: Write>(stream: &mut S, status: u16, msg: &str) -> std::io::Result<()> {
    let body = format!("HTTP/1.1 {status} {msg}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(body.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The limiter caps concurrent permits and blocks a further acquire until one is released.
    #[test]
    fn limiter_caps_and_releases() {
        let limiter = Arc::new(ConnectionLimiter::new(2));
        let a = limiter.acquire();
        let b = limiter.acquire();
        assert_eq!(*limiter.available.lock().unwrap(), 0, "both slots taken");

        // A third acquire on another thread must block until a slot frees.
        let limiter2 = limiter.clone();
        let handle = std::thread::spawn(move || {
            let _c = limiter2.acquire(); // blocks until `a` (or `b`) drops
        });
        // Give the spawned thread a moment to reach the blocked wait.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!handle.is_finished(), "third acquire must block while full");

        drop(a); // free one slot → the blocked acquire proceeds
        handle.join().unwrap();
        drop(b);
        assert_eq!(*limiter.available.lock().unwrap(), 2, "all slots returned");
    }

    /// A zero cap is clamped to one slot so the accept loop can never deadlock on a misconfig.
    #[test]
    fn zero_cap_is_clamped_to_one() {
        let limiter = Arc::new(ConnectionLimiter::new(0));
        assert_eq!(*limiter.available.lock().unwrap(), 1);
        let _permit = limiter.acquire(); // does not deadlock
    }

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

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
        stop: Arc<AtomicBool>,
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
            let stop = Arc::new(AtomicBool::new(false));
            let stopping = stop.clone();
            std::thread::spawn(move || accept_loop(listener, Arc::new(shared), stopping));
            Self { addr, stop }
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

    impl Drop for Gateway {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(self.addr);
        }
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

    impl Read for LateLastByte<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.bytes.len() == 1 {
                std::thread::sleep(self.wait);
            }
            let Some((first, rest)) = self.bytes.split_first() else {
                return Ok(0);
            };
            out[0] = *first;
            self.bytes = rest;
            Ok(1)
        }
    }

    /// **A head whose last byte arrives after its deadline is refused**, also when the read of that
    /// byte started before the deadline.
    #[test]
    fn a_head_that_ends_after_its_deadline_is_refused() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let later = Instant::now() + Duration::from_secs(60);
        assert_eq!(
            read_until_headers_end(&mut &head[..], later)
                .unwrap()
                .as_bytes(),
            head
        );
        let mut late = LateLastByte {
            bytes: head,
            wait: Duration::from_millis(600),
        };
        let deadline = Instant::now() + Duration::from_millis(300);
        let error = read_until_headers_end(&mut late, deadline).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
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
        stop: Arc<AtomicBool>,
    }

    impl UnixGateway {
        /// Serve `shared` with one slot, on a socket that `name` makes unique.
        fn serve(mut shared: SharedState, name: &str) -> Self {
            shared.config.max_connections = 1;
            let path =
                std::env::temp_dir().join(format!("gwcl-{}-{name}.sock", std::process::id()));
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let stopping = stop.clone();
            std::thread::spawn(move || accept_loop_unix(listener, Arc::new(shared), stopping));
            Self { path, stop }
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
            self.stop.store(true, Ordering::SeqCst);
            let _ = UnixStream::connect(&self.path);
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
        let ack = read_until_headers_end(client, Instant::now() + Duration::from_secs(10)).unwrap();
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
}
