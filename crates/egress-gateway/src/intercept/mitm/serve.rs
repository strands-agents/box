//! The hyper drivers of one connection: the server toward the workload, and the client toward the
//! upstream.
//!
//! | Part | Does |
//! |---|---|
//! | [`serve_tls`] | Accept the workload's TLS with the minted leaf, then serve its requests on hyper |
//! | [`serve_plain`] | Serve plain-HTTP requests on hyper, after the first head that the front read |
//! | `Session` | Run one request: intake, the request phases and the decision, the round trip, the release |
//! | `after_reply` | The close rule: whether the connection carries another request after a reply |
//! | `round_trip` | Send the decided request over the pinned socket, and read the whole reply or take the upgrade |
//! | `Session::switch` | Release the `101` of a WebSocket handshake; the connection task then runs the relay |
//! | [`WriteCount`], `Counted` | Count the bytes that a stream accepted, for the outcome of each permit |
//! | `Watched` | Tell the session when a kept-alive connection starts and ends its wait between requests |
//!
//! One client connection carries its requests one at a time. Each request opens its own governed
//! upstream socket, with its own `Resolve` and `Connect` decisions, so a request on a kept-alive
//! connection records the same attempts as the same request on a connection of its own.
//!
//! Each block of synchronous phases runs in one [`off_worker`] call with no `.await` inside it, so
//! a slow decision, credential fetch, or record stalls only its own exchange, and a decision and the
//! record that reports it share one thread.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use http::header::{CONNECTION, PROXY_AUTHORIZATION, UPGRADE};
use http::{Request, Response, StatusCode, Version};
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::connect::{self, ConnectRequest};
use super::convert::{self, UpstreamRequest, Whole, error_text};
use super::deadline::{CLIENT_IDLE_PASSED, Disarm, Idle, UPSTREAM_IDLE_PASSED};
use super::exchange::{
    Binding, Exchange, REQUEST_PHASES, RESPONSE_PHASES, Refusal, Reply, Subject, Unfinished,
    audit_release, claim_release, decide_request, prepare_request, prepare_response,
    record_refusal, record_request_failure, record_unfinished, screen_websocket,
};
use super::l7::{split_target, validate_request_binding};
use super::listener::{PROXY_AUTHENTICATION_REQUIRED, open_governed_upstream};
use super::slots::Slot;
use super::websocket::{self, Expected};
use super::{SharedState, http1, tls};
use crate::audit::RequestId;
use crate::boundary::{BodyRef, InterceptedRequest, InterceptedResponse, Target};
use crate::effect::{ClaimedEffectPermit, EffectOutcome, off_worker};
use crate::error::{ProxyError, Result};

/// The largest read buffer of one hyper connection, which bounds one head to 64 KiB as the old
/// reader did.
const MAX_BUF_BYTES: usize = 64 * 1024;

/// The most header lines in one head, as the old reader allowed.
const MAX_HEADERS: usize = 64;

/// One CONNECT tunnel, after its upstream is open and its `200` is written.
pub(super) struct TlsSession<C> {
    /// The raw client stream, before the TLS handshake.
    pub(super) client: C,
    /// The pinned upstream socket, connected, with its `Connect` outcome recorded.
    pub(super) upstream: std::net::TcpStream,
    pub(super) connect: ConnectRequest,
    pub(super) correlation: RequestId,
    /// The slot of the connection, which the session holds to its end.
    pub(super) slot: Slot,
}

/// Terminate the workload's TLS with the leaf minted for the CONNECT host, and serve its requests.
///
/// The client idle bound wraps the raw stream under TLS, so it bounds the handshake too.
pub(super) async fn serve_tls<C>(state: Arc<SharedState>, session: TlsSession<C>) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ca = state
        .ca
        .as_ref()
        .ok_or_else(|| ProxyError::Intercept("no ephemeral CA (tls-intercept off)".to_string()))?;
    let server_config = tls::server_config_for_host(ca, &session.connect.host)?;
    let client = Idle::new(session.client, state.client_limits.idle, CLIENT_IDLE_PASSED);
    let client = TlsAcceptor::from(Arc::new(server_config))
        .accept(client)
        .await
        .map_err(|e| ProxyError::Io(format!("client TLS handshake: {}", error_text(&e))))?;
    let upstream = TcpStream::from_std(session.upstream)
        .map_err(|e| ProxyError::Io(format!("registering the upstream socket: {e}")))?;
    let session = Session::new(
        state,
        Route::Tunnel {
            connect: session.connect,
            correlation: session.correlation,
            upstream: Mutex::new(Some(upstream)),
        },
        session.slot,
    );
    session.serve(client).await
}

/// One plain-HTTP connection, after the front read its first head.
pub(super) struct PlainSession<C> {
    /// The raw client stream, after the first head.
    pub(super) client: C,
    /// The first head, as the front read it, which hyper reads again before the next bytes.
    pub(super) head: Vec<u8>,
    /// The slot of the connection, which the session holds to its end.
    pub(super) slot: Slot,
}

/// Serve plain-HTTP (absolute-form) requests: the same controls as the CONNECT path —
/// `net:connect`, then the request and response phases — over plaintext, with no CONNECT ack.
///
/// Each request is read whole before any decision, so a refused or broken request opens no
/// upstream socket. One connection can carry requests to different hosts, and each one is
/// resolved, pinned, and decided for its own host.
pub(super) async fn serve_plain<C>(state: Arc<SharedState>, session: PlainSession<C>) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let client = Idle::new(session.client, state.client_limits.idle, CLIENT_IDLE_PASSED);
    let client = Replay::new(session.head, client);
    let session = Session::new(state, Route::Plain, session.slot);
    session.serve(client).await
}

/// What a connection carries.
enum Route {
    /// A CONNECT tunnel: its admitted authority, the correlation of its connect decisions, and the
    /// upstream socket that the gateway opened before the `200`, which the first request uses.
    Tunnel {
        connect: ConnectRequest,
        correlation: RequestId,
        upstream: Mutex<Option<TcpStream>>,
    },
    /// Plain-HTTP requests, whose absolute targets name their destinations.
    Plain,
}

/// Where a client connection stands between its requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// A request is in progress, from the first byte of its head to the end of its reply.
    Exchange,
    /// The reply keeps the connection open, and it has not left whole yet.
    Replying,
    /// The last reply left, and no byte of the next head has arrived. The slot is in the idle
    /// queue.
    Waiting,
}

/// One served connection, and the state that its service shares with its end.
struct Session {
    state: Arc<SharedState>,
    route: Route,
    /// The slot of the connection, and its place in the idle queue.
    slot: Slot,
    /// What the client stream accepted.
    client_writes: Arc<WriteCount>,
    /// Where the connection stands between its requests.
    phase: Mutex<Phase>,
    /// The release that waits until hyper has written the governed response whole: until the
    /// connection waits for its next request, the next request starts, or the connection ends.
    pending: Mutex<Option<PendingRelease>>,
    /// The WebSocket that waits until hyper has written its `101`.
    relay: Mutex<Option<websocket::Pending>>,
    /// Why the service ended the exchange, for the audit line.
    failure: Mutex<Option<ProxyError>>,
    /// Whether a request head arrived.
    requested: AtomicBool,
    /// Whether the request in progress was decided and sent toward the upstream.
    forwarded: AtomicBool,
}

/// A claimed release, and the client write count when it was claimed.
struct PendingRelease {
    permit: ClaimedEffectPermit,
    start: usize,
}

/// The error that the service gives hyper. The real error waits in [`Session::failure`].
#[derive(Debug)]
struct Ended;

impl std::fmt::Display for Ended {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the exchange ended")
    }
}

impl std::error::Error for Ended {}

/// The future of one call of the service.
type Answer = Pin<Box<dyn Future<Output = std::result::Result<Response<Whole>, Ended>> + Send>>;

impl Session {
    fn new(state: Arc<SharedState>, route: Route, slot: Slot) -> Arc<Self> {
        Arc::new(Self {
            state,
            route,
            slot,
            client_writes: WriteCount::new(),
            phase: Mutex::new(Phase::Exchange),
            pending: Mutex::new(None),
            relay: Mutex::new(None),
            failure: Mutex::new(None),
            requested: AtomicBool::new(false),
            forwarded: AtomicBool::new(false),
        })
    }

    /// Serve the connection's requests on hyper, then record the outcome of the last release, and
    /// relay a WebSocket whose `101` hyper wrote.
    ///
    /// The gateway stop, or a new connection that needs the slot while this one waits between
    /// requests, asks hyper to close: at once when no request is in progress, else after its reply.
    /// When a reply has left whole and the connection waits, its release is recorded then, not at
    /// the end of the wait.
    async fn serve<C>(self: Arc<Self>, client: C) -> Result<()>
    where
        C: AsyncRead + AsyncWrite + Disarm + Unpin + Send + 'static,
    {
        let client = Counted::new(client, Arc::clone(&self.client_writes));
        let client = Watched {
            inner: client,
            session: Arc::clone(&self),
        };
        let session = Arc::clone(&self);
        let service = hyper::service::service_fn(move |request| -> Answer {
            let session = Arc::clone(&session);
            Box::pin(async move { session.answer(request).await })
        });
        let mut connection =
            server_builder(&self.state).serve_connection(TokioIo::new(client), service);
        let mut released = std::pin::pin!(self.slot.released());
        let mut closing = false;
        let served = std::future::poll_fn(|cx| {
            if !closing && released.as_mut().poll(cx).is_ready() {
                closing = true;
                Pin::new(&mut connection).graceful_shutdown();
            }
            let served = connection.poll_without_shutdown(cx);
            if served.is_pending()
                && *self.phase() == Phase::Waiting
                && let Err(error) = self.record_release(true)
            {
                *self.failure.lock().unwrap_or_else(|e| e.into_inner()) = Some(error);
                closing = true;
                Pin::new(&mut connection).graceful_shutdown();
                cx.waker().wake_by_ref();
            }
            served
        })
        .await;
        self.finish(served, connection.into_parts()).await
    }

    /// Answer one request, and keep the reason when the exchange ends without a reply.
    async fn answer(
        &self,
        request: Request<Incoming>,
    ) -> std::result::Result<Response<Whole>, Ended> {
        self.request_entered();
        let reusable = reusable(&request);
        let result = async {
            self.settle_release().await?;
            self.requested.store(true, Ordering::Relaxed);
            match &self.route {
                Route::Tunnel {
                    connect,
                    correlation,
                    upstream,
                } => self.tunnel(request, connect, correlation, upstream).await,
                Route::Plain => self.plain(request).await,
            }
        }
        .await;
        let mut response = result.map_err(|error| {
            *self.failure.lock().unwrap_or_else(|e| e.into_inner()) = Some(error);
            Ended
        })?;
        let answered = if self.pending().is_some() {
            ReplyKind::Released
        } else {
            ReplyKind::ByGateway
        };
        // Every reply carries `Connection: close` until the close rule keeps the connection open.
        if after_reply(answered, reusable) == AfterReply::KeepOpen {
            response.headers_mut().remove(CONNECTION);
            *self.phase() = Phase::Replying;
        }
        Ok(response)
    }

    fn phase(&self) -> std::sync::MutexGuard<'_, Phase> {
        self.phase.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, Option<PendingRelease>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A byte of the next head arrived: a connection that waited leaves the idle queue.
    fn byte_arrived(&self) {
        let mut phase = self.phase();
        if *phase == Phase::Waiting {
            self.slot.busy();
            *phase = Phase::Exchange;
        }
    }

    /// hyper handed a request to the service, also from bytes that it read before the wait.
    fn request_entered(&self) {
        let mut phase = self.phase();
        if *phase == Phase::Waiting {
            self.slot.busy();
        }
        *phase = Phase::Exchange;
    }

    /// A flush of the client stream succeeded. When it ends a reply that keeps the connection
    /// open, the connection waits for its next request, and its slot joins the idle queue.
    fn flushed(&self) {
        let mut phase = self.phase();
        if *phase == Phase::Replying && self.client_writes.snapshot().flushed {
            *phase = Phase::Waiting;
            self.forwarded.store(false, Ordering::Relaxed);
            self.slot.idle();
        }
    }

    /// Record the outcome of the release of the reply before this request, once that reply has
    /// left. hyper reads the next head only after the reply before it has left, so the wait ends at
    /// once; it keeps the record right if that order changes.
    async fn settle_release(&self) -> Result<()> {
        if self.pending().is_none() {
            return Ok(());
        }
        self.client_writes.settled().await;
        let written = self.client_writes.snapshot();
        self.record_release(written.flushed)
    }

    /// Record the outcome of the claimed release, if one waits: `delivered` says that the reply
    /// left whole.
    fn record_release(&self, delivered: bool) -> Result<()> {
        let Some(release) = self.pending().take() else {
            return Ok(());
        };
        let outcome = release_outcome(self.client_writes.snapshot(), release.start, delivered);
        off_worker(|| release.permit.record_outcome(outcome)).map_err(|error| {
            ProxyError::Io(format!(
                "recording governed response outcome after I/O: {error}"
            ))
        })
    }

    /// Record the outcome of the last release once hyper has written the response, then close, or
    /// run the relay after a `101`.
    async fn finish<C, S>(
        &self,
        served: hyper::Result<()>,
        parts: hyper::server::conn::http1::Parts<TokioIo<Watched<Counted<C>>>, S>,
    ) -> Result<()>
    where
        C: AsyncRead + AsyncWrite + Disarm + Unpin + Send,
    {
        let delivered = served.is_ok() || self.client_writes.snapshot().flushed;
        self.record_release(delivered)?;
        let failure = self
            .failure
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(failure) = failure {
            return Err(failure);
        }
        // A connection that waited for its next request ends there: the client closed it, it
        // waited past the idle bound, or the stop or a new connection asked for its slot. No
        // request was in progress, so the end leaves no audit line.
        if *self.phase() == Phase::Waiting {
            // `close_notify`, then the end of the write side.
            let _ = parts.io.into_inner().shutdown().await;
            return Ok(());
        }
        // A plain-HTTP request that never reached the upstream was answered, by hyper or with the
        // gateway's static reply, and an end there leaves no audit line.
        if served.is_err()
            && matches!(self.route, Route::Plain)
            && !self.forwarded.load(Ordering::Relaxed)
        {
            return Ok(());
        }
        let requested = self.requested.load(Ordering::Relaxed);
        match served {
            Ok(()) => {
                let relay = self.relay.lock().unwrap_or_else(|e| e.into_inner()).take();
                if let Some(relay) = relay {
                    // hyper wrote the `101` and handed the stream back with the bytes that it read
                    // past the head. The relay's idle limit replaces the client idle bound, and the
                    // connection is never used for HTTP again.
                    let mut client = parts.io.into_inner().inner.inner;
                    client.disarm();
                    let client = Replay::new(parts.read_buf.to_vec(), client);
                    return websocket::run(relay, client, &self.state, self.slot.stopping()).await;
                }
                // `close_notify`, then the end of the write side.
                let _ = parts.io.into_inner().shutdown().await;
                if requested {
                    Ok(())
                } else {
                    Err(ProxyError::Intercept(format!(
                        "{} before HTTP head",
                        http1::CLOSED_EARLY
                    )))
                }
            }
            Err(error) if error.is_parse() => {
                // hyper answered the head itself. The request never reached a decision. On a
                // tunnel that served no request, the record names the connection that the gateway
                // decided and opened; a later head opened no upstream socket, so it records nothing.
                let error =
                    ProxyError::Intercept(format!("parsing request: {}", error_text(&error)));
                match &self.route {
                    Route::Tunnel {
                        connect,
                        correlation,
                        ..
                    } if !requested => off_worker(|| {
                        record_request_failure(
                            &self.state,
                            &Subject::connection(connect, correlation),
                            &error,
                        );
                    }),
                    Route::Tunnel { .. } | Route::Plain => {}
                }
                Err(error)
            }
            Err(error) => Err(ProxyError::Io(format!(
                "serving the client: {}",
                error_text(&error)
            ))),
        }
    }

    /// Run one request of a CONNECT tunnel.
    ///
    /// The first request uses the socket that the gateway opened before the `200`. Each later
    /// request opens its own governed socket before its body is read, with a new correlation, as a
    /// new tunnel opens one at its `CONNECT`: so the request records the same attempts, and a
    /// connect rule that refuses now refuses it on an open tunnel too.
    async fn tunnel(
        &self,
        request: Request<Incoming>,
        connect: &ConnectRequest,
        correlation: &RequestId,
        upstream: &Mutex<Option<TcpStream>>,
    ) -> Result<Response<Whole>> {
        let state = &*self.state;
        let first = upstream.lock().unwrap_or_else(|e| e.into_inner()).take();
        let (upstream, correlation) = match first {
            Some(upstream) => (upstream, correlation.clone()),
            None => {
                let correlation = RequestId::unique();
                let opened = off_worker(|| open_governed_upstream(state, connect, &correlation));
                let upstream = match opened {
                    Ok(upstream) => upstream,
                    Err(error) => {
                        return Ok(error.response(request.method().as_str(), request.version()));
                    }
                };
                let upstream = TcpStream::from_std(upstream)
                    .map_err(|e| ProxyError::Io(format!("registering the upstream socket: {e}")))?;
                (upstream, correlation)
            }
        };
        let inbound = convert::request_in(request, state.config.response_limits.max_body_bytes)
            .await
            .inspect_err(|error| {
                off_worker(|| {
                    record_request_failure(
                        state,
                        &Subject::connection(connect, &correlation),
                        error,
                    );
                });
            })?;
        let version = inbound.version;
        // The name is converted before any decision, so a host that cannot be one fails first.
        let name = ServerName::try_from(connect.host.clone()).map_err(|_| {
            ProxyError::UpstreamConnect(format!("invalid upstream host {}", connect.host))
        })?;
        let correlation = correlation.with_headers(&inbound.headers);
        // Pre-leg binding: the inner request must name the CONNECT authority, before any mutation.
        if let Err(error) =
            validate_request_binding(connect, &inbound.method, &inbound.target, &inbound.headers)
        {
            let subject = Subject {
                host: &connect.host,
                port: connect.port,
                method: &inbound.method,
                path: &inbound.target,
                correlation: &correlation,
            };
            off_worker(|| record_refusal(state, &subject, &error.to_string()));
            return Ok(convert::diagnostic_response(
                &inbound.method,
                version,
                error.http_status(),
                Bytes::from_static(b"request authority rejected"),
            ));
        }
        let mut target = Target::new(connect.host.clone(), connect.port);
        (target.path, target.query) = split_target(&inbound.target);
        let request = InterceptedRequest {
            target,
            method: Some(inbound.method),
            headers: inbound.headers,
            body: BodyRef::Bytes(inbound.body),
            advisory_note: None,
        };
        // TLS was terminated to see this request, so it stays bound to the CONNECT authority.
        let exchange = Exchange::new(
            connect,
            Binding::ConnectAuthority,
            true,
            correlation,
            request,
            inbound.handshake,
            state,
        );
        self.forward(exchange, version, upstream, Hop::Tls(name))
            .await
    }

    /// Run one request of a plain-HTTP connection.
    async fn plain(&self, request: Request<Incoming>) -> Result<Response<Whole>> {
        let state = &*self.state;
        let version = request.version();
        // The hop-by-hop strip removes `Proxy-Authorization` from the request, so the token check
        // reads this request's own value before the intake.
        let proxy_authorization = request
            .headers()
            .get(PROXY_AUTHORIZATION)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).trim().to_string());
        let bad_request = || convert::status_response(version, 400, "bad request");
        let Ok(inbound) =
            convert::request_in(request, state.config.response_limits.max_body_bytes).await
        else {
            return Ok(bad_request());
        };
        // Absolute-form only: a plain-HTTP proxy request names the full URL. An origin-form target
        // with no CONNECT has no destination and is refused.
        let Some((host, port, origin_target)) = connect::parse_absolute_target(&inbound.target)
        else {
            return Ok(bad_request());
        };
        // A plain-HTTP proxy request may carry `Proxy-Authorization` too (RFC 7235), so the token
        // check runs on this transport as well, with the value from the raw head.
        let connect = ConnectRequest {
            host,
            port,
            proxy_authorization,
        };
        let correlation = RequestId::unique().with_headers(&inbound.headers);
        // Best-effort token check — never the primary defense.
        if !connect::token_ok(
            state.expected_token.as_deref(),
            connect.proxy_authorization.as_deref(),
        ) {
            off_worker(|| {
                record_refusal(
                    state,
                    &Subject::connection(&connect, &correlation),
                    PROXY_AUTHENTICATION_REQUIRED,
                );
            });
            return Ok(convert::status_response(
                version,
                407,
                PROXY_AUTHENTICATION_REQUIRED,
            ));
        }
        let mut target = Target::new(connect.host.clone(), connect.port);
        (target.path, target.query) = split_target(&origin_target);
        let mut request = InterceptedRequest {
            target,
            method: Some(inbound.method),
            headers: inbound.headers,
            body: BodyRef::Bytes(inbound.body),
            advisory_note: None,
        };
        // Bind the `Host` header to the URL authority the gateway judged. A plain-HTTP request
        // carries its destination twice — in the absolute-form request line and in `Host` — and the
        // workload controls both. The TLS path re-checks that they agree
        // (`validate_request_binding`); the plain path has no CONNECT authority to bind against, so
        // it normalizes instead: rewrite `Host` to the URL host, so the destination the box
        // authorized is the one the upstream routes on (no vhost smuggling).
        //
        // The port is omitted only for 80 — plain HTTP's sole default. `http://host:443/` keeps
        // `:443`, because 443 is not the default under the `http` scheme, and a dropped port would
        // make `Host` name a different authority than the one authorized.
        let host_value = if connect.port == 80 {
            connect.host.clone()
        } else {
            format!("{}:{}", connect.host, connect.port)
        };
        request.headers.set("Host", host_value);
        // Plain HTTP was never encrypted, so it is not TLS-intercepted and has no authority to bind.
        let mut exchange = Exchange::new(
            &connect,
            Binding::None,
            false,
            correlation.clone(),
            request,
            inbound.handshake,
            state,
        );
        // The gateway relays no WebSocket on plain HTTP, so it refuses a request that names
        // `websocket` before the policy decides the connection, and dials no upstream for it.
        if let Err(refusal) = screen_websocket(&mut exchange, state) {
            return Ok(off_worker(|| refuse(&exchange, refusal, state, version)));
        }
        // Shared L4: the pre-resolution `net:connect`, resolve-once/pin, and the per-address
        // `net:connect` effect — identical to the CONNECT path, in one `off_worker` call.
        let upstream = match off_worker(|| open_governed_upstream(state, &connect, &correlation)) {
            Ok(upstream) => upstream,
            Err(error) => return Ok(error.response(&exchange.method, version)),
        };
        let upstream = TcpStream::from_std(upstream)
            .map_err(|e| ProxyError::Io(format!("registering the upstream socket: {e}")))?;
        self.forward(exchange, version, upstream, Hop::Plain).await
    }

    /// Decide the request, send it, record its outcome, and release the governed response.
    async fn forward(
        &self,
        mut exchange: Exchange<'_>,
        version: Version,
        upstream: TcpStream,
        hop: Hop,
    ) -> Result<Response<Whole>> {
        let state = &*self.state;
        let writes = WriteCount::new();
        let (permit, request, expected) =
            match off_worker(|| decide(&mut exchange, state, version, Arc::clone(&writes)))? {
                Decided::Forward(permit, request, expected) => (permit, request, expected),
                Decided::Answer(response) => return Ok(response),
            };
        self.forwarded.store(true, Ordering::Relaxed);
        let trip = round_trip(
            state,
            upstream,
            hop,
            request,
            &exchange.method,
            Arc::clone(&writes),
            expected,
        )
        .await;
        let sent = writes.snapshot();
        let outcome = request_outcome(sent, trip.status);
        off_worker(|| {
            permit.record_outcome(outcome).map_err(|error| {
                record_unfinished(state, &exchange.subject(), Unfinished::OutcomeUnrecorded);
                let after = if trip.reply.is_ok() {
                    "the reply"
                } else {
                    "a failed reply"
                };
                ProxyError::Io(format!(
                    "recording upstream request outcome after {after}: {error}"
                ))
            })
        })?;
        // A reply to a request that did not leave whole is never released.
        let reply = match (sent.flushed, trip.reply) {
            (true, reply) => reply,
            (false, Err(error)) => Err(error),
            (false, Ok(_)) => Err(ProxyError::Io(format!(
                "delivering upstream request: {}",
                io::Error::from(sent.error.unwrap_or(io::ErrorKind::Other))
            ))),
        };
        let answered = reply.inspect_err(|error| {
            off_worker(|| {
                exchange.record_upstream_failure(state, error, upstream_timed_out(error));
            });
        })?;
        off_worker(|| match answered {
            Answered::Whole(response) => self.release(&mut exchange, response, version),
            Answered::Switched(head, upstream) => self.switch(&mut exchange, head, upstream),
            // F5: the workload gets no `101` before the gateway accepted the upstream's.
            Answered::Refused(reason) => {
                let refusal = Refusal {
                    reason: format!("websocket: {reason}"),
                    reply: Reply::Diagnostic {
                        status: 502,
                        body: b"WebSocket upgrade response refused",
                    },
                };
                Ok(refuse(&exchange, refusal, state, version))
            }
        })
    }

    /// Run the response phases, build the governed response, and claim its release.
    fn release(
        &self,
        exchange: &mut Exchange<'_>,
        mut response: InterceptedResponse,
        version: Version,
    ) -> Result<Response<Whole>> {
        let state = &*self.state;
        for phase in RESPONSE_PHASES {
            if let Err(refusal) = phase(exchange, &mut response, state) {
                return Ok(refuse(exchange, refusal, state, version));
            }
        }
        let (status, body_bytes) = (response.status, response.body.as_bytes().len());
        // Build only after response controls and leakback scrubbing have finished, then claim the
        // release immediately before hyper writes the governed bytes to the workload.
        let governed = prepare_response(exchange, &mut response, version)
            .inspect_err(|error| exchange.record_upstream_failure(state, error, false))?;
        let permit = match claim_release(exchange, status, body_bytes, state) {
            Ok(permit) => permit,
            Err(refusal) => return Ok(refuse(exchange, refusal, state, version)),
        };
        audit_release(exchange, state);
        // The reply is the next message on the client stream: it has left when a flush follows
        // the moment hyper took its body.
        self.client_writes.begin_message();
        *self.pending() = Some(PendingRelease {
            permit,
            start: self.client_writes.snapshot().accepted,
        });
        Ok(governed.map(|body| body.reported_to(Arc::clone(&self.client_writes))))
    }

    /// Run the response phases on the head of an accepted `101`, build the `101` to the workload,
    /// and claim its release. The release admits the messages of the session, which the connection
    /// task relays once hyper has written the `101`.
    fn switch(
        &self,
        exchange: &mut Exchange<'_>,
        mut head: InterceptedResponse,
        upstream: Box<dyn websocket::Duplex>,
    ) -> Result<Response<Whole>> {
        let state = &*self.state;
        for phase in RESPONSE_PHASES {
            if let Err(refusal) = phase(exchange, &mut head, state) {
                return Ok(refuse(exchange, refusal, state, Version::HTTP_11));
            }
        }
        let governed = convert::switching_out(&head.headers)
            .inspect_err(|error| exchange.record_upstream_failure(state, error, false))?;
        let permit = match claim_release(exchange, 101, 0, state) {
            Ok(permit) => permit,
            Err(refusal) => return Ok(refuse(exchange, refusal, state, Version::HTTP_11)),
        };
        audit_release(exchange, state);
        // The `101` is the next message on the client stream, also after earlier requests on a
        // kept-alive connection.
        self.client_writes.begin_message();
        *self.pending() = Some(PendingRelease {
            permit,
            start: self.client_writes.snapshot().accepted,
        });
        *self.relay.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(exchange.relay(upstream, state));
        Ok(governed.map(|body| body.reported_to(Arc::clone(&self.client_writes))))
    }
}

/// Who wrote the reply to a request, as the close rule reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplyKind {
    /// The gateway released a governed upstream reply.
    Released,
    /// The gateway wrote the reply itself: a refusal, a diagnostic, or an interceptor error.
    ByGateway,
}

/// Whether the client connection carries another request after a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AfterReply {
    KeepOpen,
    Close,
}

/// The close rule. Only a released reply to a `reusable` request keeps the connection open. Every
/// reply that the gateway wrote closes it, because some refusals come before the request body is
/// read, and one rule for every refusal is simpler to review than a rule for each.
fn after_reply(answered: ReplyKind, reusable: bool) -> AfterReply {
    match answered {
        ReplyKind::Released if reusable => AfterReply::KeepOpen,
        ReplyKind::Released | ReplyKind::ByGateway => AfterReply::Close,
    }
}

/// Whether a request can have another request after it on its connection: it is HTTP/1.1, the
/// client did not ask to close, and it names no `Upgrade`, so its next bytes are an HTTP head. An
/// HTTP/1.0 request closes after its reply, which carries the version of the request.
fn reusable<B>(request: &Request<B>) -> bool {
    let headers = request.headers();
    let asks_to_close = headers.get_all(CONNECTION).iter().any(|value| {
        value
            .as_bytes()
            .split(|byte| *byte == b',')
            .any(|option| option.trim_ascii().eq_ignore_ascii_case(b"close"))
    });
    request.version() == Version::HTTP_11 && !asks_to_close && !headers.contains_key(UPGRADE)
}

/// What the request phases and the decision leave.
enum Decided {
    /// The permit, the request to send, and what a `101` must answer when it is a handshake.
    Forward(ClaimedEffectPermit, UpstreamRequest, Option<Expected>),
    /// A refusal, already recorded, and its reply.
    Answer(Response<Whole>),
}

/// Run the request phases, build the upstream request, then claim and record `http:request`.
fn decide(
    exchange: &mut Exchange<'_>,
    state: &SharedState,
    version: Version,
    writes: Arc<WriteCount>,
) -> Result<Decided> {
    for phase in REQUEST_PHASES {
        if let Err(refusal) = phase(exchange, state) {
            return Ok(Decided::Answer(refuse(exchange, refusal, state, version)));
        }
    }
    // Build the fully mutated request before claiming its effect permit. A mutation can leave a
    // target or a header value that HTTP cannot carry, such as a spliced secret with a space: the
    // request is refused with a record, and no byte of it leaves. The error text holds no peer or
    // secret byte.
    let request = match prepare_request(exchange, state, writes) {
        Ok(request) => request,
        Err(error) => {
            let refusal = Refusal {
                reason: error.to_string(),
                reply: Reply::Diagnostic {
                    status: 502,
                    body: b"the request cannot be sent upstream",
                },
            };
            return Ok(Decided::Answer(refuse(exchange, refusal, state, version)));
        }
    };
    // A `101` must answer the handshake as forwarded, after the credential fold.
    let expected = exchange
        .websocket_key()
        .map(|key| request.expected_answer(key));
    Ok(match decide_request(exchange, state) {
        Ok(permit) => Decided::Forward(permit, request, expected),
        Err(reply) => Decided::Answer(reply_response(
            &exchange.method,
            version,
            reply,
            exchange.request.body.as_bytes(),
        )),
    })
}

/// Record a refusal of the exchange, and return the reply to the workload.
fn refuse(
    exchange: &Exchange<'_>,
    refusal: Refusal,
    state: &SharedState,
    version: Version,
) -> Response<Whole> {
    record_refusal(state, &exchange.subject(), &refusal.reason);
    reply_response(
        &exchange.method,
        version,
        refusal.reply,
        exchange.request.body.as_bytes(),
    )
}

/// The reply of a refusal; `mcp_request` is the request body, for a JSON-RPC refusal.
fn reply_response(
    request_method: &str,
    version: Version,
    reply: Reply,
    mcp_request: &[u8],
) -> Response<Whole> {
    match reply {
        Reply::Diagnostic { status, body } => {
            convert::diagnostic_response(request_method, version, status, Bytes::from_static(body))
        }
        Reply::Interceptor { error, mcp } => convert::interceptor_response(
            request_method,
            version,
            &error,
            mcp.then_some(mcp_request),
        ),
    }
}

/// The hyper server toward the workload: requests in turn, each head bounded as before.
fn server_builder(state: &SharedState) -> hyper::server::conn::http1::Builder {
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        // Without a timer, hyper drops its header timeout with no message. On a kept-alive
        // connection the timer starts again when the connection goes idle, so one bound covers the
        // wait for the next head and that head together.
        .timer(TokioTimer::new())
        .header_read_timeout(state.client_limits.first_head)
        // hyper serves the next request after a reply that does not say `Connection: close`, one
        // service call at a time, so pipelined requests run in order. With keep-alive off, hyper
        // would also write `Connection: close` on a `101`, and the client would refuse the handshake.
        .keep_alive(true)
        // A client that closes its write side after its request still gets the reply.
        .half_close(true)
        .title_case_headers(true)
        .auto_date_header(false)
        .max_headers(MAX_HEADERS)
        .max_buf_size(MAX_BUF_BYTES);
    builder
}

/// The hyper client toward the upstream, for one request.
fn client_builder() -> hyper::client::conn::http1::Builder {
    let mut builder = hyper::client::conn::http1::Builder::new();
    builder
        .title_case_headers(true)
        .max_headers(MAX_HEADERS)
        .max_buf_size(MAX_BUF_BYTES);
    builder
}

/// How the request reaches the upstream.
enum Hop {
    /// Over TLS to the CONNECT host, which the upstream certificate must name.
    Tls(ServerName<'static>),
    /// In plaintext, as the workload sent it.
    Plain,
}

/// The end of one upstream round trip.
struct Trip {
    /// The status of the reply head, once one arrived.
    status: Option<u16>,
    /// The reply, or why it did not arrive.
    reply: Result<Answered>,
}

/// What the upstream answered.
enum Answered {
    /// The whole reply.
    Whole(InterceptedResponse),
    /// A `101` that answers the forwarded handshake: its head, and the upstream after it.
    Switched(InterceptedResponse, Box<dyn websocket::Duplex>),
    /// A `101` that does not answer the handshake, or an upgrade that failed, and why.
    Refused(&'static str),
}

/// Send `request` over the pinned socket and read the whole reply.
///
/// Each read and write of the upstream socket waits at most the upstream deadline with no byte in
/// either direction; there is no total bound. The TLS handshake starts here, after the request decision, so no
/// upstream byte leaves before it.
async fn round_trip(
    state: &SharedState,
    upstream: TcpStream,
    hop: Hop,
    request: UpstreamRequest,
    method: &str,
    writes: Arc<WriteCount>,
    expected: Option<Expected>,
) -> Trip {
    let upstream = Idle::new(
        upstream,
        state.config.upstream_read_deadline,
        UPSTREAM_IDLE_PASSED,
    );
    let max = state.config.response_limits.max_body_bytes;
    match hop {
        Hop::Tls(name) => {
            let connector = TlsConnector::from(Arc::clone(&state.upstream_config));
            match connector.connect(name, upstream).await {
                Ok(tls) => send(tls, request, method, max, writes, expected).await,
                Err(error) => {
                    writes.failed(error.kind(), false);
                    Trip {
                        status: None,
                        reply: Err(ProxyError::Io(format!(
                            "delivering upstream request: {}",
                            error_text(&error)
                        ))),
                    }
                }
            }
        }
        Hop::Plain => send(upstream, request, method, max, writes, expected).await,
    }
}

/// Send `request` on `stream` with the hyper client, and read the whole reply. A `101` goes to the
/// upgrade only when it answers the handshake that `expected` describes; any other `101` is refused
/// (F6).
async fn send<S>(
    stream: S,
    request: UpstreamRequest,
    method: &str,
    max: usize,
    writes: Arc<WriteCount>,
    expected: Option<Expected>,
) -> Trip
where
    S: AsyncRead + AsyncWrite + Disarm + Unpin + Send + 'static,
{
    let io = TokioIo::new(Counted::new(stream, Arc::clone(&writes)));
    let (mut sender, connection) = match client_builder().handshake(io).await {
        Ok(handshake) => handshake,
        Err(error) => {
            return Trip {
                status: None,
                reply: Err(upstream_error(&error)),
            };
        }
    };
    // The connection runs on its own task, so it keeps writing while this task waits in a seam
    // call, and it ends with the exchange. After a `101` it hands the stream to the upgrade.
    let mut connection = AbortOnDrop(tokio::spawn(connection.with_upgrades()));
    let sent = sender.send_request(request.into_inner()).await;
    drop(sender);
    let trip = match sent {
        Ok(response) => Trip {
            status: Some(response.status().as_u16()),
            reply: match &expected {
                Some(expected) if response.status() == StatusCode::SWITCHING_PROTOCOLS => {
                    switched::<S>(response, expected).await
                }
                _ => convert::response_in(response, method, max)
                    .await
                    .map(Answered::Whole),
            },
        },
        Err(error) => Trip {
            status: None,
            reply: Err(upstream_error(&error)),
        },
    };
    // hyper can read the reply before it has written the whole request. The outcome waits until
    // the request has left, or its send has failed.
    tokio::select! {
        () = writes.settled() => {}
        _ = &mut connection.0 => {}
    }
    trip
}

/// Check an upstream `101` against the forwarded handshake, then take the upgraded upstream. The
/// upstream bound gives way to the relay's idle limit.
async fn switched<S>(mut response: Response<Incoming>, expected: &Expected) -> Result<Answered>
where
    S: AsyncRead + AsyncWrite + Disarm + Unpin + Send + 'static,
{
    const FAILED: &str = "the upstream upgrade failed";
    if let Err(reason) = websocket::check_switching_protocols(response.headers(), expected) {
        return Ok(Answered::Refused(reason));
    }
    let head = convert::switching_in(response.headers())?;
    let Ok(upgraded) = hyper::upgrade::on(&mut response).await else {
        return Ok(Answered::Refused(FAILED));
    };
    let Ok(parts) = upgraded.downcast::<TokioIo<Counted<S>>>() else {
        return Ok(Answered::Refused(FAILED));
    };
    let mut upstream = parts.io.into_inner().inner;
    upstream.disarm();
    let upstream = Replay::new(parts.read_buf.to_vec(), upstream);
    Ok(Answered::Switched(head, Box::new(upstream)))
}

/// The error of a failed upstream exchange: a reply that the gateway refuses, an upstream that
/// closed early, or a failed read or write.
fn upstream_error(error: &hyper::Error) -> ProxyError {
    if error.is_parse() {
        ProxyError::Intercept(format!("parsing response: {}", error_text(error)))
    } else if error.is_incomplete_message() {
        ProxyError::Intercept(format!("{} before the reply ended", http1::CLOSED_EARLY))
    } else {
        ProxyError::Io(format!("upstream exchange: {}", error_text(error)))
    }
}

/// Whether the upstream idle bound ended a failed upstream step.
fn upstream_timed_out(error: &ProxyError) -> bool {
    matches!(error, ProxyError::Io(message) if message.ends_with(UPSTREAM_IDLE_PASSED))
}

/// A task that is aborted when this value drops.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A stream that yields bytes that were read already, before its next bytes: the first head that
/// the front read, or what hyper read past the head of a `101`.
struct Replay<S> {
    head: Vec<u8>,
    replayed: usize,
    inner: S,
}

impl<S> Replay<S> {
    fn new(head: Vec<u8>, inner: S) -> Self {
        Self {
            head,
            replayed: 0,
            inner,
        }
    }
}

impl<S: Disarm> Disarm for Replay<S> {
    fn disarm(&mut self) {
        self.inner.disarm();
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Replay<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let rest = &this.head[this.replayed..];
        if rest.is_empty() {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        let count = rest.len().min(buf.remaining());
        buf.put_slice(&rest[..count]);
        this.replayed += count;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replay<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// A client stream that tells its session where a kept-alive connection stands: a byte that
/// arrives starts the next request, and a flush that ends a reply that keeps the connection open
/// starts the wait for the next head.
struct Watched<S> {
    inner: S,
    session: Arc<Session>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let read = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(read, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            this.session.byte_arrived();
        }
        read
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let flushed = ready!(Pin::new(&mut this.inner).poll_flush(cx));
        if flushed.is_ok() {
            this.session.flushed();
        }
        Poll::Ready(flushed)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The outcome of the request permit, from what the upstream stream accepted.
fn request_outcome(sent: Writes, status: Option<u16>) -> EffectOutcome {
    let accepted_bytes = sent.accepted;
    if sent.flushed {
        match status {
            Some(status) => EffectOutcome::Replied {
                accepted_bytes,
                status,
            },
            None => EffectOutcome::Completed(accepted_bytes),
        }
    } else if sent.flush_error && sent.body_taken {
        EffectOutcome::Indeterminate { accepted_bytes }
    } else {
        unsent(accepted_bytes, sent.error)
    }
}

/// The outcome of the release permit, from what the client stream accepted since the claim.
fn release_outcome(written: Writes, start: usize, delivered: bool) -> EffectOutcome {
    let accepted_bytes = written.accepted.saturating_sub(start);
    if delivered {
        EffectOutcome::Completed(accepted_bytes)
    } else if written.flush_error {
        EffectOutcome::Indeterminate { accepted_bytes }
    } else {
        unsent(accepted_bytes, written.error)
    }
}

/// The outcome of a message that did not leave whole.
fn unsent(accepted_bytes: usize, error: Option<io::ErrorKind>) -> EffectOutcome {
    let error_kind = error.unwrap_or(io::ErrorKind::Other);
    if accepted_bytes == 0 {
        EffectOutcome::Failed {
            accepted_bytes: 0,
            error_kind,
        }
    } else {
        EffectOutcome::Partial {
            accepted_bytes,
            error_kind,
        }
    }
}

/// What one stream accepted, as its writer saw it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Writes {
    /// The bytes that the stream accepted.
    pub(super) accepted: usize,
    /// Whether hyper has taken the whole body of the message.
    pub(super) body_taken: bool,
    /// Whether a flush succeeded after the body was taken: the whole message left.
    pub(super) flushed: bool,
    /// The kind of the first write or flush error.
    pub(super) error: Option<io::ErrorKind>,
    /// Whether that error came from a flush, after every byte was accepted.
    pub(super) flush_error: bool,
    /// The bytes that the stream had accepted when its current message started.
    pub(super) message_start: usize,
}

/// The write count of one stream, shared by the stream and the exchange.
pub(super) struct WriteCount(watch::Sender<Writes>);

impl WriteCount {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self(watch::Sender::new(Writes::default())))
    }

    /// What the stream has accepted so far.
    pub(super) fn snapshot(&self) -> Writes {
        *self.0.borrow()
    }

    /// hyper has taken the whole body. It buffers the body before its next flush.
    pub(super) fn body_taken(&self) {
        self.0.send_modify(|writes| writes.body_taken = true);
    }

    /// The next message starts on the stream, as on a kept-alive client connection: its body is
    /// not taken, and it has not left.
    fn begin_message(&self) {
        self.0.send_modify(|writes| {
            writes.body_taken = false;
            writes.flushed = false;
            writes.message_start = writes.accepted;
        });
    }

    fn accepted(&self, bytes: usize) {
        self.0.send_modify(|writes| writes.accepted += bytes);
    }

    /// hyper flushes only an empty write buffer, so a flush after the body was taken means that
    /// the whole message left.
    fn flushed(&self) {
        self.0.send_if_modified(|writes| {
            let left =
                writes.body_taken && writes.accepted > writes.message_start && !writes.flushed;
            writes.flushed |= left;
            left
        });
    }

    fn failed(&self, kind: io::ErrorKind, during_flush: bool) {
        self.0.send_if_modified(|writes| {
            let first = writes.error.is_none();
            if first {
                writes.error = Some(kind);
                writes.flush_error = during_flush;
            }
            first
        });
    }

    /// Wait until the whole message has left, or a write or flush has failed.
    async fn settled(&self) {
        let mut writes = self.0.subscribe();
        let _ = writes
            .wait_for(|writes| writes.flushed || writes.error.is_some())
            .await;
    }
}

/// A stream that reports what it accepted to a [`WriteCount`].
pub(super) struct Counted<S> {
    inner: S,
    writes: Arc<WriteCount>,
}

impl<S> Counted<S> {
    fn new(inner: S, writes: Arc<WriteCount>) -> Self {
        Self { inner, writes }
    }

    fn count(&self, written: Poll<io::Result<usize>>) -> Poll<io::Result<usize>> {
        match &written {
            Poll::Ready(Ok(bytes)) => self.writes.accepted(*bytes),
            Poll::Ready(Err(error)) => self.writes.failed(error.kind(), false),
            Poll::Pending => {}
        }
        written
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.count(written)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.count(written)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let flushed = ready!(Pin::new(&mut this.inner).poll_flush(cx));
        match &flushed {
            Ok(()) => this.writes.flushed(),
            Err(error) => this.writes.failed(error.kind(), true),
        }
        Poll::Ready(flushed)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writes(accepted: usize, body_taken: bool, flushed: bool) -> Writes {
        Writes {
            accepted,
            body_taken,
            flushed,
            ..Writes::default()
        }
    }

    fn failed(accepted: usize, kind: io::ErrorKind, flush_error: bool) -> Writes {
        Writes {
            accepted,
            body_taken: true,
            error: Some(kind),
            flush_error,
            ..Writes::default()
        }
    }

    /// **The request outcome follows the write count**: one row for each way a request ends.
    #[test]
    fn request_outcome_follows_the_write_count() {
        use io::ErrorKind::{BrokenPipe, InvalidData, Other, TimedOut};
        let rows = [
            (
                writes(90, true, true),
                Some(200),
                EffectOutcome::Replied {
                    accepted_bytes: 90,
                    status: 200,
                },
            ),
            (writes(90, true, true), None, EffectOutcome::Completed(90)),
            (
                failed(0, InvalidData, false),
                None,
                EffectOutcome::Failed {
                    accepted_bytes: 0,
                    error_kind: InvalidData,
                },
            ),
            (
                failed(3, TimedOut, false),
                Some(413),
                EffectOutcome::Partial {
                    accepted_bytes: 3,
                    error_kind: TimedOut,
                },
            ),
            (
                failed(90, BrokenPipe, true),
                None,
                EffectOutcome::Indeterminate { accepted_bytes: 90 },
            ),
            (
                writes(40, false, false),
                None,
                EffectOutcome::Partial {
                    accepted_bytes: 40,
                    error_kind: Other,
                },
            ),
        ];
        for (sent, status, outcome) in rows {
            assert_eq!(request_outcome(sent, status), outcome, "{sent:?}");
        }
    }

    /// **The release counts only the bytes after its claim**, so an interim `100 Continue` that
    /// hyper wrote first is not part of the reply.
    #[test]
    fn the_release_counts_only_reply_bytes() {
        let written = writes(125, false, false);
        assert_eq!(
            release_outcome(written, 25, true),
            EffectOutcome::Completed(100)
        );
        let cut = Writes {
            accepted: 60,
            error: Some(io::ErrorKind::TimedOut),
            ..Writes::default()
        };
        assert_eq!(
            release_outcome(cut, 25, false),
            EffectOutcome::Partial {
                accepted_bytes: 35,
                error_kind: io::ErrorKind::TimedOut
            }
        );
        assert_eq!(
            release_outcome(cut, 60, false),
            EffectOutcome::Failed {
                accepted_bytes: 0,
                error_kind: io::ErrorKind::TimedOut
            }
        );
    }

    /// **The close rule**: only a released reply to a request that can have another after it keeps
    /// the connection open. Every reply that the gateway wrote closes it, and so does a reply to an
    /// HTTP/1.0 request, to a client `Connection: close`, and to a request that names `Upgrade`.
    #[test]
    fn after_reply_closes_every_gateway_answer_and_every_request_that_ends_its_connection() {
        assert_eq!(after_reply(ReplyKind::Released, true), AfterReply::KeepOpen);
        for (answered, reusable) in [
            (ReplyKind::Released, false),
            (ReplyKind::ByGateway, true),
            (ReplyKind::ByGateway, false),
        ] {
            assert_eq!(after_reply(answered, reusable), AfterReply::Close);
        }
        let request = |version: Version, headers: &[(&str, &str)]| {
            let mut request = Request::builder().version(version);
            for (name, value) in headers {
                request = request.header(*name, *value);
            }
            request.body(()).unwrap()
        };
        assert!(reusable(&request(Version::HTTP_11, &[])));
        assert!(reusable(&request(
            Version::HTTP_11,
            &[("connection", "keep-alive")]
        )));
        assert!(!reusable(&request(
            Version::HTTP_10,
            &[("connection", "keep-alive")]
        )));
        assert!(!reusable(&request(
            Version::HTTP_11,
            &[("connection", "keep-alive"), ("connection", "x, Close ")]
        )));
        assert!(!reusable(&request(
            Version::HTTP_11,
            &[("connection", "upgrade"), ("upgrade", "websocket")]
        )));
    }

    /// **A flush counts as the end of a message only after hyper took its body.** hyper flushes an
    /// empty buffer before it has a message too.
    #[test]
    fn a_flush_before_the_body_is_taken_is_not_the_end_of_the_message() {
        let count = WriteCount::new();
        count.flushed();
        count.accepted(40);
        count.flushed();
        assert!(!count.snapshot().flushed, "the head alone left");
        count.body_taken();
        count.accepted(10);
        count.flushed();
        assert!(count.snapshot().flushed);
        assert_eq!(count.snapshot().accepted, 50);

        // The next message on a kept-alive stream has left only after its own body and a flush.
        count.begin_message();
        count.flushed();
        assert!(
            !count.snapshot().flushed,
            "nothing of the next message left"
        );
        count.body_taken();
        count.flushed();
        assert!(
            !count.snapshot().flushed,
            "no byte of the next message left"
        );
        count.accepted(7);
        count.flushed();
        assert!(count.snapshot().flushed);
    }
}
