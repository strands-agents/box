//! The hyper drivers of one connection: the server toward the workload, and the client toward the
//! upstream.
//!
//! | Part | Does |
//! |---|---|
//! | [`serve_tls`] | Accept the workload's TLS with the minted leaf, then serve one exchange on hyper |
//! | [`serve_plain`] | Serve one plain-HTTP exchange on hyper, after the first head that the front read |
//! | `Session` | Run one request: intake, the request phases and the decision, the round trip, the release |
//! | `round_trip` | Send the decided request over the pinned socket, and read the whole reply or take the upgrade |
//! | `Session::switch` | Release the `101` of a WebSocket handshake; the connection task then runs the relay |
//! | [`WriteCount`], `Counted` | Count the bytes that a stream accepted, for the outcome of each permit |
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
    record_refusal, record_request_failure, record_unfinished,
};
use super::l7::{split_target, validate_request_binding};
use super::listener::{PROXY_AUTHENTICATION_REQUIRED, open_governed_upstream};
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
    /// The gateway's stop signal, which ends a relay.
    pub(super) stop: watch::Receiver<bool>,
}

/// Terminate the workload's TLS with the leaf minted for the CONNECT host, and serve one exchange.
///
/// The client idle bound wraps the raw stream under TLS, so it bounds the handshake too. The
/// connection task holds the slot.
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
        session.stop,
    );
    session.serve(client).await
}

/// One plain-HTTP connection, after the front read its first head.
pub(super) struct PlainSession<C> {
    /// The raw client stream, after the first head.
    pub(super) client: C,
    /// The first head, as the front read it, which hyper reads again before the next bytes.
    pub(super) head: Vec<u8>,
    /// The `Proxy-Authorization` of the raw head. The hop-by-hop strip removes it from the request,
    /// so reading it there would always see nothing and the token check would accept every request.
    pub(super) proxy_authorization: Option<String>,
    /// The gateway's stop signal.
    pub(super) stop: watch::Receiver<bool>,
}

/// Serve one plain-HTTP (absolute-form) exchange: the same controls as the CONNECT path —
/// `net:connect`, then the request and response phases — over plaintext, with no CONNECT ack.
///
/// The request is read whole before any decision, so a refused or broken request opens no
/// upstream socket. The connection task holds the slot.
pub(super) async fn serve_plain<C>(state: Arc<SharedState>, session: PlainSession<C>) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let client = Idle::new(session.client, state.client_limits.idle, CLIENT_IDLE_PASSED);
    let client = Replay::new(session.head, client);
    let session = Session::new(
        state,
        Route::Plain {
            proxy_authorization: session.proxy_authorization,
        },
        session.stop,
    );
    session.serve(client).await
}

/// What a connection carries.
enum Route {
    /// A CONNECT tunnel: its admitted authority, and the upstream socket that its one request uses.
    Tunnel {
        connect: ConnectRequest,
        correlation: RequestId,
        upstream: Mutex<Option<TcpStream>>,
    },
    /// A plain-HTTP request, whose absolute target names its destination.
    Plain { proxy_authorization: Option<String> },
}

/// One served connection, and the state that its service shares with its end.
struct Session {
    state: Arc<SharedState>,
    route: Route,
    /// What the client stream accepted.
    client_writes: Arc<WriteCount>,
    /// The release that waits until hyper has written the governed response.
    pending: Mutex<Option<PendingRelease>>,
    /// The WebSocket that waits until hyper has written its `101`.
    relay: Mutex<Option<websocket::Pending>>,
    /// The gateway's stop signal, which ends a relay.
    stop: watch::Receiver<bool>,
    /// Why the service ended the exchange, for the audit line.
    failure: Mutex<Option<ProxyError>>,
    /// Whether a request head arrived.
    requested: AtomicBool,
    /// Whether the request was decided and sent toward the upstream.
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
    fn new(state: Arc<SharedState>, route: Route, stop: watch::Receiver<bool>) -> Arc<Self> {
        Arc::new(Self {
            state,
            route,
            client_writes: WriteCount::new(),
            pending: Mutex::new(None),
            relay: Mutex::new(None),
            stop,
            failure: Mutex::new(None),
            requested: AtomicBool::new(false),
            forwarded: AtomicBool::new(false),
        })
    }

    /// Serve the connection on hyper, then record the outcome of the release, and relay a WebSocket
    /// whose `101` hyper wrote.
    async fn serve<C>(self: Arc<Self>, client: C) -> Result<()>
    where
        C: AsyncRead + AsyncWrite + Disarm + Unpin + Send + 'static,
    {
        let client = Counted::new(client, Arc::clone(&self.client_writes));
        let session = Arc::clone(&self);
        let service = hyper::service::service_fn(move |request| -> Answer {
            let session = Arc::clone(&session);
            Box::pin(async move { session.answer(request).await })
        });
        let served = server_builder(&self.state)
            .serve_connection(TokioIo::new(client), service)
            .without_shutdown()
            .await;
        self.finish(served).await
    }

    /// Answer one request, and keep the reason when the exchange ends without a reply.
    async fn answer(
        &self,
        request: Request<Incoming>,
    ) -> std::result::Result<Response<Whole>, Ended> {
        self.requested.store(true, Ordering::Relaxed);
        let answered = match &self.route {
            Route::Tunnel {
                connect,
                correlation,
                upstream,
            } => self.tunnel(request, connect, correlation, upstream).await,
            Route::Plain {
                proxy_authorization,
            } => self.plain(request, proxy_authorization.as_deref()).await,
        };
        answered.map_err(|error| {
            *self.failure.lock().unwrap_or_else(|e| e.into_inner()) = Some(error);
            Ended
        })
    }

    /// Record the outcome of the release once hyper has written the response, then close, or run
    /// the relay after a `101`.
    async fn finish<C, S>(
        &self,
        served: hyper::Result<hyper::server::conn::http1::Parts<TokioIo<Counted<C>>, S>>,
    ) -> Result<()>
    where
        C: AsyncRead + AsyncWrite + Disarm + Unpin + Send,
    {
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(release) = pending {
            let outcome =
                release_outcome(self.client_writes.snapshot(), release.start, served.is_ok());
            off_worker(|| release.permit.record_outcome(outcome)).map_err(|error| {
                ProxyError::Io(format!(
                    "recording governed response outcome after I/O: {error}"
                ))
            })?;
        }
        let failure = self
            .failure
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(failure) = failure {
            return Err(failure);
        }
        // A plain-HTTP request that never reached the upstream was answered, by hyper or with the
        // gateway's static reply, and an end there leaves no audit line.
        if served.is_err()
            && matches!(self.route, Route::Plain { .. })
            && !self.forwarded.load(Ordering::Relaxed)
        {
            return Ok(());
        }
        match served {
            Ok(parts) => {
                let relay = self.relay.lock().unwrap_or_else(|e| e.into_inner()).take();
                if let Some(relay) = relay {
                    // hyper wrote the `101` and handed the stream back with the bytes that it read
                    // past the head. The relay's idle limit replaces the client idle bound.
                    let mut client = parts.io.into_inner().inner;
                    client.disarm();
                    let client = Replay::new(parts.read_buf.to_vec(), client);
                    return websocket::run(relay, client, &self.state, self.stop.clone()).await;
                }
                // `close_notify`, then the end of the write side.
                let _ = parts.io.into_inner().shutdown().await;
                if self.requested.load(Ordering::Relaxed) {
                    Ok(())
                } else {
                    Err(ProxyError::Intercept(format!(
                        "{} before HTTP head",
                        http1::CLOSED_EARLY
                    )))
                }
            }
            Err(error) if error.is_parse() => {
                // hyper answered the head itself. The request never reached a decision, so the
                // record names the connection.
                let error =
                    ProxyError::Intercept(format!("parsing request: {}", error_text(&error)));
                match &self.route {
                    Route::Tunnel {
                        connect,
                        correlation,
                        ..
                    } => off_worker(|| {
                        record_request_failure(
                            &self.state,
                            &Subject::connection(connect, correlation),
                            &error,
                        );
                    }),
                    Route::Plain { .. } => {}
                }
                Err(error)
            }
            Err(error) => Err(ProxyError::Io(format!(
                "serving the client: {}",
                error_text(&error)
            ))),
        }
    }

    /// Run the one request of a CONNECT tunnel.
    async fn tunnel(
        &self,
        request: Request<Incoming>,
        connect: &ConnectRequest,
        correlation: &RequestId,
        upstream: &Mutex<Option<TcpStream>>,
    ) -> Result<Response<Whole>> {
        let state = &*self.state;
        let inbound = convert::request_in(request, state.config.response_limits.max_body_bytes)
            .await
            .inspect_err(|error| {
                off_worker(|| {
                    record_request_failure(
                        state,
                        &Subject::connection(connect, correlation),
                        error,
                    );
                });
            })?;
        let version = inbound.version;
        // The name is converted before any decision, so a host that cannot be one fails first.
        let name = ServerName::try_from(connect.host.clone()).map_err(|_| {
            ProxyError::UpstreamConnect(format!("invalid upstream host {}", connect.host))
        })?;
        let correlation = correlation.clone().with_headers(&inbound.headers);
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
        let upstream = upstream
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| ProxyError::Intercept("a tunnel carries one request".to_string()))?;
        self.forward(exchange, version, upstream, Hop::Tls(name))
            .await
    }

    /// Run the one request of a plain-HTTP connection.
    async fn plain(
        &self,
        request: Request<Incoming>,
        proxy_authorization: Option<&str>,
    ) -> Result<Response<Whole>> {
        let state = &*self.state;
        let version = request.version();
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
            proxy_authorization: proxy_authorization.map(str::to_string),
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
        // Shared L4: the pre-resolution `net:connect`, resolve-once/pin, and the per-address
        // `net:connect` effect — identical to the CONNECT path, in one `off_worker` call.
        let upstream = match off_worker(|| open_governed_upstream(state, &connect, &correlation)) {
            Ok(upstream) => upstream,
            Err(error) => return Ok(error.response(&inbound.method, version)),
        };
        let upstream = TcpStream::from_std(upstream)
            .map_err(|e| ProxyError::Io(format!("registering the upstream socket: {e}")))?;
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
        let exchange = Exchange::new(
            &connect,
            Binding::None,
            false,
            correlation,
            request,
            inbound.handshake,
            state,
        );
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
        *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(PendingRelease {
            permit,
            start: self.client_writes.snapshot().accepted,
        });
        Ok(governed)
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
        *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(PendingRelease {
            permit,
            start: self.client_writes.snapshot().accepted,
        });
        *self.relay.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(exchange.relay(upstream, state));
        Ok(governed)
    }
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
        .map(|key| Expected::new(key, request.headers()));
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

/// The hyper server toward the workload: one exchange, the heads bounded as before.
fn server_builder(state: &SharedState) -> hyper::server::conn::http1::Builder {
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        // Without a timer, hyper drops its header timeout with no message.
        .timer(TokioTimer::new())
        .header_read_timeout(state.client_limits.first_head)
        // One exchange per connection: every reply but a `101` carries `Connection: close`, which
        // ends the connection after it. Keep-alive stays on, because with it off hyper writes
        // `Connection: close` on a `101` too, and the client refuses the handshake.
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

    fn accepted(&self, bytes: usize) {
        self.0.send_modify(|writes| writes.accepted += bytes);
    }

    /// hyper flushes only an empty write buffer, so a flush after the body was taken means that
    /// the whole message left.
    fn flushed(&self) {
        self.0.send_if_modified(|writes| {
            let left = writes.body_taken && writes.accepted > 0 && !writes.flushed;
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
    }
}
