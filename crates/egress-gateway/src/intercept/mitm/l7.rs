//! The L7 interception path: terminate TLS, run the request/response legs, forward.

use std::borrow::Cow;
use std::io::{self, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::audit::RequestId;
use rustls::{ClientConnection, ServerConnection, StreamOwned};
use zeroize::Zeroizing;

use super::connect::{ConnectRequest, parse_authority, same_host};
use super::http1::Hop;
use super::request_leg::{self, RequestDecision};
use super::response_leg::{self, ResponseDecision};
use super::websocket::{self, UpgradeRequest, Upgraded};
use super::{SharedState, http1, tls};
use crate::audit::Decision as AuditDecision;
use crate::audit::{EgressDecision, NetworkAuditEvent};
use crate::boundary::{BodyRef, HeaderMap, InterceptedRequest, InterceptedResponse, Target};
use crate::capability::CapabilityContext;
use crate::effect::{ClaimedEffectPermit, EffectAttempt, EffectOutcome, McpFrame, McpListReply};
use crate::error::{ProxyError, Result};
use crate::mcp::{
    McpTarget, McpTargetIdentity, canonicalize_mcp_frame, mcp_denial_response, normalize_path,
};

/// Terminate the client's TLS, run the L7 legs, and forward to the pinned upstream.
///
/// A thin transport wrapper: it does the TLS-specific setup (present a per-host leaf, open the
/// upstream TLS), reads the request, checks the CONNECT binding, then hands the shared request and
/// response legs to [`run_l7_legs`]. An accepted WebSocket handshake continues in
/// [`websocket::relay`] on the same two connections.
pub(super) fn intercept_tls<C: Read + Write + AsRawFd>(
    client: C,
    upstream: TcpStream,
    connect: &ConnectRequest,
    state: &SharedState,
    correlation: RequestId,
) -> Result<()> {
    let ca = state
        .ca
        .as_ref()
        .ok_or_else(|| ProxyError::Intercept("no ephemeral CA (tls-intercept off)".to_string()))?;

    // --- Server side: present a per-host leaf to the workload ---
    let server_config = tls::server_config_for_host(ca, &connect.host, state.config.enable_h2)?;
    let server_conn = ServerConnection::new(Arc::new(server_config))
        .map_err(|e| ProxyError::Intercept(format!("server TLS init: {e}")))?;
    // Wrap the client TLS stream in a BufReader so the HTTP head is read line-buffered (not one
    // syscall per byte). Writes go through `get_mut()` to the underlying stream.
    let mut client_tls = BufReader::new(StreamOwned::new(server_conn, client));

    // --- Request leg: read plaintext, then run the shared legs ---
    let parsed = http1::read_request(&mut client_tls, state.config.response_limits.max_body_bytes)?;

    // --- Client side: connect to the pinned upstream over the additive trust bundle ---
    // The listener already opened this exact pinned socket under the Connect lifecycle. A TLS
    // handshake failure here is a hard-fail drop, never a second socket attempt.
    let mut upstream_tls = BufReader::new(start_upstream_tls(
        &connect.host,
        Bounded::new(upstream, state.config.upstream_read_deadline),
        state,
    )?);
    let correlation = correlation.with_headers(&parsed.headers);
    // Pre-leg binding: the inner request must name the CONNECT authority, before any mutation.
    if let Err(error) =
        validate_request_binding(connect, &parsed.method, &parsed.target, &parsed.headers)
    {
        let reason = error.to_string();
        emit_decision(
            state,
            DecisionSubject {
                host: &connect.host,
                port: connect.port,
                method: &parsed.method,
                path: &parsed.target,
            },
            AuditDecision::Deny,
            &reason,
            correlation.clone(),
        );
        state.audit.push(NetworkAuditEvent::deny(
            &connect.host,
            connect.port,
            reason,
            correlation,
        ));
        write_trusted_diagnostic(
            client_tls.get_mut(),
            &parsed.method,
            error.http_status(),
            b"request authority rejected",
        );
        return Ok(());
    }
    let mut target = Target::new(connect.host.clone(), connect.port);
    let (path, query) = split_target(&parsed.target);
    target.path = path;
    target.query = query;

    // Move the parsed fields into the boundary request — `parsed` is dead after this, so cloning the
    // (potentially large) body/headers would be a wasted full copy on every request.
    let req = InterceptedRequest {
        target,
        method: Some(parsed.method),
        headers: parsed.headers,
        body: BodyRef::Bytes(parsed.body),
        advisory_note: None,
    };

    // The post-mutation binding re-check is TLS-only, so it rides in as a closure rather than as a
    // flag inside the shared core.
    let Some(upgraded) = run_l7_legs(
        connect,
        req,
        parsed.upgrade,
        &mut upstream_tls,
        client_tls.get_mut(),
        state,
        correlation,
        true, // TLS was terminated to see this request
        |method, target, headers| validate_request_binding(connect, method, target, headers),
    )?
    else {
        return Ok(());
    };
    // The relay takes the plaintext each side sent after its head.
    let client_carried = client_tls.buffer().to_vec();
    let StreamOwned { conn, sock } = client_tls.into_inner();
    let client = websocket::Peer::new(conn, sock, client_carried);
    let upstream_carried = upstream_tls.buffer().to_vec();
    let StreamOwned {
        conn: upstream_conn,
        sock: upstream_sock,
    } = upstream_tls.into_inner();
    let upstream =
        websocket::Peer::new(upstream_conn, upstream_sock.into_inner(), upstream_carried);
    websocket::relay(client, upstream, connect, upgraded, state)
}

/// Run the shared L7 request/response legs over an already-open client writer and upstream stream.
///
/// Both the TLS ([`intercept_tls`]) and plain-HTTP ([`forward_plain`]) paths converge here after
/// their transport-specific setup: `req` is the parsed request, `upstream` the buffered upstream,
/// and `client_writer` the sink for diagnostics and the governed response. `revalidate` runs after
/// the credential mutation — the TLS path re-checks the CONNECT binding there; plain HTTP has no
/// authority to bind, so it passes a no-op. Every control (request/response legs, effect lifecycle,
/// audit) fires identically for both. Returns what the relay needs when the exchange released a
/// `101` for a WebSocket handshake.
#[allow(clippy::too_many_arguments)]
fn run_l7_legs<S, CW>(
    connect: &ConnectRequest,
    mut req: InterceptedRequest,
    upgrade: UpgradeRequest,
    upstream: &mut BufReader<S>,
    client_writer: &mut CW,
    state: &SharedState,
    correlation: RequestId,
    intercepted: bool,
    revalidate: impl FnOnce(&str, &str, &HeaderMap) -> Result<()>,
) -> Result<Option<Upgraded>>
where
    S: Read + Write,
    CW: Write,
{
    let correlation = correlation.with_headers(&req.headers);
    let correlation = if state.mcp_server_for(&connect.host).is_some() {
        correlation.with_mcp(req.body.as_bytes())
    } else {
        correlation
    };
    // Canonicalize the request path ONCE, before it is judged (`workload_path`), matched for
    // credentials (`cx`), or forwarded (`reconstruct_target`) — so the box judges, matches, and
    // forwards the SAME bytes the origin will resolve. Percent-decodes only unreserved octets (never
    // `%2F`, which would change segment structure) and removes dot-segments, closing the "judge one
    // spelling, forward another" gap where `/%61dmin` or `/x/../admin` dodges a path `forbid` yet the
    // origin routes to `/admin`. The query is left untouched — a `UrlPath` credential can live there,
    // and it is deliberately kept out of the judged path.
    req.target.path = match canonicalize_request_path(&req.target.path) {
        Ok(path) => path,
        Err(reason) => {
            refuse_request(
                state,
                connect,
                client_writer,
                RefusedRequest {
                    method: req.method.as_deref(),
                    path: &req.target.path,
                    reason: &reason,
                    status: 403,
                    diagnostic: b"request path is not a valid address",
                },
                correlation,
            );
            return Ok(None);
        }
    };

    // Refuse a WebSocket upgrade the relay cannot govern, before any request leg runs.
    let (websocket_key, refusal) = match upgrade {
        UpgradeRequest::None => (None, None),
        UpgradeRequest::Malformed(reason) => (
            None,
            Some((reason, 400, &b"malformed WebSocket handshake"[..])),
        ),
        UpgradeRequest::WebSocket(_) if !intercepted => (
            None,
            Some((
                "upgrade on a plaintext request",
                403,
                &b"WebSocket requires TLS"[..],
            )),
        ),
        UpgradeRequest::WebSocket(_) if state.mcp_server_for(&connect.host).is_some() => (
            None,
            Some((
                "upgrade to a remote MCP server",
                403,
                &b"WebSocket refused for an MCP server"[..],
            )),
        ),
        UpgradeRequest::WebSocket(key) => (Some(key), None),
    };
    if let Some((reason, status, diagnostic)) = refusal {
        refuse_request(
            state,
            connect,
            client_writer,
            RefusedRequest {
                method: req.method.as_deref(),
                path: &req.target.path,
                reason: &format!("websocket: {reason}"),
                status,
                diagnostic,
            },
            correlation,
        );
        return Ok(None);
    }

    // A secret rides only TLS: refuse on the same canonical target the credential match below sees.
    if !intercepted && state.controls.matches_any(&req.target.as_destination()) {
        refuse_request(
            state,
            connect,
            client_writer,
            RefusedRequest {
                method: req.method.as_deref(),
                path: &req.target.path,
                reason: "credential would attach on a plaintext request; refused — a secret must ride TLS",
                status: 403,
                diagnostic: b"credential not permitted on a plaintext request",
            },
            correlation,
        );
        return Ok(None);
    }

    let cx = CapabilityContext::new(
        correlation.clone(),
        state.now_unix_secs(),
        req.target.clone(),
    );

    // The path as the workload sent it, captured BEFORE any credential mutation is applied.
    //
    // A `UrlPath` credential splices the secret into the path, so after `evaluate_and_apply`
    // `req.target.path` *is* the secret. Every authorization and audit input below reads this value
    // instead, so an attempt or a durable record never carries credential material.
    let workload_path = req.target.path.clone();

    let credentialed = match request_leg::evaluate_and_apply(&state.controls, &mut req, &cx) {
        RequestDecision::Block(reason) => {
            let reason = reason.to_string(); // format once, use for both audit sinks
            state.audit.push(NetworkAuditEvent::deny(
                &connect.host,
                connect.port,
                reason.clone(),
                correlation.clone(),
            ));
            emit_decision(
                state,
                DecisionSubject {
                    host: &connect.host,
                    port: connect.port,
                    method: req.method.as_deref().unwrap_or_default(),
                    path: &workload_path,
                },
                AuditDecision::Deny,
                &reason,
                correlation,
            );
            write_trusted_diagnostic(
                client_writer,
                req.method.as_deref().unwrap_or("GET"),
                403,
                b"blocked by egress control",
            );
            return Ok(None);
        }
        RequestDecision::Forward { credentialed } => credentialed,
    };

    // A capability may annotate this allow — an advisory credential injection records that a secret
    // was attached against an absent or unrecognised placeholder. Journalled on the allow decision
    // below, so the injection is reconstructable (destination, reason, and requester correlation).
    let allow_reason = req.advisory_note.clone().unwrap_or_default();

    // Serialize the fully mutated request before claiming its effect permit.
    let fwd_target = reconstruct_target(&req.target);
    let request_method = req.method.clone().unwrap_or_else(|| "GET".to_string());
    if let Err(error) = revalidate(&request_method, &fwd_target, &req.headers) {
        let reason = error.to_string();
        state.audit.push(NetworkAuditEvent::deny(
            &connect.host,
            connect.port,
            reason.clone(),
            correlation.clone(),
        ));
        emit_decision(
            state,
            DecisionSubject {
                host: &connect.host,
                port: connect.port,
                method: req.method.as_deref().unwrap_or_default(),
                path: &workload_path,
            },
            AuditDecision::Deny,
            &reason,
            correlation,
        );
        write_trusted_diagnostic(
            client_writer,
            &request_method,
            error.http_status(),
            b"request authority rejected",
        );
        return Ok(None);
    }
    // Remote MCP door: if this destination is a configured MCP server, classify the JSON-RPC frame
    // so the `mcp:call` gate can run alongside `http:request`. The `server` is config-assigned (the
    // matched host's name), never read from the body, so an agent cannot borrow another server's
    // identity. A frame the classifier refuses — unparseable, a batch, a client-sent response, or an
    // act frame naming no item — is fail-closed here, before the request is authorized or forwarded.
    // A protocol-floor frame (`ping`, `server/discover`) yields no target and stays a plain
    // `http:request`.
    let mcp_target: Option<(&str, McpTarget)> = match state.mcp_server_for(&connect.host) {
        Some(server) => match McpTarget::of_http_request(req.body.as_bytes()) {
            Ok(Some(target)) => Some((server, target)),
            Ok(None) => None,
            Err(error) => {
                let reason = format!("MCP frame refused: {error}");
                state.audit.push(NetworkAuditEvent::deny(
                    &connect.host,
                    connect.port,
                    reason.clone(),
                    correlation.clone(),
                ));
                emit_decision(
                    state,
                    DecisionSubject {
                        host: &connect.host,
                        port: connect.port,
                        method: &request_method,
                        path: &workload_path,
                    },
                    AuditDecision::Deny,
                    &reason,
                    correlation,
                );
                write_trusted_diagnostic(client_writer, &request_method, 403, b"MCP frame refused");
                return Ok(None);
            }
        },
        None => None,
    };

    // The serialized request carries the credential the request leg just attached, so the buffer is
    // wiped on drop. This is the last copy on the byte path before the transport takes it (which is
    // not `Zeroize`-aware, a known residual).
    // Forward the CANONICAL frame, not the raw one. The local door rewrites a
    // `resources/read` uri at ingress so it judges and forwards ONE identity; the remote door must do
    // the same, or a respelling this classifier judged as one identity would be FETCHED as another by
    // the upstream server. Only `resources/read` whose canonical form differs is rewritten; every
    // other frame (and an unparseable body) forwards byte-identical.
    let forwarded_body: Cow<[u8]> = match &mcp_target {
        Some((_, target)) if matches!(target.identity, McpTargetIdentity::Resource(_)) => {
            canonicalize_mcp_frame(req.body.as_bytes())
                .map_or_else(|| Cow::Borrowed(req.body.as_bytes()), Cow::Owned)
        }
        _ => Cow::Borrowed(req.body.as_bytes()),
    };
    // The `101` must answer the handshake as forwarded, after the request leg ran.
    let expected = websocket_key
        .as_deref()
        .map(|key| websocket::Expected::new(key, &req.headers));
    let hop = match expected {
        Some(_) => Hop::WebSocket,
        None => Hop::Close,
    };
    let mut prepared_request = Zeroizing::new(Vec::new());
    http1::write_request(
        &mut *prepared_request,
        &request_method,
        &fwd_target,
        &req.headers,
        &forwarded_body,
        hop,
    )?;
    let request_attempt = EffectAttempt::HttpRequest {
        host: &connect.host,
        port: connect.port,
        method: &request_method,
        path: &workload_path,
        body_bytes: forwarded_body.len(),
        intercepted,
        upgrade: expected.as_ref().map(|_| websocket::PROTOCOL),
        mcp: mcp_target.as_ref().map(|(server, target)| {
            let server = *server;
            match &target.identity {
                McpTargetIdentity::Tool(tool) => McpFrame::ToolCall {
                    server,
                    tool: tool.as_str(),
                    arguments: target.arguments.as_str(),
                },
                McpTargetIdentity::Prompt(prompt) => McpFrame::PromptGet {
                    server,
                    prompt: prompt.as_str(),
                },
                McpTargetIdentity::Resource(uri) => McpFrame::ResourceRead {
                    server,
                    uri: uri.as_str(),
                },
                McpTargetIdentity::Method(method) => McpFrame::List {
                    server,
                    method: method.as_str(),
                },
            }
        }),
    };
    let request_permit = match claim_effect(state, &request_attempt) {
        Ok(permit) => permit,
        Err(error) => {
            let reason = format!("request effect interception failed: {error}");
            state.audit.push(NetworkAuditEvent::deny(
                &connect.host,
                connect.port,
                reason.clone(),
                correlation.clone(),
            ));
            emit_decision(
                state,
                DecisionSubject {
                    host: &connect.host,
                    port: connect.port,
                    method: req.method.as_deref().unwrap_or_default(),
                    path: &workload_path,
                },
                AuditDecision::Deny,
                &reason,
                correlation.clone(),
            );
            write_interceptor_error(
                client_writer,
                &request_method,
                &error,
                state
                    .mcp_server_for(&connect.host)
                    .map(|_| req.body.as_bytes()),
            );
            return Ok(None);
        }
    };
    emit_decision(
        state,
        DecisionSubject {
            host: &connect.host,
            port: connect.port,
            method: &request_method,
            path: &workload_path,
        },
        AuditDecision::Allow,
        &allow_reason,
        correlation.clone(),
    );
    // The request permit is consumed at reply time, or when no reply comes.
    let (request_permit, request_bytes) = deliver_or_record_failure(
        upstream.get_mut(),
        &prepared_request,
        request_permit,
        "upstream request",
    )?;

    // --- Response leg: read, evaluate+apply, return ---
    let parsed_res = match http1::read_response(
        &mut *upstream,
        &request_method,
        state.config.response_limits.max_body_bytes,
        expected.as_ref(),
    ) {
        Ok(parsed_res) => parsed_res,
        Err(failure) => {
            let outcome = match failure.status {
                Some(status) => EffectOutcome::Replied {
                    accepted_bytes: request_bytes,
                    status,
                },
                None => EffectOutcome::Completed(request_bytes),
            };
            request_permit.record_outcome(outcome).map_err(|error| {
                ProxyError::Io(format!(
                    "recording upstream request outcome after a failed reply: {error}"
                ))
            })?;
            if expected.is_some() && failure.status == Some(101) {
                let reason = match failure.error {
                    ProxyError::Intercept(reason) => reason,
                    other => other.to_string(),
                };
                let reason = format!("websocket: {reason}");
                state.audit.push(NetworkAuditEvent::deny(
                    &connect.host,
                    connect.port,
                    reason.clone(),
                    correlation.clone(),
                ));
                emit_decision(
                    state,
                    DecisionSubject {
                        host: &connect.host,
                        port: connect.port,
                        method: &request_method,
                        path: &workload_path,
                    },
                    AuditDecision::Deny,
                    &reason,
                    correlation,
                );
                write_trusted_diagnostic(
                    client_writer,
                    &request_method,
                    502,
                    b"WebSocket upgrade response refused",
                );
                return Ok(None);
            }
            return Err(failure.error);
        }
    };
    request_permit
        .record_outcome(EffectOutcome::Replied {
            accepted_bytes: request_bytes,
            status: parsed_res.status,
        })
        .map_err(|error| {
            ProxyError::Io(format!(
                "recording upstream request outcome after the reply: {error}"
            ))
        })?;
    // Move, don't clone — `parsed_res` is dead after this; the body can be large.
    let mut res = InterceptedResponse::http(
        parsed_res.status,
        parsed_res.headers,
        BodyRef::Bytes(parsed_res.body),
    );
    // Only the gateway claims a refusal, so a relayed response never carries the marker. An origin
    // that set it would otherwise make a permitted answer read as a denial, with its own first body
    // line as the reason.
    res.headers.remove(crate::PROXY_ORIGIN_HEADER);

    let redirect_location = match response_leg::evaluate_and_apply(&state.controls, &mut res, &cx) {
        ResponseDecision::Block(reason) => {
            let reason = reason.to_string(); // format once, use for both audit sinks
            state.audit.push(NetworkAuditEvent::deny(
                &connect.host,
                connect.port,
                reason.clone(),
                correlation.clone(),
            ));
            write_trusted_diagnostic(
                client_writer,
                &request_method,
                403,
                b"response blocked by egress control",
            );
            return Ok(None);
        }
        ResponseDecision::RedirectReentry(location) => Some(location),
        ResponseDecision::Return => None,
    };

    // Lazy remote MCP discovery: on the workload's `tools/list` to a configured MCP server, stage
    // the response catalog into the authority so the server's per-tool actions reach runtime
    // (docs/design/decisions.md#remote-tool-schemas-are-discovered-at-runtime-in-memory).
    // Best-effort: a staging failure warns and the catalog still returns.
    if let Some((server, target)) = &mcp_target
        && target.method() == "tools/list"
        && let Err(error) = state.effect_interceptor.stage_mcp_catalog(
            server,
            McpListReply {
                session: req.headers.get("mcp-session-id"),
                cursor: list_cursor(req.body.as_bytes()).as_deref(),
                body: res.body.as_bytes(),
            },
        )
    {
        eprintln!(
            "strands-box: warning: staging remote MCP catalog for {server:?} failed: {error}"
        );
    }

    // Serialize only after response controls and leakback scrubbing have finished, then claim the
    // release immediately before the governed bytes are delivered to the workload.
    let mut prepared_response = Vec::new();
    http1::write_response(
        &mut prepared_response,
        &request_method,
        res.status,
        &res.headers,
        res.body.as_bytes(),
    )?;
    let response_attempt = EffectAttempt::ResponseRelease {
        host: &connect.host,
        port: connect.port,
        method: &request_method,
        path: &workload_path,
        status: res.status,
        body_bytes: res.body.as_bytes().len(),
    };
    let response_permit = match claim_effect(state, &response_attempt) {
        Ok(permit) => permit,
        Err(error) => {
            let reason = format!("response release interception failed: {error}");
            state.audit.push(NetworkAuditEvent::deny(
                &connect.host,
                connect.port,
                reason.clone(),
                correlation.clone(),
            ));
            write_interceptor_error(client_writer, &request_method, &error, None);
            return Ok(None);
        }
    };

    if let Some(location) = redirect_location {
        // The client, not the proxy, follows this redirect and therefore re-enters all connection
        // checks. The already-scrubbed redirect response still crosses the governed release boundary.
        let reason = format!("cross-host redirect not followed: {location}");
        state.audit.push(NetworkAuditEvent::deny(
            &connect.host,
            connect.port,
            reason.clone(),
            correlation.clone(),
        ));
    } else {
        state.audit.push(NetworkAuditEvent::allow(
            &connect.host,
            connect.port,
            correlation.clone(),
        ));
    }

    deliver_effect(
        client_writer,
        &prepared_response,
        response_permit,
        "governed response",
    )?;
    Ok(
        (expected.is_some() && res.status == 101).then_some(Upgraded {
            cx,
            credentialed,
            correlation,
            path: workload_path,
        }),
    )
}

/// Forward a plain-HTTP (non-TLS) exchange to an already-open plaintext upstream.
///
/// A thin transport wrapper mirroring [`intercept_tls`] without any TLS: the request was already
/// read (`parsed`) and `origin_target` is its origin-form target (`/path?query`) from the absolute
/// URL. It builds the boundary request and hands the shared legs to [`run_l7_legs`], which
/// canonicalizes the path and refuses a credential on it. Plain HTTP has no CONNECT authority to bind
/// against, so the post-mutation re-check is a no-op.
pub(super) fn forward_plain(
    client_writer: &mut TcpStream,
    upstream: TcpStream,
    connect: &ConnectRequest,
    parsed: http1::ParsedRequest,
    origin_target: String,
    state: &SharedState,
    correlation: RequestId,
) -> Result<()> {
    let mut upstream_buf =
        BufReader::new(Bounded::new(upstream, state.config.upstream_read_deadline));

    let mut target = Target::new(connect.host.clone(), connect.port);
    let (path, query) = split_target(&origin_target);
    target.path = path;
    target.query = query;

    let mut req = InterceptedRequest {
        target,
        method: Some(parsed.method),
        headers: parsed.headers,
        body: BodyRef::Bytes(parsed.body),
        advisory_note: None,
    };

    // Bind the `Host` header to the URL authority the gateway judged. A plain-HTTP request carries its
    // destination twice — in the absolute-form request line and in `Host` — and the workload controls
    // both. The TLS path re-checks that they agree (`validate_request_binding`); the plain path has no
    // CONNECT authority to bind against, so it normalizes instead: rewrite `Host` to the URL host, so
    // the destination the box authorized is the one the upstream routes on (no vhost smuggling).
    //
    // The port is omitted only for 80 — plain HTTP's sole default. `http://host:443/` keeps `:443`,
    // because 443 is not the default under the `http` scheme, and a dropped port would make `Host`
    // name a different authority than the one authorized.
    let host_value = if connect.port == 80 {
        connect.host.clone()
    } else {
        format!("{}:{}", connect.host, connect.port)
    };
    req.headers.set("Host", host_value);

    let upgraded = run_l7_legs(
        connect,
        req,
        parsed.upgrade,
        &mut upstream_buf,
        client_writer,
        state,
        correlation,
        false, // plain HTTP was never encrypted — not TLS-intercepted
        |_method, _target, _headers| Ok(()),
    )?;
    match upgraded {
        None => Ok(()),
        Some(_) => Err(ProxyError::Intercept(
            "a WebSocket on a plaintext request has no relay".to_string(),
        )),
    }
}

/// Wrap the already-open pinned upstream socket in the additive TLS trust bundle.
fn start_upstream_tls<S: Read + Write>(
    host: &str,
    tcp: S,
    state: &SharedState,
) -> Result<StreamOwned<ClientConnection, S>> {
    let server_name = host
        .to_string()
        .try_into()
        .map_err(|_| ProxyError::UpstreamConnect(format!("invalid upstream host {host}")))?;
    let conn = ClientConnection::new(state.upstream_config.clone(), server_name)
        .map_err(|e| ProxyError::Intercept(format!("upstream TLS init: {e}")))?;
    Ok(StreamOwned::new(conn, tcp))
}

/// An upstream stream whose reads and writes fail once the exchange's deadline has passed.
struct Bounded<S> {
    inner: S,
    deadline: Instant,
}

impl<S> Bounded<S> {
    fn new(inner: S, within: Duration) -> Self {
        Self {
            inner,
            deadline: Instant::now() + within,
        }
    }

    /// The stream without its deadline, for the relay after a `101`.
    fn into_inner(self) -> S {
        self.inner
    }

    fn check(&self, direction: &'static str) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("upstream {direction} deadline passed"),
            ));
        }
        Ok(())
    }
}

impl<S: Read> Read for Bounded<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.check("read")?;
        self.inner.read(buf)
    }
}

/// The most bytes one upstream write hands the inner stream.
const BOUNDED_WRITE_CHUNK: usize = 64 * 1024;

impl<S: Write> Write for Bounded<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check("write")?;
        // Split a large plain-HTTP write, as TLS already splits one into records.
        self.inner.write(&buf[..buf.len().min(BOUNDED_WRITE_CHUNK)])
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Claim one effect from the authorization authority.
fn claim_effect(
    state: &SharedState,
    attempt: &EffectAttempt<'_>,
) -> io::Result<ClaimedEffectPermit> {
    state
        .effect_interceptor
        .intercept(attempt)
        .map(ClaimedEffectPermit::new)
}

/// Write an effect refusal or a static interceptor failure.
pub(super) fn write_interceptor_error<W: Write>(
    stream: &mut W,
    request_method: &str,
    error: &io::Error,
    mcp_request: Option<&[u8]>,
) {
    if error.kind() != io::ErrorKind::PermissionDenied {
        write_trusted_diagnostic(
            stream,
            request_method,
            502,
            b"effect interceptor unavailable",
        );
        return;
    }
    let message = super::diagnostic::denial_message(error);
    if let Some(response) = mcp_request.and_then(|request| mcp_denial_response(request, &message)) {
        let mut headers = proxy_originated_headers();
        headers.set("Content-Type", "application/json".to_string());
        let _ = http1::write_response(stream, request_method, 403, &headers, response.as_bytes());
        let _ = stream.flush();
    } else {
        write_trusted_diagnostic(stream, request_method, 403, message.as_bytes());
    }
}

/// Write a proxy-originated diagnostic outside the response-release lifecycle.
fn write_trusted_diagnostic<W: Write>(
    stream: &mut W,
    request_method: &str,
    status: u16,
    body: &[u8],
) {
    let _ = http1::write_response(
        stream,
        request_method,
        status,
        &proxy_originated_headers(),
        body,
    );
    let _ = stream.flush();
}

/// The headers every response the gateway originates carries, and no relayed response does.
fn proxy_originated_headers() -> crate::boundary::HeaderMap {
    let mut headers = crate::boundary::HeaderMap::new();
    headers.set(
        crate::PROXY_ORIGIN_HEADER,
        crate::PROXY_ORIGIN_VALUE.to_string(),
    );
    headers
}

/// Deliver prepared bytes and consume the claimed permit with the observed truth.
fn deliver_effect<W: Write>(
    stream: &mut W,
    prepared: &[u8],
    permit: ClaimedEffectPermit,
    description: &str,
) -> Result<()> {
    let (permit, accepted_bytes) =
        deliver_or_record_failure(stream, prepared, permit, description)?;
    permit
        .record_outcome(EffectOutcome::Completed(accepted_bytes))
        .map_err(|error| {
            ProxyError::Io(format!(
                "recording {description} outcome after I/O: {error}"
            ))
        })
}

/// Deliver prepared bytes; a failure consumes the permit, and a delivery hands it back with the
/// accepted count so the caller records the outcome it observes.
fn deliver_or_record_failure<W: Write>(
    stream: &mut W,
    prepared: &[u8],
    permit: ClaimedEffectPermit,
    description: &str,
) -> Result<(ClaimedEffectPermit, usize)> {
    match http1::write_prepared_and_flush(stream, prepared) {
        Ok(accepted_bytes) => Ok((permit, accepted_bytes)),
        Err(failure) => {
            let error_kind = failure.error.kind();
            let error_message = failure.error.to_string();
            let outcome = if failure.during_flush {
                EffectOutcome::Indeterminate {
                    accepted_bytes: failure.accepted_bytes,
                }
            } else if failure.accepted_bytes == 0 {
                EffectOutcome::Failed {
                    accepted_bytes: 0,
                    error_kind,
                }
            } else {
                EffectOutcome::Partial {
                    accepted_bytes: failure.accepted_bytes,
                    error_kind,
                }
            };
            permit.record_outcome(outcome).map_err(|error| {
                ProxyError::Io(format!(
                    "recording failed {description} outcome after I/O: {error}"
                ))
            })?;
            Err(ProxyError::Io(format!(
                "delivering {description}: {error_message}"
            )))
        }
    }
}

/// What an egress decision is *about* — the non-secret identity of one exchange.
pub(super) struct DecisionSubject<'a> {
    pub(super) host: &'a str,
    pub(super) port: u16,
    pub(super) method: &'a str,
    pub(super) path: &'a str,
}

/// Emit one final egress decision.
pub(super) fn emit_decision(
    state: &SharedState,
    subject: DecisionSubject<'_>,
    decision: AuditDecision,
    reason: &str,
    correlation: RequestId,
) {
    state.emitter.emit(EgressDecision {
        host: subject.host.to_string(),
        port: subject.port,
        method: subject.method.to_string(),
        path: subject.path.to_string(),
        decision,
        reason: reason.to_string(),
        correlation,
    });
}

/// The RFC 3986 normal form of an origin-form request path, `/` when it is empty, or why it is refused.
fn canonicalize_request_path(path: &str) -> std::result::Result<String, String> {
    let normal = normalize_path(path)?;
    Ok(if normal.is_empty() {
        "/".to_string()
    } else {
        normal
    })
}

/// A request the gateway refuses before any request leg runs.
struct RefusedRequest<'a> {
    method: Option<&'a str>,
    path: &'a str,
    reason: &'a str,
    status: u16,
    diagnostic: &'a [u8],
}

/// Record a refused request and answer the client with its status.
fn refuse_request(
    state: &SharedState,
    connect: &ConnectRequest,
    client_writer: &mut impl Write,
    refused: RefusedRequest<'_>,
    correlation: RequestId,
) {
    state.audit.push(NetworkAuditEvent::deny(
        &connect.host,
        connect.port,
        refused.reason.to_string(),
        correlation.clone(),
    ));
    emit_decision(
        state,
        DecisionSubject {
            host: &connect.host,
            port: connect.port,
            method: refused.method.unwrap_or_default(),
            path: refused.path,
        },
        AuditDecision::Deny,
        refused.reason,
        correlation,
    );
    write_trusted_diagnostic(
        client_writer,
        refused.method.unwrap_or("GET"),
        refused.status,
        refused.diagnostic,
    );
}

/// The `params.cursor` a `tools/list` request names.
fn list_cursor(body: &[u8]) -> Option<String> {
    let request: serde_json::Value = serde_json::from_slice(body).ok()?;
    request
        .get("params")?
        .get("cursor")?
        .as_str()
        .map(str::to_string)
}

/// Split an origin-form request target into `(path, query)`.
fn split_target(target: &str) -> (String, String) {
    match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.to_string(), String::new()),
    }
}

/// Reconstruct the origin-form target (`path[?query]`) from a (possibly mutated) [`Target`].
fn reconstruct_target(target: &Target) -> String {
    if target.query.is_empty() {
        target.path.clone()
    } else {
        format!("{}?{}", target.path, target.query)
    }
}

/// Require the inner HTTP request to name the authority admitted by CONNECT.
fn validate_request_binding(
    connect: &ConnectRequest,
    method: &str,
    target: &str,
    headers: &HeaderMap,
) -> Result<()> {
    if target == "*" {
        if !method.eq_ignore_ascii_case("OPTIONS") {
            return Err(ProxyError::ControlDenied(
                "asterisk-form request target is only valid for OPTIONS".to_string(),
            ));
        }
    } else if !target.starts_with('/') || target.starts_with("//") {
        return Err(ProxyError::ControlDenied(
            "intercepted TLS requires an origin-form request target".to_string(),
        ));
    }

    let mut hosts = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("host"));
    let Some((_, host_value)) = hosts.next() else {
        return Err(ProxyError::ControlDenied(
            "intercepted HTTP/1 request is missing Host".to_string(),
        ));
    };
    if hosts.next().is_some() || host_value.contains(',') {
        return Err(ProxyError::ControlDenied(
            "intercepted HTTP/1 request has multiple Host authorities".to_string(),
        ));
    }

    let Some((host, port)) = parse_authority(host_value, Some(443)) else {
        return Err(ProxyError::ControlDenied(
            "intercepted HTTP/1 request has a malformed Host authority".to_string(),
        ));
    };
    if port != connect.port || !same_host(&host, &connect.host) {
        return Err(ProxyError::ControlDenied(
            "intercepted HTTP/1 Host does not match CONNECT authority".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effect::EffectPermit;

    /// **A gateway-originated refusal carries the marker.** The client turns the marker into a
    /// denial, so a refusal this gateway writes must name itself.
    #[test]
    fn a_gateway_refusal_carries_the_marker() {
        let mut response = Vec::new();
        write_interceptor_error(
            &mut response,
            "GET",
            &io::Error::new(io::ErrorKind::PermissionDenied, "refused"),
            None,
        );
        let response = String::from_utf8(response).unwrap();
        let marker = format!(
            "{}: {}",
            crate::PROXY_ORIGIN_HEADER,
            crate::PROXY_ORIGIN_VALUE
        );
        assert!(
            response
                .to_ascii_lowercase()
                .contains(&marker.to_ascii_lowercase()),
            "the gateway's own refusal names itself: {response}"
        );
    }

    #[test]
    fn interceptor_diagnostics_bound_and_escape_denials_without_exposing_failures() {
        let frame = br#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#;
        for request in [None, Some(frame.as_slice())] {
            let error = io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("refused\n\u{1b}\u{202e}{}", "🦀".repeat(5000)),
            );
            let mut response = Vec::new();
            write_interceptor_error(&mut response, "POST", &error, request);
            let response = String::from_utf8(response).unwrap();
            let (head, body) = response.split_once("\r\n\r\n").unwrap();
            assert!(head.starts_with("HTTP/1.1 403 "));
            let decoded: serde_json::Value;
            let message = if request.is_some() {
                decoded = serde_json::from_str(body).unwrap();
                decoded["error"]["message"].as_str().unwrap()
            } else {
                body
            };
            assert!(message.starts_with(r"refused\n\u{1b}\u{202e}"));
            assert!(message.ends_with("..."));
            assert!(message.len() <= 8192);
            assert!(!message.chars().any(char::is_control));
            assert!(!message.contains('\u{202e}'));

            let mut response = Vec::new();
            write_interceptor_error(
                &mut response,
                "POST",
                &io::Error::other("private backend failure"),
                request,
            );
            let response = String::from_utf8(response).unwrap();
            assert!(response.starts_with("HTTP/1.1 502 "));
            assert!(response.ends_with("effect interceptor unavailable"));
            assert!(!response.contains("private"));
        }
        let mut response = Vec::new();
        write_interceptor_error(
            &mut response,
            "HEAD",
            &io::Error::new(io::ErrorKind::PermissionDenied, "refused"),
            None,
        );
        let response = String::from_utf8(response).unwrap();
        assert!(response.ends_with("\r\n\r\n"));
    }

    /// FIX B (finding 1): the judged path is percent-decoded (unreserved only) so `/%61dmin` cannot
    /// dodge a `forbid "/admin*"` while the origin routes to `/admin`.
    #[test]
    fn canonicalize_decodes_unreserved_percent_escapes() {
        assert_eq!(canonicalize_request_path("/%61dmin"), "/admin");
        assert_eq!(canonicalize_request_path("/%61%64min"), "/admin");
    }

    /// The canonical path of a spelling the test expects to be valid.
    fn canonicalize_request_path(path: &str) -> String {
        super::canonicalize_request_path(path).unwrap()
    }

    #[test]
    fn canonicalize_request_path_is_idempotent() {
        for spelling in crate::mcp::generated_spellings() {
            for path in [spelling.clone(), format!("/{spelling}")] {
                if let Ok(once) = super::canonicalize_request_path(&path) {
                    assert_eq!(
                        super::canonicalize_request_path(&once),
                        Ok(once.clone()),
                        "{path:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_path_that_is_not_rfc_3986_is_refused() {
        for path in ["/%", "/%4", "/%zz", "/a%%41", "/a#b", "/a b", "/\u{e9}"] {
            assert!(super::canonicalize_request_path(path).is_err(), "{path:?}");
        }
    }

    /// FIX B: dot-segments are removed, so `/tmp/../etc/passwd` cannot dodge a `forbid` on `/etc/*`.
    #[test]
    fn canonicalize_removes_dot_segments() {
        assert_eq!(
            canonicalize_request_path("/tmp/../etc/passwd"),
            "/etc/passwd"
        );
        assert_eq!(canonicalize_request_path("/a/./b"), "/a/b");
        assert_eq!(canonicalize_request_path("/a/b/../../c"), "/c");
    }

    /// FIX B: a reserved octet stays encoded — `%2F` must NOT become `/`, or segment structure would
    /// change and open a different gap.
    #[test]
    fn canonicalize_keeps_reserved_octets_encoded() {
        assert_eq!(canonicalize_request_path("/a%2Fb"), "/a%2Fb");
        // hex is normalized to uppercase, but the octet stays encoded.
        assert_eq!(canonicalize_request_path("/a%2fb"), "/a%2Fb");
    }

    /// FIX B: canonicalization is path-only; the query rides through `split_target`/`reconstruct`
    /// untouched (a credential may live in the query — kept out of the judged path).
    #[test]
    fn canonicalize_is_path_only_query_untouched() {
        let (path, query) = split_target("/x?%61=%62");
        assert_eq!(canonicalize_request_path(&path), "/x");
        assert_eq!(query, "%61=%62", "the query is not canonicalized");
        let mut target = Target::new("h".to_string(), 443);
        target.path = canonicalize_request_path(&path);
        target.query = query;
        assert_eq!(
            reconstruct_target(&target),
            "/x?%61=%62",
            "the forwarded target keeps the canonical path and the verbatim query"
        );
    }

    fn connect(host: &str, port: u16) -> ConnectRequest {
        ConnectRequest {
            host: host.to_string(),
            port,
            proxy_authorization: None,
        }
    }

    fn headers(values: &[&str]) -> HeaderMap {
        HeaderMap::from_pairs(
            values
                .iter()
                .map(|value| ("Host".to_string(), (*value).to_string())),
        )
    }

    #[test]
    fn request_binding_accepts_case_default_port_and_bracketed_ipv6() {
        assert!(
            validate_request_binding(
                &connect("Api.Example.com", 443),
                "GET",
                "/v1",
                &headers(&["api.example.COM"]),
            )
            .is_ok()
        );
        assert!(
            validate_request_binding(
                &connect("2001:db8::1", 8443),
                "GET",
                "/v1",
                &headers(&["[2001:db8::1]:8443"]),
            )
            .is_ok()
        );
    }

    #[test]
    fn request_binding_rejects_authority_pivots() {
        let bound = connect("api.example.com", 443);
        for (target, hosts) in [
            ("/", vec!["metadata.google.internal"]),
            ("/", vec!["api.example.com", "metadata.google.internal"]),
            (
                "http://169.254.169.254/latest/meta-data",
                vec!["api.example.com"],
            ),
            (
                "//169.254.169.254/latest/meta-data",
                vec!["api.example.com"],
            ),
        ] {
            assert!(
                validate_request_binding(&bound, "GET", target, &headers(&hosts)).is_err(),
                "target={target:?}, hosts={hosts:?}"
            );
        }
    }
    use std::sync::{Arc, Mutex};

    struct RecordingPermit {
        outcomes: Arc<Mutex<Vec<EffectOutcome>>>,
    }

    impl EffectPermit for RecordingPermit {
        fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
            self.outcomes.lock().unwrap().push(outcome);
            Ok(())
        }

        fn mark_indeterminate(self: Box<Self>) {
            panic!("delivery tests always report a terminal outcome");
        }
    }

    fn permit(outcomes: &Arc<Mutex<Vec<EffectOutcome>>>) -> ClaimedEffectPermit {
        ClaimedEffectPermit::new(Box::new(RecordingPermit {
            outcomes: outcomes.clone(),
        }))
    }

    struct FailingWriter {
        limit: usize,
        accepted: usize,
        fail_flush: bool,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.accepted == self.limit {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "write failed"));
            }
            let count = bytes.len().min(self.limit - self.accepted);
            self.accepted += count;
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::new(io::ErrorKind::TimedOut, "flush failed"))
            } else {
                Ok(())
            }
        }
    }

    fn recorded_outcome(writer: &mut impl Write, bytes: &[u8]) -> (Result<()>, EffectOutcome) {
        let outcomes = Arc::new(Mutex::new(Vec::new()));
        let result = deliver_effect(writer, bytes, permit(&outcomes), "test message");
        let outcome = outcomes.lock().unwrap()[0];
        (result, outcome)
    }

    #[test]
    fn delivery_records_completed_bytes() {
        let mut writer = Vec::new();
        let (result, outcome) = recorded_outcome(&mut writer, b"message");
        assert!(result.is_ok());
        assert_eq!(outcome, EffectOutcome::Completed(7));
    }

    #[test]
    fn delivery_records_zero_byte_failure() {
        let mut writer = FailingWriter {
            limit: 0,
            accepted: 0,
            fail_flush: false,
        };
        let (result, outcome) = recorded_outcome(&mut writer, b"message");
        assert!(result.is_err());
        assert_eq!(
            outcome,
            EffectOutcome::Failed {
                accepted_bytes: 0,
                error_kind: io::ErrorKind::BrokenPipe,
            }
        );
    }

    #[test]
    fn delivery_records_partial_write() {
        let mut writer = FailingWriter {
            limit: 3,
            accepted: 0,
            fail_flush: false,
        };
        let (result, outcome) = recorded_outcome(&mut writer, b"message");
        assert!(result.is_err());
        assert_eq!(
            outcome,
            EffectOutcome::Partial {
                accepted_bytes: 3,
                error_kind: io::ErrorKind::BrokenPipe,
            }
        );
    }

    #[test]
    fn delivery_records_indeterminate_flush() {
        let mut writer = FailingWriter {
            limit: usize::MAX,
            accepted: 0,
            fail_flush: true,
        };
        let (result, outcome) = recorded_outcome(&mut writer, b"message");
        assert!(result.is_err());
        assert_eq!(outcome, EffectOutcome::Indeterminate { accepted_bytes: 7 });
    }
}
