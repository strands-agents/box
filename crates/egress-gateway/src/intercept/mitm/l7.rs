//! The L7 interception path: run the request/response legs, forward.

use std::borrow::Cow;
use std::io;
use std::net::TcpStream;

use crate::audit::RequestId;

use super::connect::{ConnectRequest, parse_authority, same_host};
use super::request_leg::{self, RequestDecision};
use super::response_leg::{self, ResponseDecision};
use super::{SharedState, http1};
use crate::audit::Decision as AuditDecision;
use crate::audit::{EgressDecision, NetworkAuditEvent};
use crate::boundary::{BodyRef, HeaderMap, InterceptedRequest, InterceptedResponse, Target};
use crate::capability::CapabilityContext;
use crate::client::http::Upstream;
use crate::effect::{ClaimedEffectPermit, EffectAttempt, McpFrame, McpListReply};
use crate::error::{ProxyError, Result};
use crate::mcp::{
    McpTarget, McpTargetIdentity, canonicalize_mcp_frame, mcp_denial_response, normalize_path,
};

/// Check the CONNECT binding of a request read in a TLS tunnel, then run [`run_l7_legs`].
pub(crate) async fn forward_tls(
    parsed: http1::ParsedRequest,
    upstream: TcpStream,
    connect: &ConnectRequest,
    state: &SharedState,
    correlation: RequestId,
) -> Result<WorkloadResponse> {
    // Check the upstream's TLS name before any request effect.
    let server_name =
        rustls::pki_types::ServerName::try_from(connect.host.clone()).map_err(|_| {
            ProxyError::UpstreamConnect(format!("invalid upstream host {}", connect.host))
        })?;
    let upstream = Upstream::new(upstream, Some(server_name), state);
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
        return Ok(WorkloadResponse::refusal(
            error.http_status(),
            b"request authority rejected",
        ));
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
    run_l7_legs(
        connect,
        req,
        upstream,
        state,
        correlation,
        |method, target, headers| validate_request_binding(connect, method, target, headers),
    )
    .await
}

/// Run the request and response legs, and return the response for the workload. `revalidate`
/// re-checks the CONNECT binding after the credential edit; plain HTTP passes a no-op.
async fn run_l7_legs(
    connect: &ConnectRequest,
    mut req: InterceptedRequest,
    upstream: Upstream,
    state: &SharedState,
    correlation: RequestId,
    revalidate: impl FnOnce(&str, &str, &HeaderMap) -> Result<()>,
) -> Result<WorkloadResponse> {
    let intercepted = upstream.is_tls();
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
            return Ok(refuse_request(
                state,
                connect,
                RefusedRequest {
                    method: req.method.as_deref(),
                    path: &req.target.path,
                    reason: &reason,
                    diagnostic: b"request path is not a valid address",
                },
                correlation,
            ));
        }
    };

    // A secret rides only TLS: refuse on the same canonical target the credential match below sees.
    if !intercepted && state.controls.matches_any(&req.target.as_destination()) {
        return Ok(refuse_request(
            state,
            connect,
            RefusedRequest {
                method: req.method.as_deref(),
                path: &req.target.path,
                reason: "credential would attach on a plaintext request; refused — a secret must ride TLS",
                diagnostic: b"credential not permitted on a plaintext request",
            },
            correlation,
        ));
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

    match request_leg::evaluate_and_apply(&state.controls, &mut req, &cx) {
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
            return Ok(WorkloadResponse::refusal(403, b"blocked by egress control"));
        }
        RequestDecision::Forward => {}
    }

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
        return Ok(WorkloadResponse::refusal(
            error.http_status(),
            b"request authority rejected",
        ));
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
                return Ok(WorkloadResponse::refusal(403, b"MCP frame refused"));
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
    let prepared_request = http1::write_request(
        &request_method,
        &fwd_target,
        &req.headers,
        forwarded_body.len(),
    )?;
    let request_attempt = EffectAttempt::HttpRequest {
        host: &connect.host,
        port: connect.port,
        method: &request_method,
        path: &workload_path,
        body_bytes: forwarded_body.len(),
        intercepted,
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
            return Ok(interceptor_error(
                &error,
                state
                    .mcp_server_for(&connect.host)
                    .map(|_| req.body.as_bytes()),
            ));
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
    let (outcome, response) = upstream
        .send(
            state,
            &request_method,
            prepared_request.as_bytes(),
            &forwarded_body,
        )
        .await;
    request_permit
        .record_outcome(outcome)
        .map_err(|error| ProxyError::Io(format!("recording upstream request outcome: {error}")))?;

    // --- Response leg: read, evaluate+apply, return ---
    let parsed_res = response?;
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
            return Ok(WorkloadResponse::refusal(
                403,
                b"response blocked by egress control",
            ));
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

    // Wait until response controls and leakback scrubbing have finished, then claim the
    // release immediately before the governed bytes are delivered to the workload.
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
            return Ok(interceptor_error(&error, None));
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

    Ok(WorkloadResponse {
        status: res.status,
        reason: None,
        headers: res.headers,
        body: match res.body {
            BodyRef::Bytes(body) => body,
            BodyRef::Empty => Vec::new(),
        },
        release: Some(response_permit),
        header_case: parsed_res.header_case,
    })
}

/// Run [`run_l7_legs`] for a plain-HTTP request; `origin_target` is its `/path?query`.
pub(crate) async fn forward_plain(
    upstream: TcpStream,
    connect: &ConnectRequest,
    parsed: http1::ParsedRequest,
    origin_target: String,
    state: &SharedState,
    correlation: RequestId,
) -> Result<WorkloadResponse> {
    let upstream = Upstream::new(upstream, None, state);

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

    run_l7_legs(
        connect,
        req,
        upstream,
        state,
        correlation,
        |_method, _target, _headers| Ok(()),
    )
    .await
}

/// The response to the workload: a gateway diagnostic, or the governed response.
pub(crate) struct WorkloadResponse {
    pub(crate) status: u16,
    /// A reason phrase in place of the standard one.
    pub(crate) reason: Option<&'static str>,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
    /// The claimed release of a governed response, recorded once hyper has written it.
    pub(crate) release: Option<ClaimedEffectPermit>,
    /// The upstream's header case. Without it, hyper writes header names in lowercase.
    pub(crate) header_case: hyper::http::Extensions,
}

impl WorkloadResponse {
    /// A proxy-originated diagnostic, outside the response-release lifecycle.
    fn refusal(status: u16, body: &[u8]) -> Self {
        Self {
            reason: None,
            headers: proxy_originated_headers(),
            body: body.to_vec(),
            ..Self::bare(status)
        }
    }

    /// A proxy-level refusal with no body, with the gateway's lowercase reason phrase.
    pub(crate) fn bare(status: u16) -> Self {
        let reason = match status {
            400 => Some("bad request"),
            407 => Some("proxy authentication required"),
            502 => Some("bad gateway"),
            _ => None,
        };
        Self {
            status,
            reason,
            headers: HeaderMap::new(),
            body: Vec::new(),
            release: None,
            header_case: hyper::http::Extensions::new(),
        }
    }

    /// The CONNECT acknowledgement: the tunnel is open.
    pub(crate) fn connected() -> Self {
        Self {
            reason: Some("Connection Established"),
            ..Self::bare(200)
        }
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

/// The response to an effect refusal or a static interceptor failure.
pub(super) fn interceptor_error(error: &io::Error, mcp_request: Option<&[u8]>) -> WorkloadResponse {
    if error.kind() != io::ErrorKind::PermissionDenied {
        return WorkloadResponse::refusal(502, b"effect interceptor unavailable");
    }
    let message = super::diagnostic::denial_message(error);
    if let Some(response) = mcp_request.and_then(|request| mcp_denial_response(request, &message)) {
        let mut refusal = WorkloadResponse::refusal(403, response.as_bytes());
        refusal
            .headers
            .set("Content-Type", "application/json".to_string());
        refusal
    } else {
        WorkloadResponse::refusal(403, message.as_bytes())
    }
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

/// What an egress decision is *about* — the non-secret identity of one exchange.
struct DecisionSubject<'a> {
    host: &'a str,
    port: u16,
    method: &'a str,
    path: &'a str,
}

/// Emit one final egress decision.
fn emit_decision(
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
    diagnostic: &'a [u8],
}

/// Record a refused request and answer the client 403.
fn refuse_request(
    state: &SharedState,
    connect: &ConnectRequest,
    refused: RefusedRequest<'_>,
    correlation: RequestId,
) -> WorkloadResponse {
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
    WorkloadResponse::refusal(403, refused.diagnostic)
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

    /// **A gateway-originated refusal carries the marker.** The client turns the marker into a
    /// denial, so a refusal this gateway writes must name itself.
    #[test]
    fn a_gateway_refusal_carries_the_marker() {
        let response = interceptor_error(
            &io::Error::new(io::ErrorKind::PermissionDenied, "refused"),
            None,
        );
        assert_eq!(
            response.headers.get(crate::PROXY_ORIGIN_HEADER),
            Some(crate::PROXY_ORIGIN_VALUE),
            "the gateway's own refusal names itself"
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
            let response = interceptor_error(&error, request);
            assert_eq!(response.status, 403);
            let body = std::str::from_utf8(&response.body).unwrap();
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

            let response = interceptor_error(&io::Error::other("private backend failure"), request);
            assert_eq!(response.status, 502);
            assert_eq!(response.body, b"effect interceptor unavailable");
        }
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
}
