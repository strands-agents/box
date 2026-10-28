//! The phases of one intercepted exchange, over one [`Exchange`] value.
//!
//! | Part | Does |
//! |---|---|
//! | [`REQUEST_PHASES`] | Judge and mutate the request; each phase can refuse it |
//! | [`prepare_request`], [`decide_request`] | Serialize the request, then decide and record `http:request` |
//! | [`RESPONSE_PHASES`] | Scrub and judge the reply; a phase can refuse it |
//! | [`prepare_response`], [`claim_release`], [`audit_release`] | Serialize, release, and audit the governed response |
//! | [`record_refusal`], [`Reply`] | Record a refusal with no I/O, and say what the workload gets |
//! | [`Unfinished`], [`record_unfinished`] | Record the gateway bound that ended a permitted exchange |

use std::io;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::OwnedSemaphorePermit;

use super::connect::ConnectRequest;
use super::convert::{UpstreamRequest, Whole, response_out, upstream_handshake, upstream_request};
use super::l7::{canonicalize_request_path, reconstruct_target, validate_request_binding};
use super::request_leg::{self, RequestDecision};
use super::response_leg::{self, ResponseDecision};
use super::serve::WriteCount;
use super::websocket::{self, Handshake};
use super::{SharedState, http1};
use crate::audit::Decision as AuditDecision;
use crate::audit::{EgressDecision, NetworkAuditEvent, RequestId};
use crate::boundary::{BodyRef, DenyReason, InterceptedRequest, InterceptedResponse};
use crate::capability::CapabilityContext;
use crate::effect::{ClaimedEffectPermit, EffectAttempt, McpFrame, McpListReply};
use crate::error::{ProxyError, Result};
use crate::mcp::{McpTarget, McpTargetIdentity, canonicalize_mcp_frame};

/// One request and the state that its phases share.
pub(super) struct Exchange<'a> {
    connect: &'a ConnectRequest,
    binding: Binding,
    intercepted: bool,
    correlation: RequestId,
    pub(super) request: InterceptedRequest,
    pub(super) method: String,
    /// What the request head asks for in `Upgrade`.
    handshake: Handshake,
    /// The session slot of a handshake that the screen admitted, held until its relay ends.
    session: Option<OwnedSemaphorePermit>,
    /// The judged path, before any credential mutation.
    workload_path: String,
    forward_target: String,
    allow_reason: String,
    context: Option<CapabilityContext>,
    mcp: Option<(String, McpTarget)>,
    forwarded_bytes: usize,
    redirect: Option<String>,
}

/// What the request must still name after the credential mutation.
pub(super) enum Binding {
    /// The authority that CONNECT admitted.
    ConnectAuthority,
    /// Nothing: plain HTTP has no CONNECT authority.
    None,
}

/// What an egress decision is about: the non-secret identity of one exchange.
pub(super) struct Subject<'a> {
    pub(super) host: &'a str,
    pub(super) port: u16,
    pub(super) method: &'a str,
    pub(super) path: &'a str,
    pub(super) correlation: &'a RequestId,
}

/// A gateway bound that ended a permitted exchange before the workload got the governed response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unfinished {
    RequestRefused,
    RequestTooLarge,
    NoAddressConnected,
    SocketUnprepared,
    OutcomeUnrecorded,
    DeadlinePassed,
    ReplyRefused,
    ReplyTooLarge,
}

/// A refusal: the reason that the records carry, and the reply that the workload gets.
pub(super) struct Refusal {
    pub(super) reason: String,
    pub(super) reply: Reply,
}

/// What the workload gets for a refusal.
pub(super) enum Reply {
    /// A static, secret-free body that the gateway writes.
    Diagnostic { status: u16, body: &'static [u8] },
    /// An interceptor refusal or failure; `mcp` asks for a JSON-RPC body.
    Interceptor { error: io::Error, mcp: bool },
}

/// One step before the request decision, which can refuse the request.
pub(super) type RequestPhase =
    for<'a> fn(&mut Exchange<'a>, &SharedState) -> std::result::Result<(), Refusal>;

/// One step after the reply, which can refuse the reply.
pub(super) type ResponsePhase = for<'a> fn(
    &mut Exchange<'a>,
    &mut InterceptedResponse,
    &SharedState,
) -> std::result::Result<(), Refusal>;

/// The request phases, in the order they run.
pub(super) const REQUEST_PHASES: &[RequestPhase] = &[
    canonicalize_path,
    screen_websocket,
    refuse_plaintext_credential,
    apply_request_capabilities,
    recheck_binding,
    classify_mcp,
];

/// The response phases, in the order they run.
pub(super) const RESPONSE_PHASES: &[ResponsePhase] = &[
    strip_origin_marker,
    apply_response_capabilities,
    stage_mcp_catalog,
];

impl<'a> Exchange<'a> {
    /// Start the exchange of `request` on the connection that `connect` admitted. `handshake` is
    /// what its head asks for in `Upgrade`.
    pub(super) fn new(
        connect: &'a ConnectRequest,
        binding: Binding,
        intercepted: bool,
        correlation: RequestId,
        request: InterceptedRequest,
        handshake: Handshake,
        state: &SharedState,
    ) -> Self {
        let correlation = correlation.with_headers(&request.headers);
        let correlation = if state.mcp_server_for(&connect.host).is_some() {
            correlation.with_mcp(request.body.as_bytes())
        } else {
            correlation
        };
        Self {
            connect,
            binding,
            intercepted,
            correlation,
            method: request.method.clone().unwrap_or_else(|| "GET".to_string()),
            handshake,
            session: None,
            workload_path: request.target.path.clone(),
            request,
            forward_target: String::new(),
            allow_reason: String::new(),
            context: None,
            mcp: None,
            forwarded_bytes: 0,
            redirect: None,
        }
    }

    /// The identity that every record of this exchange names.
    pub(super) fn subject(&self) -> Subject<'_> {
        Subject {
            host: &self.connect.host,
            port: self.connect.port,
            method: &self.method,
            path: &self.workload_path,
            correlation: &self.correlation,
        }
    }

    /// The key of the WebSocket handshake that this request is, if it is one.
    pub(super) fn websocket_key(&self) -> Option<&str> {
        match &self.handshake {
            Handshake::WebSocket { key } => Some(key),
            Handshake::None | Handshake::Malformed(_) => None,
        }
    }

    /// The relay of this handshake after its `101`, with the upgraded `upstream`. It takes the
    /// session slot that the screen took, and the capability context when a credential route
    /// matches the destination, so that the relay scrubs each server message.
    pub(super) fn relay(
        &mut self,
        upstream: Box<dyn websocket::Duplex>,
        state: &SharedState,
    ) -> websocket::Pending {
        websocket::Pending {
            host: self.connect.host.clone(),
            port: self.connect.port,
            path: self.workload_path.clone(),
            correlation: self.correlation.clone(),
            scrub: self
                .context
                .take()
                .filter(|context| state.controls.matches_any(&context.target.as_destination())),
            upstream,
            slot: self
                .session
                .take()
                .expect("the screen takes a session slot for each handshake that it admits"),
        }
    }

    /// Record the gateway bound that ended this exchange at a failed upstream step, if a bound did.
    /// `timed_out` says that the upstream deadline ended the step.
    pub(super) fn record_upstream_failure(
        &self,
        state: &SharedState,
        error: &ProxyError,
        timed_out: bool,
    ) {
        if let Some(why) = Unfinished::of_upstream(error, timed_out) {
            record_unfinished(state, &self.subject(), why);
        }
    }
}

impl<'a> Subject<'a> {
    /// The identity of the connection leg, which has no method and no path.
    pub(super) fn connection(connect: &'a ConnectRequest, correlation: &'a RequestId) -> Self {
        Self {
            host: &connect.host,
            port: connect.port,
            method: "",
            path: "/",
            correlation,
        }
    }
}

impl Unfinished {
    /// The gateway bound that ended a failed read of the inner request, or `None` when the workload
    /// ended it.
    pub(super) fn of_request(error: &ProxyError) -> Option<Self> {
        match error {
            ProxyError::ResponseLimit(_) => Some(Self::RequestTooLarge),
            ProxyError::Intercept(_) if !http1::closed_early(error) => Some(Self::RequestRefused),
            _ => None,
        }
    }

    /// The gateway bound that ended a failed upstream step (the request write, the reply read, or the
    /// reply serialization), or `None` when the upstream ended it. `timed_out` says that the
    /// upstream deadline ended the step.
    pub(super) fn of_upstream(error: &ProxyError, timed_out: bool) -> Option<Self> {
        if timed_out {
            return Some(Self::DeadlinePassed);
        }
        match error {
            ProxyError::ResponseLimit(_) => Some(Self::ReplyTooLarge),
            ProxyError::Intercept(_) if !http1::closed_early(error) => Some(Self::ReplyRefused),
            _ => None,
        }
    }

    /// The fixed reason that the records carry, which holds no peer byte.
    pub(super) fn reason(self) -> &'static str {
        match self {
            Self::RequestRefused => {
                "the request was refused: the gateway does not accept its head or framing"
            }
            Self::RequestTooLarge => "the request was refused: its body is larger than the limit",
            Self::NoAddressConnected => "no permitted address accepted the connection",
            Self::SocketUnprepared => "the upstream socket could not be prepared",
            Self::OutcomeUnrecorded => "the outcome of the permitted effect was not recorded",
            Self::DeadlinePassed => "the exchange passed the upstream deadline",
            Self::ReplyRefused => {
                "the reply was refused: the gateway does not accept its head, framing, or upgrade"
            }
            Self::ReplyTooLarge => "the reply was refused: its body is larger than the limit",
        }
    }
}

/// Put the request path in its RFC 3986 normal form, or refuse it.
fn canonicalize_path(
    exchange: &mut Exchange<'_>,
    _state: &SharedState,
) -> std::result::Result<(), Refusal> {
    // Canonicalize the request path ONCE, before it is judged (`workload_path`), matched for
    // credentials (`context`), or forwarded (`forward_target`) — so the box judges, matches, and
    // forwards the SAME bytes the origin will resolve. Percent-decodes only unreserved octets (never
    // `%2F`, which would change segment structure) and removes dot-segments, closing the "judge one
    // spelling, forward another" gap where `/%61dmin` or `/x/../admin` dodges a path `forbid` yet the
    // origin routes to `/admin`. The query is left untouched — a `UrlPath` credential can live there,
    // and it is deliberately kept out of the judged path.
    let path =
        canonicalize_request_path(&exchange.request.target.path).map_err(|reason| Refusal {
            reason,
            reply: Reply::Diagnostic {
                status: 403,
                body: b"request path is not a valid address",
            },
        })?;
    // The judged path is captured BEFORE any credential mutation. A `UrlPath` credential splices the
    // secret into the path, so after the fold `request.target.path` *is* the secret. Every
    // authorization and audit input reads `workload_path` instead, so an attempt or a durable record
    // never carries credential material.
    exchange.request.target.path.clone_from(&path);
    exchange.workload_path = path;
    Ok(())
}

/// Refuse a WebSocket handshake that the gateway does not relay, before any credential or policy
/// sees it. For one that it relays, take a session slot, and remove the extensions and the length.
fn screen_websocket(
    exchange: &mut Exchange<'_>,
    state: &SharedState,
) -> std::result::Result<(), Refusal> {
    let (reason, status, body): (&str, u16, &'static [u8]) = match &exchange.handshake {
        Handshake::None => return Ok(()),
        Handshake::Malformed(reason) => (reason, 400, b"malformed WebSocket handshake"),
        // Every message of a plain-HTTP WebSocket crosses in clear text, and a secret rides only
        // TLS.
        Handshake::WebSocket { .. } if !exchange.intercepted => (
            "upgrade on a plaintext request",
            403,
            b"WebSocket requires TLS",
        ),
        // Frames to a remote MCP server would cross with no `mcp:call` decision.
        Handshake::WebSocket { .. } if state.mcp_server_for(&exchange.connect.host).is_some() => (
            "upgrade to a remote MCP server",
            403,
            b"WebSocket refused for an MCP server",
        ),
        Handshake::WebSocket { .. } => match Arc::clone(&state.sessions).try_acquire_owned() {
            Ok(slot) => {
                exchange.session = Some(slot);
                // `permessage-deflate` compresses each message before the gateway reads it, so the
                // scrub could not find a secret in it. The fold and the upstream never see the
                // offer. The handshake has no body, so a signer must not sign a length.
                exchange.request.headers.remove("sec-websocket-extensions");
                exchange.request.headers.remove("content-length");
                return Ok(());
            }
            // Open WebSockets hold their share of the connection slots; the rest stay free for
            // ordinary requests.
            Err(_) => (
                "the open WebSockets hold their share of the connection slots",
                503,
                b"WebSocket session limit reached",
            ),
        },
    };
    Err(Refusal {
        reason: format!("websocket: {reason}"),
        reply: Reply::Diagnostic { status, body },
    })
}

/// Refuse a plain-HTTP request on which a credential would attach.
fn refuse_plaintext_credential(
    exchange: &mut Exchange<'_>,
    state: &SharedState,
) -> std::result::Result<(), Refusal> {
    // A secret rides only TLS: refuse on the same canonical target the credential match sees.
    if !exchange.intercepted
        && state
            .controls
            .matches_any(&exchange.request.target.as_destination())
    {
        return Err(Refusal {
            reason:
                "credential would attach on a plaintext request; refused — a secret must ride TLS"
                    .to_string(),
            reply: Reply::Diagnostic {
                status: 403,
                body: b"credential not permitted on a plaintext request",
            },
        });
    }
    Ok(())
}

/// Run the credential fold, which applies its mutations only when it allows.
fn apply_request_capabilities(
    exchange: &mut Exchange<'_>,
    state: &SharedState,
) -> std::result::Result<(), Refusal> {
    let context = CapabilityContext::new(
        exchange.correlation.clone(),
        state.now_unix_secs(),
        exchange.request.target.clone(),
    );
    let decision =
        request_leg::evaluate_and_apply(&state.controls, &mut exchange.request, &context);
    exchange.context = Some(context);
    match decision {
        RequestDecision::Block(reason) => {
            return Err(Refusal {
                reason: reason.to_string(),
                reply: Reply::Diagnostic {
                    status: 403,
                    body: b"blocked by egress control",
                },
            });
        }
        RequestDecision::Forward => {}
    }
    // A capability may annotate this allow — an advisory credential injection records that a secret
    // was attached against an absent or unrecognised placeholder. Journalled on the allow decision,
    // so the injection is reconstructable (destination, reason, and requester correlation).
    exchange.allow_reason = exchange.request.advisory_note.clone().unwrap_or_default();
    Ok(())
}

/// Check that the mutated request still names the authority that it is bound to.
fn recheck_binding(
    exchange: &mut Exchange<'_>,
    _state: &SharedState,
) -> std::result::Result<(), Refusal> {
    exchange.forward_target = reconstruct_target(&exchange.request.target);
    match exchange.binding {
        Binding::ConnectAuthority => validate_request_binding(
            exchange.connect,
            &exchange.method,
            &exchange.forward_target,
            &exchange.request.headers,
        )
        .map_err(|error| Refusal {
            reason: error.to_string(),
            reply: Reply::Diagnostic {
                status: error.http_status(),
                body: b"request authority rejected",
            },
        }),
        Binding::None => Ok(()),
    }
}

/// Classify the JSON-RPC frame of a request to a configured remote MCP server.
fn classify_mcp(
    exchange: &mut Exchange<'_>,
    state: &SharedState,
) -> std::result::Result<(), Refusal> {
    // Remote MCP door: if this destination is a configured MCP server, classify the JSON-RPC frame
    // so the `mcp:call` gate can run alongside `http:request`. The `server` is config-assigned (the
    // matched host's name), never read from the body, so an agent cannot borrow another server's
    // identity. A frame the classifier refuses — unparseable, a batch, a client-sent response, or an
    // act frame naming no item — is fail-closed here, before the request is authorized or forwarded.
    // A protocol-floor frame (`ping`, `server/discover`) yields no target and stays a plain
    // `http:request`.
    let Some(server) = state.mcp_server_for(&exchange.connect.host) else {
        return Ok(());
    };
    match McpTarget::of_http_request(exchange.request.body.as_bytes()) {
        Ok(Some(target)) => exchange.mcp = Some((server.to_string(), target)),
        Ok(None) => {}
        Err(error) => {
            return Err(Refusal {
                reason: format!("MCP frame refused: {error}"),
                reply: Reply::Diagnostic {
                    status: 403,
                    body: b"MCP frame refused",
                },
            });
        }
    }
    Ok(())
}

/// The canonical frame of a remote `resources/read` whose canonical form differs, which the gateway
/// forwards in place of the body.
fn canonical_frame(exchange: &Exchange<'_>) -> Option<Vec<u8>> {
    // Forward the CANONICAL frame, not the raw one. The local door rewrites a
    // `resources/read` uri at ingress so it judges and forwards ONE identity; the remote door must do
    // the same, or a respelling this classifier judged as one identity would be FETCHED as another by
    // the upstream server. Only `resources/read` whose canonical form differs is rewritten; every
    // other frame (and an unparseable body) forwards byte-identical.
    match &exchange.mcp {
        Some((_, target)) if matches!(target.identity, McpTargetIdentity::Resource(_)) => {
            canonicalize_mcp_frame(exchange.request.body.as_bytes())
        }
        _ => None,
    }
}

/// Build the upstream request from the mutated request, with the canonical frame of a remote
/// `resources/read`. `writes` learns when hyper takes the body.
pub(super) fn prepare_request(
    exchange: &mut Exchange<'_>,
    state: &SharedState,
    writes: Arc<WriteCount>,
) -> Result<UpstreamRequest> {
    // A handshake has no body (the classification refuses one), so it forwards none.
    if exchange.websocket_key().is_some() {
        return upstream_handshake(&exchange.forward_target, &exchange.request.headers, writes);
    }
    let body = match canonical_frame(exchange) {
        Some(frame) => frame,
        // A request to a remote MCP server keeps its body for the JSON-RPC refusal and the catalog
        // cursor. Nothing reads the body of any other request after this, so it moves.
        None if state.mcp_server_for(&exchange.connect.host).is_some() => {
            exchange.request.body.as_bytes().to_vec()
        }
        None => match std::mem::take(&mut exchange.request.body) {
            BodyRef::Bytes(body) => body,
            BodyRef::Empty => Vec::new(),
        },
    };
    exchange.forwarded_bytes = body.len();
    upstream_request(
        &exchange.method,
        &exchange.forward_target,
        &exchange.request.headers,
        body,
        writes,
    )
}

/// Claim the request permit, then record its decision, with no other seam call between the two.
pub(super) fn decide_request(
    exchange: &Exchange<'_>,
    state: &SharedState,
) -> std::result::Result<ClaimedEffectPermit, Reply> {
    let attempt = EffectAttempt::HttpRequest {
        host: &exchange.connect.host,
        port: exchange.connect.port,
        method: &exchange.method,
        path: &exchange.workload_path,
        body_bytes: exchange.forwarded_bytes,
        intercepted: exchange.intercepted,
        mcp: exchange.mcp.as_ref().map(|(server, target)| {
            let server = server.as_str();
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
    match claim_effect(state, &attempt) {
        Ok(permit) => {
            emit_decision(
                state,
                &exchange.subject(),
                AuditDecision::Allow,
                &exchange.allow_reason,
            );
            Ok(permit)
        }
        Err(error) => {
            record_refusal(
                state,
                &exchange.subject(),
                &format!("request effect interception failed: {error}"),
            );
            Err(Reply::Interceptor {
                mcp: state.mcp_server_for(&exchange.connect.host).is_some(),
                error,
            })
        }
    }
}

/// Remove the refusal marker from a relayed response.
fn strip_origin_marker(
    _exchange: &mut Exchange<'_>,
    response: &mut InterceptedResponse,
    _state: &SharedState,
) -> std::result::Result<(), Refusal> {
    // Only the gateway claims a refusal, so a relayed response never carries the marker. An origin
    // that set it would otherwise make a permitted answer read as a denial, with its own first body
    // line as the reason.
    response.headers.remove(crate::PROXY_ORIGIN_HEADER);
    Ok(())
}

/// Run the response fold, which scrubs a leaked secret and finds a cross-host redirect.
fn apply_response_capabilities(
    exchange: &mut Exchange<'_>,
    response: &mut InterceptedResponse,
    state: &SharedState,
) -> std::result::Result<(), Refusal> {
    let context = exchange
        .context
        .as_ref()
        .expect("the request fold builds the capability context");
    match response_leg::evaluate_and_apply(&state.controls, response, context) {
        ResponseDecision::Block(reason) => Err(Refusal {
            reason: format!(
                "response blocked by egress control: {}",
                refusal_kind(&reason)
            ),
            reply: Reply::Diagnostic {
                status: 403,
                body: b"response blocked by egress control",
            },
        }),
        ResponseDecision::RedirectReentry(location) => {
            exchange.redirect = Some(location);
            Ok(())
        }
        ResponseDecision::Return => Ok(()),
    }
}

/// The kind of a response-fold refusal, without its payload.
pub(super) fn refusal_kind(reason: &DenyReason) -> &'static str {
    match reason {
        DenyReason::HostDenied(_) => "host denied",
        DenyReason::IpDenied(_) => "ip denied",
        DenyReason::MutationCollision(_) => "mutation collision",
        DenyReason::Credential(_) => "credential denied",
        DenyReason::ControlDenied(_) => "control denied",
        DenyReason::ResponseLimit(_) => "response limit",
        DenyReason::NotAuthorized => "not authorized",
    }
}

/// Stage the catalog of a remote `tools/list` reply into the authority; a failure only warns.
fn stage_mcp_catalog(
    exchange: &mut Exchange<'_>,
    response: &mut InterceptedResponse,
    state: &SharedState,
) -> std::result::Result<(), Refusal> {
    // Lazy remote MCP discovery: on the workload's `tools/list` to a configured MCP server, stage
    // the response catalog into the authority so the server's per-tool actions reach runtime
    // (docs/design/decisions.md#remote-tool-schemas-are-discovered-at-runtime-in-memory).
    // Best-effort: a staging failure warns and the catalog still returns.
    if let Some((server, target)) = &exchange.mcp
        && target.method() == "tools/list"
        && let Err(error) = state.effect_interceptor.stage_mcp_catalog(
            server,
            McpListReply {
                session: exchange.request.headers.get("mcp-session-id"),
                cursor: list_cursor(exchange.request.body.as_bytes()).as_deref(),
                body: response.body.as_bytes(),
            },
        )
    {
        eprintln!(
            "strands-box: warning: staging remote MCP catalog for {server:?} failed: {error}"
        );
    }
    Ok(())
}

/// Build the governed response, after every response phase. The body moves into it; `version` is
/// the version of the request.
pub(super) fn prepare_response(
    exchange: &Exchange<'_>,
    response: &mut InterceptedResponse,
    version: http::Version,
) -> Result<http::Response<Whole>> {
    let body = match std::mem::take(&mut response.body) {
        BodyRef::Bytes(body) => Bytes::from(body),
        BodyRef::Empty => Bytes::new(),
    };
    response_out(
        &exchange.method,
        version,
        response.status,
        &response.headers,
        body,
    )
}

/// Claim the release of the governed response of `status` with `body_bytes` of body.
pub(super) fn claim_release(
    exchange: &Exchange<'_>,
    status: u16,
    body_bytes: usize,
    state: &SharedState,
) -> std::result::Result<ClaimedEffectPermit, Refusal> {
    let attempt = EffectAttempt::ResponseRelease {
        host: &exchange.connect.host,
        port: exchange.connect.port,
        method: &exchange.method,
        path: &exchange.workload_path,
        status,
        body_bytes,
    };
    claim_effect(state, &attempt).map_err(|error| Refusal {
        reason: format!("response release interception failed: {error}"),
        reply: Reply::Interceptor { error, mcp: false },
    })
}

/// Push the audit event of a released response.
pub(super) fn audit_release(exchange: &Exchange<'_>, state: &SharedState) {
    let event = match &exchange.redirect {
        // The client, not the proxy, follows this redirect and therefore re-enters all connection
        // checks. The already-scrubbed redirect response still crosses the governed release boundary.
        Some(location) => NetworkAuditEvent::deny(
            &exchange.connect.host,
            exchange.connect.port,
            format!("cross-host redirect not followed: {location}"),
            exchange.correlation.clone(),
        ),
        None => NetworkAuditEvent::allow(
            &exchange.connect.host,
            exchange.connect.port,
            exchange.correlation.clone(),
        ),
    };
    state.audit.push(event);
}

/// Record a refusal in the audit log and in telemetry, with no I/O.
pub(super) fn record_refusal(state: &SharedState, subject: &Subject<'_>, reason: &str) {
    state.audit.push(NetworkAuditEvent::deny(
        subject.host,
        subject.port,
        reason,
        subject.correlation.clone(),
    ));
    emit_decision(state, subject, AuditDecision::Deny, reason);
}

/// Record the gateway bound that ended a permitted exchange, in telemetry only.
pub(super) fn record_unfinished(state: &SharedState, subject: &Subject<'_>, why: Unfinished) {
    emit_decision(state, subject, AuditDecision::Deny, why.reason());
}

/// Record the gateway bound that ended a failed read of the request in a tunnel, if a bound did.
pub(super) fn record_request_failure(
    state: &SharedState,
    subject: &Subject<'_>,
    error: &ProxyError,
) {
    if let Some(why) = Unfinished::of_request(error) {
        record_unfinished(state, subject, why);
    }
}

/// Emit one final egress decision.
pub(super) fn emit_decision(
    state: &SharedState,
    subject: &Subject<'_>,
    decision: AuditDecision,
    reason: &str,
) {
    state.emitter.emit(EgressDecision {
        host: subject.host.to_string(),
        port: subject.port,
        method: subject.method.to_string(),
        path: subject.path.to_string(),
        decision,
        reason: reason.to_string(),
        correlation: subject.correlation.clone(),
    });
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

/// The `params.cursor` a `tools/list` request names.
fn list_cursor(body: &[u8]) -> Option<String> {
    let request: serde_json::Value = serde_json::from_slice(body).ok()?;
    request
        .get("params")?
        .get("cursor")?
        .as_str()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use credentials::DestinationPattern;

    use super::*;
    use crate::boundary::{BodyRef, HeaderMap, Target};
    use crate::capability::{CapabilityOutcome, CapabilitySet, EgressCapability};
    use crate::effect::{EffectInterceptor, EffectPermit};
    use crate::intercept::mitm::{ClientLimits, MitmConfig, tls};
    use crate::seams::StubEmitter;

    /// A credential on `api.example.com` that refuses each request, as a phantom mismatch does.
    struct MismatchedPhantom;

    impl EgressCapability for MismatchedPhantom {
        fn pattern(&self) -> &DestinationPattern {
            static PATTERN: std::sync::OnceLock<DestinationPattern> = std::sync::OnceLock::new();
            PATTERN.get_or_init(|| DestinationPattern::parse("api.example.com").unwrap())
        }

        fn on_request(
            &self,
            _request: &mut InterceptedRequest,
            _context: &CapabilityContext,
        ) -> CapabilityOutcome {
            CapabilityOutcome::unavailable("phantom mismatch")
        }
    }

    /// An authority that the request phases never consult.
    struct Unconsulted;

    impl EffectInterceptor for Unconsulted {
        fn intercept(&self, _attempt: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
            panic!("no request phase claims an effect")
        }
    }

    fn state() -> SharedState {
        SharedState {
            controls: CapabilitySet::from_parts(vec![Box::new(MismatchedPhantom)]),
            config: MitmConfig {
                mcp_servers: vec![("mcp.example.com".to_string(), "demo".to_string())],
                ..MitmConfig::default()
            },
            ca: None,
            upstream_config: Arc::new(tls::upstream_client_config(&[]).unwrap()),
            audit: crate::audit::SharedAuditLog::new(),
            emitter: Box::new(StubEmitter::new()),
            effect_interceptor: Arc::new(Unconsulted),
            expected_token: None,
            client_limits: ClientLimits::default(),
            sessions: Arc::new(tokio::sync::Semaphore::new(0)),
        }
    }

    /// The reason of the first request phase that refuses a request with no `Host` to `host`.
    fn first_refusal(host: &str, path: &str, binding: Binding, body: &[u8]) -> String {
        let state = state();
        let connect = ConnectRequest {
            host: host.to_string(),
            port: 443,
            proxy_authorization: None,
        };
        let mut target = Target::new(host, 443);
        target.path = path.to_string();
        let request = InterceptedRequest {
            target,
            method: Some("POST".to_string()),
            headers: HeaderMap::new(),
            body: BodyRef::Bytes(body.to_vec()),
            advisory_note: None,
        };
        let intercepted = matches!(binding, Binding::ConnectAuthority);
        let mut exchange = Exchange::new(
            &connect,
            binding,
            intercepted,
            RequestId::new("phases"),
            request,
            Handshake::None,
            &state,
        );
        REQUEST_PHASES
            .iter()
            .find_map(|phase| phase(&mut exchange, &state).err())
            .map(|refusal| refusal.reason)
            .expect("a request phase refuses")
    }

    /// **The request phases run in their stated order.** Each case meets at least two refusals, and
    /// the earliest phase gives the reason.
    #[test]
    fn the_request_phases_run_in_order() {
        // A path that is not RFC 3986 is refused before the plaintext credential check.
        assert_eq!(
            first_refusal("api.example.com", "/%zz", Binding::None, b""),
            canonicalize_request_path("/%zz").unwrap_err()
        );
        // A credential on plain HTTP is refused before the fold sees the phantom mismatch.
        assert_eq!(
            first_refusal("api.example.com", "/v1", Binding::None, b""),
            "credential would attach on a plaintext request; refused — a secret must ride TLS"
        );
        // The fold refuses the phantom mismatch before the binding check sees no `Host`.
        assert!(
            first_refusal("api.example.com", "/v1", Binding::ConnectAuthority, b"")
                .contains("phantom mismatch")
        );
        // The binding check refuses before the MCP classifier sees a frame that is not JSON.
        assert!(
            first_refusal(
                "mcp.example.com",
                "/mcp",
                Binding::ConnectAuthority,
                b"not json"
            )
            .ends_with("intercepted HTTP/1 request is missing Host")
        );
    }

    /// **A failure after a permit is classified by its variant, and only a bound records.** An early
    /// close by a peer, and every I/O failure, is an end that the peer caused.
    #[test]
    fn a_failure_after_a_permit_is_classified_by_variant() {
        let intercept = |message: &str| ProxyError::Intercept(message.to_string());
        // Once the upstream deadline passes, the deadline ended the exchange, whatever failed.
        let assert_deadline_passed = |error: &ProxyError| {
            assert_eq!(
                Unfinished::of_upstream(error, true),
                Some(Unfinished::DeadlinePassed),
                "{error}"
            );
        };
        // A read of the request in a tunnel and an upstream step can each fail in these ways.
        let shared = [
            (
                ProxyError::ResponseLimit("body length 9 exceeds limit 8".to_string()),
                Some(Unfinished::RequestTooLarge),
                Some(Unfinished::ReplyTooLarge),
            ),
            (
                intercept("message contains both Content-Length and Transfer-Encoding"),
                Some(Unfinished::RequestRefused),
                Some(Unfinished::ReplyRefused),
            ),
            (intercept("connection closed before HTTP head"), None, None),
            (
                intercept("connection closed while reading chunk-size line"),
                None,
                None,
            ),
            (
                ProxyError::Io("reading body: unexpected end of file".to_string()),
                None,
                None,
            ),
        ];
        for (error, request, upstream) in shared {
            assert_eq!(Unfinished::of_request(&error), request, "{error}");
            assert_eq!(Unfinished::of_upstream(&error, false), upstream, "{error}");
            assert_deadline_passed(&error);
        }
        // Only an upstream step fails in these ways: a reply that asks to switch protocols, and a
        // request write that fails, also on an upstream certificate that the gateway does not trust.
        let upstream_only = [
            (
                intercept("HTTP protocol upgrades are not supported"),
                Some(Unfinished::ReplyRefused),
            ),
            (
                ProxyError::Io("delivering upstream request: reset".to_string()),
                None,
            ),
            (
                ProxyError::Io(
                    "delivering upstream request: invalid peer certificate: UnknownIssuer"
                        .to_string(),
                ),
                None,
            ),
        ];
        for (error, upstream) in upstream_only {
            assert_eq!(Unfinished::of_upstream(&error, false), upstream, "{error}");
            assert_deadline_passed(&error);
        }
    }

    /// **The response-block reason names the kind of refusal, never its payload.** A payload can
    /// carry upstream bytes: an encoding name, or the name of a header that the scrub edits.
    #[test]
    fn the_response_block_reason_names_only_the_kind_of_refusal() {
        let reason = DenyReason::Credential(
            "the response to a credentialed request arrived with Content-Encoding marker-1234"
                .to_string(),
        );
        assert_eq!(refusal_kind(&reason), "credential denied");
        assert_eq!(
            refusal_kind(&DenyReason::MutationCollision(
                "Header(\"x-upstream\")".to_string()
            )),
            "mutation collision"
        );
    }
}
