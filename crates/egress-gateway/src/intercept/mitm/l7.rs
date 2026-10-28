//! The L7 interception path: terminate TLS, run the request/response legs, forward.

use std::io::{self, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Instant;

use crate::audit::RequestId;
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use super::connect::{ConnectRequest, parse_authority, same_host};
use super::exchange::{
    Binding, Exchange, REQUEST_PHASES, RESPONSE_PHASES, Refusal, Reply, Subject, Unfinished,
    audit_release, claim_release, decide_request, prepare_request, prepare_response,
    record_refusal, record_request_failure, record_unfinished,
};
use super::{SharedState, http1, tls};
use crate::boundary::{BodyRef, HeaderMap, InterceptedRequest, InterceptedResponse, Target};
use crate::effect::{ClaimedEffectPermit, EffectOutcome};
use crate::error::{ProxyError, Result};
use crate::mcp::{mcp_denial_response, normalize_path};

/// Terminate the client's TLS, run the L7 legs, and forward to the pinned upstream.
///
/// A thin transport wrapper: it does the TLS-specific setup (present a per-host leaf, open the
/// upstream TLS), reads the request, checks the CONNECT binding, then hands the shared request and
/// response legs to [`run_l7_legs`].
pub(super) fn intercept_tls<C: Read + Write>(
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
    let server_config = tls::server_config_for_host(ca, &connect.host)?;
    let server_conn = ServerConnection::new(Arc::new(server_config))
        .map_err(|e| ProxyError::Intercept(format!("server TLS init: {e}")))?;
    // Wrap the client TLS stream in a BufReader so the HTTP head is read line-buffered (not one
    // syscall per byte). Writes go through `get_mut()` to the underlying stream.
    let mut client_tls = BufReader::new(StreamOwned::new(server_conn, client));

    // --- Request leg: read plaintext, then run the shared legs ---
    let parsed = http1::read_request(&mut client_tls, state.config.response_limits.max_body_bytes)
        .inspect_err(|error| {
            record_request_failure(state, &Subject::connection(connect, &correlation), error);
        })?;

    // --- Client side: connect to the pinned upstream over the additive trust bundle ---
    // The listener already opened this exact pinned socket under the Connect lifecycle. A TLS
    // handshake failure here is a hard-fail drop, never a second socket attempt.
    let upstream_deadline = Instant::now() + state.config.upstream_read_deadline;
    let mut upstream_tls = BufReader::new(start_upstream_tls(
        &connect.host,
        Bounded::until(upstream, upstream_deadline),
        state,
    )?);
    let correlation = correlation.with_headers(&parsed.headers);
    // Pre-leg binding: the inner request must name the CONNECT authority, before any mutation.
    if let Err(error) =
        validate_request_binding(connect, &parsed.method, &parsed.target, &parsed.headers)
    {
        let subject = Subject {
            host: &connect.host,
            port: connect.port,
            method: &parsed.method,
            path: &parsed.target,
            correlation: &correlation,
        };
        record_refusal(state, &subject, &error.to_string());
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

    // TLS was terminated to see this request, so it stays bound to the CONNECT authority.
    let exchange = Exchange::new(
        connect,
        Binding::ConnectAuthority,
        true,
        correlation,
        req,
        upstream_deadline,
        state,
    );
    run_l7_legs(exchange, &mut upstream_tls, client_tls.get_mut(), state)
}

/// Run the phases of one exchange over an already-open client writer and upstream stream.
///
/// Both the TLS ([`intercept_tls`]) and plain-HTTP ([`forward_plain`]) paths converge here after
/// their transport-specific setup: `upstream` is the buffered upstream, and `client_writer` the sink
/// for diagnostics and the governed response. Every control (request/response legs, effect
/// lifecycle, audit) fires identically for both.
fn run_l7_legs<S, CW>(
    mut exchange: Exchange<'_>,
    upstream: &mut BufReader<S>,
    client_writer: &mut CW,
    state: &SharedState,
) -> Result<()>
where
    S: Read + Write,
    CW: Write,
{
    for phase in REQUEST_PHASES {
        if let Err(refusal) = phase(&mut exchange, state) {
            refuse(&exchange, refusal, state, client_writer);
            return Ok(());
        }
    }
    // Serialize the fully mutated request before claiming its effect permit.
    let prepared_request = prepare_request(&mut exchange)?;
    let request_permit = match decide_request(&exchange, state) {
        Ok(permit) => permit,
        Err(reply) => {
            write_reply(
                client_writer,
                &exchange.method,
                reply,
                Some(exchange.request.body.as_bytes()),
            );
            return Ok(());
        }
    };
    // The request permit is consumed at reply time, or when no reply comes.
    let (request_permit, request_bytes) = deliver_or_record_failure(
        upstream.get_mut(),
        &prepared_request,
        request_permit,
        "upstream request",
    )
    .inspect_err(|error| exchange.record_upstream_failure(state, error))?;
    drop(prepared_request);

    // --- Response leg: read, evaluate+apply, return ---
    let mut response = read_reply(upstream, &exchange, request_permit, request_bytes, state)?;
    for phase in RESPONSE_PHASES {
        if let Err(refusal) = phase(&mut exchange, &mut response, state) {
            refuse(&exchange, refusal, state, client_writer);
            return Ok(());
        }
    }

    // Serialize only after response controls and leakback scrubbing have finished, then claim the
    // release immediately before the governed bytes are delivered to the workload.
    let prepared_response = prepare_response(&exchange, &response)
        .inspect_err(|error| exchange.record_upstream_failure(state, error))?;
    let response_permit = match claim_release(&exchange, &response, state) {
        Ok(permit) => permit,
        Err(refusal) => {
            refuse(&exchange, refusal, state, client_writer);
            return Ok(());
        }
    };
    audit_release(&exchange, state);
    deliver_effect(
        client_writer,
        &prepared_response,
        response_permit,
        "governed response",
    )
}

/// Read the upstream reply, and record the request outcome that it shows.
fn read_reply<S: Read>(
    upstream: &mut BufReader<S>,
    exchange: &Exchange<'_>,
    request_permit: ClaimedEffectPermit,
    request_bytes: usize,
    state: &SharedState,
) -> Result<InterceptedResponse> {
    let unrecorded =
        || record_unfinished(state, &exchange.subject(), Unfinished::OutcomeUnrecorded);
    let parsed_res = match http1::read_response(
        upstream,
        &exchange.method,
        state.config.response_limits.max_body_bytes,
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
                unrecorded();
                ProxyError::Io(format!(
                    "recording upstream request outcome after a failed reply: {error}"
                ))
            })?;
            exchange.record_upstream_failure(state, &failure.error);
            return Err(failure.error);
        }
    };
    request_permit
        .record_outcome(EffectOutcome::Replied {
            accepted_bytes: request_bytes,
            status: parsed_res.status,
        })
        .map_err(|error| {
            unrecorded();
            ProxyError::Io(format!(
                "recording upstream request outcome after the reply: {error}"
            ))
        })?;
    // Move, don't clone — `parsed_res` is dead after this; the body can be large.
    Ok(InterceptedResponse::http(
        parsed_res.status,
        parsed_res.headers,
        BodyRef::Bytes(parsed_res.body),
    ))
}

/// Record a refusal of the request, then answer the workload.
fn refuse<W: Write>(
    exchange: &Exchange<'_>,
    refusal: Refusal,
    state: &SharedState,
    client_writer: &mut W,
) {
    record_refusal(state, &exchange.subject(), &refusal.reason);
    write_reply(
        client_writer,
        &exchange.method,
        refusal.reply,
        Some(exchange.request.body.as_bytes()),
    );
}

/// Answer the workload with the reply of a refusal.
fn write_reply<W: Write>(
    client_writer: &mut W,
    request_method: &str,
    reply: Reply,
    mcp_request: Option<&[u8]>,
) {
    match reply {
        Reply::Diagnostic { status, body } => {
            write_trusted_diagnostic(client_writer, request_method, status, body);
        }
        Reply::Interceptor { error, mcp } => write_interceptor_error(
            client_writer,
            request_method,
            &error,
            mcp_request.filter(|_| mcp),
        ),
    }
}

/// Forward a plain-HTTP (non-TLS) exchange to an already-open plaintext upstream.
///
/// A thin transport wrapper mirroring [`intercept_tls`] without any TLS: the request was already
/// read (`parsed`) and `origin_target` is its origin-form target (`/path?query`) from the absolute
/// URL. It builds the boundary request and hands the shared legs to [`run_l7_legs`], which
/// canonicalizes the path and refuses a credential on it. Plain HTTP has no CONNECT authority to bind
/// against, so the post-mutation re-check does nothing.
pub(super) fn forward_plain(
    client_writer: &mut TcpStream,
    upstream: TcpStream,
    connect: &ConnectRequest,
    parsed: http1::ParsedRequest,
    origin_target: String,
    state: &SharedState,
    correlation: RequestId,
) -> Result<()> {
    let upstream_deadline = Instant::now() + state.config.upstream_read_deadline;
    let mut upstream_buf = BufReader::new(Bounded::until(upstream, upstream_deadline));

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

    // Plain HTTP was never encrypted, so it is not TLS-intercepted and has no authority to bind.
    let exchange = Exchange::new(
        connect,
        Binding::None,
        false,
        correlation,
        req,
        upstream_deadline,
        state,
    );
    run_l7_legs(exchange, &mut upstream_buf, client_writer, state)
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
    fn until(inner: S, deadline: Instant) -> Self {
        Self { inner, deadline }
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

/// The RFC 3986 normal form of an origin-form request path, `/` when it is empty, or why it is refused.
pub(super) fn canonicalize_request_path(path: &str) -> std::result::Result<String, String> {
    let normal = normalize_path(path)?;
    Ok(if normal.is_empty() {
        "/".to_string()
    } else {
        normal
    })
}

/// Split an origin-form request target into `(path, query)`.
fn split_target(target: &str) -> (String, String) {
    match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.to_string(), String::new()),
    }
}

/// Reconstruct the origin-form target (`path[?query]`) from a (possibly mutated) [`Target`].
pub(super) fn reconstruct_target(target: &Target) -> String {
    if target.query.is_empty() {
        target.path.clone()
    } else {
        format!("{}?{}", target.path, target.query)
    }
}

/// Require the inner HTTP request to name the authority admitted by CONNECT.
pub(super) fn validate_request_binding(
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
