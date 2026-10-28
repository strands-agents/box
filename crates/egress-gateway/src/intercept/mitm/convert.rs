//! Conversions between hyper messages and the boundary types of an exchange.
//!
//! | Direction | Function |
//! |---|---|
//! | Workload request to the exchange | [`request_in`] |
//! | Exchange to the upstream request | [`upstream_request`], in an [`UpstreamRequest`] |
//! | Upstream reply to the exchange | [`response_in`] |
//! | Exchange to the workload reply | [`response_out`], [`diagnostic_response`], [`interceptor_response`] |
//!
//! hyper reads and writes the HTTP/1.1 framing. These functions keep the Box rules around it: the
//! hop-by-hop strip, a fresh `Content-Length`, `Connection: close`, and Box's reason phrases.

use std::convert::Infallible;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::{CONNECTION, CONTENT_LENGTH, TRANSFER_ENCODING};
use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use zeroize::Zeroizing;

use super::http1::{self, ResponseBodyMode};
use super::serve::WriteCount;
use crate::boundary::{BodyRef, HeaderMap, InterceptedResponse};
use crate::error::{ProxyError, Result};
use crate::mcp::mcp_denial_response;

/// A buffer that is wiped when the last [`Bytes`] that shares it drops.
pub(super) struct WipedBytes(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for WipedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A copy of `bytes` in a buffer that is wiped on drop. hyper and `http` keep the buffer and do not
/// copy it again.
fn wiped(bytes: &[u8]) -> Bytes {
    Bytes::from_owner(WipedBytes(Zeroizing::new(bytes.to_vec())))
}

/// A whole body, which hyper writes under the `Content-Length` that the head states.
///
/// An empty body with data still reports its length, so hyper keeps the `Content-Length` header
/// where the gateway put it. [`Whole::none`] is a message with no body at all.
pub(super) struct Whole {
    data: Option<Bytes>,
    length: u64,
    /// The write count to tell when hyper has taken the body.
    taken: Option<Arc<WriteCount>>,
}

impl Whole {
    /// A body of `data`.
    pub(super) fn new(data: Bytes) -> Self {
        Self {
            length: data.len() as u64,
            data: Some(data),
            taken: None,
        }
    }

    /// No body: a reply that cannot carry one, or a `HEAD` reply.
    pub(super) fn none() -> Self {
        Self {
            data: None,
            length: 0,
            taken: None,
        }
    }

    /// Tell `writes` when hyper takes the body. hyper never asks for an empty body under
    /// `Content-Length: 0`, so the head alone is the message, and the body counts as taken at once.
    fn reported_to(mut self, writes: Arc<WriteCount>) -> Self {
        if self.length == 0 {
            writes.body_taken();
        } else {
            self.taken = Some(writes);
        }
        self
    }
}

impl Body for Whole {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        let frame = this.data.take().map(|data| Ok(Frame::data(data)));
        if let Some(writes) = this.taken.take() {
            writes.body_taken();
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(if self.data.is_some() { self.length } else { 0 })
    }
}

/// An intercepted request as the exchange judges it.
pub(super) struct Inbound {
    pub(super) method: String,
    /// The target as `http::Uri` spells it: origin form, absolute form, or `*`.
    pub(super) target: String,
    pub(super) version: Version,
    /// The headers without hop-by-hop fields, with a fresh `Content-Length` when the request had
    /// a body framing.
    pub(super) headers: HeaderMap,
    pub(super) body: Vec<u8>,
}

/// Read the head and the whole body of one request from the workload, up to `max` body bytes.
pub(super) async fn request_in<B>(request: Request<B>, max: usize) -> Result<Inbound>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let (parts, body) = request.into_parts();
    // `Method` compares case-sensitively, and `connect` is an extension method to hyper. The front
    // and the body modes read the method case-insensitively, so this check does too.
    if parts.method.as_str().eq_ignore_ascii_case("CONNECT") {
        return Err(ProxyError::Intercept(
            "nested CONNECT tunneling is not supported".to_string(),
        ));
    }
    let framed =
        parts.headers.contains_key(CONTENT_LENGTH) || parts.headers.contains_key(TRANSFER_ENCODING);
    let mut headers = header_map_from(&parts.headers);
    let body = collect_body(body, max, "request").await?;
    http1::strip_hop_by_hop_headers(&mut headers)?;
    if framed {
        headers.set("Content-Length", body.len().to_string());
    }
    Ok(Inbound {
        method: parts.method.as_str().to_string(),
        target: parts.uri.to_string(),
        version: parts.version,
        headers,
        body,
    })
}

/// Read the head and the whole body of the upstream reply to `request_method`, up to `max` body
/// bytes. A reply that asks to switch protocols is refused.
pub(super) async fn response_in<B>(
    response: Response<B>,
    request_method: &str,
    max: usize,
) -> Result<InterceptedResponse>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let (parts, body) = response.into_parts();
    let status = parts.status.as_u16();
    if status == 101 {
        return Err(ProxyError::Intercept(
            "HTTP protocol upgrades are not supported".to_string(),
        ));
    }
    let framed =
        parts.headers.contains_key(CONTENT_LENGTH) || parts.headers.contains_key(TRANSFER_ENCODING);
    let mut headers = header_map_from(&parts.headers);
    let body = collect_body(body, max, "response").await?;
    http1::strip_hop_by_hop_headers(&mut headers)?;
    match http1::response_body_mode(request_method, status) {
        ResponseBodyMode::Payload if framed || !body.is_empty() => {
            headers.set("Content-Length", body.len().to_string());
        }
        ResponseBodyMode::Forbidden => {
            headers.remove("content-length");
        }
        ResponseBodyMode::Payload | ResponseBodyMode::MetadataOnly => {}
    }
    Ok(InterceptedResponse::http(
        status,
        headers,
        BodyRef::Bytes(body),
    ))
}

/// Collect a whole body into one buffer, sized from its declared length, and refuse it when it is
/// larger than `max`. A trailer section is dropped: the gateway forwards every body under a fresh
/// `Content-Length`.
async fn collect_body<B>(mut body: B, max: usize, what: &str) -> Result<Vec<u8>>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let declared = body.size_hint().lower();
    if declared > max as u64 {
        return Err(ProxyError::ResponseLimit(format!(
            "{what} body length {declared} exceeds limit {max}"
        )));
    }
    let mut collected = Vec::with_capacity(declared as usize);
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| body_error(&error, what))?;
        if let Ok(data) = frame.into_data() {
            if collected.len() + data.len() > max {
                return Err(ProxyError::ResponseLimit(format!(
                    "{what} body exceeds limit {max}"
                )));
            }
            collected.extend_from_slice(&data);
        }
    }
    Ok(collected)
}

/// The error of a failed body read: a peer that closed before the body ended, or a failed read.
fn body_error(error: &(dyn std::error::Error + 'static), what: &str) -> ProxyError {
    let mut cause = Some(error);
    while let Some(error) = cause {
        let ended = error
            .downcast_ref::<hyper::Error>()
            .is_some_and(hyper::Error::is_incomplete_message)
            || error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::UnexpectedEof);
        if ended {
            return ProxyError::Intercept(format!(
                "{} before the {what} body ended",
                http1::CLOSED_EARLY
            ));
        }
        cause = error.source();
    }
    ProxyError::Io(format!("reading the {what} body: {}", error_text(error)))
}

/// The text of `error` and of each error under it.
pub(super) fn error_text(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.ends_with(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

/// Build a boundary [`HeaderMap`] from hyper's headers, in their order.
fn header_map_from(headers: &http::HeaderMap) -> HeaderMap {
    HeaderMap::from_pairs(headers.iter().map(|(name, value)| {
        (
            name.as_str().to_string(),
            String::from_utf8_lossy(value.as_bytes()).into_owned(),
        )
    }))
}

/// The upstream request, which is never formatted: its `Uri` and header values carry the
/// credential.
pub(super) struct UpstreamRequest(Request<Whole>);

impl fmt::Debug for UpstreamRequest {
    /// The method only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamRequest")
            .field("method", self.0.method())
            .finish_non_exhaustive()
    }
}

impl UpstreamRequest {
    /// The request, for hyper to send.
    pub(super) fn into_inner(self) -> Request<Whole> {
        self.0
    }
}

/// Build the upstream request from exactly the re-checked method, target, and headers.
///
/// It carries `Connection: close` and a fresh `Content-Length`, after every other header. The
/// target and each header value live in wiped buffers, and each header value is marked sensitive.
/// `writes` learns when hyper has taken the body.
pub(super) fn upstream_request(
    method: &str,
    target: &str,
    headers: &HeaderMap,
    body: Vec<u8>,
    writes: Arc<WriteCount>,
) -> Result<UpstreamRequest> {
    let refused = |what: &str| ProxyError::Intercept(format!("the upstream request has {what}"));
    let method = Method::from_bytes(method.as_bytes()).map_err(|_| refused("an invalid method"))?;
    let uri = Uri::from_maybe_shared(wiped(target.as_bytes()))
        .map_err(|_| refused("an invalid target"))?;
    let nominated = http1::connection_nominated_headers(headers)?;
    let mut forwarded = http::HeaderMap::with_capacity(headers.len() + 2);
    for (name, value) in headers.iter() {
        if name.eq_ignore_ascii_case("content-length")
            || http1::is_hop_by_hop_header(name, &nominated)
        {
            continue;
        }
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| refused("an invalid header"))?;
        let mut value = HeaderValue::from_maybe_shared(wiped(value.as_bytes()))
            .map_err(|_| refused("an invalid header value"))?;
        value.set_sensitive(true);
        forwarded.append(name, value);
    }
    forwarded.insert(CONNECTION, HeaderValue::from_static("close"));
    forwarded.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
    let mut request = Request::new(Whole::new(Bytes::from(body)).reported_to(writes));
    *request.method_mut() = method;
    *request.uri_mut() = uri;
    *request.headers_mut() = forwarded;
    Ok(UpstreamRequest(request))
}

/// Build the reply to the workload, as the old writer framed it.
///
/// Every header but `Content-Length` and the hop-by-hop fields, then `Connection: close`, then the
/// `Content-Length` that the body mode allows. The status line carries Box's reason phrase, and the
/// version of the request, so an HTTP/1.0 client gets one exchange.
pub(super) fn response_out(
    request_method: &str,
    version: Version,
    status: u16,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response<Whole>> {
    let refused = |what: &str| ProxyError::Intercept(format!("the governed response has {what}"));
    let status_code = StatusCode::from_u16(status).map_err(|_| refused("an invalid status"))?;
    let body_mode = http1::response_body_mode(request_method, status);
    let metadata_length = if body_mode == ResponseBodyMode::MetadataOnly {
        headers
            .get("content-length")
            .and_then(|value| value.trim().parse::<u64>().ok())
            .or_else(|| (request_method == "HEAD" && !body.is_empty()).then_some(body.len() as u64))
    } else {
        None
    };
    let nominated = http1::connection_nominated_headers(headers)?;
    let mut relayed = http::HeaderMap::with_capacity(headers.len() + 2);
    for (name, value) in headers.iter() {
        if name.eq_ignore_ascii_case("content-length")
            || http1::is_hop_by_hop_header(name, &nominated)
        {
            continue;
        }
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| refused("an invalid header"))?;
        let value =
            HeaderValue::from_bytes(value.as_bytes()).map_err(|_| refused("an invalid header"))?;
        relayed.append(name, value);
    }
    relayed.insert(CONNECTION, HeaderValue::from_static("close"));
    let body = match body_mode {
        ResponseBodyMode::Payload => {
            relayed.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
            Whole::new(body)
        }
        ResponseBodyMode::MetadataOnly => {
            if let Some(length) = metadata_length {
                relayed.insert(CONTENT_LENGTH, HeaderValue::from(length));
            }
            Whole::none()
        }
        ResponseBodyMode::Forbidden => Whole::none(),
    };
    let mut response = Response::new(body);
    *response.status_mut() = status_code;
    *response.version_mut() = version;
    *response.headers_mut() = relayed;
    response
        .extensions_mut()
        .insert(hyper::ext::ReasonPhrase::from_static(
            http1::reason(status).as_bytes(),
        ));
    Ok(response)
}

/// A static proxy-level reply with no body and no marker: `HTTP/1.1 <status> <message>`, then
/// `Content-Length: 0` and `Connection: close`, as the front writes it.
pub(super) fn status_response(
    version: Version,
    status: u16,
    message: &'static str,
) -> Response<Whole> {
    let mut response = Response::new(Whole::new(Bytes::new()));
    *response.status_mut() =
        StatusCode::from_u16(status).expect("a static reply has a valid status");
    *response.version_mut() = version;
    let headers = response.headers_mut();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    headers.insert(CONNECTION, HeaderValue::from_static("close"));
    response
        .extensions_mut()
        .insert(hyper::ext::ReasonPhrase::from_static(message.as_bytes()));
    response
}

/// A proxy-originated diagnostic: a static, secret-free body under the refusal marker.
pub(super) fn diagnostic_response(
    request_method: &str,
    version: Version,
    status: u16,
    body: Bytes,
) -> Response<Whole> {
    marked_response(request_method, version, status, None, body)
}

/// The reply to an effect refusal or an interceptor failure; `mcp_request` asks for a JSON-RPC
/// body.
pub(super) fn interceptor_response(
    request_method: &str,
    version: Version,
    error: &io::Error,
    mcp_request: Option<&[u8]>,
) -> Response<Whole> {
    if error.kind() != io::ErrorKind::PermissionDenied {
        return diagnostic_response(
            request_method,
            version,
            502,
            Bytes::from_static(b"effect interceptor unavailable"),
        );
    }
    let message = super::diagnostic::denial_message(error);
    match mcp_request.and_then(|request| mcp_denial_response(request, &message)) {
        Some(response) => marked_response(
            request_method,
            version,
            403,
            Some("application/json"),
            Bytes::from(response),
        ),
        None => diagnostic_response(request_method, version, 403, Bytes::from(message)),
    }
}

/// A reply under the refusal marker, with an optional `Content-Type`.
fn marked_response(
    request_method: &str,
    version: Version,
    status: u16,
    content_type: Option<&str>,
    body: Bytes,
) -> Response<Whole> {
    let mut headers = HeaderMap::new();
    headers.set(
        crate::PROXY_ORIGIN_HEADER,
        crate::PROXY_ORIGIN_VALUE.to_string(),
    );
    if let Some(content_type) = content_type {
        headers.set("Content-Type", content_type.to_string());
    }
    response_out(request_method, version, status, &headers, body)
        .expect("a marked response has a valid status and static headers")
}

#[cfg(test)]
mod tests {
    use super::*;

    use http_body_util::BodyExt;

    /// A request header and a target that carry a secret.
    const SECRET: &str = "sk_live_convert_secret";

    fn credentialed_request() -> UpstreamRequest {
        let headers = HeaderMap::from_pairs([
            ("Host".to_string(), "api.example.com".to_string()),
            ("Authorization".to_string(), format!("Bearer {SECRET}")),
        ]);
        upstream_request(
            "POST",
            &format!("/v1/{SECRET}?key={SECRET}"),
            &headers,
            b"body".to_vec(),
            WriteCount::new(),
        )
        .unwrap()
    }

    /// **The upstream request prints no secret.** Neither the request nor its header map prints a
    /// header secret, and the request prints no target secret.
    #[test]
    fn the_upstream_request_prints_no_secret() {
        let request = credentialed_request();
        let printed = format!("{request:?}");
        assert!(!printed.contains(SECRET), "{printed}");
        assert!(printed.contains("POST"), "{printed}");
        let request = request.into_inner();
        let headers = format!("{:?}", request.headers());
        assert!(!headers.contains(SECRET), "{headers}");
        assert!(request.headers()["authorization"].is_sensitive());
    }

    /// **The upstream request is the re-checked request, re-framed.** The method, the target, and
    /// each header are the ones given; `content-length` and the hop-by-hop fields are dropped, and
    /// `Connection: close` and a fresh `Content-Length` come last.
    #[test]
    fn the_upstream_request_is_the_rechecked_request() {
        let headers = HeaderMap::from_pairs(
            [
                ("Host", "api.example.com"),
                ("Content-Length", "99"),
                ("Connection", "X-Hop"),
                ("X-Hop", "drop-me"),
                ("Keep-Alive", "timeout=5"),
                ("Accept", "a"),
                ("Accept", "b"),
            ]
            .map(|(name, value)| (name.to_string(), value.to_string())),
        );
        let request = upstream_request(
            "PUT",
            "/a/b?c=d",
            &headers,
            b"hello".to_vec(),
            WriteCount::new(),
        )
        .unwrap()
        .into_inner();
        assert_eq!(request.method(), Method::PUT);
        assert_eq!(request.uri(), "/a/b?c=d");
        let names: Vec<&str> = request.headers().keys().map(HeaderName::as_str).collect();
        assert_eq!(names, ["host", "accept", "connection", "content-length"]);
        assert_eq!(request.headers()["connection"], "close");
        assert_eq!(request.headers()["content-length"], "5");
        let accepts: Vec<&HeaderValue> = request.headers().get_all("accept").iter().collect();
        assert_eq!(accepts, ["a", "b"]);
    }

    /// **The forwarded header values share a wiped owner.** `http` keeps the buffer that the
    /// gateway made, so the wipe on drop reaches the bytes that hyper reads.
    #[test]
    fn forwarded_header_values_share_a_wiped_owner() {
        let owner = wiped(b"Bearer secret");
        let start = owner.as_ptr();
        let value = HeaderValue::from_maybe_shared(owner).unwrap();
        assert_eq!(value.as_bytes().as_ptr(), start);
    }

    /// **The forwarded target shares a wiped owner**, as the header values do.
    #[test]
    fn the_forwarded_target_shares_a_wiped_owner() {
        let target = wiped(b"/v1/secret?key=secret");
        let start = target.as_ptr();
        let uri = Uri::from_maybe_shared(target).unwrap();
        assert_eq!(uri.path().as_ptr(), start);
    }

    /// **A reply keeps Box's framing.** The relayed headers, then `Connection: close`, then the
    /// `Content-Length` of the body, under Box's reason phrase and the version of the request.
    #[test]
    fn a_reply_keeps_the_box_framing() {
        let headers = HeaderMap::from_pairs(
            [
                ("Content-Length", "1"),
                ("X-Upstream", "u"),
                ("Upgrade", "h2c"),
            ]
            .map(|(name, value)| (name.to_string(), value.to_string())),
        );
        let response = response_out(
            "GET",
            Version::HTTP_10,
            404,
            &headers,
            Bytes::from_static(b"gone"),
        )
        .unwrap();
        assert_eq!(response.version(), Version::HTTP_10);
        assert_eq!(
            response
                .extensions()
                .get::<hyper::ext::ReasonPhrase>()
                .unwrap()
                .as_bytes(),
            b"Client Error"
        );
        let names: Vec<&str> = response.headers().keys().map(HeaderName::as_str).collect();
        assert_eq!(names, ["x-upstream", "connection", "content-length"]);
        assert_eq!(response.headers()["content-length"], "4");

        let head = response_out("HEAD", Version::HTTP_11, 200, &headers, Bytes::new()).unwrap();
        assert_eq!(head.headers()["content-length"], "1");
        assert!(head.body().is_end_stream());
        let no_content =
            response_out("GET", Version::HTTP_11, 204, &headers, Bytes::new()).unwrap();
        assert!(!no_content.headers().contains_key(CONTENT_LENGTH));
    }

    /// **An effect refusal carries the marker, and an interceptor failure leaks nothing.**
    #[test]
    fn a_refusal_reply_carries_the_marker() {
        let denied = io::Error::new(io::ErrorKind::PermissionDenied, "refused by policy");
        let response = interceptor_response("GET", Version::HTTP_11, &denied, None);
        assert_eq!(response.status(), 403);
        assert_eq!(
            response.headers()[crate::PROXY_ORIGIN_HEADER],
            crate::PROXY_ORIGIN_VALUE
        );
        let failed = io::Error::other("private backend failure");
        let response = interceptor_response("GET", Version::HTTP_11, &failed, None);
        assert_eq!(response.status(), 502);
        let body = futures_body(response);
        assert_eq!(body, b"effect interceptor unavailable");
    }

    /// **The upstream request and the reply drop each hop-by-hop field and each field that
    /// `Connection` names**, and keep the end-to-end fields, with one `Connection: close`.
    #[test]
    fn writers_strip_hop_by_hop_and_connection_nominated_headers() {
        let headers = HeaderMap::from_pairs([
            ("Connection".to_string(), "keep-alive, X-Remove".to_string()),
            ("Keep-Alive".to_string(), "timeout=5".to_string()),
            ("Proxy-Connection".to_string(), "keep-alive".to_string()),
            (
                "Proxy-Authorization".to_string(),
                "Basic c2VjcmV0".to_string(),
            ),
            (
                "Proxy-Authenticate".to_string(),
                "Basic realm=\"proxy\"".to_string(),
            ),
            ("TE".to_string(), "trailers".to_string()),
            ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ("Upgrade".to_string(), "websocket".to_string()),
            ("Trailer".to_string(), "Digest".to_string()),
            ("X-Remove".to_string(), "hop-only".to_string()),
            ("X-End-To-End".to_string(), "keep".to_string()),
        ]);

        let request = upstream_request("POST", "/", &headers, b"body".to_vec(), WriteCount::new())
            .unwrap()
            .into_inner();
        let response = response_out(
            "POST",
            Version::HTTP_11,
            200,
            &headers,
            Bytes::from_static(b"body"),
        )
        .unwrap();
        for sent in [request.headers(), response.headers()] {
            let names: Vec<&str> = sent.keys().map(HeaderName::as_str).collect();
            assert_eq!(names, ["x-end-to-end", "connection", "content-length"]);
            assert_eq!(sent["connection"], "close");
            assert_eq!(sent["x-end-to-end"], "keep");
            assert_eq!(sent["content-length"], "4");
        }
    }

    /// **A request that ends before its body is an early close**, not a framing refusal, so it
    /// records no gateway bound.
    #[test]
    fn a_request_that_ends_early_is_an_early_close() {
        use hyper_util::rt::TokioIo;
        use tokio::io::AsyncWriteExt;

        for sent in [
            &b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc"[..],
            &b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4"[..],
        ] {
            let error = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (gateway, mut client) = tokio::io::duplex(1024);
                    let (read, mut errors) = tokio::sync::mpsc::unbounded_channel();
                    let service = hyper::service::service_fn(move |request| {
                        let read = read.clone();
                        async move {
                            let _ = read.send(request_in(request, 64).await.err());
                            Ok::<_, Infallible>(Response::new(Whole::none()))
                        }
                    });
                    let served = tokio::spawn(
                        hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(gateway), service),
                    );
                    client.write_all(sent).await.unwrap();
                    drop(client);
                    let error = errors.recv().await.unwrap();
                    let _ = served.await;
                    error
                });
            let error = error.expect("a request that ends early is not read");
            assert!(http1::closed_early(&error), "{error}");
        }
    }

    /// The bytes of a whole body.
    fn futures_body(response: Response<Whole>) -> Vec<u8> {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async { response.into_body().collect().await.unwrap().to_bytes() })
            .to_vec()
    }
}
