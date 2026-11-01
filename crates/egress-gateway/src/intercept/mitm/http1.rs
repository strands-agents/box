//! The box's HTTP/1.1 rules around hyper.

use http_body_util::BodyExt;
use zeroize::Zeroizing;

use crate::boundary::HeaderMap;
use crate::error::{ProxyError, Result};

/// A parsed HTTP/1.1 request read off the wire.
#[derive(Debug)]
pub(crate) struct ParsedRequest {
    /// The method (`GET`, `POST`, …).
    pub(super) method: String,
    /// The request target (origin-form path, e.g. `/v1/x?a=1`).
    pub(crate) target: String,
    /// The request headers.
    pub(crate) headers: HeaderMap,
    /// The request body (materialized, bounded by the read limit).
    pub(super) body: Vec<u8>,
}

/// A parsed HTTP/1.1 response read off the wire.
#[derive(Debug)]
pub(crate) struct ParsedResponse {
    /// The status code.
    pub(super) status: u16,
    /// The response headers.
    pub(super) headers: HeaderMap,
    /// The response body (materialized, bounded by the read limit).
    pub(crate) body: Vec<u8>,
    /// The header case the upstream sent, which hyper writes back to the workload.
    pub(super) header_case: hyper::http::Extensions,
}

/// The validated `Content-Length`, rejecting repeated, comma-coalesced, or malformed values so an
/// upstream and this proxy cannot disagree about message boundaries.
fn content_length(headers: &HeaderMap) -> Result<Option<usize>> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"));
    let Some((_, value)) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() || value.contains(',') {
        return Err(ProxyError::Intercept(
            "multiple Content-Length values".to_string(),
        ));
    }
    let value = trim_ows(value);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProxyError::Intercept(
            "malformed Content-Length".to_string(),
        ));
    }
    value
        .parse::<usize>()
        .map(Some)
        .map_err(|_| ProxyError::Intercept("Content-Length exceeds usize".to_string()))
}

/// Whether the message uses the one supported transfer coding: exactly one final `chunked` coding.
fn uses_chunked_transfer_encoding(headers: &HeaderMap) -> Result<bool> {
    let mut chunked = false;
    for (_, value) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
    {
        for coding in value.split(',') {
            let coding = trim_ows(coding);
            if coding.is_empty() {
                return Err(ProxyError::Intercept(
                    "malformed Transfer-Encoding".to_string(),
                ));
            }
            if coding.contains(';') || !coding.eq_ignore_ascii_case("chunked") {
                return Err(ProxyError::Intercept(
                    "unsupported Transfer-Encoding (only chunked is supported)".to_string(),
                ));
            }
            if chunked {
                return Err(ProxyError::Intercept(
                    "duplicate chunked transfer coding".to_string(),
                ));
            }
            chunked = true;
        }
    }
    Ok(chunked)
}

/// Whether a byte is valid in an HTTP token (RFC 9110 section 5.6.2).
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Trim HTTP optional whitespace (SP / HTAB), without accepting other Unicode whitespace.
fn trim_ows(value: &str) -> &str {
    value.trim_matches(|character| matches!(character, ' ' | '\t'))
}

/// Explicit body framing selected from the message headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyFraming {
    ContentLength(usize),
    Chunked,
}

/// Validate message framing and reject `Content-Length` plus `Transfer-Encoding` ambiguity.
fn explicit_body_framing(headers: &HeaderMap) -> Result<Option<BodyFraming>> {
    let content_length = content_length(headers)?;
    let chunked = uses_chunked_transfer_encoding(headers)?;
    if chunked && content_length.is_some() {
        return Err(ProxyError::Intercept(
            "message contains both Content-Length and Transfer-Encoding".to_string(),
        ));
    }
    Ok(if chunked {
        Some(BodyFraming::Chunked)
    } else {
        content_length.map(BodyFraming::ContentLength)
    })
}

/// Parse the header names nominated by all `Connection` fields.
fn connection_nominated_headers(headers: &HeaderMap) -> Result<Vec<String>> {
    let mut nominated = Vec::new();
    for (_, value) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
    {
        for option in value.split(',') {
            let option = trim_ows(option);
            if option.is_empty() || !option.bytes().all(is_token_byte) {
                return Err(ProxyError::Intercept(
                    "malformed Connection header".to_string(),
                ));
            }
            nominated.push(option.to_string());
        }
    }
    Ok(nominated)
}

/// Whether a header describes only the current transport hop.
fn is_hop_by_hop_header(name: &str, nominated: &[String]) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "keep-alive"
            | "te"
            | "transfer-encoding"
            | "upgrade"
            | "trailer"
    ) || nominated
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
}

/// Remove hop-by-hop fields before controls or credential signing inspect the message.
fn strip_hop_by_hop_headers(headers: &mut HeaderMap) -> Result<()> {
    let nominated = connection_nominated_headers(headers)?;
    for name in [
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "keep-alive",
        "te",
        "transfer-encoding",
        "upgrade",
        "trailer",
    ] {
        headers.remove(name);
    }
    for name in nominated {
        headers.remove(&name);
    }
    Ok(())
}

/// Collect a body up to `max`, and refuse a trailer section, which hyper would drop.
async fn collect<B>(body: B, max: usize) -> Result<Vec<u8>>
where
    B: hyper::body::Body<Data = hyper::body::Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let over = || ProxyError::ResponseLimit(format!("body length exceeds limit {max}"));
    let hint = body.size_hint();
    if hint.lower() > max as u64 {
        return Err(over());
    }
    let mut collected = Vec::with_capacity(hint.exact().map_or(0, |len| len as usize));
    let mut body = std::pin::pin!(body);
    while let Some(frame) = body.frame().await {
        let frame =
            frame.map_err(|error| ProxyError::Io(format!("reading body: {}", error.into())))?;
        match frame.into_data() {
            Ok(data) if collected.len() + data.len() > max => return Err(over()),
            Ok(data) => collected.extend_from_slice(&data),
            Err(frame)
                if frame
                    .trailers_ref()
                    .is_some_and(|trailers| !trailers.is_empty()) =>
            {
                return Err(ProxyError::Intercept(
                    "chunked trailers are not supported".to_string(),
                ));
            }
            Err(_) => {}
        }
    }
    Ok(collected)
}

/// Reject transfer coding on HTTP/1.0, where chunked framing is not defined.
fn validate_transfer_coding_version(
    version: Option<u8>,
    framing: Option<BodyFraming>,
) -> Result<()> {
    if framing == Some(BodyFraming::Chunked) && version != Some(1) {
        return Err(ProxyError::Intercept(
            "Transfer-Encoding requires HTTP/1.1".to_string(),
        ));
    }
    Ok(())
}

/// Read one request from its raw `head`, which the box judges, and hyper's decoded `body`.
pub(crate) async fn read_request<B>(head: &[u8], body: B, max_body: usize) -> Result<ParsedRequest>
where
    B: hyper::body::Body<Data = hyper::body::Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut header_storage = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut header_storage);
    let status = req
        .parse(head)
        .map_err(|e| ProxyError::Intercept(format!("parsing request: {e}")))?;
    if status.is_partial() {
        return Err(ProxyError::Intercept(
            "incomplete HTTP request head".to_string(),
        ));
    }
    let method = req.method.unwrap_or("GET").to_string();
    if method.eq_ignore_ascii_case("CONNECT") {
        return Err(ProxyError::Intercept(
            "nested CONNECT tunneling is not supported".to_string(),
        ));
    }
    let target = req.path.unwrap_or("/").to_string();
    let mut headers = header_map_from(req.headers);
    let framing = explicit_body_framing(&headers)?;
    validate_transfer_coding_version(req.version, framing)?;
    // RFC 7230 §3.3.3 rule 6: no framing means no body.
    let body = collect(body, max_body).await?;
    strip_hop_by_hop_headers(&mut headers)?;
    if framing.is_some() {
        headers.set("Content-Length", body.len().to_string());
    }
    Ok(ParsedRequest {
        method,
        target,
        headers,
        body,
    })
}

/// Read the upstream's final response up to `max_body`, and refuse an ambiguous framing first.
pub(crate) async fn read_response(
    response: hyper::Response<hyper::body::Incoming>,
    max_body: usize,
) -> Result<ParsedResponse> {
    let (mut head, body) = response.into_parts();
    let status = head.status.as_u16();
    if status == 101 {
        return Err(ProxyError::Intercept(
            "HTTP protocol upgrades are not supported".to_string(),
        ));
    }
    let mut headers = HeaderMap::from_pairs(head.headers.iter().map(|(name, value)| {
        (
            name.as_str().to_string(),
            String::from_utf8_lossy(value.as_bytes()).into_owned(),
        )
    }));
    let framing = explicit_body_framing(&headers)?;
    validate_transfer_coding_version(
        Some(u8::from(head.version == hyper::Version::HTTP_11)),
        framing,
    )?;
    let body = collect(body, max_body).await?;
    strip_hop_by_hop_headers(&mut headers)?;
    // Pass on the header case, not the upstream's reason phrase.
    head.extensions.remove::<hyper::ext::ReasonPhrase>();
    Ok(ParsedResponse {
        status,
        headers,
        body,
        header_case: head.extensions,
    })
}

/// Build a [`HeaderMap`] from parsed httparse headers (preserving order + casing).
fn header_map_from(headers: &[httparse::Header]) -> HeaderMap {
    HeaderMap::from_pairs(headers.iter().filter(|h| !h.name.is_empty()).map(|h| {
        (
            h.name.to_string(),
            String::from_utf8_lossy(h.value).into_owned(),
        )
    }))
}

/// Append one header line (`name: value\r\n`) directly to `out` — no temporary `format!` allocation.
fn push_header_line(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push_str(": ");
    out.push_str(value);
    out.push_str("\r\n");
}

/// Append the refreshed `Content-Length` header and the blank-line head terminator, formatting the
/// length in place (no temporary allocation).
fn write_content_length_and_terminator(out: &mut String, len: usize) {
    use std::fmt::Write as _;
    let _ = write!(out, "Content-Length: {len}\r\n\r\n");
}

/// A head-buffer capacity that the write cannot exceed, so `out` allocates **once**.
fn estimate_head_capacity(headers: &HeaderMap, caller_overhead: usize) -> usize {
    let headers_bytes: usize = headers.iter().map(|(n, v)| n.len() + v.len() + 4).sum();
    // `Connection: close\r\n` is 19; `Content-Length: \r\n\r\n` is 20 framing bytes plus at most 20
    // digits for a `u64`-sized length. 8 bytes of slack absorbs a future single-header addition.
    headers_bytes + caller_overhead + 19 + 20 + 20 + 8
}

/// The request line's contribution to [`estimate_head_capacity`]:
/// `METHOD` + ` ` + `target` + ` HTTP/1.1\r\n` (11 fixed bytes plus the two separators).
fn request_line_bytes(method: &str, target: &str) -> usize {
    method.len() + target.len() + 12
}

/// Serialize the request head for the upstream, with `Content-Length` set to the body length.
/// hyper sends a stand-in in place of these bytes, so the secret never enters its buffers.
pub(super) fn write_request(
    method: &str,
    target: &str,
    headers: &HeaderMap,
    body_len: usize,
) -> Result<Zeroizing<String>> {
    let nominated = connection_nominated_headers(headers)?;
    // The head buffer is where the attached credential is serialized, so it is wiped on drop. The
    // request leg has already run by the time this is called: one of the header values below *is* the
    // operator's real secret.
    let mut out = Zeroizing::new(String::with_capacity(estimate_head_capacity(
        headers,
        request_line_bytes(method, target),
    )));
    out.push_str(method);
    out.push(' ');
    out.push_str(target);
    out.push_str(" HTTP/1.1\r\n");
    for (name, value) in headers.iter() {
        if name.eq_ignore_ascii_case("content-length") || is_hop_by_hop_header(name, &nominated) {
            continue; // refreshed below
        }
        push_header_line(&mut out, name, value);
    }
    out.push_str("Connection: close\r\n");
    write_content_length_and_terminator(&mut out, body_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use hyper::body::Bytes;

    use crate::transport::socket::block_on;

    /// The box's framing verdict on the head of `raw`.
    fn check(raw: &str) -> Result<Option<BodyFraming>> {
        let mut storage = [httparse::EMPTY_HEADER; 64];
        let (version, headers) = if raw.starts_with("HTTP/") {
            let mut res = httparse::Response::new(&mut storage);
            res.parse(raw.as_bytes()).unwrap();
            (res.version, header_map_from(res.headers))
        } else {
            let mut req = httparse::Request::new(&mut storage);
            req.parse(raw.as_bytes()).unwrap();
            (req.version, header_map_from(req.headers))
        };
        let framing = explicit_body_framing(&headers)?;
        validate_transfer_coding_version(version, framing)?;
        Ok(framing)
    }

    /// A head that starts with blank lines is judged by the request after them, as hyper reads it.
    #[test]
    fn a_request_after_blank_lines_is_judged_by_its_framing() {
        let head = b"\r\n\r\nPOST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
        let refused = block_on(read_request(head, Full::new(Bytes::new()), 1024)).unwrap();
        assert!(matches!(refused, Err(ProxyError::Intercept(_))));
    }

    #[test]
    fn a_request_keeps_the_header_names_and_order_the_workload_sent() {
        let head = b"POST /x HTTP/1.1\r\nX-B: 1\r\nhost: h\r\nX-A: 2\r\nContent-Length: 2\r\n\r\n";
        let parsed = block_on(read_request(
            head,
            Full::new(Bytes::from_static(b"ok")),
            1024,
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            parsed
                .headers
                .iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            ["X-B", "host", "X-A", "Content-Length"]
        );
        assert_eq!(parsed.body, b"ok");
    }

    #[test]
    fn nonempty_chunked_trailers_are_rejected() {
        let body = Full::new(Bytes::from_static(b"ok")).with_trailers(async {
            let mut trailers = hyper::HeaderMap::new();
            trailers.insert("digest", "sha-256=abc".parse().unwrap());
            Some(Ok(trailers))
        });
        let error = block_on(collect(body, 1024)).unwrap().unwrap_err();
        assert!(matches!(error, ProxyError::Intercept(_)));
    }

    #[test]
    fn body_over_limit_is_response_limit_error() {
        let body = Full::new(Bytes::from_static(b"12345678"));
        let error = block_on(collect(body, 7)).unwrap().unwrap_err();
        assert!(matches!(error, ProxyError::ResponseLimit(_)));
        let body = Full::new(Bytes::from_static(b"1234567"));
        assert_eq!(block_on(collect(body, 7)).unwrap().unwrap(), b"1234567");
    }

    #[test]
    fn content_length_and_transfer_encoding_conflict_is_rejected() {
        for raw in [
            concat!(
                "POST /x HTTP/1.1\r\n",
                "Content-Length: 4\r\n",
                "Transfer-Encoding: chunked\r\n",
                "\r\n",
                "4\r\nbody\r\n0\r\n\r\n"
            ),
            concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Length: 2\r\n",
                "Transfer-Encoding: chunked\r\n",
                "\r\n",
                "2\r\nok\r\n0\r\n\r\n"
            ),
        ] {
            assert!(matches!(check(raw), Err(ProxyError::Intercept(_))));
        }
    }

    #[test]
    fn unsupported_transfer_coding_is_rejected() {
        for value in [
            "gzip",
            "gzip, chunked",
            "chunked, gzip",
            "chunked;level=1",
            "chunked, chunked",
        ] {
            let raw = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: {value}\r\n\r\n");
            assert!(
                matches!(check(&raw), Err(ProxyError::Intercept(_))),
                "{value}"
            );
        }

        let raw = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n"
        );
        assert!(matches!(check(raw), Err(ProxyError::Intercept(_))));
    }

    #[test]
    fn repeated_or_malformed_content_lengths_are_rejected() {
        for headers in [
            "Content-Length: 2\r\nContent-Length: 2\r\n",
            "Content-Length: 2, 2\r\n",
            "Content-Length: not-a-number\r\n",
            "Content-Length:\r\n",
        ] {
            let raw = format!("HTTP/1.1 200 OK\r\n{headers}\r\n");
            assert!(
                matches!(check(&raw), Err(ProxyError::Intercept(_))),
                "{headers:?}"
            );
        }
    }

    #[test]
    fn unicode_whitespace_in_framing_headers_is_rejected() {
        for header in [
            "Content-Length: \u{a0}2\r\n",
            "Transfer-Encoding: \u{a0}chunked\r\n",
        ] {
            let raw = format!("HTTP/1.1 200 OK\r\n{header}\r\n");
            assert!(
                matches!(check(&raw), Err(ProxyError::Intercept(_))),
                "{header:?}"
            );
        }
    }

    #[test]
    fn http10_chunked_messages_are_rejected() {
        let request = "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n";
        assert!(matches!(check(request), Err(ProxyError::Intercept(_))));

        let response = "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n";
        assert!(matches!(check(response), Err(ProxyError::Intercept(_))));
    }

    /// The head buffer never outgrows its estimate, so the credential in it is never `memcpy`'d to a
    /// new allocation and left behind unscrubbed.
    #[test]
    fn the_head_buffer_never_outgrows_its_estimate() {
        let long_credential = "A".repeat(512);
        let long_token = "T".repeat(900);

        /// One request shape to budget, chosen to have no incidental slack: no inbound
        /// `Content-Length` and no hop-by-hop header, so nothing is budgeted-then-skipped.
        struct Case<'a> {
            method: &'a str,
            target: &'a str,
            headers: Vec<(&'a str, &'a str)>,
        }

        let cases = vec![
            Case {
                method: "GET",
                target: "/",
                headers: vec![("Host", "h")],
            },
            Case {
                method: "POST",
                target: "/v1/messages",
                headers: vec![
                    ("Host", "api.anthropic.com"),
                    ("Authorization", "Bearer sk-ant-REAL-SECRET-VALUE"),
                ],
            },
            // A long target and a long credential, the shape a `UrlPath` inject mode produces.
            Case {
                method: "PUT",
                target: "/v1/objects/a-fairly-long-resource-path/with/segments?q=1&r=2",
                headers: vec![
                    ("Host", "s3.us-west-2.amazonaws.com"),
                    ("Authorization", long_credential.as_str()),
                    ("X-Amz-Security-Token", long_token.as_str()),
                ],
            },
            // No headers at all: the fixed overhead has to stand on its own.
            Case {
                method: "DELETE",
                target: "/x",
                headers: vec![],
            },
        ];

        for Case {
            method,
            target,
            headers: pairs,
        } in cases
        {
            let headers = HeaderMap::from_pairs(
                pairs
                    .iter()
                    .map(|(n, v)| ((*n).to_string(), (*v).to_string())),
            );
            let budget = estimate_head_capacity(&headers, request_line_bytes(method, target));

            // Rebuild exactly what `write_request` writes.
            let mut out = String::with_capacity(budget);
            out.push_str(method);
            out.push(' ');
            out.push_str(target);
            out.push_str(" HTTP/1.1\r\n");
            for (name, value) in headers.iter() {
                push_header_line(&mut out, name, value);
            }
            out.push_str("Connection: close\r\n");
            write_content_length_and_terminator(&mut out, usize::MAX);

            assert!(
                out.len() <= budget,
                "{method} {target}: wrote {} bytes into a {budget}-byte budget, so the buffer \
                 reallocated with the credential in it",
                out.len()
            );
        }
    }

    /// An existing inbound Content-Length is dropped and refreshed to the actual body length.
    #[test]
    fn write_refreshes_content_length() {
        let mut headers = HeaderMap::new();
        headers.append("Content-Length", "9999"); // stale
        let s = write_request("POST", "/", &headers, 3).unwrap();
        assert!(s.contains("Content-Length: 3\r\n"));
        assert!(!s.contains("9999"));
    }

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

        let wire = write_request("POST", "/", &headers, 4)
            .unwrap()
            .to_ascii_lowercase();
        for removed in [
            "keep-alive:",
            "proxy-connection:",
            "proxy-authorization:",
            "proxy-authenticate:",
            "te:",
            "transfer-encoding:",
            "upgrade:",
            "trailer:",
            "x-remove:",
        ] {
            assert!(!wire.contains(removed), "{removed} survived: {wire}");
        }
        assert_eq!(wire.matches("connection: close\r\n").count(), 1);
        assert!(!wire.contains("keep-alive, x-remove"));
        assert!(wire.contains("x-end-to-end: keep\r\n"));
        assert!(wire.contains("content-length: 4\r\n"));
    }
}
