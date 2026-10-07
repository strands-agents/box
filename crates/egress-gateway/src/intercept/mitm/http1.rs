//! Minimal synchronous HTTP/1.1 read/write over a plaintext stream (the intercepted leg).

use std::io::{self, BufRead, Write};

use zeroize::Zeroizing;

use crate::boundary::HeaderMap;
use crate::error::{ProxyError, Result};

/// A parsed HTTP/1.1 request read off the wire.
#[derive(Debug)]
pub(super) struct ParsedRequest {
    /// The method (`GET`, `POST`, …).
    pub(super) method: String,
    /// The request target (origin-form path, e.g. `/v1/x?a=1`).
    pub(super) target: String,
    /// The request headers.
    pub(super) headers: HeaderMap,
    /// The request body (materialized, bounded by the read limit).
    pub(super) body: Vec<u8>,
}

/// A parsed HTTP/1.1 response read off the wire.
#[derive(Debug)]
pub(super) struct ParsedResponse {
    /// The status code.
    pub(super) status: u16,
    /// The response headers.
    pub(super) headers: HeaderMap,
    /// The response body (materialized, bounded by the read limit).
    pub(super) body: Vec<u8>,
}

/// The largest head (request/response line + headers) we buffer before giving up — a hostile client
/// cannot make us buffer unboundedly looking for the `\r\n\r\n` terminator.
///
/// That sentence was false for as long as `read_head` used `read_until`, which appended a whole line
/// before the check and so bounded the line *count*. `read_head` now checks before each copy.
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Maximum wire length of one chunk-size or trailer line, including its terminating CRLF.
const MAX_CHUNK_LINE_BYTES: usize = 8 * 1024;

/// Maximum aggregate chunk framing metadata. This bounds pathological streams made of tiny chunks
/// with large extensions even when their decoded body remains under the body-size limit.
const MAX_CHUNK_METADATA_BYTES: usize = 64 * 1024;

/// Maximum interim responses accepted before the final upstream response.
const MAX_INFORMATIONAL_RESPONSES: usize = 16;

/// Read the HTTP head (everything up to and including the `\r\n\r\n` terminator) from a **buffered**
/// stream, bounded by [`MAX_HEAD_BYTES`] as it goes.
///
/// **The limit is checked BEFORE each copy, not after each line, and that is the whole fix.** This
/// used `read_until(b'\n', &mut buf)`, which returns only at a newline or at EOF — so it appended a
/// whole line to `buf` and *then* compared `buf.len()` against the limit. One line with no newline in
/// it was therefore buffered in full, and the constant bounded the line *count* rather than the byte
/// count. A single hostile header line made the proxy hold it all.
///
/// The correct shape already existed 300 lines below in this file, in `read_chunk_line`: take from
/// `fill_buf`, find the newline, check the prospective length against the limit, then copy and
/// `consume`. This is that loop with the head's terminator condition.
///
/// `stream.take(MAX_HEAD_BYTES)` was the other option and is worse: the cap surfaces as `Ok(0)`, which
/// this function must report as "connection closed before HTTP head" — a misleading message for a head
/// that was too long rather than truncated.
fn read_head<R: BufRead>(stream: &mut R) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut line_start = 0usize;
    loop {
        let available = stream
            .fill_buf()
            .map_err(|e| ProxyError::Io(format!("reading head: {e}")))?;
        if available.is_empty() {
            // EOF before the terminator.
            return Err(ProxyError::Intercept(
                "connection closed before HTTP head".to_string(),
            ));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |position| position + 1);
        let next_len = buf
            .len()
            .checked_add(take)
            .ok_or_else(|| ProxyError::Intercept("HTTP head length overflow".to_string()))?;
        if next_len > MAX_HEAD_BYTES {
            return Err(ProxyError::Intercept("HTTP head exceeds limit".to_string()));
        }
        buf.extend_from_slice(&available[..take]);
        stream.consume(take);

        if newline.is_none() {
            // The buffer ran out mid-line. Keep `line_start` where it is and read more.
            continue;
        }
        // The head ends at the first blank line: the line just completed is exactly the terminator.
        let line = &buf[line_start..];
        if line == b"\r\n" || line == b"\n" {
            return Ok(buf);
        }
        line_start = buf.len();
    }
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

fn trim_ows_start(mut bytes: &[u8]) -> &[u8] {
    while matches!(bytes.first(), Some(b' ' | b'\t')) {
        bytes = &bytes[1..];
    }
    bytes
}

fn trim_ows_end(mut bytes: &[u8]) -> &[u8] {
    while matches!(bytes.last(), Some(b' ' | b'\t')) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

/// Validate chunk extensions before discarding them.
fn validate_chunk_extensions(mut extensions: &[u8]) -> Result<()> {
    extensions = trim_ows_start(extensions);
    while !extensions.is_empty() {
        if extensions[0] != b';' {
            return Err(ProxyError::Intercept(
                "malformed chunk extension".to_string(),
            ));
        }
        extensions = trim_ows_start(&extensions[1..]);

        let name_len = extensions
            .iter()
            .take_while(|byte| is_token_byte(**byte))
            .count();
        if name_len == 0 {
            return Err(ProxyError::Intercept(
                "malformed chunk extension name".to_string(),
            ));
        }
        extensions = &extensions[name_len..];
        extensions = trim_ows_start(extensions);

        if extensions.first() == Some(&b'=') {
            extensions = trim_ows_start(&extensions[1..]);
            if extensions.first() == Some(&b'"') {
                extensions = quoted_extension_remainder(extensions)?;
            } else {
                let value_len = extensions
                    .iter()
                    .take_while(|byte| is_token_byte(**byte))
                    .count();
                if value_len == 0 {
                    return Err(ProxyError::Intercept(
                        "malformed chunk extension value".to_string(),
                    ));
                }
                extensions = &extensions[value_len..];
            }
        }
        extensions = trim_ows_start(extensions);

        if !extensions.is_empty() && extensions[0] != b';' {
            return Err(ProxyError::Intercept(
                "malformed chunk extension".to_string(),
            ));
        }
    }
    Ok(())
}

/// Validate one quoted chunk-extension value and return the bytes after its closing quote.
fn quoted_extension_remainder(value: &[u8]) -> Result<&[u8]> {
    let mut escaped = false;
    for (index, byte) in value.iter().copied().enumerate().skip(1) {
        if escaped {
            let valid =
                byte == b'\t' || byte == b' ' || (b'!'..=b'~').contains(&byte) || byte >= 0x80;
            if !valid {
                return Err(ProxyError::Intercept(
                    "malformed quoted chunk extension".to_string(),
                ));
            }
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'"' => return Ok(&value[index + 1..]),
            b'\t' | b' ' | b'!' => {}
            b'#'..=b'[' | b']'..=b'~' => {}
            0x80..=0xff => {}
            _ => {
                return Err(ProxyError::Intercept(
                    "malformed quoted chunk extension".to_string(),
                ));
            }
        }
    }
    Err(ProxyError::Intercept(
        "unterminated quoted chunk extension".to_string(),
    ))
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

/// Read exactly `len` body bytes from a **buffered** stream, bounded by `max`.
fn read_body<R: BufRead>(stream: &mut R, len: usize, max: usize) -> Result<Vec<u8>> {
    if len > max {
        return Err(ProxyError::ResponseLimit(format!(
            "body length {len} exceeds limit {max}"
        )));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|e| ProxyError::Io(format!("reading body: {e}")))?;
    Ok(body)
}

/// Read one CRLF-terminated chunk framing line without allowing `read_until` to allocate past the
/// line limit before returning.
fn read_chunk_line<R: BufRead>(stream: &mut R, what: &str) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let available = stream
            .fill_buf()
            .map_err(|e| ProxyError::Io(format!("reading {what}: {e}")))?;
        if available.is_empty() {
            return Err(ProxyError::Intercept(format!(
                "connection closed while reading {what}"
            )));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |position| position + 1);
        let next_len = line
            .len()
            .checked_add(take)
            .ok_or_else(|| ProxyError::Intercept(format!("{what} length overflow")))?;
        if next_len > MAX_CHUNK_LINE_BYTES {
            return Err(ProxyError::Intercept(format!("{what} exceeds limit")));
        }
        line.extend_from_slice(&available[..take]);
        stream.consume(take);
        if newline.is_some() {
            break;
        }
    }
    if !line.ends_with(b"\r\n") {
        return Err(ProxyError::Intercept(format!(
            "{what} is not CRLF-terminated"
        )));
    }
    line.truncate(line.len() - 2);
    Ok(line)
}

/// Account for chunk framing overhead and reject pathological metadata growth.
fn account_chunk_metadata(total: &mut usize, bytes: usize) -> Result<()> {
    let next = total
        .checked_add(bytes)
        .ok_or_else(|| ProxyError::Intercept("chunk metadata length overflow".to_string()))?;
    if next > MAX_CHUNK_METADATA_BYTES {
        return Err(ProxyError::Intercept(
            "chunk framing metadata exceeds limit".to_string(),
        ));
    }
    *total = next;
    Ok(())
}

/// Read and decode one chunked body, bounded by both decoded-body and framing-metadata limits.
fn read_chunked_body<R: BufRead>(stream: &mut R, max: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut metadata_bytes = 0usize;
    loop {
        let line = read_chunk_line(stream, "chunk-size line")?;
        account_chunk_metadata(&mut metadata_bytes, line.len() + 2)?;
        let extension_start = line.iter().position(|byte| *byte == b';');
        let (size_digits, extensions) = match extension_start {
            Some(index) => (trim_ows_end(&line[..index]), &line[index..]),
            None => (&line[..], &[][..]),
        };
        if size_digits.is_empty() || !size_digits.iter().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ProxyError::Intercept("malformed chunk size".to_string()));
        }
        validate_chunk_extensions(extensions)?;
        let size_digits = std::str::from_utf8(size_digits)
            .map_err(|_| ProxyError::Intercept("malformed chunk size".to_string()))?;
        let size = usize::from_str_radix(size_digits, 16)
            .map_err(|_| ProxyError::Intercept("chunk size exceeds usize".to_string()))?;

        if size == 0 {
            let trailer = read_chunk_line(stream, "chunk trailer line")?;
            account_chunk_metadata(&mut metadata_bytes, trailer.len() + 2)?;
            if !trailer.is_empty() {
                return Err(ProxyError::Intercept(
                    "chunked trailers are not supported".to_string(),
                ));
            }
            return Ok(body);
        }

        let next_len = body
            .len()
            .checked_add(size)
            .ok_or_else(|| ProxyError::ResponseLimit("body length overflow".to_string()))?;
        if next_len > max {
            return Err(ProxyError::ResponseLimit(format!(
                "chunked body length exceeds limit {max}"
            )));
        }
        let old_len = body.len();
        body.resize(next_len, 0);
        stream
            .read_exact(&mut body[old_len..])
            .map_err(|e| ProxyError::Io(format!("reading chunk data: {e}")))?;

        let mut terminator = [0u8; 2];
        stream
            .read_exact(&mut terminator)
            .map_err(|e| ProxyError::Io(format!("reading chunk terminator: {e}")))?;
        if terminator != *b"\r\n" {
            return Err(ProxyError::Intercept(
                "chunk data is not CRLF-terminated".to_string(),
            ));
        }
        account_chunk_metadata(&mut metadata_bytes, terminator.len())?;
    }
}

/// Read the body until end-of-stream (connection close), bounded by `max` — RFC 7230 §3.3.3 rule 7,
/// the "body delimited by connection close" framing used by a response that carries **no**
/// `Content-Length` and **no** `Transfer-Encoding`.
fn read_body_to_close<R: BufRead>(stream: &mut R, max: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream
            .read(&mut chunk)
            .map_err(|e| ProxyError::Io(format!("reading body: {e}")))?;
        if n == 0 {
            return Ok(body); // EOF: the close delimits the body.
        }
        if body.len() + n > max {
            return Err(ProxyError::ResponseLimit(format!(
                "response body exceeds limit {max} (connection-close framed)"
            )));
        }
        body.extend_from_slice(&chunk[..n]);
    }
}

/// How the request method and response status constrain response payload framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResponseBodyMode {
    /// The response carries a regular payload.
    Payload,
    /// The response has no wire payload but may retain representation-length metadata.
    MetadataOnly,
    /// The response has no payload and must not retain payload framing metadata.
    Forbidden,
}

fn response_body_mode(request_method: &str, status: u16) -> ResponseBodyMode {
    if (100..200).contains(&status)
        || status == 204
        || (request_method.eq_ignore_ascii_case("CONNECT") && (200..300).contains(&status))
    {
        ResponseBodyMode::Forbidden
    } else if request_method == "HEAD" || status == 304 {
        ResponseBodyMode::MetadataOnly
    } else {
        ResponseBodyMode::Payload
    }
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

/// Read and parse one HTTP/1.1 request from a **buffered** `stream`, materializing the body up to
/// `max_body`.
pub(super) fn read_request<R: BufRead>(stream: &mut R, max_body: usize) -> Result<ParsedRequest> {
    let head = read_head(stream)?;
    let mut header_storage = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut header_storage);
    let status = req
        .parse(&head)
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
    // RFC 7230 §3.3.3 rule 6: a request with no explicit framing has no body. Unlike a response, a
    // request is never delimited by connection close.
    let body = match framing {
        Some(BodyFraming::ContentLength(len)) => read_body(stream, len, max_body)?,
        Some(BodyFraming::Chunked) => read_chunked_body(stream, max_body)?,
        None => Vec::new(),
    };
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

/// A reply that did not fully arrive, with the status its head carried once the head was read.
#[derive(Debug)]
pub(super) struct ReplyFailure {
    pub(super) status: Option<u16>,
    pub(super) error: ProxyError,
}

impl ReplyFailure {
    fn before_head(error: ProxyError) -> Self {
        Self {
            status: None,
            error,
        }
    }

    fn after_head(status: u16) -> impl Fn(ProxyError) -> Self {
        move |error| Self {
            status: Some(status),
            error,
        }
    }
}

/// Read one HTTP/1.1 response, normalizing its framing and headers.
fn read_one_response<R: BufRead>(
    stream: &mut R,
    request_method: &str,
    max_body: usize,
) -> std::result::Result<ParsedResponse, ReplyFailure> {
    let head = read_head(stream).map_err(ReplyFailure::before_head)?;
    let mut header_storage = [httparse::EMPTY_HEADER; 64];
    let mut res = httparse::Response::new(&mut header_storage);
    let status = res.parse(&head).map_err(|e| {
        ReplyFailure::before_head(ProxyError::Intercept(format!("parsing response: {e}")))
    })?;
    if status.is_partial() {
        return Err(ReplyFailure::before_head(ProxyError::Intercept(
            "incomplete HTTP response head".to_string(),
        )));
    }
    let code = res.code.unwrap_or(0);
    let headers = header_map_from(res.headers);
    read_response_body(stream, request_method, res.version, code, headers, max_body)
        .map_err(ReplyFailure::after_head(code))
}

/// Read the body a parsed head announces, and normalize the headers around it.
fn read_response_body<R: BufRead>(
    stream: &mut R,
    request_method: &str,
    version: Option<u8>,
    code: u16,
    mut headers: HeaderMap,
    max_body: usize,
) -> Result<ParsedResponse> {
    let framing = explicit_body_framing(&headers)?;
    validate_transfer_coding_version(version, framing)?;
    let body_mode = response_body_mode(request_method, code);
    // RFC 7230 §3.3.3 response-body framing precedence:
    //   1. HEAD/1xx/204/304/successful CONNECT → no body regardless of headers.
    //   2. an explicit Content-Length → read exactly that many bytes.
    //   3. neither Content-Length nor Transfer-Encoding → the body runs until connection close
    //      (rule 7). We MUST read to EOF here; defaulting to 0 would silently drop the whole body.
    //      This is safe only because the v1 adapter never reuses an upstream connection.
    let body = if body_mode != ResponseBodyMode::Payload {
        Vec::new()
    } else {
        match framing {
            Some(BodyFraming::ContentLength(len)) => read_body(stream, len, max_body)?,
            Some(BodyFraming::Chunked) => read_chunked_body(stream, max_body)?,
            None => read_body_to_close(stream, max_body)?,
        }
    };
    strip_hop_by_hop_headers(&mut headers)?;
    match body_mode {
        ResponseBodyMode::Payload if framing.is_some() || !body.is_empty() => {
            headers.set("Content-Length", body.len().to_string());
        }
        ResponseBodyMode::Forbidden => {
            headers.remove("content-length");
        }
        ResponseBodyMode::Payload | ResponseBodyMode::MetadataOnly => {}
    }
    Ok(ParsedResponse {
        status: code,
        headers,
        body,
    })
}

/// Read the final HTTP/1.1 response for `request_method`, consuming bounded informational responses.
pub(super) fn read_response<R: BufRead>(
    stream: &mut R,
    request_method: &str,
    max_body: usize,
) -> std::result::Result<ParsedResponse, ReplyFailure> {
    let mut informational_responses = 0;
    loop {
        let response = read_one_response(stream, request_method, max_body)?;
        let refused = ReplyFailure::after_head(response.status);
        if response.status == 101 {
            return Err(refused(ProxyError::Intercept(
                "HTTP protocol upgrades are not supported".to_string(),
            )));
        }
        if request_method.eq_ignore_ascii_case("CONNECT") && (200..300).contains(&response.status) {
            return Err(refused(ProxyError::Intercept(
                "nested CONNECT tunneling is not supported".to_string(),
            )));
        }
        if !(100..200).contains(&response.status) {
            return Ok(response);
        }
        informational_responses += 1;
        if informational_responses > MAX_INFORMATIONAL_RESPONSES {
            return Err(refused(ProxyError::Intercept(
                "too many informational responses".to_string(),
            )));
        }
    }
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

/// The body-size threshold under which the body is coalesced into the head buffer for a **single**
/// `write_all` (one TLS record). Above it, the head and body are written separately so a large body
/// is not copied into the head buffer just to save a record.
const COALESCE_BODY_LIMIT: usize = 32 * 1024;

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

/// The status line's contribution to [`estimate_head_capacity`]: `HTTP/1.1 NNN ` plus a reason
/// phrase plus CRLF. 64 bounds every phrase [`reason`] returns.
const STATUS_LINE_BYTES: usize = 64;

/// Write an assembled `head` + `body` to `stream`, coalescing a small body into one write (one TLS
/// record) and writing a large body separately to avoid copying it into the head buffer.
fn write_message<W: Write>(
    stream: &mut W,
    head: Zeroizing<String>,
    body: &[u8],
    what: &str,
) -> Result<()> {
    let io_err = |e| ProxyError::Io(format!("writing {what}: {e}"));
    if !body.is_empty() && body.len() <= COALESCE_BODY_LIMIT {
        // Small body: concatenate into one byte buffer and write once → a single TLS record, no extra
        // per-message encrypt/frame. The body may be binary, so work in bytes, not str.
        //
        // `head` holds the attached credential, so the coalesced buffer does too — hence `Zeroizing`.
        //
        // **The buffer is sized for head + body before either is copied in, and that is a correctness
        // requirement rather than a tuning choice.** An earlier version did
        // `take(&mut *head).into_bytes()` then `extend_from_slice(body)`, reusing the head's
        // allocation. `into_bytes` preserves the head's *capacity*, which is sized for the head alone,
        // so appending any body that did not fit relocated the buffer and left an un-wiped copy of the
        // credential in freed heap — measured relocating in 300/300 runs. `Zeroizing` only ever wipes
        // the final allocation.
        //
        // So this allocates once at the full size and copies the head in. That is one extra copy of
        // the head relative to the move, and it is the cheaper mistake: a copy whose destination is
        // wiped, instead of a move whose abandoned source is not.
        let mut buf = Zeroizing::new(Vec::with_capacity(head.len() + body.len()));
        buf.extend_from_slice(head.as_bytes());
        buf.extend_from_slice(body);
        debug_assert_eq!(
            buf.len(),
            buf.capacity(),
            "the coalesce buffer must not have grown after the credential was copied in"
        );
        stream.write_all(&buf).map_err(io_err)
    } else if body.is_empty() {
        stream.write_all(head.as_bytes()).map_err(io_err)
    } else {
        // Large body: keep it out of the head buffer; two writes beat a multi-MB copy.
        stream
            .write_all(head.as_bytes())
            .and_then(|_| stream.write_all(body))
            .map_err(io_err)
    }
}

/// A counted failure while delivering a fully prepared message.
#[derive(Debug)]
pub(super) struct WriteFailure {
    /// Bytes accepted by `Write` before the failure.
    pub(super) accepted_bytes: usize,
    /// The underlying write or flush error.
    pub(super) error: io::Error,
    /// Whether all message bytes were accepted and the later flush failed.
    pub(super) during_flush: bool,
}

/// Deliver fully prepared wire bytes with exact accepted-byte accounting.
pub(super) fn write_prepared_and_flush<W: Write>(
    stream: &mut W,
    prepared: &[u8],
) -> std::result::Result<usize, WriteFailure> {
    let mut accepted_bytes = 0;
    while accepted_bytes < prepared.len() {
        match stream.write(&prepared[accepted_bytes..]) {
            Ok(0) => {
                return Err(WriteFailure {
                    accepted_bytes,
                    error: io::Error::new(
                        io::ErrorKind::WriteZero,
                        "writer accepted no prepared bytes",
                    ),
                    during_flush: false,
                });
            }
            Ok(written) => accepted_bytes += written,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(WriteFailure {
                    accepted_bytes,
                    error,
                    during_flush: false,
                });
            }
        }
    }

    stream.flush().map_err(|error| WriteFailure {
        accepted_bytes,
        error,
        during_flush: true,
    })?;
    Ok(accepted_bytes)
}

/// Serialize a request in origin form (`METHOD target HTTP/1.1\r\nheaders\r\n\r\nbody`) for
/// forwarding to the upstream, refreshing `Content-Length` to the (possibly mutated) body length.
pub(super) fn write_request<W: Write>(
    stream: &mut W,
    method: &str,
    target: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<()> {
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
    write_content_length_and_terminator(&mut out, body.len());
    write_message(stream, out, body, "request")
}

/// Serialize a response (`HTTP/1.1 status\r\nheaders\r\n\r\nbody`) for return to the workload,
/// refreshing `Content-Length` to the (possibly scrubbed) body length.
pub(super) fn write_response<W: Write>(
    stream: &mut W,
    request_method: &str,
    status: u16,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<()> {
    use std::fmt::Write as _;
    let body_mode = response_body_mode(request_method, status);
    let metadata_length = if body_mode == ResponseBodyMode::MetadataOnly {
        content_length(headers)?
            .or_else(|| (request_method == "HEAD" && !body.is_empty()).then_some(body.len()))
    } else {
        None
    };
    let nominated = connection_nominated_headers(headers)?;
    // Wrapped for symmetry with `write_request` and because `write_message` takes one type. A response
    // head should hold no credential — the leak-back scrubber replaced any echoed secret with
    // `[REDACTED]` before this — so this wipes bytes that are usually not secret. That is the cheap
    // side of the trade: the alternative is two `write_message` spellings and a caller choosing.
    let mut out = Zeroizing::new(String::with_capacity(estimate_head_capacity(
        headers,
        STATUS_LINE_BYTES,
    )));
    // `write!` formats the status number in place — no temporary String.
    let _ = write!(*out, "HTTP/1.1 {status} {}\r\n", reason(status));
    for (name, value) in headers.iter() {
        if name.eq_ignore_ascii_case("content-length") || is_hop_by_hop_header(name, &nominated) {
            continue;
        }
        push_header_line(&mut out, name, value);
    }
    out.push_str("Connection: close\r\n");
    match body_mode {
        ResponseBodyMode::Payload => {
            write_content_length_and_terminator(&mut out, body.len());
            write_message(stream, out, body, "response")
        }
        ResponseBodyMode::MetadataOnly => {
            if let Some(length) = metadata_length {
                write_content_length_and_terminator(&mut out, length);
            } else {
                out.push_str("\r\n");
            }
            write_message(stream, out, &[], "response")
        }
        ResponseBodyMode::Forbidden => {
            out.push_str("\r\n");
            write_message(stream, out, &[], "response")
        }
    }
}

/// A minimal reason phrase for a status code (only the ones the proxy itself emits need be exact).
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        403 => "Forbidden",
        407 => "Proxy Authentication Required",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ if (200..300).contains(&status) => "OK",
        _ if (300..400).contains(&status) => "Redirect",
        _ if (400..500).contains(&status) => "Client Error",
        _ => "Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn a_reply_that_fails_after_its_head_keeps_its_status() {
        let mut cursor =
            Cursor::new(b"HTTP/1.1 500 Internal\r\nContent-Length: 100\r\n\r\nshort".to_vec());
        let failure = read_response(&mut cursor, "GET", 1024).unwrap_err();
        assert_eq!(failure.status, Some(500));

        let mut cursor = Cursor::new(b"HTTP/1.1 5".to_vec());
        let failure = read_response(&mut cursor, "GET", 1024).unwrap_err();
        assert_eq!(failure.status, None);
    }

    /// **One header line with no newline is refused by BYTE count, not buffered whole.**
    ///
    /// `read_head` used `read_until(b'\n', …)`, which returns only at a newline or EOF, so it appended
    /// the entire line and *then* compared against [`MAX_HEAD_BYTES`]. The constant therefore bounded
    /// the number of lines, not the bytes: one hostile line was held in full. 268 MB from a single
    /// connection was measured before the fix.
    ///
    /// **The assertion is on BYTES CONSUMED, because the message alone cannot catch this.** The old
    /// `read_until` implementation also ended in `HTTP head exceeds limit` — it just buffered the
    /// whole line first. A test asserting only the error text passes against the defect, and the
    /// first draft of this test did exactly that.
    ///
    /// So the reader counts. Fed 1 MiB with no CRLF anywhere, a bounded reader stops within one
    /// refill of the 64 KiB limit; `read_until` pulls all 1 MiB before it looks.
    #[test]
    fn a_single_oversized_header_line_is_refused_by_the_limit() {
        /// A `BufRead` that hands out fixed-size chunks and counts what was consumed.
        struct Counting {
            data: Vec<u8>,
            position: usize,
            chunk: usize,
            served: usize,
        }
        impl std::io::Read for Counting {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                let available = self.fill_buf()?.len().min(out.len());
                out[..available]
                    .copy_from_slice(&self.data[self.position..self.position + available]);
                self.consume(available);
                Ok(available)
            }
        }
        impl BufRead for Counting {
            fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
                let end = (self.position + self.chunk).min(self.data.len());
                Ok(&self.data[self.position..end])
            }
            fn consume(&mut self, amount: usize) {
                self.position += amount;
                self.served += amount;
            }
        }

        const CHUNK: usize = 8 * 1024;
        let mut reader = Counting {
            data: vec![b'a'; 1024 * 1024],
            position: 0,
            chunk: CHUNK,
            served: 0,
        };

        let error = read_head(&mut reader).expect_err("an oversized head must be refused");
        match error {
            ProxyError::Intercept(message) => assert!(
                message.contains("exceeds limit"),
                "the limit must be what refuses, not EOF: {message}"
            ),
            other => panic!("expected an Intercept refusal, got {other:?}"),
        }
        assert!(
            reader.served <= MAX_HEAD_BYTES + CHUNK,
            "the head reader must stop within one refill of the limit, not buffer the whole line: \
             consumed {} bytes for a {} byte limit",
            reader.served,
            MAX_HEAD_BYTES
        );
    }

    /// The paired positive, so the bound cannot be satisfied by refusing every head.
    ///
    /// A head split across several `fill_buf` refills must still assemble: the loop carries
    /// `line_start` across refills, and getting that wrong would make a long-but-legal header look
    /// like a terminator or never terminate.
    #[test]
    fn a_long_but_legal_head_still_assembles() {
        let value = "b".repeat(4096);
        let raw = format!("GET / HTTP/1.1\r\nHost: api.example.com\r\nX-Long: {value}\r\n\r\n");
        let mut cursor = Cursor::new(raw.clone().into_bytes());
        let head = read_head(&mut cursor).expect("a legal head under the limit must assemble");
        assert_eq!(
            head,
            raw.as_bytes(),
            "the head must be returned verbatim, terminator included"
        );
    }

    #[test]
    fn round_trips_a_request() {
        let raw = "POST /v1/x HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5\r\n\r\nhello";
        let mut cursor = Cursor::new(raw.as_bytes().to_vec());
        let req = read_request(&mut cursor, 1024).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.target, "/v1/x");
        assert_eq!(req.headers.get("host"), Some("api.example.com"));
        assert_eq!(req.body, b"hello");

        let mut out = Vec::new();
        write_request(&mut out, &req.method, &req.target, &req.headers, &req.body).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("POST /v1/x HTTP/1.1\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn reads_a_response() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut cursor = Cursor::new(raw.as_bytes().to_vec());
        let res = read_response(&mut cursor, "GET", 1024)
            .map_err(|failure| failure.error)
            .unwrap();
        assert_eq!(res.status, 200);
        assert_eq!(res.body, b"ok");
    }

    #[test]
    fn body_over_limit_is_response_limit_error() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        let mut cursor = Cursor::new(raw.as_bytes().to_vec());
        let err = read_response(&mut cursor, "GET", 10)
            .map_err(|failure| failure.error)
            .unwrap_err();
        assert!(matches!(err, ProxyError::ResponseLimit(_)));
    }

    #[test]
    fn decodes_chunked_response_with_extensions_and_normalizes_headers() {
        let raw = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Trailer: X-Checksum\r\n",
            "Connection: keep-alive, X-Hop\r\n",
            "Keep-Alive: timeout=5\r\n",
            "Proxy-Authenticate: Basic realm=\"proxy\"\r\n",
            "X-Hop: remove-me\r\n",
            "\r\n",
            "2 \t; source = \"mantle\" \t; stream\r\n",
            "ok\r\n",
            "5\r\n",
            "there\r\n",
            "0\r\n",
            "\r\n"
        );
        let mut cursor = Cursor::new(raw.as_bytes().to_vec());
        let response = read_response(&mut cursor, "GET", 1024)
            .map_err(|failure| failure.error)
            .unwrap();
        assert_eq!(response.body, b"okthere");
        assert_eq!(response.headers.get("content-length"), Some("7"));
        assert!(!response.headers.contains("transfer-encoding"));
        assert!(!response.headers.contains("trailer"));
        assert!(!response.headers.contains("connection"));
        assert!(!response.headers.contains("keep-alive"));
        assert!(!response.headers.contains("proxy-authenticate"));
        assert!(!response.headers.contains("x-hop"));

        let mut out = Vec::new();
        write_response(
            &mut out,
            "GET",
            response.status,
            &response.headers,
            &response.body,
        )
        .unwrap();
        let wire = String::from_utf8(out).unwrap();
        assert!(wire.contains("Content-Length: 7\r\n"));
        assert!(!wire.to_ascii_lowercase().contains("transfer-encoding"));
        assert!(!wire.to_ascii_lowercase().contains("trailer:"));
    }

    #[test]
    fn decodes_chunked_request_case_insensitively() {
        let raw = concat!(
            "POST /x HTTP/1.1\r\n",
            "Host: h\r\n",
            "Transfer-Encoding: CHUNKED\r\n",
            "Connection: close, X-Hop\r\n",
            "Proxy-Authorization: Basic c2VjcmV0\r\n",
            "X-Hop: remove-me\r\n",
            "\r\n",
            "4\r\n",
            "body\r\n",
            "0\r\n",
            "\r\n"
        );
        let mut cursor = Cursor::new(raw.as_bytes().to_vec());
        let request = read_request(&mut cursor, 1024).unwrap();
        assert_eq!(request.body, b"body");
        assert_eq!(request.headers.get("content-length"), Some("4"));
        assert!(!request.headers.contains("transfer-encoding"));
        assert!(!request.headers.contains("connection"));
        assert!(!request.headers.contains("proxy-authorization"));
        assert!(!request.headers.contains("x-hop"));

        let mut out = Vec::new();
        write_request(
            &mut out,
            &request.method,
            &request.target,
            &request.headers,
            &request.body,
        )
        .unwrap();
        let wire = String::from_utf8(out).unwrap();
        assert!(wire.contains("Content-Length: 4\r\n"));
        assert!(!wire.to_ascii_lowercase().contains("transfer-encoding"));
    }

    #[test]
    fn malformed_chunk_framing_fails_closed() {
        for raw in [
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\nok\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nokXX0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\no",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;=bad\r\nok\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;name=\r\nok\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;name=\"open\r\nok\r\n0\r\n\r\n",
        ] {
            let mut cursor = Cursor::new(raw.as_bytes().to_vec());
            let error = read_response(&mut cursor, "GET", 1024)
                .map_err(|failure| failure.error)
                .unwrap_err();
            assert!(
                matches!(error, ProxyError::Intercept(_) | ProxyError::Io(_)),
                "malformed chunk stream must fail closed: {error:?}"
            );
        }
    }

    #[test]
    fn chunked_body_respects_decoded_size_limit() {
        let raw = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "4\r\n",
            "abcd\r\n",
            "4\r\n",
            "efgh\r\n",
            "0\r\n",
            "\r\n"
        );
        let mut cursor = Cursor::new(raw.as_bytes().to_vec());
        let error = read_response(&mut cursor, "GET", 7)
            .map_err(|failure| failure.error)
            .unwrap_err();
        assert!(matches!(error, ProxyError::ResponseLimit(_)));
    }

    #[test]
    fn oversized_chunk_metadata_fails_closed() {
        let extension = "x".repeat(MAX_CHUNK_LINE_BYTES);
        let raw = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;{extension}\r\na\r\n0\r\n\r\n"
        );
        let mut cursor = Cursor::new(raw.into_bytes());
        let error = read_response(&mut cursor, "GET", 1024)
            .map_err(|failure| failure.error)
            .unwrap_err();
        assert!(matches!(error, ProxyError::Intercept(_)));
    }

    #[test]
    fn aggregate_chunk_metadata_limit_is_enforced() {
        let extension = "x".repeat(4090);
        let chunk = format!("1;{extension}\r\na\r\n");
        let raw = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{}0\r\n\r\n",
            chunk.repeat(17)
        );
        let mut cursor = Cursor::new(raw.into_bytes());
        let error = read_response(&mut cursor, "GET", 1024)
            .map_err(|failure| failure.error)
            .unwrap_err();
        assert!(
            matches!(error, ProxyError::Intercept(message) if message.contains("metadata exceeds limit"))
        );
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
            let mut cursor = Cursor::new(raw.as_bytes().to_vec());
            let error = if raw.starts_with("POST") {
                read_request(&mut cursor, 1024).unwrap_err()
            } else {
                read_response(&mut cursor, "GET", 1024)
                    .map_err(|failure| failure.error)
                    .unwrap_err()
            };
            assert!(matches!(error, ProxyError::Intercept(_)));
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
            let mut cursor = Cursor::new(raw.into_bytes());
            let error = read_response(&mut cursor, "GET", 1024)
                .map_err(|failure| failure.error)
                .unwrap_err();
            assert!(matches!(error, ProxyError::Intercept(_)), "{value}");
        }

        let raw = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n"
        );
        let mut cursor = Cursor::new(raw.as_bytes());
        assert!(matches!(
            read_response(&mut cursor, "GET", 1024).map_err(|failure| failure.error),
            Err(ProxyError::Intercept(_))
        ));
    }

    #[test]
    fn nonempty_chunked_trailers_are_rejected() {
        let raw = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Trailer: Digest\r\n",
            "\r\n",
            "2\r\n",
            "ok\r\n",
            "0\r\n",
            "Digest: sha-256=abc\r\n",
            "\r\n"
        );
        let mut cursor = Cursor::new(raw.as_bytes().to_vec());
        let error = read_response(&mut cursor, "GET", 1024)
            .map_err(|failure| failure.error)
            .unwrap_err();
        assert!(matches!(error, ProxyError::Intercept(_)));
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
            let mut cursor = Cursor::new(raw.into_bytes());
            let error = read_response(&mut cursor, "GET", 1024)
                .map_err(|failure| failure.error)
                .unwrap_err();
            assert!(matches!(error, ProxyError::Intercept(_)), "{headers:?}");
        }
    }

    #[test]
    fn unicode_whitespace_in_framing_headers_is_rejected() {
        for header in [
            "Content-Length: \u{a0}2\r\n",
            "Transfer-Encoding: \u{a0}chunked\r\n",
        ] {
            let raw = format!("HTTP/1.1 200 OK\r\n{header}\r\n");
            let mut cursor = Cursor::new(raw.into_bytes());
            assert!(
                matches!(
                    read_response(&mut cursor, "GET", 1024).map_err(|failure| failure.error),
                    Err(ProxyError::Intercept(_))
                ),
                "{header:?}"
            );
        }
    }

    #[test]
    fn http10_chunked_messages_are_rejected() {
        let request = "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n";
        let mut cursor = Cursor::new(request.as_bytes());
        assert!(matches!(
            read_request(&mut cursor, 1024),
            Err(ProxyError::Intercept(_))
        ));

        let response = "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n";
        let mut cursor = Cursor::new(response.as_bytes());
        assert!(matches!(
            read_response(&mut cursor, "GET", 1024).map_err(|failure| failure.error),
            Err(ProxyError::Intercept(_))
        ));
    }

    #[test]
    fn nested_connect_is_rejected_in_both_directions() {
        let request = "CONNECT inner.example:443 HTTP/1.1\r\nHost: inner.example:443\r\n\r\n";
        let mut cursor = Cursor::new(request.as_bytes());
        assert!(matches!(
            read_request(&mut cursor, 1024),
            Err(ProxyError::Intercept(_))
        ));

        let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        let mut cursor = Cursor::new(response.as_bytes());
        assert!(matches!(
            read_response(&mut cursor, "CONNECT", 1024).map_err(|failure| failure.error),
            Err(ProxyError::Intercept(_))
        ));

        for method in ["connect", "Connect", "cOnNeCt"] {
            let request = format!("{method} inner.example:443 HTTP/1.1\r\nHost: h\r\n\r\n");
            let mut cursor = Cursor::new(request.into_bytes());
            assert!(
                matches!(
                    read_request(&mut cursor, 1024),
                    Err(ProxyError::Intercept(_))
                ),
                "{method}"
            );
        }
    }

    /// A response with NO Content-Length and NO Transfer-Encoding is delimited by connection close
    /// (RFC 7230 rule 7): the body must be read to EOF, not silently dropped to empty. The `Cursor`
    /// EOF stands in for the peer closing the connection.
    #[test]
    fn response_without_content_length_reads_to_eof() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nstreamed body with no length";
        let mut cursor = Cursor::new(raw.as_bytes().to_vec());
        let res = read_response(&mut cursor, "GET", 1024)
            .map_err(|failure| failure.error)
            .unwrap();
        assert_eq!(res.status, 200);
        assert_eq!(res.body, b"streamed body with no length");
    }

    /// A connection-close-framed body is still bounded: exceeding the limit fails closed rather than
    /// buffering unboundedly.
    #[test]
    fn connection_close_body_respects_limit() {
        let big = "z".repeat(1000);
        let raw = format!("HTTP/1.1 200 OK\r\n\r\n{big}");
        let mut cursor = Cursor::new(raw.into_bytes());
        let err = read_response(&mut cursor, "GET", 100)
            .map_err(|failure| failure.error)
            .unwrap_err();
        assert!(matches!(err, ProxyError::ResponseLimit(_)), "got {err:?}");
    }

    #[test]
    fn final_bodyless_statuses_do_not_consume_payload_bytes() {
        for (status_line, code) in [
            ("HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n", 204),
            (
                "HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n",
                304,
            ),
        ] {
            let raw = format!("{status_line}LEFTOVER");
            let mut cursor = Cursor::new(raw.into_bytes());
            let res = read_response(&mut cursor, "GET", 1024)
                .map_err(|failure| failure.error)
                .unwrap();
            assert_eq!(res.status, code);
            assert!(res.body.is_empty(), "status {code} must have no body");
        }
    }

    #[test]
    fn informational_response_is_consumed_before_final_response() {
        let raw = concat!(
            "HTTP/1.1 100 Continue\r\n",
            "\r\n",
            "HTTP/1.1 200 OK\r\n",
            "Content-Length: 2\r\n",
            "\r\n",
            "ok"
        );
        let mut cursor = Cursor::new(raw.as_bytes().to_vec());
        let response = read_response(&mut cursor, "POST", 1024)
            .map_err(|failure| failure.error)
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
    }

    #[test]
    fn informational_response_cap_is_enforced() {
        let raw = "HTTP/1.1 100 Continue\r\n\r\n".repeat(MAX_INFORMATIONAL_RESPONSES + 1);
        let mut cursor = Cursor::new(raw.into_bytes());
        let error = read_response(&mut cursor, "POST", 1024)
            .map_err(|failure| failure.error)
            .unwrap_err();
        assert!(
            matches!(error, ProxyError::Intercept(message) if message == "too many informational responses")
        );
    }

    #[test]
    fn protocol_upgrade_response_is_rejected() {
        let raw =
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let mut cursor = Cursor::new(raw.as_bytes().to_vec());
        let error = read_response(&mut cursor, "GET", 1024)
            .map_err(|failure| failure.error)
            .unwrap_err();
        assert!(matches!(error, ProxyError::Intercept(_)));
    }

    #[test]
    fn head_response_preserves_metadata_length_without_payload() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nLEFTOVER";
        let mut cursor = Cursor::new(raw.as_bytes().to_vec());
        let response = read_response(&mut cursor, "HEAD", 1024)
            .map_err(|failure| failure.error)
            .unwrap();
        assert!(response.body.is_empty());
        assert_eq!(response.headers.get("content-length"), Some("9"));

        let mut out = Vec::new();
        write_response(
            &mut out,
            "HEAD",
            response.status,
            &response.headers,
            b"must-not-be-written",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 9\r\n\r\n"
        );
    }

    #[test]
    fn lowercase_head_is_an_extension_method_with_a_payload() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut cursor = Cursor::new(raw.as_bytes());
        let response = read_response(&mut cursor, "head", 1024).unwrap();
        assert_eq!(response.body, b"ok");

        let mut out = Vec::new();
        write_response(
            &mut out,
            "head",
            response.status,
            &response.headers,
            &response.body,
        )
        .unwrap();
        assert!(out.ends_with(b"\r\n\r\nok"));
    }

    /// A body larger than one internal read chunk is materialized in full via `read_exact` — proving
    /// the buffered path reassembles a multi-read body correctly.
    #[test]
    fn reads_a_large_body_in_full() {
        let big = "x".repeat(50_000);
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{big}",
            big.len()
        );
        let mut cursor = Cursor::new(raw.into_bytes());
        let res = read_response(&mut cursor, "GET", 1 << 20).unwrap();
        assert_eq!(res.body.len(), 50_000);
        assert!(res.body.iter().all(|&b| b == b'x'));
    }

    /// A body shorter than its declared `Content-Length` (upstream closed early) is a fail-closed I/O
    /// error, never a silently truncated body.
    #[test]
    fn short_body_fails_closed() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"; // 5 bytes, claims 10
        let mut cursor = Cursor::new(raw.as_bytes().to_vec());
        let err = read_response(&mut cursor, "GET", 1024)
            .map_err(|failure| failure.error)
            .unwrap_err();
        assert!(
            matches!(err, ProxyError::Io(_)),
            "a short body must fail: {err:?}"
        );
    }

    /// A head with no body reads cleanly (the blank line terminates it; `read_exact(0)` is a no-op).
    #[test]
    fn reads_head_with_no_body() {
        let raw = "GET / HTTP/1.1\r\nHost: h\r\n\r\n";
        let mut cursor = Cursor::new(raw.as_bytes().to_vec());
        let req = read_request(&mut cursor, 1024).unwrap();
        assert_eq!(req.method, "GET");
        assert!(req.body.is_empty());
    }

    /// The coalesced write path preserves a **binary** body byte-for-byte (no utf8 corruption) and
    /// the head is written with the refreshed Content-Length.
    #[test]
    fn write_response_coalesces_binary_body_intact() {
        let mut headers = HeaderMap::new();
        headers.append("Content-Type", "application/octet-stream");
        let body = vec![0u8, 159, 146, 150, 255, 1, 2, 3]; // invalid utf8 on purpose
        let mut out = Vec::new();
        write_response(&mut out, "GET", 200, &headers, &body).unwrap();

        // Split head/body at the blank line and check the body survived exactly.
        let sep = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let (head, wire_body) = out.split_at(sep);
        assert_eq!(wire_body, &body[..], "binary body must be byte-identical");
        let head = String::from_utf8_lossy(head);
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head.contains("Content-Length: 8\r\n"));
        assert!(head.contains("Content-Type: application/octet-stream\r\n"));
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

    /// The status-line budget covers every reason phrase the proxy emits.
    #[test]
    fn the_status_line_budget_covers_every_reason_phrase() {
        for status in [
            100u16, 101, 200, 204, 301, 302, 304, 307, 308, 400, 401, 403, 404, 405, 407, 408, 411,
            413, 414, 421, 429, 500, 502, 503, 504, 505, 599,
        ] {
            // `HTTP/1.1 ` (9) + 3 digits + ` ` + reason + CRLF
            let width = 9 + 3 + 1 + reason(status).len() + 2;
            assert!(
                width <= STATUS_LINE_BYTES,
                "status {status} renders a {width}-byte line against a \
                 {STATUS_LINE_BYTES}-byte budget"
            );
        }
    }

    /// A body larger than the coalesce limit takes the split-write path but still lands intact.
    #[test]
    fn write_request_large_body_via_split_path() {
        let big = vec![b'z'; COALESCE_BODY_LIMIT + 1];
        let headers = HeaderMap::new();
        let mut out = Vec::new();
        write_request(&mut out, "PUT", "/upload", &headers, &big).unwrap();
        let sep = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let (head, wire_body) = out.split_at(sep);
        assert_eq!(wire_body, &big[..]);
        assert!(
            String::from_utf8_lossy(head).contains(&format!("Content-Length: {}\r\n", big.len()))
        );
    }

    /// An existing inbound Content-Length is dropped and refreshed to the actual body length.
    #[test]
    fn write_refreshes_content_length() {
        let mut headers = HeaderMap::new();
        headers.append("Content-Length", "9999"); // stale
        let mut out = Vec::new();
        write_request(&mut out, "POST", "/", &headers, b"abc").unwrap();
        let s = String::from_utf8_lossy(&out);
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

        let mut out = Vec::new();
        write_request(&mut out, "POST", "/", &headers, b"body").unwrap();
        let wire = String::from_utf8(out).unwrap().to_ascii_lowercase();
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

    #[test]
    fn prepared_write_reports_zero_byte_failure() {
        let mut writer = FailingWriter {
            limit: 0,
            accepted: 0,
            fail_flush: false,
        };
        let failure = write_prepared_and_flush(&mut writer, b"message").unwrap_err();
        assert_eq!(failure.accepted_bytes, 0);
        assert_eq!(failure.error.kind(), io::ErrorKind::BrokenPipe);
        assert!(!failure.during_flush);
    }

    #[test]
    fn prepared_write_reports_partial_prefix() {
        let mut writer = FailingWriter {
            limit: 3,
            accepted: 0,
            fail_flush: false,
        };
        let failure = write_prepared_and_flush(&mut writer, b"message").unwrap_err();
        assert_eq!(failure.accepted_bytes, 3);
        assert_eq!(failure.error.kind(), io::ErrorKind::BrokenPipe);
        assert!(!failure.during_flush);
    }

    #[test]
    fn prepared_write_distinguishes_indeterminate_flush() {
        let mut writer = FailingWriter {
            limit: usize::MAX,
            accepted: 0,
            fail_flush: true,
        };
        let failure = write_prepared_and_flush(&mut writer, b"message").unwrap_err();
        assert_eq!(failure.accepted_bytes, 7);
        assert_eq!(failure.error.kind(), io::ErrorKind::TimedOut);
        assert!(failure.during_flush);
    }
}
