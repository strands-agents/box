//! The HTTP/1.1 rules that the gateway keeps around hyper: the hop-by-hop strip, the response body
//! modes, Box's reason phrases, and the writer of the static refusals before the CONNECT
//! acknowledgement. hyper reads and writes every other message.

use std::io::{self, Write};

use crate::boundary::HeaderMap;
use crate::error::{ProxyError, Result};

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

/// Parse the header names nominated by all `Connection` fields.
pub(super) fn connection_nominated_headers(headers: &HeaderMap) -> Result<Vec<String>> {
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
pub(super) fn is_hop_by_hop_header(name: &str, nominated: &[String]) -> bool {
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
pub(super) fn strip_hop_by_hop_headers(headers: &mut HeaderMap) -> Result<()> {
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

/// How the request method and response status constrain response payload framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ResponseBodyMode {
    /// The response carries a regular payload.
    Payload,
    /// The response has no wire payload but may retain representation-length metadata.
    MetadataOnly,
    /// The response has no payload and must not retain payload framing metadata.
    Forbidden,
}

pub(super) fn response_body_mode(request_method: &str, status: u16) -> ResponseBodyMode {
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

/// Write a static, proxy-originated response: the status line, `headers`, `Connection: close`, and
/// the `Content-Length` that the body mode allows. Only the refusals before the CONNECT
/// acknowledgement use it; hyper writes every other reply.
pub(super) fn write_static_response<W: Write>(
    stream: &mut W,
    request_method: &str,
    status: u16,
    headers: &HeaderMap,
    body: &[u8],
) -> io::Result<()> {
    use std::fmt::Write as _;
    let mut head = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    for (name, value) in headers.iter() {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    head.push_str("Connection: close\r\n");
    let body = match response_body_mode(request_method, status) {
        ResponseBodyMode::Payload => {
            let _ = write!(head, "Content-Length: {}\r\n\r\n", body.len());
            body
        }
        // A `HEAD` refusal names the length of the body that it does not carry.
        ResponseBodyMode::MetadataOnly if !body.is_empty() => {
            let _ = write!(head, "Content-Length: {}\r\n\r\n", body.len());
            &[]
        }
        ResponseBodyMode::MetadataOnly | ResponseBodyMode::Forbidden => {
            head.push_str("\r\n");
            &[]
        }
    };
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)
}

/// A minimal reason phrase for a status code (only the ones the proxy itself emits need be exact).
pub(super) fn reason(status: u16) -> &'static str {
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

    /// **The hop-by-hop strip removes each hop field and each field that `Connection` names**, and
    /// keeps every end-to-end field.
    #[test]
    fn the_hop_by_hop_strip_keeps_only_end_to_end_headers() {
        let mut headers = HeaderMap::from_pairs(
            [
                ("Connection", "keep-alive, X-Remove"),
                ("Keep-Alive", "timeout=5"),
                ("Proxy-Connection", "keep-alive"),
                ("Proxy-Authorization", "Basic c2VjcmV0"),
                ("TE", "trailers"),
                ("Transfer-Encoding", "chunked"),
                ("Upgrade", "websocket"),
                ("Trailer", "Digest"),
                ("X-Remove", "hop-only"),
                ("X-End-To-End", "keep"),
            ]
            .map(|(name, value)| (name.to_string(), value.to_string())),
        );
        strip_hop_by_hop_headers(&mut headers).unwrap();
        let names: Vec<&str> = headers.iter().map(|(name, _)| name).collect();
        assert_eq!(names, ["X-End-To-End"]);

        let mut malformed = HeaderMap::from_pairs([("Connection".to_string(), "a b".to_string())]);
        assert!(strip_hop_by_hop_headers(&mut malformed).is_err());
    }
}
