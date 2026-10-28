//! The request checks that every exchange shares, and the static refusals that the gateway writes
//! before the CONNECT acknowledgement.

use std::io::{self, Write};

use super::connect::{ConnectRequest, parse_authority, same_host};
use super::http1;
use crate::boundary::{HeaderMap, Target};
use crate::error::{ProxyError, Result};
use crate::mcp::{mcp_denial_response, normalize_path};

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
        let _ = http1::write_static_response(
            stream,
            request_method,
            403,
            &headers,
            response.as_bytes(),
        );
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
    let _ = http1::write_static_response(
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
pub(super) fn split_target(target: &str) -> (String, String) {
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
}
