//! CONNECT parsing and the best-effort proxy session-token check.

use std::net::IpAddr;

use crate::capability::normalize_host;

/// A parsed CONNECT request: the target `host` and `port`, plus any `Proxy-Authorization` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ConnectRequest {
    /// The target host from the CONNECT authority.
    pub(super) host: String,
    /// The target port from the CONNECT authority.
    pub(super) port: u16,
    /// The `Proxy-Authorization` header value, if the client supplied one (best-effort).
    pub(super) proxy_authorization: Option<String>,
}

/// Parse a raw HTTP/1.1 CONNECT request head (the bytes up to and including the blank line).
pub(super) fn parse_connect(head: &str) -> Option<ConnectRequest> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    if !parts.next()?.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    let authority = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() || !version.starts_with("HTTP/") {
        return None;
    }
    let (host, port) = parse_authority(authority, None)?;

    Some(ConnectRequest {
        host,
        port,
        proxy_authorization: proxy_authorization_from_head(head),
    })
}

/// Extract a `Proxy-Authorization` value from a raw HTTP head (request line + headers, up to the
/// blank line). The plain-HTTP path must read it from the RAW head, because `read_request` strips
/// `Proxy-Authorization` as a hop-by-hop header before the parsed request is available.
pub(super) fn proxy_authorization_from_head(head: &str) -> Option<String> {
    head.split("\r\n")
        .skip(1) // the request line
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("proxy-authorization")
                .then(|| value.trim().to_string())
        })
}

/// Parse an HTTP authority into an unbracketed host and port.
pub(super) fn parse_authority(authority: &str, default_port: Option<u16>) -> Option<(String, u16)> {
    let authority = authority.trim_matches(|character| matches!(character, ' ' | '\t'));
    if authority.is_empty() {
        return None;
    }

    let (host, explicit_port) = if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        if !matches!(host.parse::<IpAddr>().ok(), Some(IpAddr::V6(_))) {
            return None;
        }
        let suffix = &rest[close + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(parse_port(suffix.strip_prefix(':')?)?)
        };
        (host, port)
    } else {
        if authority.bytes().filter(|byte| *byte == b':').count() > 1 {
            return None;
        }
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(parse_port(port)?)),
            None => (authority, None),
        }
    };

    // Normalize the host to the one spelling the policy decision, the DNS resolve, and the audit
    // record must agree on (trailing-dot trim + lowercase), THEN validate the normalized value.
    // Validating the raw form first would accept an all-dots host like `.` or `...` (non-empty,
    // ASCII, only `.`), which normalizes to the empty string — binding an empty `context.input.host`
    // and defeating `valid_host`'s non-empty guarantee. Binding the raw form instead would let a host
    // `forbid` miss while DNS still reaches the host. A bare IP literal is unaffected (no trailing
    // dot; only IPv6 hex is case-folded, which is canonical).
    let host = normalize_host(host);
    if !valid_host(&host) {
        return None;
    }
    Some((host, explicit_port.or(default_port)?))
}

/// Split a plain-HTTP absolute-form request target (`http://host[:port]/path?query`) into the
/// destination host, port, and the origin-form target (`/path?query`) to forward upstream.
///
/// Returns `None` for anything that is not an absolute `http` URL, so an origin-form request arriving
/// without a CONNECT (which names no destination) is refused rather than guessed at.
///
/// `https://` is refused too. This path forwards over a plaintext upstream, so forwarding an https
/// request would send it in cleartext to an origin that expects TLS — a silent downgrade. A real
/// HTTPS client reaches the proxy with CONNECT (the TLS path) and never here, so an `https://`
/// absolute-form request is illegitimate rather than something to forward unencrypted.
pub(super) fn parse_absolute_target(target: &str) -> Option<(String, u16, String)> {
    let default_port = 80u16;
    let rest = target.strip_prefix("http://")?;
    // A fragment is a client-only construct (RFC 3986 §3.5) and must never reach an origin server, so
    // drop it before anything else. The authority then ends at the first `/` or `?`; a query with no
    // path still needs an origin-form target that begins with `/`.
    let rest = rest.split('#').next().unwrap_or(rest);
    let (authority, origin) = match rest.find(['/', '?']) {
        Some(index) if rest.as_bytes()[index] == b'/' => {
            (&rest[..index], rest[index..].to_string())
        }
        Some(index) => (&rest[..index], format!("/{}", &rest[index..])),
        None => (rest, "/".to_string()),
    };
    let (host, port) = parse_authority(authority, Some(default_port))?;
    Some((host, port, origin))
}

/// Compare authority hosts without making DNS names case- or trailing-dot-sensitive. The
/// dot-insensitivity keeps the Host-header-vs-CONNECT binding check (`validate_request_binding`) in
/// agreement with the normalized `ConnectRequest.host`: a client may spell a trailing-dot FQDN on one
/// side and not the other, and both name the same host.
pub(super) fn same_host(left: &str, right: &str) -> bool {
    match (left.parse::<IpAddr>(), right.parse::<IpAddr>()) {
        (Ok(left), Ok(right)) => left == right,
        (Err(_), Err(_)) => left
            .trim_end_matches('.')
            .eq_ignore_ascii_case(right.trim_end_matches('.')),
        _ => false,
    }
}

fn parse_port(port: &str) -> Option<u16> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    (port != 0).then_some(port)
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && (host.parse::<IpAddr>().is_ok()
            || (host.is_ascii()
                && host.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                })))
}

/// The best-effort session-token check.
pub(super) fn token_ok(expected: Option<&str>, observed: Option<&str>) -> bool {
    match (expected, observed) {
        // No expected token configured → always ok.
        (None, _) => true,
        // Expected but the client omitted it → allowed (best-effort; kernel pin is the real defense).
        (Some(_), None) => true,
        // Expected and supplied → must match.
        (Some(exp), Some(obs)) => obs == format!("Bearer {exp}") || obs == exp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_authority_and_header() {
        let head = "CONNECT api.example.com:443 HTTP/1.1\r\n\
                    Host: api.example.com:443\r\n\
                    Proxy-Authorization: Bearer tok123\r\n\
                    \r\n";
        let parsed = parse_connect(head).unwrap();
        assert_eq!(parsed.host, "api.example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.proxy_authorization.as_deref(), Some("Bearer tok123"));
    }

    #[test]
    fn rejects_non_connect() {
        assert!(parse_connect("GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_connect("CONNECT no-port HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn parses_bracketed_ipv6_without_leaking_brackets_into_host() {
        let parsed = parse_connect("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(parsed.host, "2001:db8::1");
        assert_eq!(parsed.port, 8443);
    }

    #[test]
    fn authority_supports_default_and_explicit_ports() {
        // The host is normalized (lowercased) as it enters the gateway, so the policy decision, the
        // DNS resolve, and the audit record all see one spelling.
        assert_eq!(
            parse_authority("Api.Example.com", Some(443)),
            Some(("api.example.com".to_string(), 443))
        );
        assert_eq!(
            parse_authority("api.example.com:8443", Some(443)),
            Some(("api.example.com".to_string(), 8443))
        );
        assert_eq!(
            parse_authority("[2001:db8::1]", Some(443)),
            Some(("2001:db8::1".to_string(), 443))
        );
        assert!(parse_authority("2001:db8::1:443", None).is_none());
    }

    /// FIX A (finding 2): a trailing-dot FQDN or mixed case must normalize to the one spelling the
    /// policy decision and the DNS resolve agree on, so a host `forbid` cannot be dodged by appending
    /// `.` or re-casing.
    #[test]
    fn parse_authority_normalizes_trailing_dot_and_case() {
        let bare = parse_authority("httpbin.org", Some(443)).unwrap();
        let trailing_dot = parse_authority("httpbin.org.", Some(443)).unwrap();
        let mixed_case = parse_authority("Httpbin.Org", Some(443)).unwrap();
        let both = parse_authority("Httpbin.Org.", Some(443)).unwrap();
        assert_eq!(bare.0, "httpbin.org");
        assert_eq!(
            trailing_dot, bare,
            "a trailing-dot FQDN must bind the same host as the bare form"
        );
        assert_eq!(
            mixed_case, bare,
            "a mixed-case host must bind the same host as the lowercase form"
        );
        assert_eq!(
            both, bare,
            "trailing dot and case together still collapse to one host"
        );
    }

    /// FIX A edge: an all-dots host is non-empty and passes the raw `valid_host` check, but
    /// normalizes to the empty string. Validating the normalized value refuses it, so no empty host
    /// is ever bound to `context.input.host` / the resolve / the audit legs.
    #[test]
    fn parse_authority_refuses_an_all_dots_host() {
        for authority in [".", "..", "...", ".:443", "...:8080"] {
            assert!(
                parse_authority(authority, Some(443)).is_none(),
                "an all-dots host normalizes to empty and must be refused: {authority:?}"
            );
        }
    }

    #[test]
    fn same_host_ignores_case_and_trailing_dot() {
        assert!(same_host("httpbin.org", "Httpbin.Org."));
        assert!(same_host("httpbin.org.", "httpbin.org"));
        assert!(!same_host("httpbin.org", "evil.org"));
    }

    #[test]
    fn absolute_target_splits_authority_from_origin() {
        // Path present: the authority ends at the `/`, and the origin keeps the whole path+query.
        assert_eq!(
            parse_absolute_target("http://example.com/mcp?x=1"),
            Some(("example.com".to_string(), 80, "/mcp?x=1".to_string()))
        );
        // No path: the origin defaults to `/`, and the default port follows the `http` scheme.
        assert_eq!(
            parse_absolute_target("http://example.com"),
            Some(("example.com".to_string(), 80, "/".to_string()))
        );
        // `https://` absolute-form is refused: the plain path forwards over plaintext, so it must not
        // downgrade an https request to cleartext against a TLS origin. A real HTTPS client uses
        // CONNECT and never reaches this path.
        assert!(parse_absolute_target("https://example.com").is_none());
        // Explicit port with a path.
        assert_eq!(
            parse_absolute_target("http://127.0.0.1:8931/mcp"),
            Some(("127.0.0.1".to_string(), 8931, "/mcp".to_string()))
        );
        // Query but NO path: the authority ends at `?`, and the origin is rebuilt with a leading `/`.
        assert_eq!(
            parse_absolute_target("http://example.com?foo=bar"),
            Some(("example.com".to_string(), 80, "/?foo=bar".to_string()))
        );
        // Fragment is client-only (RFC 3986 §3.5): it is dropped, never forwarded. With no path the
        // origin is just `/`.
        assert_eq!(
            parse_absolute_target("http://example.com#frag"),
            Some(("example.com".to_string(), 80, "/".to_string()))
        );
        // Fragment after a path/query: the path and query are kept, the fragment is dropped.
        assert_eq!(
            parse_absolute_target("http://example.com/mcp?x=1#frag"),
            Some(("example.com".to_string(), 80, "/mcp?x=1".to_string()))
        );
        // Not an absolute URL: an origin-form target names no destination and is refused.
        assert!(parse_absolute_target("/mcp?foo=bar").is_none());
    }

    #[test]
    fn proxy_authorization_read_from_a_plain_http_head() {
        // The plain-HTTP path reads the token from the raw head (before `read_request` strips the
        // hop-by-hop header), so a non-CONNECT head must still yield the value.
        let head = "GET http://api.example.com/ HTTP/1.1\r\n\
                    Host: api.example.com\r\n\
                    Proxy-Authorization: Bearer tok123\r\n\
                    \r\n";
        assert_eq!(
            proxy_authorization_from_head(head).as_deref(),
            Some("Bearer tok123")
        );
        // Absent header → None.
        let without = "GET http://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        assert!(proxy_authorization_from_head(without).is_none());
    }

    #[test]
    fn token_check_is_best_effort() {
        // No expected token → always ok.
        assert!(token_ok(None, None));
        assert!(token_ok(None, Some("anything")));
        // Expected but missing → allowed (best-effort).
        assert!(token_ok(Some("tok"), None));
        // Expected and matching (bare or Bearer) → ok.
        assert!(token_ok(Some("tok"), Some("tok")));
        assert!(token_ok(Some("tok"), Some("Bearer tok")));
        // Expected and mismatched → rejected.
        assert!(!token_ok(Some("tok"), Some("Bearer wrong")));
    }
}
