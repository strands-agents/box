//! RFC 3986 canonicalization of an MCP resource URI.

use serde_json::Value;

/// Rewrite a `resources/read` frame's `params.uri` to its canonical form, or `None` when nothing changes.
pub(crate) fn canonicalize_frame_uri(frame: &[u8]) -> Option<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(frame).ok()?;
    if value.get("method").and_then(Value::as_str) != Some("resources/read") {
        return None;
    }
    let params = value.get_mut("params").and_then(Value::as_object_mut)?;
    let uri = params.get("uri").and_then(Value::as_str)?.to_owned();
    let canonical = canonicalize_resource_uri(&uri);
    if canonical == uri {
        return None;
    }
    params.insert("uri".to_string(), Value::String(canonical));
    Some(value.to_string().into_bytes())
}

pub(crate) fn canonicalize_resource_uri(uri: &str) -> String {
    let Some((scheme, rest)) = uri.split_once(':') else {
        return uri.to_string(); // no scheme — not a URI the box normalizes
    };
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "file" | "http" | "https") {
        return uri.to_string(); // opaque / custom scheme — never touch
    }

    // Split off `#fragment` then `?query`, kept verbatim (a literal or credential may live there, and
    // canonicalizing the path must not touch them — mirrors the egress query handling).
    let (before_fragment, fragment) = match rest.split_once('#') {
        Some((before, fragment)) => (before, Some(fragment)),
        None => (rest, None),
    };
    let (hierarchical, query) = match before_fragment.split_once('?') {
        Some((hierarchical, query)) => (hierarchical, Some(query)),
        None => (before_fragment, None),
    };

    // Split authority from path. `//authority/path` carries an authority; a leading `/` with no `//`
    // is the no-authority form RFC 8089 treats as an empty (local) authority for `file:`.
    let (authority, path) = if let Some(after) = hierarchical.strip_prefix("//") {
        match after.find('/') {
            Some(slash) => (Some(&after[..slash]), &after[slash..]),
            None => (Some(after), ""), // authority only, no path
        }
    } else if hierarchical.starts_with('/') {
        (None, hierarchical)
    } else {
        // An opaque hier-part under a scheme we would otherwise normalize (e.g. `file:etc`); leaving
        // it verbatim is safer than guessing where a path begins.
        return uri.to_string();
    };

    // Decode unreserved octets, collapse empty path segments (`//` resolves to `/` on common
    // file/HTTP resolvers, so `file:////etc/passwd` is the same identity as `file:///etc/passwd` —
    // a `/`-padded respelling is not a new path), then remove dot-segments.
    //
    // Reserved-octet residual: `%2F` (and other reserved escapes) are left ENCODED, RFC 3986
    // §2.2/§6.2.2 — a `%2F` denotes a literal slash *within* a segment, not a separator, so `..%2Fetc`
    // stays one segment and does not pop. This is sound for servers that treat `%2F` as literal (and
    // matches the egress request-path canonicalization, which never decodes `%2F`). A local stdio
    // server that percent-decodes reserved delimiters before resolving would read `..%2Fetc` as
    // `../etc` and traverse; on this (local) door that residual is backstopped ONLY when the server is
    // contained — the leaf box then bounds the filesystem on the resolved path. An uncontained
    // stdio server has no such backstop, so this stays a called-out residual at the string layer.
    let canonical_path = remove_dot_segments(&collapse_slashes(&decode_unreserved(path)));

    let mut out = String::with_capacity(uri.len());
    out.push_str(&scheme);
    out.push(':');
    // Emit `//` only where an authority belongs: when one is present, or for `file:`, whose
    // no-authority form (`file:/x`) is the empty local authority (RFC 8089) — so it canonicalizes to
    // `file:///x`. http/https with NO authority (`http:/etc/passwd`) must stay path-only: fabricating
    // `http:///etc/passwd` invents an empty authority and changes the URI's meaning.
    let has_authority = match authority {
        // Normalize first, unconditionally; decide the local-authority case on the normalized
        // form, not the raw string. Catches every spelling of "this machine" (case, trailing dot,
        // percent-encoding, loopback IP literals), not just the one exact string `localhost`.
        Some(auth) => {
            let normalized = normalize_authority(auth, &scheme);
            if scheme == "file" && is_local_file_authority(&normalized) {
                out.push_str("//");
            } else {
                out.push_str("//");
                out.push_str(&normalized);
            }
            true
        }
        // No authority: `file:` gets the empty local authority; http/https keep the path-only form.
        None if scheme == "file" => {
            out.push_str("//");
            true
        }
        None => false,
    };
    // RFC 3986 §6.2.3: an authority with an empty path normalizes to a path of `/`, so
    // `http://example.com` cannot dodge a `uri like "http://example.com/*"` by omitting the path.
    if canonical_path.is_empty() && has_authority {
        out.push('/');
    } else {
        out.push_str(&canonical_path);
    }
    if let Some(query) = query {
        out.push('?');
        out.push_str(query);
    }
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

/// Whether a NORMALIZED `file:` authority is this machine: `localhost`, or a loopback IP literal (RFC 5735 `127.0.0.0/8`; RFC 4291 `::1`).
fn is_local_file_authority(normalized_auth: &str) -> bool {
    if normalized_auth == "localhost" {
        return true;
    }
    if normalized_auth.starts_with('[') && normalized_auth.ends_with(']') {
        let inner = &normalized_auth[1..normalized_auth.len() - 1];
        return inner == "::1" || inner.eq_ignore_ascii_case("0:0:0:0:0:0:0:1");
    }
    is_loopback_v4(normalized_auth)
}

/// Whether `host` (no port) is a loopback IPv4 literal in `127.0.0.0/8`.
fn is_loopback_v4(host: &str) -> bool {
    let mut octets = host.split('.');
    let first = octets.next().and_then(|o| o.parse::<u8>().ok());
    let rest_ok = octets.clone().count() == 3 && octets.all(|o| o.parse::<u8>().is_ok());
    matches!(first, Some(127)) && rest_ok
}

/// Fully canonicalize an authority per RFC 3986 §6.2, so equivalent respellings of the host/port are one identity and cannot dodge a host-based `uri` forbid: - **host** — percent-decode its unreserved octets (§6.2.2.2, so `%65xample.com` == `example.com`), strip a trailing dot (a fully-qualified `host.` is the same host), and lowercase (§6.2.2.1, case-insensitive).
fn normalize_authority(auth: &str, scheme: &str) -> String {
    let (userinfo, hostport) = match auth.rsplit_once('@') {
        Some((user, rest)) => (Some(user), rest),
        None => (None, auth),
    };
    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        // IPv6 literal `[..]` (optionally `:port`); the literal is left as written.
        match rest.split_once(']') {
            Some((inner, tail)) => (
                format!("[{inner}]"),
                tail.strip_prefix(':').map(str::to_string),
            ),
            None => (hostport.to_string(), None),
        }
    } else {
        match hostport.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), Some(port.to_string())),
            None => (hostport.to_string(), None),
        }
    };
    let host = if host.starts_with('[') {
        host // IPv6 literal — not percent-decoded or re-cased.
    } else {
        let decoded = decode_unreserved(&host);
        decoded.trim_end_matches('.').to_ascii_lowercase()
    };
    let port = port.filter(|port| !is_default_port(scheme, port));
    let mut out = String::with_capacity(auth.len());
    if let Some(user) = userinfo {
        out.push_str(user);
        out.push('@');
    }
    out.push_str(&host);
    if let Some(port) = port {
        out.push(':');
        out.push_str(&port);
    }
    out
}

/// Whether `port` is the default for `scheme` and so drops out of the canonical authority (RFC 3986 §6.2.3).
fn is_default_port(scheme: &str, port: &str) -> bool {
    matches!((scheme, port), ("http", "80") | ("https", "443"))
}

/// Collapse runs of literal `/` to a single `/`: an empty path segment resolves to the same file as a single separator on common file/HTTP resolvers, so a `/`-padded respelling (`file:////etc/passwd`) canonicalizes to one identity.
fn collapse_slashes(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut prev_slash = false;
    for ch in path.chars() {
        if ch == '/' {
            if !prev_slash {
                out.push('/');
            }
            prev_slash = true;
        } else {
            out.push(ch);
            prev_slash = false;
        }
    }
    out
}

/// Percent-decode only the unreserved octets of `path`; leave every reserved (or otherwise non-unreserved) escape encoded, normalizing its hex digits to uppercase (RFC 3986 §6.2.2.1).
pub(crate) fn decode_unreserved(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            let octet = high * 16 + low;
            if is_unreserved(octet) {
                out.push(octet);
            } else {
                out.push(b'%');
                out.push(bytes[index + 1].to_ascii_uppercase());
                out.push(bytes[index + 2].to_ascii_uppercase());
            }
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The value of one hex digit, or `None` if `byte` is not a hex digit.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Whether `byte` is an RFC 3986 unreserved octet — the only octets safe to percent-decode without changing how the URI parses.
fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Remove dot-segments from a path per RFC 3986 §5.2.4.
pub(crate) fn remove_dot_segments(path: &str) -> String {
    let mut cursor = 0;
    let mut output = String::with_capacity(path.len());
    while cursor < path.len() {
        let rest = &path[cursor..];
        if rest.starts_with("../") {
            cursor += 3;
        } else if rest.starts_with("./") || rest.starts_with("/./") {
            cursor += 2;
        } else if rest == "/." {
            output.push('/');
            cursor += 2;
        } else if rest.starts_with("/../") {
            pop_last_segment(&mut output);
            cursor += 3;
        } else if rest == "/.." {
            pop_last_segment(&mut output);
            output.push('/');
            cursor += 3;
        } else if rest == "." {
            cursor += 1;
        } else if rest == ".." {
            cursor += 2;
        } else {
            let start = usize::from(rest.starts_with('/'));
            let end = rest[start..]
                .find('/')
                .map_or(rest.len(), |offset| start + offset);
            output.push_str(&rest[..end]);
            cursor += end;
        }
    }
    output
}

/// Remove the last `/`-delimited segment (and its leading `/`) from `output`, for the `/..` cases.
fn pop_last_segment(output: &mut String) {
    match output.rfind('/') {
        Some(position) => output.truncate(position),
        None => output.clear(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three bypass classes from the finding all collapse to the one canonical spelling the
    /// server resolves, so a `forbid ... uri like "file:///etc/*"` now matches.
    #[test]
    fn the_finding_bypass_classes_canonicalize_to_one_identity() {
        let canonical = "file:///etc/passwd";
        assert_eq!(
            canonicalize_resource_uri("file:/etc/passwd"),
            canonical,
            "no-authority form"
        );
        assert_eq!(
            canonicalize_resource_uri("file:///%65tc/passwd"),
            canonical,
            "percent-encoding"
        );
        assert_eq!(
            canonicalize_resource_uri("file:///tmp/../etc/passwd"),
            canonical,
            "dot-segments"
        );
        assert_eq!(
            canonicalize_resource_uri("file://localhost/etc/passwd"),
            canonical,
            "RFC 8089 localhost authority is the empty (local) authority"
        );
        // Every equivalent spelling of "this machine" collapses too, not just the bare literal
        // `localhost` — case, trailing dot, percent-encoding, and loopback IP literals.
        for uri in [
            "file://localhost./etc/passwd",
            "file://LOCALHOST/etc/passwd",
            "file://%6cocalhost/etc/passwd",
            "file://127.0.0.1/etc/passwd",
            "file://127.0.0.2/etc/passwd",
            "file://[::1]/etc/passwd",
        ] {
            assert_eq!(canonicalize_resource_uri(uri), canonical, "{uri}");
        }
        // Non-local authorities, and a port-qualified loopback literal, must NOT collapse.
        assert_eq!(
            canonicalize_resource_uri("file://example.com/etc/passwd"),
            "file://example.com/etc/passwd"
        );
        assert_eq!(
            canonicalize_resource_uri("file://[::1]:99/etc/passwd"),
            "file://[::1]:99/etc/passwd"
        );
        // An already-canonical uri is unchanged (idempotent).
        assert_eq!(canonicalize_resource_uri(canonical), canonical);
    }

    /// A reserved octet stays encoded — `%2F` must NOT become `/`, or segment structure would change.
    #[test]
    fn reserved_octets_stay_encoded() {
        assert_eq!(canonicalize_resource_uri("file:///a%2Fb"), "file:///a%2Fb");
        // hex is normalized to uppercase, but the octet stays encoded.
        assert_eq!(canonicalize_resource_uri("file:///a%2fb"), "file:///a%2Fb");
    }

    /// http/https paths canonicalize like the egress twin; the host lowercases with it.
    #[test]
    fn http_paths_and_host_canonicalize() {
        assert_eq!(
            canonicalize_resource_uri("https://Example.com/a/../%62"),
            "https://example.com/b",
            "`%62`→`b`, `/a/..` pops to `/b`, and the host lowercases (RFC 3986 §6.2.2.1)"
        );
    }

    /// An opaque or custom scheme is never rewritten — `%`/`.` may be literal payload there.
    #[test]
    fn opaque_and_custom_schemes_are_untouched() {
        for uri in [
            "urn:example:%2e%2e",
            "data:text/plain,%2e%2e",
            "myapp://x/../y",
            "not-a-uri",
        ] {
            assert_eq!(canonicalize_resource_uri(uri), uri, "left verbatim: {uri}");
        }
    }

    /// The query and fragment ride through untouched; only the path is canonicalized.
    #[test]
    fn query_and_fragment_are_preserved() {
        assert_eq!(
            canonicalize_resource_uri("file:///a/../b?x=%2e#f=%2e"),
            "file:///b?x=%2e#f=%2e"
        );
    }

    /// The frame rewrite replaces only `params.uri`, and leaves a uri-free frame byte-identical.
    #[test]
    fn frame_rewrite_touches_only_the_uri() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///%65tc/passwd"}}"#;
        let rewritten = canonicalize_frame_uri(raw.as_bytes()).expect("the uri is rewritten");
        let parsed: Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(parsed["params"]["uri"], "file:///etc/passwd");
        assert_eq!(parsed["method"], "resources/read");
        assert_eq!(parsed["id"], 1);

        let no_uri = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        assert!(canonicalize_frame_uri(no_uri.as_bytes()).is_none());

        assert!(canonicalize_frame_uri(b"not json").is_none());
    }

    /// A path-only http/https URI has NO authority, and canonicalization must not fabricate one:
    /// `http:/etc/passwd` stays path-only, not `http:///etc/passwd` (which would invent an empty
    /// authority and change the URI's meaning). `file:` still gets its empty local authority.
    #[test]
    fn empty_path_segments_collapse_so_slash_padding_is_not_a_bypass() {
        // `//` resolves to `/`, so a `/`-padded respelling must not dodge a `file:///etc/*` forbid.
        assert_eq!(
            canonicalize_resource_uri("file:////etc/passwd"),
            "file:///etc/passwd",
            "leading `//` in the path collapses"
        );
        assert_eq!(
            canonicalize_resource_uri("file:///tmp//..//etc/passwd"),
            "file:///etc/passwd",
            "interior empty segments collapse, then dot-segments pop"
        );
        // `%2F` is a literal slash within a segment (RFC-literal), NOT collapsed: `..%2Fetc` stays one
        // segment and does not pop — the documented reserved-octet residual.
        assert_eq!(
            canonicalize_resource_uri("file:///tmp/%2e%2e%2Fetc/passwd"),
            "file:///tmp/..%2Fetc/passwd",
            "%2F stays encoded and does not enable a dot-segment pop"
        );
    }

    #[test]
    fn an_http_host_is_lowercased_and_trailing_dot_stripped() {
        // RFC 3986 §6.2.2.1: the host is case-insensitive and `host.` == `host`. Without this a
        // host-cased `resources/read` uri would dodge a `forbid ... uri like "http://example.com/*"`.
        assert_eq!(
            canonicalize_resource_uri("http://EXAMPLE.com/secret"),
            "http://example.com/secret",
            "host lowercased"
        );
        assert_eq!(
            canonicalize_resource_uri("https://Example.COM./a/../b"),
            "https://example.com/b",
            "host lowercased + trailing dot stripped, path still canonicalized"
        );
        assert_eq!(
            canonicalize_resource_uri("http://user@HOST:8080/x"),
            "http://user@host:8080/x",
            "host lowercased; userinfo and non-default port preserved"
        );
    }

    #[test]
    fn the_authority_is_fully_canonicalized_per_rfc_6_2() {
        // Percent-encoded host (§6.2.2.2): `%65`→`e`, so it cannot dodge a host forbid.
        assert_eq!(
            canonicalize_resource_uri("http://%65xample.com/x"),
            "http://example.com/x",
            "host unreserved octets decoded"
        );
        // Default port (§6.2.3): http/:80 and https/:443 drop.
        assert_eq!(
            canonicalize_resource_uri("http://example.com:80/x"),
            "http://example.com/x"
        );
        assert_eq!(
            canonicalize_resource_uri("https://example.com:443/x"),
            "https://example.com/x"
        );
        // A non-default port is kept.
        assert_eq!(
            canonicalize_resource_uri("http://example.com:8080/x"),
            "http://example.com:8080/x"
        );
        // Empty path with an authority normalizes to `/` (§6.2.3), so the path-less form cannot dodge
        // a `uri like "http://example.com/*"`.
        assert_eq!(
            canonicalize_resource_uri("http://example.com"),
            "http://example.com/"
        );
        assert_eq!(
            canonicalize_resource_uri("https://EXAMPLE.com.:443"),
            "https://example.com/"
        );
    }

    #[test]
    fn a_path_only_http_uri_keeps_its_path_only_form() {
        assert_eq!(
            canonicalize_resource_uri("http:/etc/passwd"),
            "http:/etc/passwd",
            "no authority present — do not fabricate `http:///`"
        );
        assert_eq!(
            canonicalize_resource_uri("https:/a/../b"),
            "https:/b",
            "path canonicalizes, but the path-only form is preserved"
        );
        assert_eq!(
            canonicalize_resource_uri("file:/etc/x"),
            "file:///etc/x",
            "`file:` no-authority is the empty local authority (RFC 8089)"
        );
    }

    /// Only `resources/read` has its `uri` rewritten. A method that carries `params.uri` for another
    /// purpose (a subscription key) is returned byte-identical, so the client's key is not re-spelled.
    #[test]
    fn only_resources_read_is_rewritten() {
        let read = r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///%65tc/x"}}"#;
        let rewritten =
            canonicalize_frame_uri(read.as_bytes()).expect("resources/read is canonicalized");
        assert_eq!(
            serde_json::from_slice::<Value>(&rewritten).unwrap()["params"]["uri"],
            "file:///etc/x"
        );

        for method in [
            "resources/subscribe",
            "resources/unsubscribe",
            "notifications/updated",
            "tools/call",
        ] {
            let frame = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{"uri":"file:///%65tc/x"}}}}"#
            );
            assert!(
                canonicalize_frame_uri(frame.as_bytes()).is_none(),
                "{method}: params.uri must NOT be rewritten"
            );
        }
    }

    /// Empty path segments collapse (`//` → `/`) so a `/`-padded respelling is one identity;
    /// `%2F` stays literal-encoded (the documented reserved-octet residual). Matches the broker copy.
    #[test]
    fn canonicalize_resource_uri_collapses_empty_segments() {
        assert_eq!(
            canonicalize_resource_uri("file:////etc/passwd"),
            "file:///etc/passwd"
        );
        assert_eq!(
            canonicalize_resource_uri("file:///tmp//..//etc/passwd"),
            "file:///etc/passwd"
        );
        assert_eq!(
            canonicalize_resource_uri("file:///tmp/%2e%2e%2Fetc/passwd"),
            "file:///tmp/..%2Fetc/passwd"
        );
    }

    /// The remote door lowercases the resource-URI host and strips a trailing dot (RFC 3986
    /// §6.2.2.1), matching the broker copy, so a host respelling cannot dodge a `uri` forbid.
    #[test]
    fn canonicalize_resource_uri_lowercases_the_host() {
        assert_eq!(
            canonicalize_resource_uri("http://EXAMPLE.com/secret"),
            "http://example.com/secret"
        );
        assert_eq!(
            canonicalize_resource_uri("https://Example.COM./a/../b"),
            "https://example.com/b"
        );
        assert_eq!(
            canonicalize_resource_uri("http://user@HOST:8080/x"),
            "http://user@host:8080/x"
        );
    }

    /// Full RFC 3986 §6.2 authority canonicalization on the remote door, matching the broker copy:
    /// percent-decoded host, dropped default port, empty-path -> `/`.
    #[test]
    fn canonicalize_resource_uri_fully_canonicalizes_the_authority() {
        assert_eq!(
            canonicalize_resource_uri("http://%65xample.com/x"),
            "http://example.com/x"
        );
        assert_eq!(
            canonicalize_resource_uri("http://example.com:80/x"),
            "http://example.com/x"
        );
        assert_eq!(
            canonicalize_resource_uri("https://example.com:443/x"),
            "https://example.com/x"
        );
        assert_eq!(
            canonicalize_resource_uri("http://example.com:8080/x"),
            "http://example.com:8080/x"
        );
        assert_eq!(
            canonicalize_resource_uri("http://example.com"),
            "http://example.com/"
        );
    }

    #[test]
    fn canonicalize_resource_uri_collapses_every_local_authority_spelling() {
        for uri in [
            "file://localhost/etc/passwd",
            "file://localhost./etc/passwd",
            "file://LOCALHOST/etc/passwd",
            "file://%6cocalhost/etc/passwd",
            "file://127.0.0.1/etc/passwd",
            "file://127.0.0.2/etc/passwd",
            "file://[::1]/etc/passwd",
        ] {
            assert_eq!(
                canonicalize_resource_uri(uri),
                "file:///etc/passwd",
                "{uri}"
            );
        }
        // Non-local authorities, and a port-qualified loopback literal, must NOT collapse.
        assert_eq!(
            canonicalize_resource_uri("file://example.com/etc/passwd"),
            "file://example.com/etc/passwd"
        );
        assert_eq!(
            canonicalize_resource_uri("file://10.0.0.5/etc/passwd"),
            "file://10.0.0.5/etc/passwd"
        );
        assert_eq!(
            canonicalize_resource_uri("file://[::1]:99/etc/passwd"),
            "file://[::1]:99/etc/passwd"
        );
    }
}
