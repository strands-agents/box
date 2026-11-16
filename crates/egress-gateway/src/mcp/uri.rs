//! RFC 3986 canonicalization of an MCP resource URI.

use std::net::Ipv6Addr;

use fluent_uri::{ParseErrorKind, UriRef};
use serde_json::Value;

use crate::boundary::hex_value;

/// Rewrite a `resources/read` frame's `params.uri` to its canonical form, or `None` when nothing changes.
pub(crate) fn canonicalize_frame_uri(frame: &[u8]) -> Option<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(frame).ok()?;
    if value.get("method").and_then(Value::as_str) != Some("resources/read") {
        return None;
    }
    let params = value.get_mut("params").and_then(Value::as_object_mut)?;
    let uri = params.get("uri").and_then(Value::as_str)?.to_owned();
    let canonical = canonicalize_resource_uri(&uri).ok()?;
    if canonical == uri {
        return None;
    }
    params.insert("uri".to_string(), Value::String(canonical));
    Some(value.to_string().into_bytes())
}

pub(crate) fn canonicalize_resource_uri(uri: &str) -> Result<String, String> {
    // RFC 3986 allows no C0 control, no space, and no bare `\` anywhere in a URI, and a URL parser
    // gives each one a meaning of its own under these schemes: it trims or removes the first two,
    // and it reads a `\` as a path separator. So one of them lets a single URI name two things. The
    // box reads `fi<tab>le:` as a custom scheme it never touches while the server reads `file:`; a
    // space the box keeps on the end of a query is one the server drops; and a `\` the box reads as
    // one more character of a name is a separator to the server. Then the two ends cannot read one
    // identity, so the URI is refused. The scheme comes from the prepared form, because that is the
    // scheme the server acts on.
    if scheme_of(&whatwg_prepared(uri)).is_some() && uri.chars().any(|ch| ch <= ' ' || ch == '\\') {
        return Err(
            "a resource URI that holds a space, a control character, or a backslash is refused: a \
                    URL parser gives each one its own meaning, so the box and the server would not \
                    read one identity"
                .to_string(),
        );
    }

    let Some((_, rest)) = uri.split_once(':') else {
        return Ok(uri.to_string()); // no scheme — not a URI the box normalizes
    };
    let Some(scheme) = scheme_of(uri) else {
        return Ok(uri.to_string()); // opaque / custom scheme — never touch
    };

    // Drop fragments and keep HTTP and HTTPS queries, including an empty query.
    let before_fragment = rest.split_once('#').map_or(rest, |(before, _)| before);
    let (hierarchical, query) = match before_fragment.split_once('?') {
        Some((hierarchical, query)) => (hierarchical, Some(query)),
        None => (before_fragment, None),
    };
    let query = query.filter(|query| scheme != "file" || !query.is_empty());

    // RFC 8089 §2 gives a `file:` URI no query — `file-URI = file-scheme ":" file-hier-part` — so a
    // query names no part of the resource, and a resolver opens the hier-part alone. Such a URI is
    // outside the grammar this function canonicalizes and has no canonical form, so it is refused
    // rather than guessed. An empty query folded away above, so a URI inside the grammar never
    // reaches this.
    if scheme == "file" && query.is_some() {
        return Err(
            "a file URI that carries a query is refused: RFC 8089 gives a file URI no \
                    query, so the box cannot say which resource it names"
                .to_string(),
        );
    }

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
        // An opaque hier-part under one of these schemes is outside both grammars: RFC 8089 §2 has
        // `local-path = path-absolute`, and RFC 9110 §4.2.1 requires `"//" authority`. A URL parser
        // supplies the delimiters the URI omits, so `file:etc/passwd` reads as `file:///etc/passwd`
        // and `https:notes/page` as `https://notes/page`. Keeping it verbatim is not the safe
        // reading it looks like: the parser does the guessing, and it reaches the resource a rule
        // names.
        return Err(
            "a resource URI whose hier-part is neither an absolute path nor an authority is \
                    refused: a URL parser supplies the delimiters it omits, so the box and the \
                    server would not read one identity"
                .to_string(),
        );
    };

    // RFC 3986 §3.2 spells `authority = [ userinfo "@" ] host [ ":" port ]`, with
    // `host = IP-literal / IPv4address / reg-name`. An authority outside that grammar has no
    // canonical form here, because normalization is string surgery — lowercase, percent-decode
    // unreserved, drop a default port — and a URL parser instead maps a host through IDNA and its
    // own forbidden-code-point rules. So a spelling the grammar refuses reaches the server as one
    // host and a rule as another. It is refused for the same reason a path outside §3.3 is, which
    // `normalize_path` already does.
    if let Some(auth) = authority
        && !is_rfc_3986_authority(auth)
    {
        return Err(
            "a resource URI whose authority is not RFC 3986 is refused: RFC 3986 §3.2 spells an \
                    authority `[userinfo@]host[:port]`, and a URL parser maps a host the grammar \
                    refuses to a different host, so the box and the server would not read one \
                    identity"
                .to_string(),
        );
    }

    // Normalize before the empty-authority check, so the refusal judges the authority this function
    // would emit rather than the authored spelling. `https://./x` normalizes to an empty authority,
    // and judging the raw `.` let it through and emitted `https:///x` — a form this same check
    // refuses, so the output was not its own fixed point.
    let normalized_authority = authority
        .map(|auth| normalize_authority(auth, &scheme))
        .transpose()?;

    // RFC 9110 §4.2.1 requires `"//" authority` and forbids an empty host, and a URL parser that
    // meets neither reads the first path segment as the host: `http:/etc/passwd` becomes host `etc`,
    // and `https:///notes/page` becomes host `notes`. `file:` is the exception the grammar states —
    // RFC 8089 makes an absent or empty authority the local one, which folds to `file:///`.
    if scheme != "file" && matches!(normalized_authority.as_deref(), None | Some("")) {
        return Err(
            "an http or https URI with no authority is refused: RFC 9110 requires \"//\" and a \
                    host, and a URL parser reads the first path segment as the host instead"
                .to_string(),
        );
    }

    // Decode unreserved octets, collapse empty path segments (`//` resolves to `/` on common
    // file/HTTP resolvers, so `file:////etc/passwd` is the same identity as `file:///etc/passwd` —
    // a `/`-padded respelling is not a new path), then remove dot-segments.
    //
    // Reserved-octet residual: `%2F` (and other reserved escapes) are left ENCODED, RFC 3986
    // §2.2/§6.2.2 — a `%2F` denotes a literal slash *within* a segment, not a separator, so `..%2Fetc`
    // stays one segment and does not pop. That is the right reading under `http`/`https`, where the
    // origin server receives the escape and may hold a segment that spells one, and it matches the
    // egress request-path canonicalization, which never decodes `%2F`.
    let canonical_path = normalize_path(&collapse_slashes(path))?;

    // Under `file:` the same escape names nothing. No POSIX or Windows file name holds a `/`, so a
    // segment spelling one resolves to no file, and a resolver that decodes it reads a path the box
    // never judged: Python's `url2pathname` and the Rust `url` crate both turn `%2F` into a
    // separator, so `/home/op%2F.env` reaches `/home/op/.env` and `..%2Fetc` traverses. Node refuses
    // the URI outright. So the escape has no canonical form here and is refused, which also takes the
    // traversal this door otherwise left to the leaf box's filesystem bound. `%5C` is NOT refused
    // with it: all three decode it to a literal `\`, which a POSIX name may hold, so it names a real
    // file of its own and the two ends agree on which.
    if scheme == "file" && canonical_path.contains("%2F") {
        return Err(
            "a file URI whose path holds an encoded slash is refused: no file name holds a `/`, \
                    so the escape names no file, and a resolver that decodes it opens a path the \
                    box did not judge"
                .to_string(),
        );
    }

    let mut out = String::with_capacity(uri.len());
    out.push_str(&scheme);
    out.push(':');
    // Every URI reaching here carries the `//` of an authority. One with none is `file:`, whose
    // no-authority form is the empty local authority RFC 8089 states, so `file:/x` becomes
    // `file:///x`; for every other scheme the refusal above took the absent and the empty cases.
    out.push_str("//");
    // The local-authority case is decided on the normalized form, not the raw string, so it catches
    // the spellings of "this machine" that normalization folds (case, trailing dot,
    // percent-encoding, loopback IP literals) and not just the exact string `localhost`. A port
    // spelling normalization leaves alone — an empty port, a leading zero, or `[::0001]` — is a
    // residual, and for `http`/`https` a live one: a URL parser reads `:0443` as the default port
    // and drops it, so two spellings reach one origin and the box reports two.
    if let Some(normalized) = normalized_authority.as_deref()
        && !(scheme == "file" && is_local_file_authority(normalized))
    {
        out.push_str(normalized);
    }
    // RFC 3986 §6.2.3: an authority with an empty path normalizes to a path of `/`, so
    // `http://example.com` cannot dodge a `uri like "http://example.com/*"` by omitting the path.
    if canonical_path.is_empty() {
        out.push('/');
    } else {
        out.push_str(&canonical_path);
    }
    if let Some(query) = query {
        out.push('?');
        out.push_str(query);
    }
    Ok(out)
}

/// The lowercased scheme of `uri`, when that scheme is one this module canonicalizes.
fn scheme_of(uri: &str) -> Option<String> {
    let scheme = uri.split_once(':')?.0.to_ascii_lowercase();
    matches!(scheme.as_str(), "file" | "http" | "https").then_some(scheme)
}

/// The URI a WHATWG URL parser reads: leading and trailing C0 controls and spaces trimmed, then every tab, CR, and LF removed.
fn whatwg_prepared(uri: &str) -> String {
    uri.trim_matches(|ch: char| ch <= '\u{1f}' || ch == ' ')
        .chars()
        .filter(|ch| !matches!(ch, '\t' | '\r' | '\n'))
        .collect()
}

/// Whether a NORMALIZED `file:` authority is this machine: `localhost`, or a loopback IP literal (RFC 5735 `127.0.0.0/8`; RFC 4291 `::1`).
fn is_local_file_authority(normalized_auth: &str) -> bool {
    if normalized_auth == "localhost" {
        return true;
    }
    if let Some(inner) = normalized_auth
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        // Parse the literal rather than compare its text. One address has many spellings — `[::1]`,
        // `[::0001]`, `[0::1]`, and `[0:0:0:0:0:0:0:1]` are the same address, and a URL parser folds
        // every one to `[::1]`, so a text comparison left the rest naming this machine to a resolver
        // while reaching a rule as a host of their own.
        return inner.parse::<Ipv6Addr>().is_ok_and(|address| {
            address.is_loopback() || address.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        });
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
fn normalize_authority(auth: &str, scheme: &str) -> Result<String, String> {
    let (userinfo, hostport) = match auth.rsplit_once('@') {
        Some((user, rest)) => (Some(user), rest),
        None => (None, auth),
    };

    // RFC 9110 §4.2.4 deprecates the userinfo under these two schemes: a sender may not generate
    // one, and a recipient of a URI from an untrusted source is asked to treat its presence as an
    // error, because it obscures the authority. The workload is the untrusted source here, and the
    // obscuring is measurable: the canonical form spells the userinfo before the host, so no rule
    // written against a host reaches a URI that carries one, while all three reference parsers
    // resolve it to that host. An empty one is worse again, because a parser drops it and this
    // function does not, so the two ends read two strings.
    if userinfo.is_some() && scheme != "file" {
        return Err(
            "an http or https URI that carries userinfo is refused: RFC 9110 §4.2.4 asks a \
                    recipient to treat it as an error, because it obscures the host the URI \
                    reaches"
                .to_string(),
        );
    }
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
        // Every escape still here decodes to a reserved octet or to a non-ASCII byte, because
        // `decode_unreserved` took the rest. A name holds neither: a URL parser percent-decodes the
        // host and then either refuses the octet or maps the byte through IDNA, which this function
        // does not implement. So the two ends read two hosts, and `%C2%AD` inside `localhost` opened
        // the file a rule named. An escape of an unreserved octet decoded above and still folds.
        if decoded.contains('%') {
            return Err(
                "a resource URI whose host holds a percent-escape of a reserved or non-ASCII \
                        octet is refused: a URL parser decodes the host and then maps that octet \
                        through IDNA, so the box and the server would not read one identity"
                    .to_string(),
            );
        }
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
    Ok(out)
}

/// Whether `authority` is an RFC 3986 §3.2 authority, which the grammar spells `[ userinfo "@" ] host [ ":" port ]`.
fn is_rfc_3986_authority(authority: &str) -> bool {
    // Parse it in the authority position of a reference, so §3.2 is read from the one RFC 3986
    // parser this module already uses for the path rather than re-stated here. The parsed authority
    // must be the whole string: a `/`, a `?`, or a `#` would end it early and leave the tail as a
    // path, and an authority this function splits off holds none of the three.
    let reference = format!("s://{authority}");
    UriRef::parse(reference.as_str())
        .ok()
        .and_then(|parsed| {
            parsed
                .authority()
                .map(|parsed| parsed.as_str() == authority)
        })
        .unwrap_or(false)
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

/// Percent-decode only the unreserved octets of `path`; leave every reserved (or otherwise non-unreserved) escape encoded, normalizing its hex digits to uppercase (RFC 3986 §6.2.2.1), and encode a `%` that starts no escape as `%25`.
fn decode_unreserved(path: &str) -> String {
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
        if bytes[index] == b'%' {
            out.extend_from_slice(b"%25");
        } else {
            out.push(bytes[index]);
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether `byte` is an RFC 3986 unreserved octet — the only octets safe to percent-decode without changing how the URI parses.
fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// The RFC 3986 normal form of a path, or why the path is refused: unreserved escapes decoded, hex uppercased, and dot-segments removed from an absolute path.
pub(crate) fn normalize_path(path: &str) -> Result<String, String> {
    let prefix = if path.is_empty() || path.starts_with('/') {
        "s://h"
    } else {
        "s:"
    };
    let reference = format!("{prefix}{path}");
    let parsed = UriRef::parse(reference.as_str()).map_err(|error| {
        let what = match error.kind() {
            ParseErrorKind::InvalidPctEncodedOctet => "an invalid percent-escape",
            _ => "a character a URI path does not allow",
        };
        let at = error.index().saturating_sub(prefix.len());
        format!("a path that is not RFC 3986 is refused: {what} at byte {at}")
    })?;
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("a path that is not RFC 3986 is refused: it holds a `?` or `#`".to_string());
    }
    Ok(parsed.normalize().path().as_str().to_string())
}

/// Every string up to four bytes over an escape-heavy alphabet, plus seeded longer ones.
#[cfg(test)]
pub(crate) fn generated_spellings() -> Vec<String> {
    const ALPHABET: &[&str] = &[
        "%", "2", "5", "e", "E", "3", "6", "7", "f", "g", "/", ".", "a", "é", "#", "?", ":", "\t",
        " ", "\\", "@", "[", "]", "_", "|",
    ];
    let mut spellings = vec![String::new()];
    let mut frontier = vec![String::new()];
    for _ in 0..4 {
        frontier = frontier
            .iter()
            .flat_map(|prefix| ALPHABET.iter().map(move |piece| format!("{prefix}{piece}")))
            .collect();
        spellings.extend(frontier.iter().cloned());
    }
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..20_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let length = 5 + (state % 28) as usize;
        let mut spelling = String::new();
        let mut draw = state;
        for _ in 0..length {
            draw = draw.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            spelling.push_str(ALPHABET[(draw >> 33) as usize % ALPHABET.len()]);
        }
        spellings.push(spelling);
    }
    spellings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical form of a URI the test expects to be valid.
    fn canonicalize_resource_uri(uri: &str) -> String {
        super::canonicalize_resource_uri(uri).unwrap()
    }

    #[test]
    fn a_resource_uri_whose_path_is_not_rfc_3986_is_refused() {
        for uri in ["file:///%%365tc/hosts", "file:///a%zz", "https://h/a b"] {
            assert!(super::canonicalize_resource_uri(uri).is_err(), "{uri}");
        }
        let frame = br#"{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"file:///%%365tc/hosts"}}"#;
        assert!(crate::mcp::McpTarget::of_http_request(frame).is_err());
        assert_eq!(canonicalize_frame_uri(frame), None);
    }

    #[test]
    fn decode_unreserved_is_idempotent() {
        for spelling in generated_spellings() {
            let once = decode_unreserved(&spelling);
            assert_eq!(decode_unreserved(&once), once, "{spelling:?}");
        }
    }

    #[test]
    fn canonicalize_resource_uri_is_idempotent() {
        for prefix in [
            "file://",
            "file:///",
            "http://h/",
            "https://%41b.",
            "file:/",
            "file:",
            "FILE:",
            // Put a generated spelling in the AUTHORITY position. Without these no prefix could
            // produce an authority that normalizes to empty, which is how `https://./x` emitted a
            // canonical form that was not its own fixed point.
            "https://",
            "file://",
        ] {
            for spelling in generated_spellings() {
                if let Ok(once) = super::canonicalize_resource_uri(&format!("{prefix}{spelling}")) {
                    assert_eq!(
                        super::canonicalize_resource_uri(&once),
                        Ok(once.clone()),
                        "{prefix}{spelling:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_well_formed_escape_decodes_only_unreserved_octets() {
        for (spelling, decoded) in [
            ("/%61dmin", "/admin"),
            ("/%2e%2E/x", "/../x"),
            ("/a%2fb", "/a%2Fb"),
            ("/a%2Fb%3f", "/a%2Fb%3F"),
            ("/%7E%5f%2D", "/~_-"),
            ("/plain/path", "/plain/path"),
            ("/%25", "/%25"),
            ("/%C3%A9", "/%C3%A9"),
        ] {
            assert_eq!(decode_unreserved(spelling), decoded, "{spelling}");
        }
    }

    #[test]
    fn a_percent_that_starts_no_escape_is_encoded() {
        for (spelling, decoded) in [
            ("/%", "/%25"),
            ("/%4", "/%254"),
            ("/%zz", "/%25zz"),
            ("/%%3761/chat", "/%25761/chat"),
            ("/v1/%%32%65%%32%65/x", "/v1/%252e%252e/x"),
            ("/%%365tc/hosts", "/%2565tc/hosts"),
        ] {
            assert_eq!(decode_unreserved(spelling), decoded, "{spelling}");
        }
    }

    /// One percent-decode of every escape, as a server does before it opens a `file:` path.
    fn server_decode(uri: &str) -> String {
        let bytes = uri.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%'
                && let (Some(&high), Some(&low)) = (bytes.get(index + 1), bytes.get(index + 2))
                && let (Some(high), Some(low)) = (hex_value(high), hex_value(low))
            {
                out.push(high * 16 + low);
                index += 3;
                continue;
            }
            out.push(bytes[index]);
            index += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn a_stray_percent_cannot_assemble_an_escape_the_server_decodes() {
        match super::canonicalize_resource_uri("file:///%%365tc/hosts") {
            Err(reason) => assert!(reason.contains("percent-escape at byte 1"), "{reason}"),
            Ok(judged) => panic!(
                "the box judged {judged}, which the server decodes to {}",
                server_decode(&judged)
            ),
        }
    }

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
            // One address, four spellings. A URL parser folds each to `[::1]`, so a text
            // comparison left these three naming this machine to a resolver while reaching a rule
            // as a host of their own. An IPv4-mapped loopback literal carries the v4 test with it.
            "file://[::0001]/etc/passwd",
            "file://[0::1]/etc/passwd",
            "file://[0:0:0:0:0:0:0:1]/etc/passwd",
            "file://[::ffff:127.0.0.1]/etc/passwd",
            "file://[::FFFF:127.0.0.1]/etc/passwd",
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

    /// A reserved octet stays encoded — `%2F` must NOT become `/`, or segment structure would
    /// change. Under `http`/`https` the origin server receives the escape, so it stays; under
    /// `file:` it names no file and is refused instead.
    #[test]
    fn reserved_octets_stay_encoded_under_http_and_are_refused_under_file() {
        assert_eq!(
            canonicalize_resource_uri("https://h/a%2Fb"),
            "https://h/a%2Fb"
        );
        // hex is normalized to uppercase, but the octet stays encoded.
        assert_eq!(
            canonicalize_resource_uri("https://h/a%2fb"),
            "https://h/a%2Fb"
        );
        // Another reserved octet still stays encoded under both schemes.
        assert_eq!(canonicalize_resource_uri("file:///a%3Fb"), "file:///a%3Fb");
        for uri in ["file:///a%2Fb", "file:///a%2fb"] {
            let refusal =
                super::canonicalize_resource_uri(uri).expect_err("an encoded slash names no file");
            assert!(refusal.contains("encoded slash"), "{uri}: {refusal}");
        }
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

    /// A non-empty query rides through untouched; only the path is canonicalized.
    #[test]
    fn a_non_empty_query_is_preserved() {
        assert_eq!(
            canonicalize_resource_uri("https://h/a/../b?x=%2e"),
            "https://h/b?x=%2e"
        );
    }

    #[test]
    fn an_empty_http_query_is_preserved() {
        for scheme in ["http", "https"] {
            for (spelling, expected) in [
                ("notes/report?", "notes/report?"),
                ("notes/report?#section", "notes/report?"),
                ("notes?", "notes/?"),
                ("NOTES/reports/../report?", "notes/report?"),
                ("notes/report", "notes/report"),
                ("notes/report#?section", "notes/report"),
                ("notes/report?format=text", "notes/report?format=text"),
            ] {
                let uri = format!("{scheme}://{spelling}");
                assert_eq!(
                    canonicalize_resource_uri(&uri),
                    format!("{scheme}://{expected}"),
                    "{uri}"
                );
            }
        }
    }

    #[test]
    fn an_empty_http_query_reaches_the_decision_and_forwarded_frame() {
        for scheme in ["http", "https"] {
            for (spelling, expected) in [
                ("notes/report?", "notes/report?"),
                ("NOTES/reports/../report?", "notes/report?"),
                ("notes/report?#section", "notes/report?"),
                ("notes?", "notes/?"),
                ("notes/report", "notes/report"),
            ] {
                let uri = format!("{scheme}://{spelling}");
                let expected = format!("{scheme}://{expected}");
                let frame = serde_json::to_vec(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "resources/read",
                    "params": {"uri": uri, "_meta": {"progressToken": "keep-me"}},
                }))
                .unwrap();
                for target in [
                    crate::mcp::McpTarget::of_http_request(&frame),
                    crate::mcp::McpTarget::of_stdio_request(&frame),
                ] {
                    assert_eq!(
                        target.unwrap().unwrap().uri(),
                        Some(expected.as_str()),
                        "policy input for {uri}"
                    );
                }
                let forwarded = canonicalize_frame_uri(&frame).unwrap_or(frame);
                let parsed: Value = serde_json::from_slice(&forwarded).unwrap();
                assert_eq!(
                    parsed,
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "resources/read",
                        "params": {"uri": expected, "_meta": {"progressToken": "keep-me"}},
                    }),
                    "the forwarded frame changes only the resource URI for {uri}"
                );
            }
        }
    }

    /// A URL parser gives a space, a control character, and a `\` each a meaning of its own, so
    /// such a URI names one resource to the box and another to the server. It is refused on every
    /// branch, including the one where the authored scheme already reads as `file`.
    #[test]
    fn a_resource_uri_a_url_parser_reads_differently_is_refused() {
        for uri in [
            " file:///home/op/.env",
            "\tfile:///home/op/.env",
            "\u{1}file:///home/op/.env",
            "fi\tle:///home/op/.env",
            "fil\re:///home/op/.env",
            "FILE\t:///home/op/.env",
            // The authored scheme already reads as `file`, so a check that only compares the
            // scheme before and after preparation misses these two.
            "file:\t///home/op/.env",
            "file:\t//localhost/home/op/.env",
            "ht\ttps://example.com/x",
            "\u{1f}https://example.com/x",
            // The query position too: the box would keep this space and a parser drops it, so the
            // canonical form would not be the resource the origin server resolves.
            "http://h/a?b=1 ",
            "http://h/a?b=1 #f",
            "http://h/a?b\t=1",
            // A `\` is a path separator to a URL parser under these schemes. The path position was
            // already refused, but the authority and the opaque hier-part let one through. Both of
            // the first two resolve to `/home/op/.env` in Node and in Rust's `url` crate.
            r"file://localhost\home\op\.env",
            r"file://localhost\home/op/.env",
            r"file:///home/op\.env",
            r"http://h/a\b",
            // The opaque hier-part, which carries no authority, under each count of leading `\`.
            r"file:\\localhost\home\op\.env",
            r"file:\\\localhost\home\op\.env",
            r"file:\\\home\op\.env",
            r"file:\home\op\.env",
        ] {
            let refusal = super::canonicalize_resource_uri(uri)
                .expect_err("the box and a URL parser must not read two identities");
            assert!(
                refusal.contains("space, a control character, or a backslash"),
                "{uri:?}: {refusal}"
            );
        }
        // A custom scheme keeps its never-touch contract, because the box claims no identity for
        // it and canonicalizes nothing there.
        for uri in [" notes:///x", "my\tapp://x/y", "not a uri", "/a:b"] {
            assert_eq!(
                canonicalize_resource_uri(uri),
                uri,
                "left verbatim: {uri:?}"
            );
        }
        let frame = b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"resources/read\",\"params\":{\"uri\":\"fi\\tle:///home/op/.env\"}}";
        assert!(crate::mcp::McpTarget::of_stdio_request(frame).is_err());
        assert_eq!(canonicalize_frame_uri(frame), None);
    }

    /// RFC 8089 gives a `file:` URI no query, so one that carries a query is refused on every
    /// branch rather than given a canonical form the resolver would not agree with.
    #[test]
    fn a_file_uri_that_carries_a_query_is_refused() {
        for uri in [
            "file:///home/op/.env?x",
            "file:///home/op/.env?a=1",
            "file:///home/op/.env?a=1#f",
            "file:///home/op/.env?a=#b",
            "file:///home/op/.env??y",
            "file:///home/op/.env?=",
            "file:/home/op/.env?x",
            "file://localhost/home/op/.env?x",
            "file://example.com/home/op/.env?x",
            "FILE:///home/op/.env?x",
            "file:etc/passwd?a=1",
        ] {
            let refusal = super::canonicalize_resource_uri(uri)
                .expect_err("a file URI with a query has no canonical form");
            assert!(
                refusal.contains("RFC 8089 gives a file URI no query"),
                "{uri}: {refusal}"
            );
        }
        // The frame rewrite reports no rewrite for a refused URI, so the decision path refuses it
        // and nothing is forwarded — the same pairing an unparsable path already gets.
        let frame = br#"{"jsonrpc":"2.0","id":9,"method":"resources/read","params":{"uri":"file:///home/op/.env?x"}}"#;
        assert!(crate::mcp::McpTarget::of_http_request(frame).is_err());
        assert!(crate::mcp::McpTarget::of_stdio_request(frame).is_err());
        assert_eq!(canonicalize_frame_uri(frame), None);
    }

    /// The refusal is the only thing a `file:` query reaches: no generated spelling that carries
    /// one is given a canonical form, and every `http`/`https` twin of it still canonicalizes.
    #[test]
    fn no_generated_file_uri_with_a_query_gets_a_canonical_form() {
        let mut refused = 0usize;
        let mut kept = 0usize;
        for prefix in ["file://", "file:///", "file:/", "file:", "FILE:"] {
            for spelling in generated_spellings() {
                let uri = format!("{prefix}{spelling}");
                // The query is what survives the fragment split, and an empty one folds away.
                let before_fragment = uri
                    .split_once('#')
                    .map_or(uri.as_str(), |(before, _)| before);
                let carries_query = before_fragment
                    .split_once('?')
                    .is_some_and(|(_, query)| !query.is_empty());
                // A space, a control character, or a `\` is refused ahead of the query.
                if !carries_query || uri.chars().any(|ch| ch <= ' ' || ch == '\\') {
                    continue;
                }
                refused += 1;
                let refusal = super::canonicalize_resource_uri(&uri)
                    .expect_err("a file URI with a query has no canonical form");
                assert!(
                    refusal.contains("RFC 8089 gives a file URI no query"),
                    "{uri}: {refusal}"
                );
                // Over-folding control: the same query under `https` is part of the request the
                // origin server receives, so it must still produce a canonical form.
                let twin = format!(
                    "https://h/{}",
                    before_fragment.trim_start_matches(|ch| ch != '?')
                );
                if let Ok(canonical) = super::canonicalize_resource_uri(&twin) {
                    assert!(
                        canonical.contains('?'),
                        "{twin} lost its query: {canonical}"
                    );
                    kept += 1;
                }
            }
        }
        assert!(
            refused > 1_000,
            "the generator reached only {refused} queries"
        );
        assert!(kept > 1_000, "the https control ran only {kept} times");
    }

    /// File delimiters fold, and HTTP queries preserve their resource identity.
    #[test]
    fn file_delimiters_fold_without_merging_http_queries() {
        let canonical = "file:///home/op/project/.env";
        for uri in [
            "file:///home/op/project/.env",
            "file:///home/op/project/.env#",
            "file:///home/op/project/.env?",
            "file:///home/op/project/.env?#",
            "file:///home/op/project/.env#x",
            "file:///home/op/project/.env#?a=1",
            "file:/home/op/project/.env#x",
            "file://localhost/home/op/project/.env?",
        ] {
            assert_eq!(canonicalize_resource_uri(uri), canonical, "{uri}");
        }
        // A non-empty query still names a different request, so it survives the fold.
        assert_eq!(
            canonicalize_resource_uri("https://h/a?b=1#f"),
            "https://h/a?b=1"
        );
        assert_eq!(canonicalize_resource_uri("https://h/a?"), "https://h/a?");
        assert_eq!(canonicalize_resource_uri("https://h/a#"), "https://h/a");
        // An authority with no path still gains its `/` once the delimiters are gone.
        assert_eq!(canonicalize_resource_uri("http://h#f"), "http://h/");
    }

    /// The fold reaches the opaque hier-part too, which returns before the path is canonicalized.
    #[test]
    fn an_opaque_hier_part_is_refused_because_a_parser_supplies_the_delimiters() {
        // A URL parser reads each of these as the authority form, reaching the resource a rule
        // names: `file:etc/passwd` becomes `file:///etc/passwd` and `https:notes/page` becomes
        // `https://notes/page`, in Node and in the Rust `url` crate alike.
        for uri in [
            "file:etc/passwd",
            "file:home/op/.env",
            "file:./home/op/.env",
            "file:etc/passwd#x",
            "FILE:etc/passwd#x",
            "https:notes/page",
            "http:etc/passwd?a=1",
        ] {
            let refusal = super::canonicalize_resource_uri(uri)
                .expect_err("an opaque hier-part has no canonical form");
            assert!(
                refusal.contains("neither an absolute path nor an authority")
                    || refusal.contains("RFC 8089 gives a file URI no query"),
                "{uri}: {refusal}"
            );
        }
    }

    /// The forwarded frame carries the same identity the decision used.
    #[test]
    fn the_forwarded_frame_loses_the_fragment_the_decision_dropped() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///home/op/.env#x"}}"#;
        let rewritten = canonicalize_frame_uri(raw.as_bytes()).expect("the uri is rewritten");
        let parsed: Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(parsed["params"]["uri"], "file:///home/op/.env");
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
        // `%2F` is a literal slash within a segment (RFC-literal), NOT collapsed: `..%2Fetc` stays
        // one segment and does not pop. Under `file:` that segment names no file and two of three
        // resolvers decode it into a separator and traverse, so it is refused rather than emitted.
        assert_eq!(
            canonicalize_resource_uri("https://h/tmp/%2e%2e%2Fetc/passwd"),
            "https://h/tmp/..%2Fetc/passwd",
            "%2F stays encoded and does not enable a dot-segment pop"
        );
        let refusal = super::canonicalize_resource_uri("file:///tmp/%2e%2e%2Fetc/passwd")
            .expect_err("an encoded slash names no file");
        assert!(refusal.contains("encoded slash"), "{refusal}");
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
            canonicalize_resource_uri("http://HOST:8080/x"),
            "http://host:8080/x",
            "host lowercased; non-default port preserved"
        );
        // A userinfo is refused under these schemes, so it is never lowercased with the host.
        assert!(super::canonicalize_resource_uri("http://user@HOST:8080/x").is_err());
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

    /// An `http`/`https` URI needs an authority, and `file:` is the grammar's exception.
    #[test]
    fn an_http_uri_with_no_authority_is_refused_and_file_keeps_its_local_one() {
        // A parser reads the first path segment as the host — `http:/etc/passwd` becomes host `etc`
        // — so keeping the path-only form was never the safe reading it looked like.
        for uri in [
            "http:/etc/passwd",
            "https:/a/../b",
            "https:///notes/page",
            "http://",
            "https://",
            // An authority that NORMALIZES to empty. Judging the authored spelling let these
            // through and emitted `https:///x`, which this same refusal rejects — so the output
            // was not its own fixed point.
            "https://./notes/page",
            "https://.../x",
            "http://%2e/x",
        ] {
            let refusal = super::canonicalize_resource_uri(uri)
                .expect_err("an http or https URI must spell an authority");
            assert!(
                refusal.contains("no authority is refused"),
                "{uri}: {refusal}"
            );
        }
        // RFC 8089 makes an absent or empty `file:` authority the local one, which still folds.
        assert_eq!(
            canonicalize_resource_uri("file:/etc/x"),
            "file:///etc/x",
            "`file:` no-authority is the empty local authority (RFC 8089)"
        );
        assert_eq!(canonicalize_resource_uri("file:///etc/x"), "file:///etc/x");
        assert_eq!(canonicalize_resource_uri("file://"), "file:///");
        assert_eq!(
            canonicalize_resource_uri("file://./x"),
            "file:///x",
            "`file:` folds an authority that normalizes to empty, rather than refusing it"
        );
        // An `http` authority that normalizes to something non-empty still canonicalizes.
        assert_eq!(canonicalize_resource_uri("https://a./x"), "https://a/x");
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
            canonicalize_resource_uri("https://h/tmp/%2e%2e%2Fetc/passwd"),
            "https://h/tmp/..%2Fetc/passwd"
        );
        assert!(super::canonicalize_resource_uri("file:///tmp/%2e%2e%2Fetc/passwd").is_err());
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
            canonicalize_resource_uri("http://HOST:8080/x"),
            "http://host:8080/x"
        );
        assert!(super::canonicalize_resource_uri("http://user@HOST:8080/x").is_err());
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

    /// RFC 3986 §3.2 spells `authority = [ userinfo "@" ] host [ ":" port ]`. Each row here is a
    /// production the spelling breaks, not a character someone happened to list: a URL parser maps
    /// a host the grammar refuses through IDNA and its own forbidden-code-point rules, so the box
    /// and the server would read two hosts.
    #[test]
    fn an_authority_outside_rfc_3986_is_refused() {
        for uri in [
            // `reg-name = *( unreserved / pct-encoded / sub-delims )` allows no raw non-ASCII, so
            // no IDNA form reaches here. Both reference parsers resolve each of these to a
            // DIFFERENT host than the box emitted: an ignorable code point drops, a Unicode dot
            // becomes a label separator, and a non-ASCII letter becomes a punycode label.
            "https://no\u{ad}tes/page",
            "https://no\u{200b}tes/page",
            "https://\u{ad}notes/page",
            "https://notes\u{200b}/page",
            "https://notes\u{3002}example/page",
            "https://notes\u{ff0e}example/page",
            "https://not\u{e9}s/page",
            "https://NOT\u{c9}S/page",
            "https://notes\u{ff03}x/page",
            "https://notes\u{ff1f}x/page",
            "file://localhost\u{200b}/home/op/.env",
            "file://localhost\u{ad}/home/op/.env",
            "file://loc\u{ad}alhost/home/op/.env",
            // A character `reg-name` holds under no production. `"`, `{`, `}`, and a backquote
            // are the ones both parsers keep as written, so each refuses a host that is not a
            // host rather than closing a measured respelling.
            "https://no\"tes/page",
            "https://no<tes/page",
            "https://no>tes/page",
            "https://no^tes/page",
            "https://no{tes/page",
            "https://no}tes/page",
            "https://no|tes/page",
            "https://no`tes/page",
            "https://notes\u{7f}/page",
            // `pct-encoded = "%" HEXDIG HEXDIG`, so a `%` that starts no escape is outside the
            // grammar. The path already refuses this through `normalize_path`.
            "https://a%/page",
            "https://a%4/page",
            "https://a%zz/page",
            // `host = IP-literal / IPv4address / reg-name`, and `IP-literal` carries its own
            // brackets. An unbracketed IPv6 literal is none of the three.
            "https://::1/page",
            "file://::/home/op/.env",
            "file://::1/home/op/.env",
            "https://[::1/page",
            "https://[::g]/page",
            "https://[]/page",
            "https://[notes]/page",
            // RFC 6874 adds a zone identifier, and RFC 3986 does not have one.
            "https://[fe80::1%25eth0]/page",
            // `userinfo` ends at the LAST `@`, and holds no second one unescaped.
            "https://a@b@notes/page",
            // `port = *DIGIT`, so an empty port conforms and a non-digit does not.
            "https://notes:443./page",
            "https://notes:+443/page",
            "https://notes:44a/page",
            "https://notes:443:443/page",
        ] {
            let refusal = super::canonicalize_resource_uri(uri)
                .expect_err("an authority outside RFC 3986 §3.2 has no canonical form");
            assert!(
                refusal.contains("authority is not RFC 3986"),
                "{uri:?}: {refusal}"
            );
        }
    }

    /// The grammar allows a percent-escape in a host, so the §3.2 check reaches the raw spelling of
    /// an ignorable code point and not the escaped one. Both reach the resource a rule names: a
    /// parser decodes the host first, so `%C2%AD` inside `localhost` opens the guarded file and
    /// `%E2%80%8B` inside a name reaches the plain name. Every escape left after the unreserved
    /// decode is a reserved octet or a non-ASCII byte, and a name holds neither.
    #[test]
    fn a_host_holding_an_escape_of_a_reserved_or_non_ascii_octet_is_refused() {
        for uri in [
            // A non-ASCII byte. Node and the Rust `url` crate map each through IDNA and reach the
            // plain host, so each opens the file or the page a rule names.
            "file://localhost%C2%AD/home/op/.env",
            "file://LOCALHOST%c2%ad/home/op/.env",
            "file://loc%C2%ADalhost/home/op/.env",
            "https://no%E2%80%8Btes/page",
            "https://no%C2%ADtes/page",
            "https://not%C3%A9s/page",
            // A reserved octet. Both parsers refuse `%2F`, `%3A`, `%40`, `%7C`, and a `%25`, so
            // refusing them costs nothing. An escaped sub-delim is the one both parsers accept, and
            // they decode it while the box kept it encoded — so that was two strings for one host.
            "https://no%2Ftes/page",
            "https://no%3Ates/page",
            "https://no%40tes/page",
            "https://no%7Ctes/page",
            "https://a%25b/page",
            "https://no%21tes/page",
            "https://no%2Btes/page",
        ] {
            let refusal = super::canonicalize_resource_uri(uri)
                .expect_err("a host holding such an escape has no canonical form");
            assert!(
                refusal.contains("host holds a percent-escape"),
                "{uri:?}: {refusal}"
            );
        }

        // An escape of an UNRESERVED octet decodes before the check, so it still folds — which is
        // the whole reason the earlier percent-encoding fold exists.
        assert_eq!(
            canonicalize_resource_uri("file://%6C%6Fcalhost/home/op/.env"),
            "file:///home/op/.env"
        );
        assert_eq!(
            canonicalize_resource_uri("https://notes%2Eexample/page"),
            "https://notes.example/page"
        );
        assert_eq!(
            canonicalize_resource_uri("http://%65xample.com/x"),
            "http://example.com/x"
        );
        // The userinfo is passed through verbatim, so an escape there is not a host escape and
        // still rides. `file:` is where that is observable, because RFC 9110 §4.2.4 refuses a
        // userinfo under the other two schemes.
        assert_eq!(
            canonicalize_resource_uri("file://US%45R@localhost/home/op/.env"),
            "file://US%45R@localhost/home/op/.env"
        );
        // An IPv6 literal is never percent-decoded, so the check does not reach inside one.
        assert_eq!(
            canonicalize_resource_uri("https://[::1]/page"),
            "https://[::1]/page"
        );
    }

    /// **An encoded slash in a `file:` path is refused, and the `http`/`https` twin still rides.**
    ///
    /// Two of the three reference resolvers decode `%2F` into a separator — Python's `url2pathname`
    /// and the Rust `url` crate — so `/home/op%2F.env` reaches `/home/op/.env` and `..%2Fetc`
    /// traverses. Node refuses the URI. No POSIX or Windows file name holds a `/`, so the escape
    /// names no file under `file:` and has no canonical form here.
    #[test]
    fn an_encoded_slash_in_a_file_path_is_refused() {
        for uri in [
            "file:///home/op%2F.env",
            "file:///home/op%2f.env",
            "file:///home%2Fop/.env",
            "file://notes/home/op%2F.env",
            "file://localhost/home/op%2F.env",
            "file:/home/op%2F.env",
            "FILE:///home/op%2F.env",
            // The traversal the escape otherwise carries past a dot-segment pop.
            "file:///tmp/%2e%2e%2Fetc/passwd",
            "file:///tmp/..%2Fetc/passwd",
            // An escape assembled from a decoded `%2e` pair still ends up as `%2F` and is caught.
            "file:///a%2Fb%2Fc",
        ] {
            let refusal =
                super::canonicalize_resource_uri(uri).expect_err("an encoded slash names no file");
            assert!(refusal.contains("encoded slash"), "{uri}: {refusal}");
        }

        // The `http`/`https` twin keeps the escape, because the origin server receives it and may
        // hold a segment that spells one. Refusing it there would be an over-fold.
        assert_eq!(
            canonicalize_resource_uri("https://notes/home/op%2F.env"),
            "https://notes/home/op%2F.env"
        );
        assert_eq!(
            canonicalize_resource_uri("http://notes/a%2fb"),
            "http://notes/a%2Fb"
        );

        // `%5C` is NOT refused with it: all three resolvers decode it to a literal `\`, which a
        // POSIX name may hold, so it names a file of its own and both ends agree on which.
        assert_eq!(
            canonicalize_resource_uri("file:///home/op%5C.env"),
            "file:///home/op%5C.env"
        );
        // Nor is any other reserved escape that names a legal file-name character.
        assert_eq!(canonicalize_resource_uri("file:///a%3Fb"), "file:///a%3Fb");
        assert_eq!(canonicalize_resource_uri("file:///a%23b"), "file:///a%23b");
        // A literal `%` followed by `2F` text is `%252F`, which holds no encoded slash.
        assert_eq!(
            canonicalize_resource_uri("file:///a%252Fb"),
            "file:///a%252Fb"
        );
        // An escape of an unreserved octet still decodes, so a path with no `%2F` still folds.
        assert_eq!(
            canonicalize_resource_uri("file:///%68ome/op/.env"),
            "file:///home/op/.env"
        );
    }

    /// **An `http`/`https` URI carrying userinfo is refused, and `file:` keeps it.**
    ///
    /// RFC 9110 §4.2.4 asks a recipient of a URI from an untrusted source to treat a userinfo as an
    /// error, because it obscures the authority. The workload is that untrusted source, and the
    /// obscuring was measurable: the canonical form spells the userinfo first, so no rule written
    /// against a host reached a URI carrying one, while all three parsers resolved it to that host.
    /// An empty one also made the two ends read two strings, because a parser drops it.
    #[test]
    fn an_http_uri_carrying_userinfo_is_refused() {
        for uri in [
            "https://@notes/page",
            "https://:@notes/page",
            "https://user@notes/page",
            "https://user:@notes/page",
            "https://:pass@notes/page",
            "https://user:pass@notes/page",
            "https://US%45R@notes/page",
            "https://user@notes:8080/page",
            "http://user@notes/page",
            "HTTP://user@notes/page",
            "https://user@notes",
            "https://user@[::1]/page",
        ] {
            let refusal = super::canonicalize_resource_uri(uri)
                .expect_err("RFC 9110 §4.2.4 asks a recipient to treat userinfo as an error");
            assert!(refusal.contains("carries userinfo"), "{uri}: {refusal}");
        }

        // `file:` is outside RFC 9110, so a userinfo there is kept and stays the documented
        // residual: Node and the Rust `url` crate refuse such a URI, and Python ignores both the
        // userinfo and the host.
        assert_eq!(
            canonicalize_resource_uri("file://user@localhost/home/op/.env"),
            "file://user@localhost/home/op/.env"
        );
        assert_eq!(
            canonicalize_resource_uri("file://@localhost/home/op/.env"),
            "file://@localhost/home/op/.env"
        );

        // An authority with no userinfo is untouched, so the refusal reaches only the `@` form.
        assert_eq!(
            canonicalize_resource_uri("https://notes/page"),
            "https://notes/page"
        );
        assert_eq!(
            canonicalize_resource_uri("https://notes:8080/page"),
            "https://notes:8080/page"
        );
        // A `%40` is not an `@`: it stays encoded in the path and names no userinfo.
        assert_eq!(
            canonicalize_resource_uri("https://notes/a%40b"),
            "https://notes/a%40b"
        );
    }

    /// The check reads the WHOLE string as an authority. A `/`, a `?`, or a `#` ends an authority
    /// early and leaves the tail as a path, and an authority this module splits off holds none of
    /// the three — so this is what the guard is for, and no URI reaches it.
    #[test]
    fn the_grammar_check_reads_the_whole_authority() {
        assert!(is_rfc_3986_authority("notes"));
        for not_an_authority in ["notes/x", "notes?x", "notes#x"] {
            assert!(
                !is_rfc_3986_authority(not_an_authority),
                "{not_an_authority:?}"
            );
        }
    }

    /// The over-rejection control. Every production §3.2 spells still canonicalizes, including the
    /// ones no respelling of a host needs — `reg-name`'s sub-delims, an empty userinfo, an empty
    /// port, an `IPvFuture` literal, and a `reg-name` that only looks like a bad IPv4 address.
    #[test]
    fn every_authority_the_grammar_spells_still_canonicalizes() {
        for uri in [
            "https://notes/page",
            "https://notes.example.com/page",
            "https://no-tes/page",
            "https://no_tes/page",
            "https://no~tes/page",
            // `sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="`
            "https://no!tes/page",
            "https://no$tes/page",
            "https://no&tes/page",
            "https://no'tes/page",
            "https://no(tes/page",
            "https://no)tes/page",
            "https://no*tes/page",
            "https://no+tes/page",
            "https://no,tes/page",
            "https://no;tes/page",
            "https://no=tes/page",
            // `pct-encoded` of an UNRESERVED octet, which decodes here and so still folds. An
            // escape of a reserved or non-ASCII octet conforms to §3.2 and is refused one step
            // later, by `a_host_holding_an_escape_of_a_reserved_or_non_ascii_octet_is_refused`.
            "https://%41b/page",
            "https://%6Eotes/page",
            "https://notes%2Eexample/page",
            // `IPv4address`, and a `reg-name` that is not one — `256.1.1.1` has no `dec-octet`
            // over 255, so the grammar reads it as a name and the box may not refuse it.
            "https://127.0.0.1/page",
            "https://256.1.1.1/page",
            "https://999.999.999.999/page",
            "https://2130706433/page",
            "https://0x7f.0.0.1/page",
            // `IP-literal`, including `IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )`
            "https://[::1]/page",
            "https://[0:0:0:0:0:0:0:1]/page",
            "https://[::ffff:127.0.0.1]/page",
            "https://[v1.x]/page",
            // `userinfo = *( unreserved / pct-encoded / sub-delims / ":" )`, so empty conforms.
            // RFC 9110 §4.2.4 refuses one under `http`/`https`, so `file:` is where the grammar
            // control for it lives — the check under test must accept all five either way.
            "file://@localhost/home/op/.env",
            "file://:@localhost/home/op/.env",
            "file://user@localhost/home/op/.env",
            "file://user:pass@localhost/home/op/.env",
            "file://US%45R@localhost/home/op/.env",
            // `port = *DIGIT`, so empty and a leading zero both conform.
            "https://notes:/page",
            "https://notes:0443/page",
            "https://notes:8080/page",
            "https://notes:443/page",
            // `file:` reaches the same check, and its local fold still runs.
            "file://localhost/home/op/.env",
            "file:///home/op/.env",
            "file://[::1]/home/op/.env",
        ] {
            super::canonicalize_resource_uri(uri)
                .unwrap_or_else(|refusal| panic!("{uri:?} conforms to §3.2: {refusal}"));
        }
    }

    /// Every generated spelling in the authority position, in both directions: the grammar decides,
    /// and nothing else does. A spelling the grammar accepts never meets the authority refusal, and
    /// one it refuses never gets a canonical form. The earlier refusals — a space, a control
    /// character, or a `\` — come first and are the one exception.
    #[test]
    fn the_authority_refusal_follows_the_grammar_in_both_directions() {
        let mut conforming = 0usize;
        let mut refused = 0usize;
        for scheme in ["https", "file"] {
            for spelling in generated_spellings() {
                if spelling.contains(['/', '?', '#'])
                    || spelling.chars().any(|ch| ch <= ' ' || ch == '\\')
                {
                    continue; // not an authority this function splits off, or refused ahead of it
                }
                let uri = format!("{scheme}://{spelling}/x");
                let judged = super::canonicalize_resource_uri(&uri);
                if is_rfc_3986_authority(&spelling) {
                    conforming += 1;
                    if let Err(refusal) = &judged {
                        assert!(
                            !refusal.contains("authority is not RFC 3986"),
                            "{uri:?} conforms to §3.2: {refusal}"
                        );
                    }
                } else {
                    refused += 1;
                    let refusal = judged.expect_err("the grammar refuses this authority");
                    assert!(
                        refusal.contains("authority is not RFC 3986"),
                        "{uri:?}: {refusal}"
                    );
                }
            }
        }
        assert!(conforming > 1_000, "only {conforming} conforming spellings");
        assert!(refused > 1_000, "only {refused} refused spellings");
    }

    /// The authority the box emits conforms too, so the canonical form is its own fixed point on
    /// this axis. Normalization is string surgery, so it could in principle emit a spelling the
    /// same check refuses — which is how judging a raw `.` emitted `https:///x` once before.
    #[test]
    fn the_emitted_authority_is_itself_rfc_3986() {
        let mut judged = 0usize;
        for prefix in ["https://", "file://", "http://"] {
            for spelling in generated_spellings() {
                let Ok(canonical) =
                    super::canonicalize_resource_uri(&format!("{prefix}{spelling}"))
                else {
                    continue;
                };
                let Some(after) = canonical.split_once("://").map(|(_, rest)| rest) else {
                    continue;
                };
                let emitted = after.split_once('/').map_or(after, |(auth, _)| auth);
                assert!(
                    is_rfc_3986_authority(emitted),
                    "{prefix}{spelling:?} emitted {canonical:?}, whose authority {emitted:?} is \
                     outside §3.2"
                );
                judged += 1;
            }
        }
        assert!(judged > 1_000, "only {judged} canonical forms were judged");
    }

    /// The host emits no percent-escape at all, so the hex-case question the path answers with
    /// uppercase (RFC 3986 §6.2.2.1) cannot arise there: an escape of an unreserved octet decodes,
    /// and every other escape is refused. The path still emits uppercase.
    #[test]
    fn the_host_emits_no_percent_escape() {
        let mut judged = 0usize;
        for prefix in ["https://", "file://", "http://"] {
            for spelling in generated_spellings() {
                let Ok(canonical) =
                    super::canonicalize_resource_uri(&format!("{prefix}{spelling}"))
                else {
                    continue;
                };
                let Some((_, rest)) = canonical.split_once("://") else {
                    continue;
                };
                let authority = rest
                    .split_once('/')
                    .map_or(rest, |(authority, _)| authority);
                // The userinfo rides through verbatim, so only the host is judged.
                let host = authority
                    .rsplit_once('@')
                    .map_or(authority, |(_, host)| host);
                assert!(
                    !host.contains('%'),
                    "{prefix}{spelling:?} emitted {canonical:?}, whose host {host:?} holds an escape"
                );
                judged += 1;
            }
        }
        assert!(judged > 1_000, "only {judged} canonical forms were judged");
        // The path keeps its uppercase hex, which is where the question is still live.
        assert_eq!(
            canonicalize_resource_uri("https://notes/a%2fb"),
            "https://notes/a%2Fb"
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
            // One address, four spellings. A URL parser folds each to `[::1]`, so a text
            // comparison left these three naming this machine to a resolver while reaching a rule
            // as a host of their own. An IPv4-mapped loopback literal carries the v4 test with it.
            "file://[::0001]/etc/passwd",
            "file://[0::1]/etc/passwd",
            "file://[0:0:0:0:0:0:0:1]/etc/passwd",
            "file://[::ffff:127.0.0.1]/etc/passwd",
            "file://[::FFFF:127.0.0.1]/etc/passwd",
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
        // A literal that is not loopback, and one that is not an address at all, must not collapse.
        for uri in [
            "file://[::2]/etc/passwd",
            "file://[2001:db8::1]/etc/passwd",
            "file://[::ffff:10.0.0.1]/etc/passwd",
            "file://[v1.x]/etc/passwd",
        ] {
            assert_eq!(canonicalize_resource_uri(uri), uri, "{uri}");
        }
    }
}
