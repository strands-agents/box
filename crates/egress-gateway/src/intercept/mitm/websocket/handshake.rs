//! The RFC 6455 opening handshake, read from the heads that hyper checked, before the hop-by-hop
//! strip removes `Upgrade` and `Connection`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::{HeaderMap, Version};

use super::super::http1::trim_ows;

/// The `Upgrade` token of a WebSocket handshake.
const PROTOCOL: &str = "websocket";

/// What a request asks for in its `Upgrade` field.
#[derive(Debug, PartialEq, Eq)]
pub(in super::super) enum Handshake {
    /// No `websocket` token in `Upgrade`: an ordinary request.
    None,
    /// A valid RFC 6455 handshake, with its `Sec-WebSocket-Key`.
    WebSocket { key: String },
    /// A request that names `websocket` and is not a valid handshake, and why.
    Malformed(&'static str),
}

/// Classify a request head as hyper parsed it, with the length of its whole body.
///
/// Another `Upgrade` token, such as `h2c`, is not a WebSocket: the hop-by-hop strip removes it, as
/// for any request.
pub(in super::super) fn classify(
    method: &str,
    version: Version,
    headers: &HeaderMap,
    body_len: usize,
) -> Handshake {
    if !tokens(headers, "upgrade").any(|token| token.eq_ignore_ascii_case(PROTOCOL)) {
        return Handshake::None;
    }
    let refusal = if method != "GET" {
        "handshake method is not GET"
    } else if version != Version::HTTP_11 {
        "handshake is not HTTP/1.1"
    } else if !tokens(headers, "connection").any(|token| token.eq_ignore_ascii_case("upgrade")) {
        "handshake lacks Connection: upgrade"
    } else if single(headers, "sec-websocket-version") != Some("13") {
        "handshake version is not 13"
    } else if body_len > 0 {
        "handshake carries a body"
    } else {
        match single(headers, "sec-websocket-key").filter(|key| is_valid_key(key)) {
            Some(key) => {
                return Handshake::WebSocket {
                    key: key.to_string(),
                };
            }
            None => "handshake key is not 16 bytes of base64",
        }
    };
    Handshake::Malformed(refusal)
}

/// Whether `key` is the base64 of 16 bytes.
fn is_valid_key(key: &str) -> bool {
    STANDARD.decode(key).is_ok_and(|bytes| bytes.len() == 16)
}

/// The value of each `name` field, without its optional whitespace. A value that is not visible
/// ASCII reads as empty, so it still counts as a field and matches no token.
fn values<'a>(headers: &'a HeaderMap, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    headers
        .get_all(name)
        .iter()
        .map(|value| trim_ows(value.to_str().unwrap_or("")))
}

/// Every comma-separated token of every `name` field.
fn tokens<'a>(headers: &'a HeaderMap, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    values(headers, name)
        .flat_map(|value| value.split(','))
        .map(trim_ows)
        .filter(|token| !token.is_empty())
}

/// The value of the one `name` field, or `None` when it is absent or repeated.
fn single<'a>(headers: &'a HeaderMap, name: &'a str) -> Option<&'a str> {
    let mut found = values(headers, name);
    match (found.next(), found.next()) {
        (Some(value), None) => Some(value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use http::{HeaderName, HeaderValue};

    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    fn handshake(extra: &[(&str, &str)]) -> HeaderMap {
        let mut pairs = vec![
            ("Host", "echo.example"),
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Version", "13"),
            ("Sec-WebSocket-Key", KEY),
        ];
        pairs.extend_from_slice(extra);
        headers(&pairs)
    }

    fn websocket() -> Handshake {
        Handshake::WebSocket {
            key: KEY.to_string(),
        }
    }

    #[test]
    fn a_valid_handshake_is_found_in_any_case() {
        assert_eq!(
            classify("GET", Version::HTTP_11, &handshake(&[]), 0),
            websocket()
        );
        let spelled = headers(&[
            ("upgrade", "h2c, WebSocket"),
            ("connection", "keep-alive, UPGRADE"),
            ("sec-websocket-version", " 13 "),
            ("sec-websocket-key", KEY),
        ]);
        assert_eq!(classify("GET", Version::HTTP_11, &spelled, 0), websocket());
    }

    #[test]
    fn another_upgrade_token_is_not_a_websocket() {
        let h2c = headers(&[
            ("Upgrade", "h2c"),
            ("Connection", "Upgrade, HTTP2-Settings"),
        ]);
        assert_eq!(classify("GET", Version::HTTP_11, &h2c, 0), Handshake::None);
        assert_eq!(
            classify("POST", Version::HTTP_11, &HeaderMap::new(), 1),
            Handshake::None
        );
    }

    #[test]
    fn an_invalid_handshake_names_its_fault() {
        let without = |name: &str| {
            let mut headers = handshake(&[]);
            headers.remove(name);
            headers
        };
        let with = |name: &'static str, value: &'static str| {
            let mut headers = handshake(&[]);
            headers.insert(name, HeaderValue::from_static(value));
            headers
        };
        let http11 = Version::HTTP_11;
        for (method, version, headers, body_len, reason) in [
            (
                "POST",
                http11,
                handshake(&[]),
                0,
                "handshake method is not GET",
            ),
            (
                "get",
                http11,
                handshake(&[]),
                0,
                "handshake method is not GET",
            ),
            (
                "GET",
                Version::HTTP_10,
                handshake(&[]),
                0,
                "handshake is not HTTP/1.1",
            ),
            (
                "GET",
                http11,
                without("connection"),
                0,
                "handshake lacks Connection: upgrade",
            ),
            (
                "GET",
                http11,
                with("connection", "keep-alive"),
                0,
                "handshake lacks Connection: upgrade",
            ),
            (
                "GET",
                http11,
                with("sec-websocket-version", "8"),
                0,
                "handshake version is not 13",
            ),
            (
                "GET",
                http11,
                without("sec-websocket-version"),
                0,
                "handshake version is not 13",
            ),
            ("GET", http11, handshake(&[]), 4, "handshake carries a body"),
            (
                "GET",
                http11,
                without("sec-websocket-key"),
                0,
                "handshake key is not 16 bytes of base64",
            ),
            (
                "GET",
                http11,
                with("sec-websocket-key", "dG9vIHNob3J0"),
                0,
                "handshake key is not 16 bytes of base64",
            ),
            (
                "GET",
                http11,
                with("sec-websocket-key", "not base64!!!!!!!!!!!!=="),
                0,
                "handshake key is not 16 bytes of base64",
            ),
            (
                "GET",
                http11,
                handshake(&[("Sec-WebSocket-Key", KEY)]),
                0,
                "handshake key is not 16 bytes of base64",
            ),
        ] {
            assert_eq!(
                classify(method, version, &headers, body_len),
                Handshake::Malformed(reason),
                "{reason}"
            );
        }
    }
}
