//! The RFC 6455 opening handshake, read from the heads that hyper checked, before the hop-by-hop
//! strip removes `Upgrade` and `Connection`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::{HeaderMap, Version};
use zeroize::Zeroizing;

use super::super::http1::trim_ows;

/// The `Upgrade` token of a WebSocket handshake.
const PROTOCOL: &str = "websocket";

/// The GUID that RFC 6455 appends to the handshake key to derive `Sec-WebSocket-Accept`.
const ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

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

/// How many `name` fields a head carries.
enum Field<'a> {
    Absent,
    One(&'a str),
    Repeated,
}

impl<'a> Field<'a> {
    fn of(headers: &'a HeaderMap, name: &'a str) -> Self {
        let mut found = values(headers, name);
        match (found.next(), found.next()) {
            (None, _) => Self::Absent,
            (Some(value), None) => Self::One(value),
            (Some(_), Some(_)) => Self::Repeated,
        }
    }
}

/// The value of the one `name` field, or `None` when it is absent or repeated.
fn single<'a>(headers: &'a HeaderMap, name: &'a str) -> Option<&'a str> {
    match Field::of(headers, name) {
        Field::One(value) => Some(value),
        Field::Absent | Field::Repeated => None,
    }
}

/// What a `101` must carry to answer one forwarded handshake.
pub(in super::super) struct Expected {
    accept: String,
    /// The offered subprotocols, in wiped owners: a credential route may inject its secret into
    /// `Sec-WebSocket-Protocol`.
    protocols: Vec<Zeroizing<String>>,
}

impl Expected {
    /// The answer to the handshake with `key`, whose head as forwarded is `headers`: after the
    /// credential fold, so a subprotocol is one that the upstream was offered.
    pub(in super::super) fn new(key: &str, headers: &HeaderMap) -> Self {
        Self {
            accept: accept_value(key),
            protocols: tokens(headers, "sec-websocket-protocol")
                .map(|token| Zeroizing::new(token.to_string()))
                .collect(),
        }
    }
}

/// The `Sec-WebSocket-Accept` value for `key`.
fn accept_value(key: &str) -> String {
    let mut digest = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    digest.update(key.as_bytes());
    digest.update(ACCEPT_GUID.as_bytes());
    STANDARD.encode(digest.finish())
}

/// Check a `101` head against the handshake that it answers, before its hop-by-hop fields are
/// removed. hyper's client takes every `101` as an upgrade, so the gateway checks it.
pub(in super::super) fn check_switching_protocols(
    headers: &HeaderMap,
    expected: &Expected,
) -> std::result::Result<(), &'static str> {
    if !single(headers, "upgrade").is_some_and(|value| value.eq_ignore_ascii_case(PROTOCOL)) {
        return Err("101 does not name Upgrade: websocket");
    }
    if !tokens(headers, "connection").any(|token| token.eq_ignore_ascii_case("upgrade")) {
        return Err("101 lacks Connection: upgrade");
    }
    if single(headers, "sec-websocket-accept") != Some(expected.accept.as_str()) {
        return Err("101 carries a wrong Sec-WebSocket-Accept");
    }
    if headers.contains_key("sec-websocket-extensions") {
        return Err("101 negotiates an extension");
    }
    match Field::of(headers, "sec-websocket-protocol") {
        Field::Absent => Ok(()),
        Field::One(protocol)
            if expected
                .protocols
                .iter()
                .any(|offered| offered.as_str() == protocol) =>
        {
            Ok(())
        }
        Field::One(_) | Field::Repeated => {
            Err("101 selects a subprotocol the request did not offer")
        }
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
    fn the_accept_value_matches_the_rfc_6455_example() {
        assert_eq!(accept_value(KEY), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
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

    fn switching(extra: &[(&str, &str)]) -> HeaderMap {
        let mut pairs = vec![
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        ];
        pairs.extend_from_slice(extra);
        headers(&pairs)
    }

    #[test]
    fn a_101_that_answers_the_handshake_is_accepted() {
        let expected = Expected::new(KEY, &handshake(&[]));
        assert_eq!(
            check_switching_protocols(&switching(&[]), &expected),
            Ok(())
        );

        let offered = Expected::new(KEY, &handshake(&[("Sec-WebSocket-Protocol", "chat, v2")]));
        assert_eq!(
            check_switching_protocols(&switching(&[("Sec-WebSocket-Protocol", "v2")]), &offered),
            Ok(())
        );
    }

    #[test]
    fn a_101_that_does_not_answer_the_handshake_is_refused() {
        let expected = Expected::new(KEY, &handshake(&[("Sec-WebSocket-Protocol", "chat")]));
        let mut wrong_upgrade = switching(&[]);
        wrong_upgrade.insert("upgrade", HeaderValue::from_static("h2c"));
        let mut no_connection = switching(&[]);
        no_connection.remove("connection");
        let mut wrong_accept = switching(&[]);
        wrong_accept.insert(
            "sec-websocket-accept",
            HeaderValue::from_str(&accept_value("AAAAAAAAAAAAAAAAAAAAAA==")).unwrap(),
        );
        for (headers, reason) in [
            (wrong_upgrade, "101 does not name Upgrade: websocket"),
            (no_connection, "101 lacks Connection: upgrade"),
            (wrong_accept, "101 carries a wrong Sec-WebSocket-Accept"),
            (
                switching(&[("Sec-WebSocket-Extensions", "permessage-deflate")]),
                "101 negotiates an extension",
            ),
            (
                switching(&[("Sec-WebSocket-Protocol", "superchat")]),
                "101 selects a subprotocol the request did not offer",
            ),
            (
                switching(&[("Sec-WebSocket-Protocol", "chat, chat")]),
                "101 selects a subprotocol the request did not offer",
            ),
        ] {
            assert_eq!(
                check_switching_protocols(&headers, &expected),
                Err(reason),
                "{reason}"
            );
        }
        let none_offered = Expected::new(KEY, &handshake(&[]));
        assert!(
            check_switching_protocols(
                &switching(&[("Sec-WebSocket-Protocol", "chat")]),
                &none_offered
            )
            .is_err()
        );
    }
}
