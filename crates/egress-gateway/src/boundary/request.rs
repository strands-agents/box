//! The request-leg boundary types: [`InterceptedRequest`], [`Target`], [`HeaderMap`], [`BodyRef`].

use zeroize::Zeroizing;

/// A case-insensitive, order-preserving multimap of HTTP headers.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct HeaderMap {
    /// `(original-name, value)` pairs in insertion order. The value is wiped on drop.
    entries: Vec<(String, Zeroizing<String>)>,
}

impl std::fmt::Debug for HeaderMap {
    /// Names in the clear, **every value redacted**.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.entries.iter().map(|(name, _)| (name, &"[REDACTED]")))
            .finish()
    }
}

impl HeaderMap {
    /// An empty header map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from `(name, value)` pairs, preserving order and original casing.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            entries: pairs
                .into_iter()
                .map(|(name, value)| (name, Zeroizing::new(value)))
                .collect(),
        }
    }

    /// The first value for `name` (case-insensitive), if any.
    pub fn get(&self, name: &str) -> Option<&str> {
        // `eq_ignore_ascii_case` compares case-insensitively without allocating, so there is no need
        // to pre-lowercase `name` — this is a hot path (looked up per request across controls).
        self.entries
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether a header named `name` is present (case-insensitive).
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Append a header, preserving `name`'s casing (does not replace an existing same-named header).
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.entries
            .push((name.into(), Zeroizing::new(value.into())));
    }

    /// Set a header: remove every existing entry whose name matches (case-insensitive), then append
    /// `name: value`. This is how a [`SetHeader`](crate::boundary::Mutation::SetHeader) mutation is
    /// applied — the new value wins with no duplicate left behind.
    pub fn set(&mut self, name: impl AsRef<str>, value: impl Into<String>) {
        self.remove(name.as_ref());
        self.entries
            .push((name.as_ref().to_string(), Zeroizing::new(value.into())));
    }

    /// Remove every header whose name matches `name` (case-insensitive). Returns whether any were
    /// removed. This is how a [`StripHeader`](crate::boundary::Mutation::StripHeader) mutation is
    /// applied.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self.entries.len() != before
    }

    /// Iterate the `(name, value)` pairs in insertion order (original casing preserved).
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }

    /// The number of header entries (counting repeats).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no headers.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The request body, borrowed or owned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum BodyRef {
    /// No body (or a body not yet read).
    #[default]
    Empty,
    /// A fully-materialized body.
    Bytes(Vec<u8>),
}

impl BodyRef {
    /// The body bytes, or an empty slice when [`Empty`](Self::Empty).
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            BodyRef::Empty => &[],
            BodyRef::Bytes(b) => b,
        }
    }

    /// Whether the body is empty.
    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }
}

/// The outbound destination the request targets — built by the adapter from the connection + request
/// line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The destination host (no port).
    pub host: String,
    /// The destination port.
    pub port: u16,
    /// The request path (e.g. `/v1/chat`), or `/` when not known (Connection-only visibility).
    pub path: String,
    /// The query string without the leading `?`, or empty when absent.
    pub query: String,
}

impl Target {
    /// Build a target for `host:port` with an all-paths default (`/`, no query) — the Connection-leg
    /// form before any request line is parsed.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            path: "/".to_string(),
            query: String::new(),
        }
    }

    /// Borrow this target as a [`credentials::Destination`] for matching against a
    /// [`credentials::DestinationPattern`] — the single-sourced matcher.
    pub fn as_destination(&self) -> credentials::Destination<'_> {
        credentials::Destination {
            host: &self.host,
            port: self.port,
            path: &self.path,
        }
    }

    /// Reconstruct the request URL (`https://host[:port]/path[?query]`) for signing / forwarding.
    pub fn url(&self) -> String {
        let (scheme, show_port) = match self.port {
            443 => ("https", false),
            80 => ("http", false),
            _ => ("https", true),
        };
        // Bracket an IPv6 literal (any host containing ':' is a v6 literal — a DNS name never does).
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let mut url = format!("{scheme}://{host}");
        if show_port {
            url.push_str(&format!(":{}", self.port));
        }
        url.push_str(&self.path);
        if !self.query.is_empty() {
            url.push('?');
            url.push_str(&self.query);
        }
        url
    }
}

/// What an interceptor captured for the outbound (request) leg — normalized and
/// interception-agnostic.
#[derive(Clone)]
pub struct InterceptedRequest {
    /// The destination (host, port, path, query) built by the adapter.
    pub target: Target,
    /// The HTTP method.
    pub method: Option<String>,
    /// The request headers.
    pub headers: HeaderMap,
    /// The request body (borrowed/streamed).
    pub body: BodyRef,
    /// A non-secret note a capability attaches for the driver to journal on the allow decision, never
    /// applied to the wire.
    pub advisory_note: Option<String>,
}

impl std::fmt::Debug for InterceptedRequest {
    /// The shape, never the payload: headers redact per-value and the body prints as its length.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterceptedRequest")
            .field("target", &self.target)
            .field("method", &self.method)
            .field("headers", &self.headers)
            .field("body_bytes", &self.body.as_bytes().len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every header value is stored wiped-on-drop, not merely redacted in `Debug`.
    #[test]
    fn every_header_value_is_wiped_on_drop() {
        let mut headers = HeaderMap::new();
        headers.append("Authorization", "Bearer sk-live-REALSECRET");

        // The compile-time half: this only type-checks because the value is `Zeroizing<String>`.
        let stored: &Zeroizing<String> = &headers.entries[0].1;
        assert_eq!(stored.as_str(), "Bearer sk-live-REALSECRET");

        // And the reader-facing accessor still yields a plain `&str`, so no call site changed.
        assert_eq!(
            headers.get("authorization"),
            Some("Bearer sk-live-REALSECRET"),
            "wiping storage must not change what a reader sees"
        );
    }

    /// A `{:?}` of a credential-bearing request never prints the credential.
    #[test]
    fn debug_redacts_every_header_value_and_the_body() {
        let mut headers = HeaderMap::new();
        headers.append("Authorization", "Bearer sk-live-REALSECRET");
        headers.append("Content-Type", "application/json");

        let rendered = format!("{headers:?}");
        assert!(
            !rendered.contains("REALSECRET"),
            "a header value must not print: {rendered}"
        );
        assert!(
            rendered.contains("Authorization") && rendered.contains("[REDACTED]"),
            "names stay in the clear so the output is still useful: {rendered}"
        );

        let req = InterceptedRequest {
            target: Target::new("api.example.test", 443),
            method: Some("POST".to_string()),
            headers,
            body: BodyRef::Bytes(b"{\"prompt\":\"secret user content\"}".to_vec()),
            advisory_note: None,
        };
        let rendered = format!("{req:?}");
        assert!(
            !rendered.contains("REALSECRET"),
            "an enclosing Debug must not leak a header value: {rendered}"
        );
        assert!(
            !rendered.contains("secret user content"),
            "the body prints as a length, not content: {rendered}"
        );
        assert!(rendered.contains("body_bytes"), "got {rendered}");
    }

    #[test]
    fn header_map_is_case_insensitive_and_order_preserving() {
        let mut h = HeaderMap::new();
        h.append("Content-Type", "application/json");
        h.append("X-Custom", "1");
        assert_eq!(h.get("content-type"), Some("application/json"));
        assert_eq!(h.get("CONTENT-TYPE"), Some("application/json"));
        assert!(h.contains("x-custom"));
        // Order + casing preserved.
        let names: Vec<&str> = h.iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["Content-Type", "X-Custom"]);
    }

    #[test]
    fn header_set_replaces_all_same_named() {
        let mut h = HeaderMap::from_pairs([
            ("Authorization".to_string(), "old-1".to_string()),
            ("authorization".to_string(), "old-2".to_string()),
        ]);
        h.set("Authorization", "new");
        // Only the new value remains (both prior entries removed).
        assert_eq!(h.get("authorization"), Some("new"));
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn header_remove_reports_and_clears() {
        let mut h = HeaderMap::new();
        h.append("X-Amz-Date", "20150830T123600Z");
        assert!(h.remove("x-amz-date"));
        assert!(!h.remove("x-amz-date")); // already gone
        assert!(!h.contains("x-amz-date"));
    }

    #[test]
    fn target_url_uses_scheme_by_port() {
        let mut t = Target::new("api.example.com", 443);
        t.path = "/v1/x".to_string();
        t.query = "a=1".to_string();
        assert_eq!(t.url(), "https://api.example.com/v1/x?a=1");

        let mut t80 = Target::new("api.example.com", 80);
        t80.path = "/".to_string();
        assert_eq!(t80.url(), "http://api.example.com/");

        let mut t8443 = Target::new("api.example.com", 8443);
        t8443.path = "/p".to_string();
        assert_eq!(t8443.url(), "https://api.example.com:8443/p");
    }

    #[test]
    fn target_url_brackets_ipv6_literal() {
        // An IPv6 literal host must be bracketed per RFC 3986, or SigV4 URL parsing breaks.
        let mut t = Target::new("::1", 8443);
        t.path = "/path".to_string();
        assert_eq!(t.url(), "https://[::1]:8443/path");

        // On the default port the brackets still apply (no explicit :port).
        let mut t443 = Target::new("2606:2800:220:1:248:1893:25c8:1946", 443);
        t443.path = "/".to_string();
        assert_eq!(t443.url(), "https://[2606:2800:220:1:248:1893:25c8:1946]/");
    }
}
