//! The request-leg vocabulary: what the vault is shown, and what it answers with.

use zeroize::Zeroizing;

use crate::{Destination, Secret};

/// An outbound request, as much of it as the vault needs to decide what to attach.
#[derive(Debug, Clone, Copy)]
pub struct Outbound<'a> {
    /// The concrete destination this request is bound for.
    pub destination: Destination<'a>,
    /// The HTTP method, for signing.
    pub method: &'a str,
    /// The absolute request URL, for signing.
    pub url: &'a str,
    /// The raw query string, with no leading `?`.
    pub query: &'a str,
    /// The request headers, in wire order.
    pub headers: &'a [(String, String)],
    /// The request body, for the SigV4 payload hash.
    pub body: &'a [u8],
}

/// An inbound response, as much of it as the vault needs to scan for a leaked secret.
#[derive(Debug, Clone, Copy)]
pub struct Inbound<'a> {
    /// The destination of the *request* this response answers — the same binding graph the request leg
    /// used, so the response is scanned for the secret that was actually attached.
    pub destination: Destination<'a>,
    /// The response headers.
    pub headers: &'a [(String, String)],
    /// The response body.
    pub body: &'a [u8],
}

/// The marker a leaked secret is replaced with. Never the real bytes, and never the phantom either — a
/// redaction is the safest re-substitution.
pub(crate) const REDACTION: &str = "[REDACTED]";

/// The edits an outbound request needs before it goes upstream.
#[derive(Clone, PartialEq, Eq)]
pub struct Attachment {
    strip_headers: Vec<String>,
    set_headers: Vec<(String, Zeroizing<String>)>,
    rewrite_path: Option<Zeroizing<String>>,
    strip_query: Vec<String>,
    set_query: Vec<(String, Zeroizing<String>)>,
    advisory: Option<String>,
}

impl Attachment {
    pub(crate) fn new() -> Self {
        Self {
            strip_headers: Vec::new(),
            set_headers: Vec::new(),
            rewrite_path: None,
            strip_query: Vec::new(),
            set_query: Vec::new(),
            advisory: None,
        }
    }

    pub(crate) fn strip_header(&mut self, name: impl Into<String>) {
        let name = name.into();
        // The attach half of a strip-then-set pair already clears the header, so a duplicate strip for
        // the same name is dropped: the caller applies these verbatim, and two strips of one header is
        // a redundant edit rather than a coordinated one.
        if !self
            .strip_headers
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&name))
        {
            self.strip_headers.push(name);
        }
    }

    pub(crate) fn set_header(&mut self, name: impl Into<String>, value: Zeroizing<String>) {
        self.set_headers.push((name.into(), value));
    }

    pub(crate) fn rewrite_path(&mut self, path: Zeroizing<String>) {
        self.rewrite_path = Some(path);
    }

    pub(crate) fn strip_query_param(&mut self, name: impl Into<String>) {
        let name = name.into();
        if !self.strip_query.contains(&name) {
            self.strip_query.push(name);
        }
    }

    pub(crate) fn set_query_param(&mut self, name: impl Into<String>, value: Zeroizing<String>) {
        self.set_query.push((name.into(), value));
    }

    /// Whether this attachment already rewrites the request path.
    pub(crate) fn rewrites_path(&self) -> bool {
        self.rewrite_path.is_some()
    }

    /// Header names to remove, before the sets are applied.
    pub fn strip_headers(&self) -> impl Iterator<Item = &str> {
        self.strip_headers.iter().map(String::as_str)
    }

    /// Headers to set, as `(name, value)`. The value carries the real credential.
    pub fn set_headers(&self) -> impl Iterator<Item = (&str, &Zeroizing<String>)> {
        self.set_headers
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }

    /// The path to rewrite the request to, when the credential attaches into the URL path.
    pub fn rewrite_path_to(&self) -> Option<&Zeroizing<String>> {
        self.rewrite_path.as_ref()
    }

    /// Query parameter names to remove, before the sets are applied.
    pub fn strip_query(&self) -> impl Iterator<Item = &str> {
        self.strip_query.iter().map(String::as_str)
    }

    /// Query parameters to set, as `(name, value)`. The value carries the real credential.
    pub fn set_query(&self) -> impl Iterator<Item = (&str, &Zeroizing<String>)> {
        self.set_query
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }

    /// Record that this attachment was made in advisory mode, against an absent or unrecognised
    /// placeholder. The `reason` is non-secret and names no placeholder value.
    pub(crate) fn note_advisory(&mut self, reason: impl Into<String>) {
        self.advisory = Some(reason.into());
    }

    /// The non-secret reason this was an advisory override, or `None` for a normal swap.
    pub fn advisory_reason(&self) -> Option<&str> {
        self.advisory.as_deref()
    }

    /// Whether this attachment asks for no edits at all.
    pub fn is_empty(&self) -> bool {
        self.strip_headers.is_empty()
            && self.set_headers.is_empty()
            && self.rewrite_path.is_none()
            && self.strip_query.is_empty()
            && self.set_query.is_empty()
    }
}

impl std::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The names are non-secret routing information and print in the clear; every *value* carries
        // the credential and renders `[REDACTED]`.
        f.debug_struct("Attachment")
            .field("strip_headers", &self.strip_headers)
            .field(
                "set_headers",
                &self
                    .set_headers
                    .iter()
                    .map(|(name, _)| (name.as_str(), REDACTION))
                    .collect::<Vec<_>>(),
            )
            .field(
                "rewrite_path",
                &self.rewrite_path.as_ref().map(|_| REDACTION),
            )
            .field("strip_query", &self.strip_query)
            .field(
                "set_query",
                &self
                    .set_query
                    .iter()
                    .map(|(name, _)| (name.as_str(), REDACTION))
                    .collect::<Vec<_>>(),
            )
            .field("advisory", &self.advisory)
            .finish()
    }
}

/// The redactions a response needs because it echoed the injected secret back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redactions {
    /// The scrubbed body, when the secret appeared in it.
    body: Option<Vec<u8>>,
    /// Header values with the secret replaced, as `(name, redacted_value)`. Non-secret by
    /// construction — the secret is what was removed.
    set_headers: Vec<(String, String)>,
}

impl Redactions {
    /// Scan `res` for `secret` and return the redactions needed, or `None` if it did not leak.
    pub(crate) fn scan(res: &Inbound<'_>, secret: &Secret) -> Option<Self> {
        let secret = secret.as_str();
        let body = redact_in_bytes(res.body, secret.as_bytes());
        let set_headers: Vec<(String, String)> = res
            .headers
            .iter()
            .filter(|(_, value)| value.contains(secret))
            .map(|(name, value)| (name.clone(), value.replace(secret, REDACTION)))
            .collect();

        (body.is_some() || !set_headers.is_empty()).then_some(Self { body, set_headers })
    }

    /// The scrubbed response body, when the secret appeared in it.
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }

    /// Header values to replace, as `(name, redacted_value)`.
    pub fn set_headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.set_headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }
}

/// Replace every occurrence of `needle` in `haystack` with the redaction marker, returning
/// `Some(new_bytes)` when any was found.
fn redact_in_bytes(haystack: &[u8], needle: &[u8]) -> Option<Vec<u8>> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    let mut found = false;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(REDACTION.as_bytes());
            i += needle.len();
            found = true;
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    found.then_some(out)
}

/// Extract the `{}` slot of a `template` from a concrete `value`: match the fixed prefix and suffix
/// around the single `{}` marker and return the middle. `None` when the value does not fit.
pub(crate) fn extract_slot<'a>(template: &str, value: &'a str) -> Option<&'a str> {
    let (prefix, suffix) = template.split_once("{}")?;
    let rest = value.strip_prefix(prefix)?;
    rest.strip_suffix(suffix)
}

/// The value of query parameter `name` in `query` (`a=1&b=2` form), if present.
pub(crate) fn query_value<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == name).then_some(v)
    })
}

/// Look up a header value case-insensitively, matching HTTP semantics.
pub(crate) fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inbound<'a>(headers: &'a [(String, String)], body: &'a [u8]) -> Inbound<'a> {
        Inbound {
            destination: Destination {
                host: "api.stripe.com",
                port: 443,
                path: "/v1/charges",
            },
            headers,
            body,
        }
    }

    /// A usable secret for the scan tests. `Secret::new` cannot fail on these values, and a panic
    /// here would mean the content rule rejected something it should accept.
    fn secret(raw: &str) -> Secret {
        Secret::new(zeroize::Zeroizing::new(raw.to_string()), "test://stub")
            .expect("the scan fixtures are usable values")
    }

    /// The secret-bearing accessors vend the wiped wrapper, so the default copy carries the wipe.
    #[test]
    fn the_secret_bearing_accessors_vend_the_wrapper_not_a_bare_str() {
        let mut attachment = Attachment::new();
        attachment.set_header("Authorization", Zeroizing::new("Bearer real".to_string()));
        attachment.rewrite_path(Zeroizing::new("/v1/real-secret-in-path".to_string()));
        attachment.set_query_param("api_key", Zeroizing::new("real-key".to_string()));

        // Each binding compiles only because the accessor yields the wrapper, not `&str`.
        let (name, value): (&str, &Zeroizing<String>) =
            attachment.set_headers().next().expect("one header");
        assert_eq!(name, "Authorization");
        assert_eq!(value.as_str(), "Bearer real");

        let path: &Zeroizing<String> = attachment.rewrite_path_to().expect("a path rewrite");
        assert_eq!(path.as_str(), "/v1/real-secret-in-path");

        let (name, value): (&str, &Zeroizing<String>) =
            attachment.set_query().next().expect("one query param");
        assert_eq!(name, "api_key");
        assert_eq!(value.as_str(), "real-key");
    }

    #[test]
    fn scan_finds_the_secret_in_the_body() {
        let redactions =
            Redactions::scan(&inbound(&[], b"{\"echo\":\"sk_live\"}"), &secret("sk_live"))
                .expect("the secret leaked");
        let body = String::from_utf8(redactions.body().unwrap().to_vec()).unwrap();
        assert!(!body.contains("sk_live"));
        assert!(body.contains("[REDACTED]"));
    }

    #[test]
    fn scan_finds_the_secret_in_a_header() {
        let headers = vec![("X-Echo".to_string(), "sk_live".to_string())];
        let redactions = Redactions::scan(&inbound(&headers, b""), &secret("sk_live"))
            .expect("the secret leaked");
        assert!(redactions.body().is_none());
        let set: Vec<(&str, &str)> = redactions.set_headers().collect();
        assert_eq!(set, [("X-Echo", "[REDACTED]")]);
    }

    #[test]
    fn scan_returns_none_when_nothing_leaked() {
        assert!(Redactions::scan(&inbound(&[], b"{\"ok\":true}"), &secret("sk_live")).is_none());
    }

    // `scan_refuses_an_empty_secret` was deleted with the guard it pinned. It asserted that an
    // empty secret disables a route's leak-back scan — locally correct, but it made C1's compounding
    // half a *tested guarantee* rather than a signal that an empty secret should never have reached a
    // binding. `scan` now takes a `Secret`, so the case it covered cannot be constructed
    // (docs/design/decisions.md#an-unusable-secret-value-is-unrepresentable).

    /// Every occurrence is redacted, not only the first.
    #[test]
    fn scan_redacts_every_occurrence() {
        let redactions =
            Redactions::scan(&inbound(&[], b"a sk_live b sk_live c"), &secret("sk_live"))
                .expect("the secret leaked twice");
        let body = String::from_utf8(redactions.body().unwrap().to_vec()).unwrap();
        assert_eq!(body, "a [REDACTED] b [REDACTED] c");
    }

    /// An `Attachment`'s `Debug` prints the routing names but never a value.
    #[test]
    fn attachment_debug_redacts_every_value() {
        let mut attachment = Attachment::new();
        attachment.strip_header("Authorization");
        attachment.set_header(
            "Authorization",
            Zeroizing::new("Bearer super-secret".to_string()),
        );
        attachment.rewrite_path(Zeroizing::new("/v1/super-secret/models".to_string()));
        attachment.set_query_param("api_key", Zeroizing::new("super-secret".to_string()));

        let rendered = format!("{attachment:?}");
        assert!(
            !rendered.contains("super-secret"),
            "secret leaked through Debug: {rendered}"
        );
        assert!(rendered.contains("Authorization"), "got {rendered}");
        assert!(rendered.contains("[REDACTED]"), "got {rendered}");
    }

    /// A duplicate strip of the same header is dropped — the caller applies these verbatim.
    /// The advisory note defaults absent and round-trips a non-secret reason.
    #[test]
    fn advisory_reason_defaults_none_and_round_trips() {
        let mut attachment = Attachment::new();
        assert_eq!(attachment.advisory_reason(), None);
        attachment.note_advisory("inject = always, against no placeholder token");
        assert_eq!(
            attachment.advisory_reason(),
            Some("inject = always, against no placeholder token")
        );
    }

    #[test]
    fn duplicate_header_strips_collapse() {
        let mut attachment = Attachment::new();
        attachment.strip_header("Authorization");
        attachment.strip_header("authorization");
        assert_eq!(attachment.strip_headers().count(), 1);
    }

    #[test]
    fn extract_slot_matches_prefix_and_suffix() {
        assert_eq!(extract_slot("Bearer {}", "Bearer abc"), Some("abc"));
        assert_eq!(extract_slot("/v1/{}/models", "/v1/abc/models"), Some("abc"));
        // A value that does not fit the template yields nothing.
        assert_eq!(extract_slot("Bearer {}", "Basic abc"), None);
        assert_eq!(extract_slot("no-slot", "anything"), None);
    }

    #[test]
    fn query_value_reads_the_named_parameter() {
        assert_eq!(query_value("a=1&api_key=k&b=2", "api_key"), Some("k"));
        assert_eq!(query_value("a=1", "missing"), None);
    }

    #[test]
    fn header_value_is_case_insensitive() {
        let headers = vec![("Authorization".to_string(), "Bearer x".to_string())];
        assert_eq!(header_value(&headers, "authorization"), Some("Bearer x"));
        assert_eq!(header_value(&headers, "AUTHORIZATION"), Some("Bearer x"));
        assert_eq!(header_value(&headers, "x-api-key"), None);
    }
}
