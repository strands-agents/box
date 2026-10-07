//! The canonical `DestinationPattern` hybrid matcher.

use crate::CredentialError;

/// How a [`DestinationPattern`] matches the host component.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HostPattern {
    /// Matches **every** host — the explicit `*` allow-all form. Used by a Connection-scope
    /// Decision Control (DNS/IP) to deliberately authorize an entire scope. Distinct from `Suffix`,
    /// which requires a `*.` prefix and excludes the apex.
    Any,
    /// Matches exactly one host (the parsed, lowercased name). A bare-host config lands here.
    Exact(String),
    /// Matches any strict sub-domain, stored with its leading dot (`.github.com`). The apex is
    /// excluded because a real host is always strictly longer than the stored suffix.
    Suffix(String),
}

/// How a [`DestinationPattern`] matches the path component.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PathPattern {
    /// Match by required path prefix; empty = all paths. A non-`/`-terminated prefix additionally
    /// requires a segment boundary after it (see [`DestinationPattern::path_matches`]).
    Prefix(String),
    /// Match by required path suffix (the `/*<suffix>` form). The stored value is the text after the
    /// leading `*` (e.g. pattern `/*/callback` stores `/callback`, `/*.json` stores `.json`): a plain
    /// `ends_with` check with no boundary constraint, so `/*.json` matches any path ending `.json`.
    Suffix(String),
}

/// A parsed binding pattern: `host` (exact or suffix) + optional exact `port` + `path` prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationPattern {
    host: HostPattern,
    /// `None` infers the standard web ports (443 for HTTPS, 80 for HTTP); `Some(p)` is exact.
    port: Option<u16>,
    path: PathPattern,
}

/// A concrete outbound destination to test against a [`DestinationPattern`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Destination<'a> {
    /// The request host (case-insensitive; the matcher lowercases it).
    pub host: &'a str,
    /// The resolved connection port.
    pub port: u16,
    /// The request path, e.g. `/v1/chat/completions` (case-sensitive).
    pub path: &'a str,
}

impl DestinationPattern {
    /// Parse a pattern string such as `api.github.com`, `api.github.com:8443/v1/`,
    /// `*.openai.com/v1/`, or `*.amazonaws.com`.
    pub fn parse(s: &str) -> Result<Self, CredentialError> {
        let (host_port, path) = match s.split_once('/') {
            // Re-attach the leading `/` the split consumed so the stored prefix is a real path.
            Some((hp, rest)) => (hp, format!("/{rest}")),
            None => (s, String::new()),
        };

        let (host_raw, port) = match host_port.split_once(':') {
            Some((h, p)) => {
                let port: u16 = p.parse().map_err(|_| {
                    CredentialError::Credential(format!(
                        "invalid port in destination pattern: {s:?}"
                    ))
                })?;
                (h, Some(port))
            }
            None => (host_port, None),
        };

        let host_lc = host_raw.to_ascii_lowercase();
        let host = Self::parse_host(&host_lc, s)?;

        Ok(Self {
            host,
            port,
            path: Self::parse_path(path),
        })
    }

    /// Classify the path component: a leading `/*` selects the suffix form (storing the text after
    /// the `*`), anything else is a prefix. Case-sensitive; the raw path is kept verbatim.
    fn parse_path(path: String) -> PathPattern {
        match path.strip_prefix("/*") {
            Some(suffix) => PathPattern::Suffix(suffix.to_string()),
            None => PathPattern::Prefix(path),
        }
    }

    /// Classify the (already-lowercased) host component, rejecting misplaced wildcards.
    fn parse_host(host: &str, original: &str) -> Result<HostPattern, CredentialError> {
        // The explicit `*` allow-all host form: a bare `*` matches every host. Deliberate and
        // auditable.
        if host == "*" {
            return Ok(HostPattern::Any);
        }
        if let Some(suffix) = host.strip_prefix("*.") {
            // `*.` is only meaningful as a whole-leading-label wildcard with a real domain behind
            // it — `*.`, `*.*`, or a second `*` are all bad patterns.
            if suffix.is_empty() || suffix.contains('*') {
                return Err(CredentialError::Credential(format!(
                    "invalid wildcard in destination pattern: {original:?}"
                )));
            }
            // Store with the leading dot so the label-boundary check is a plain `ends_with`.
            return Ok(HostPattern::Suffix(format!(".{suffix}")));
        }

        if host.is_empty() {
            return Err(CredentialError::Credential(format!(
                "empty host in destination pattern: {original:?}"
            )));
        }
        // A `*` anywhere other than the leading `*.` form is not a valid host.
        if host.contains('*') {
            return Err(CredentialError::Credential(format!(
                "misplaced wildcard in destination pattern: {original:?}"
            )));
        }

        Ok(HostPattern::Exact(host.to_string()))
    }

    /// A destination matches iff **both** its host+port and its path match. The AND only narrows.
    pub fn matches(&self, dest: &Destination) -> bool {
        self.host_matches(dest.host, dest.port) && self.path_matches(dest.path)
    }

    /// Whether this pattern's host half matches **every** host (the explicit `*` form).
    pub fn matches_every_host(&self) -> bool {
        matches!(self.host, HostPattern::Any)
    }

    /// The pattern as the operator wrote it — the round-trip of [`parse`](Self::parse).
    pub fn as_written(&self) -> String {
        let mut out = match &self.host {
            HostPattern::Any => "*".to_string(),
            HostPattern::Exact(host) => host.clone(),
            // A suffix stores its leading dot (`.github.com`), which is written `*.github.com`.
            HostPattern::Suffix(suffix) => format!("*{suffix}"),
        };
        if let Some(port) = self.port {
            out.push(':');
            out.push_str(&port.to_string());
        }
        match &self.path {
            // An empty prefix matches every path and is written by omitting the path entirely.
            PathPattern::Prefix(prefix) if prefix.is_empty() => {}
            PathPattern::Prefix(prefix) => out.push_str(prefix),
            // A suffix pattern stores the text after the leading `*` of its `/*<suffix>` form.
            PathPattern::Suffix(suffix) => {
                out.push_str("/*");
                out.push_str(suffix);
            }
        }
        out
    }

    /// Whether two patterns can be satisfied by the **same** concrete destination — i.e. there
    /// exists a host+port+path that [`matches`](Self::matches) both. Because `matches` ANDs the three
    /// components, two patterns overlap iff their host-sets, port-sets, and path-sets each intersect.
    pub fn overlaps(&self, other: &Self) -> bool {
        self.hosts_overlap(other) && self.ports_overlap(other) && self.paths_overlap(other)
    }

    /// Host-set intersection. `Any` (wildcard-all) intersects every host; Exact/Exact iff equal;
    /// Exact/Suffix iff the exact host is a strict sub-domain of the suffix; Suffix/Suffix iff one
    /// suffix contains the other (any host under the more specific one is also under the less
    /// specific).
    fn hosts_overlap(&self, other: &Self) -> bool {
        match (&self.host, &other.host) {
            // A wildcard-all host matches everything, so it overlaps any other host pattern.
            (HostPattern::Any, _) | (_, HostPattern::Any) => true,
            (HostPattern::Exact(a), HostPattern::Exact(b)) => a == b,
            (HostPattern::Exact(h), HostPattern::Suffix(s))
            | (HostPattern::Suffix(s), HostPattern::Exact(h)) => {
                h.len() > s.len() && h.ends_with(s.as_str())
            }
            (HostPattern::Suffix(a), HostPattern::Suffix(b)) => {
                a.ends_with(b.as_str()) || b.ends_with(a.as_str())
            }
        }
    }

    /// Port-set intersection, where an unset port is the standard-web set {443, 80}.
    fn ports_overlap(&self, other: &Self) -> bool {
        match (self.port, other.port) {
            (Some(a), Some(b)) => a == b,
            (Some(p), None) | (None, Some(p)) => p == 443 || p == 80,
            (None, None) => true,
        }
    }

    /// Path-set intersection. Two prefixes intersect iff one is a segment-boundary prefix of the
    /// other; a prefix and a suffix can always be bridged by a witness path; two suffixes intersect
    /// iff one ends with the other.
    fn paths_overlap(&self, other: &Self) -> bool {
        match (&self.path, &other.path) {
            (PathPattern::Prefix(a), PathPattern::Prefix(b)) => {
                Self::prefix_boundary_contains(a, b) || Self::prefix_boundary_contains(b, a)
            }
            (PathPattern::Prefix(_), PathPattern::Suffix(_))
            | (PathPattern::Suffix(_), PathPattern::Prefix(_)) => true,
            (PathPattern::Suffix(a), PathPattern::Suffix(b)) => {
                a.ends_with(b.as_str()) || b.ends_with(a.as_str())
            }
        }
    }

    /// Whether `prefix` boundary-matches `candidate` (a longer prefix) as `path_matches` would a
    /// request path: an empty prefix contains all; otherwise `candidate` must start with `prefix` and
    /// sit on a segment boundary there.
    fn prefix_boundary_contains(prefix: &str, candidate: &str) -> bool {
        if prefix.is_empty() {
            return true;
        }
        if !candidate.starts_with(prefix) {
            return false;
        }
        if prefix.ends_with('/') {
            return true;
        }
        matches!(candidate.as_bytes().get(prefix.len()), None | Some(b'/'))
    }

    /// Host+port match: suffix-or-exact with a label-boundary check, and an **exact** port
    /// (an unset pattern port infers the standard web ports 443/80). Hosts are case-insensitive.
    pub(crate) fn host_matches(&self, host: &str, port: u16) -> bool {
        let host = host.to_ascii_lowercase();
        let host_ok = match &self.host {
            HostPattern::Any => true,
            HostPattern::Exact(h) => *h == host,
            // `host` must be strictly longer than `.suffix`, so the leading dot guarantees a real
            // label before it — this excludes the apex and blocks `notgithub.com`/`evil-github.com`.
            HostPattern::Suffix(suffix) => {
                host.len() > suffix.len() && host.ends_with(suffix.as_str())
            }
        };
        host_ok && self.port_matches(port)
    }

    /// Exact port comparison; an unset pattern port matches only the standard web defaults.
    fn port_matches(&self, port: u16) -> bool {
        match self.port {
            Some(p) => p == port,
            None => port == 443 || port == 80,
        }
    }

    /// Path match. The `Prefix` form matches by prefix with a
    /// **segment-boundary** check: an empty prefix matches all paths; a `/`-terminated prefix is
    /// already at a boundary; otherwise the char after the prefix must be `/`, `?`, `#`, or
    /// end-of-string — so `/v1/chat` matches `/v1/chat/completions` but not `/v1/chatbot`. The
    /// `Suffix` form (the `/*<suffix>` pattern) matches by a plain
    /// `ends_with` on the request path, so `/*.json` matches any path ending in `.json`. Both are
    /// case-sensitive.
    pub(crate) fn path_matches(&self, path: &str) -> bool {
        match &self.path {
            PathPattern::Suffix(suffix) => path.ends_with(suffix.as_str()),
            PathPattern::Prefix(prefix) => {
                if prefix.is_empty() {
                    return true;
                }
                if !path.starts_with(prefix.as_str()) {
                    return false;
                }
                // A trailing-slash prefix (`/v1/`) already sits on a segment boundary.
                if prefix.ends_with('/') {
                    return true;
                }
                // Otherwise the next byte must terminate the segment (or the path must end here).
                matches!(
                    path.as_bytes().get(prefix.len()),
                    None | Some(b'/' | b'?' | b'#')
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `as_written` round-trips every surface form, so an operator reads back the line they wrote.
    #[test]
    fn as_written_round_trips_every_surface_form() {
        for written in [
            "api.github.com",
            "*.github.com",
            "api.github.com:8443",
            "*.openai.com:8443",
            "api.github.com/v1/chat",
            "*.openai.com/v1/",
            "api.github.com:8443/v1/",
            "*",
            "example.com/*/callback",
            "example.com/*.json",
        ] {
            let parsed = DestinationPattern::parse(written).expect(written);
            assert_eq!(
                parsed.as_written(),
                written,
                "round-trip failed for {written}"
            );
            // And the round-tripped text re-parses to the same pattern.
            assert_eq!(
                DestinationPattern::parse(&parsed.as_written()).unwrap(),
                parsed
            );
        }
    }

    // --- overlaps ------------------------------------------------------------

    fn overlap(a: &str, b: &str) -> bool {
        DestinationPattern::parse(a)
            .unwrap()
            .overlaps(&DestinationPattern::parse(b).unwrap())
    }

    #[test]
    fn overlaps_is_symmetric_and_covers_host_port_path() {
        // Same exact host overlaps itself; distinct exact hosts do not.
        assert!(overlap("api.github.com", "api.github.com"));
        assert!(!overlap("api.github.com", "api.openai.com"));

        // A wildcard covers a strict sub-domain (both directions).
        assert!(overlap("*.example.com", "api.example.com"));
        assert!(overlap("api.example.com", "*.example.com"));
        // ...but not the apex, and not a different suffix.
        assert!(!overlap("*.example.com", "example.com"));
        assert!(!overlap("*.example.com", "api.other.com"));

        // Nested wildcards overlap (one suffix contains the other).
        assert!(overlap("*.example.com", "*.api.example.com"));

        // Ports: unset infers {443,80}; a non-standard explicit port does not overlap the default.
        assert!(overlap("api.example.com", "api.example.com:443"));
        assert!(!overlap("api.example.com", "api.example.com:8443"));
        assert!(overlap("api.example.com:8443", "api.example.com:8443"));

        // Paths: a boundary prefix of the other overlaps; a non-boundary one does not.
        assert!(overlap("api.example.com/v1/", "api.example.com/v1/chat"));
        assert!(!overlap("api.example.com/v1/chat", "api.example.com/v2/"));
    }

    // --- parse ---------------------------------------------------------------

    #[test]
    fn parse_bare_host_is_exact_all_paths() {
        let p = DestinationPattern::parse("api.github.com").unwrap();
        assert_eq!(p.host, HostPattern::Exact("api.github.com".into()));
        assert_eq!(p.port, None);
        assert_eq!(p.path, PathPattern::Prefix(String::new()));
        // Exact + all-paths: every path under the exact host matches.
        assert!(p.matches(&Destination {
            host: "api.github.com",
            port: 443,
            path: "/anything/at/all"
        }));
    }

    #[test]
    fn parse_lowercases_host_keeps_path_case() {
        let p = DestinationPattern::parse("API.GitHub.COM/V1/Chat").unwrap();
        assert_eq!(p.host, HostPattern::Exact("api.github.com".into()));
        // Path is case-sensitive: not lowercased at parse.
        assert_eq!(p.path, PathPattern::Prefix("/V1/Chat".into()));
    }

    #[test]
    fn parse_wildcard_stores_leading_dot() {
        let p = DestinationPattern::parse("*.openai.com/v1/").unwrap();
        assert_eq!(p.host, HostPattern::Suffix(".openai.com".into()));
        assert_eq!(p.path, PathPattern::Prefix("/v1/".into()));
    }

    #[test]
    fn parse_host_port_and_path() {
        let p = DestinationPattern::parse("api.github.com:8443/v1/").unwrap();
        assert_eq!(p.host, HostPattern::Exact("api.github.com".into()));
        assert_eq!(p.port, Some(8443));
        assert_eq!(p.path, PathPattern::Prefix("/v1/".into()));
    }

    #[test]
    fn parse_rejects_bad_patterns() {
        for bad in [
            "",              // empty
            "/v1/only-path", // empty host
            ":443/x",        // empty host with port
            "host:notaport", // non-numeric port
            "host:99999",    // out-of-range u16
            "*.",            // wildcard with no domain
            "ev*l.com",      // misplaced wildcard
            "*.*.com",       // second wildcard
        ] {
            assert!(
                DestinationPattern::parse(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    // --- host: `*` allow-all ------------------------------------------------

    /// `*` parses to the allow-all host form and matches every host.
    #[test]
    fn star_parses_to_any_and_matches_every_host() {
        let p = DestinationPattern::parse("*").unwrap();
        assert_eq!(p.host, HostPattern::Any);
        // Matches arbitrary hosts, including the apex a `*.` suffix would exclude.
        assert!(p.host_matches("github.com", 443));
        assert!(p.host_matches("api.github.com", 443));
        assert!(p.host_matches("anything.example.org", 80));
        // Still an all-paths, web-default-port pattern.
        assert!(p.matches(&Destination {
            host: "whatever.test",
            port: 443,
            path: "/any/path"
        }));
        // The unset port still infers web defaults only — `*` scopes host, not port.
        assert!(!p.host_matches("github.com", 8080));
    }

    /// `*` with a port and/or path narrows normally — the host is the only universal part.
    #[test]
    fn star_with_port_and_path_still_narrows() {
        let p = DestinationPattern::parse("*:8443/v1/").unwrap();
        assert_eq!(p.host, HostPattern::Any);
        assert!(p.host_matches("any.host", 8443));
        assert!(!p.host_matches("any.host", 443));
        assert!(p.path_matches("/v1/chat"));
        assert!(!p.path_matches("/v2/chat"));
    }

    // --- host: suffix + label boundary + apex exclusion ----------------------

    #[test]
    fn suffix_matches_subdomains_only() {
        let p = DestinationPattern::parse("*.github.com").unwrap();
        // Subdomains match.
        assert!(p.host_matches("api.github.com", 443));
        assert!(p.host_matches("gist.github.com", 443));
        // Deep subdomains match too.
        assert!(p.host_matches("a.b.github.com", 443));
        // Apex is excluded — must be bound separately.
        assert!(!p.host_matches("github.com", 443));
        // Label-boundary attacks are blocked.
        assert!(!p.host_matches("notgithub.com", 443));
        assert!(!p.host_matches("evil-github.com", 443));
    }

    #[test]
    fn exact_host_matches_only_itself() {
        let p = DestinationPattern::parse("api.github.com").unwrap();
        assert!(p.host_matches("api.github.com", 443));
        assert!(!p.host_matches("gist.github.com", 443));
        assert!(!p.host_matches("github.com", 443));
    }

    #[test]
    fn host_matching_is_case_insensitive() {
        let p = DestinationPattern::parse("*.github.com").unwrap();
        assert!(p.host_matches("API.GitHub.COM", 443));
        let e = DestinationPattern::parse("api.github.com").unwrap();
        assert!(e.host_matches("API.GITHUB.COM", 443));
    }

    // --- port: exact, with default inference ---------------------------------

    #[test]
    fn port_is_exact() {
        let p = DestinationPattern::parse("api.github.com:443").unwrap();
        assert!(p.host_matches("api.github.com", 443));
        // :443 never matches :8443.
        assert!(!p.host_matches("api.github.com", 8443));
    }

    #[test]
    fn unset_port_infers_web_defaults() {
        let p = DestinationPattern::parse("api.github.com").unwrap();
        assert!(p.host_matches("api.github.com", 443)); // HTTPS
        assert!(p.host_matches("api.github.com", 80)); // HTTP
        // But not an arbitrary port.
        assert!(!p.host_matches("api.github.com", 8080));
    }

    // --- path: prefix + segment boundary -------------------------------------

    #[test]
    fn path_prefix_respects_segment_boundary() {
        let p = DestinationPattern::parse("api.openai.com/v1/chat").unwrap();
        // Exact prefix (EOS boundary).
        assert!(p.path_matches("/v1/chat"));
        // Next char is `/` — a real sub-path.
        assert!(p.path_matches("/v1/chat/completions"));
        // Next char is `?` or `#` — query/fragment boundary.
        assert!(p.path_matches("/v1/chat?stream=true"));
        assert!(p.path_matches("/v1/chat#frag"));
        // `/v1/chatbot` shares the text prefix but crosses no boundary — must NOT match.
        assert!(!p.path_matches("/v1/chatbot"));
    }

    #[test]
    fn trailing_slash_prefix_matches_under_it() {
        let p = DestinationPattern::parse("api.openai.com/v1/").unwrap();
        assert!(p.path_matches("/v1/"));
        assert!(p.path_matches("/v1/chat"));
        assert!(p.path_matches("/v1/chat/completions"));
        // A sibling that only shares the un-slashed stem does not match.
        assert!(!p.path_matches("/v1beta/chat"));
    }

    #[test]
    fn empty_path_prefix_matches_all() {
        let p = DestinationPattern::parse("api.github.com").unwrap();
        assert!(p.path_matches("/"));
        assert!(p.path_matches("/anything"));
        assert!(p.path_matches(""));
    }

    #[test]
    fn path_matching_is_case_sensitive() {
        let p = DestinationPattern::parse("api.openai.com/v1/chat").unwrap();
        assert!(p.path_matches("/v1/chat"));
        assert!(!p.path_matches("/v1/CHAT"));
    }

    // --- path: suffix (the `/*<suffix>` form) --------------------------------

    /// A `/*<suffix>` pattern stores the text after the `*` and matches by `ends_with`.
    #[test]
    fn parse_path_suffix_stores_text_after_star() {
        let p = DestinationPattern::parse("example.com/*/callback").unwrap();
        assert_eq!(p.path, PathPattern::Suffix("/callback".into()));
        let dot = DestinationPattern::parse("example.com/*.json").unwrap();
        assert_eq!(dot.path, PathPattern::Suffix(".json".into()));
    }

    /// A path suffix matches any path ending in it, regardless of the leading segments (the mirror
    /// of the host `*.` suffix form), and rejects a path that does not end in the suffix.
    #[test]
    fn path_suffix_matches_by_ends_with() {
        let p = DestinationPattern::parse("example.com/*/callback").unwrap();
        assert!(p.path_matches("/oauth/callback"));
        assert!(p.path_matches("/a/b/c/callback"));
        // Must end in the suffix — a longer path that merely contains it does not match.
        assert!(!p.path_matches("/callback/extra"));
        assert!(!p.path_matches("/oauth/callbackx"));

        let dot = DestinationPattern::parse("example.com/*.json").unwrap();
        assert!(dot.path_matches("/v1/data.json"));
        assert!(dot.path_matches("/report.json"));
        assert!(!dot.path_matches("/report.jsonl"));
        assert!(!dot.path_matches("/report.xml"));
    }

    /// Path suffix matching is case-sensitive, like the prefix form.
    #[test]
    fn path_suffix_is_case_sensitive() {
        let p = DestinationPattern::parse("example.com/*.json").unwrap();
        assert!(p.path_matches("/a.json"));
        assert!(!p.path_matches("/a.JSON"));
    }

    // --- matches = host AND path ---------------------------------------------

    #[test]
    fn matches_requires_both_host_and_path() {
        let p = DestinationPattern::parse("*.openai.com/v1/").unwrap();
        // Both match.
        assert!(p.matches(&Destination {
            host: "api.openai.com",
            port: 443,
            path: "/v1/chat/completions"
        }));
        // Host mismatch (apex).
        assert!(!p.matches(&Destination {
            host: "openai.com",
            port: 443,
            path: "/v1/chat"
        }));
        // Path mismatch.
        assert!(!p.matches(&Destination {
            host: "api.openai.com",
            port: 443,
            path: "/v2/chat"
        }));
        // Port mismatch (unset pattern port only accepts 443/80).
        assert!(!p.matches(&Destination {
            host: "api.openai.com",
            port: 8443,
            path: "/v1/chat"
        }));
    }
}
