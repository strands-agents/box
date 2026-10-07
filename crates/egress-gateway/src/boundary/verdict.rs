//! [`Verdict`], [`Mutation`], and [`DenyReason`] — the folded result the interceptor acts on.

use zeroize::Zeroizing;

use crate::boundary::{HeaderMap, Target};

/// A pure description of an edit the interceptor applies to a request or response.
#[derive(Clone, PartialEq, Eq)]
pub enum Mutation {
    /// Set a header (replacing any existing same-named header). The value MAY be secret.
    SetHeader {
        /// The header name (non-secret).
        name: String,
        /// The header value (MAY be a real credential — redacted in `Debug`, wiped on drop).
        value: Zeroizing<String>,
    },
    /// Strip every header with this name (non-secret).
    StripHeader {
        /// The header name to remove.
        name: String,
    },
    /// Rewrite the request path (e.g. to splice a secret into a `UrlPath` inject mode). MAY be secret.
    RewritePath {
        /// The new request path (MAY embed a secret — redacted in `Debug`, wiped on drop).
        path: Zeroizing<String>,
    },
    /// Add a query parameter. The value MAY be secret (a `QueryParam` inject mode).
    AddQueryParam {
        /// The parameter name (non-secret).
        name: String,
        /// The parameter value (MAY be a real credential — redacted in `Debug`, wiped on drop).
        value: Zeroizing<String>,
    },
    /// Remove every query parameter with this name (non-secret).
    StripQueryParam {
        /// The parameter name to remove.
        name: String,
    },
}

impl Mutation {
    /// The **target key** two mutations collide on: the concrete thing being edited (a header name,
    /// the path, a query-param name), normalized for headers (case-insensitive). Two `Allow`
    /// mutations with the same target key from different Controls are a config-load collision.
    /// A `StripHeader` and a `SetHeader` of the same header collide on the same key, and that is
    /// intended: two Controls fighting over one header is a misconfiguration.
    pub fn target_key(&self) -> MutationTarget {
        match self {
            Mutation::SetHeader { name, .. } | Mutation::StripHeader { name } => {
                MutationTarget::Header(name.to_ascii_lowercase())
            }
            Mutation::RewritePath { .. } => MutationTarget::Path,
            // A strip and an add of the same parameter share one target key, exactly as
            // `StripHeader`/`SetHeader` do — that pairing is one capability's coordinated swap, and
            // the collision detector skips the strip half so the pair does not self-collide.
            Mutation::AddQueryParam { name, .. } | Mutation::StripQueryParam { name } => {
                MutationTarget::QueryParam(name.clone())
            }
        }
    }

    /// Apply this mutation to a request's `headers` and `target` in place, by reference.
    pub fn apply(&self, headers: &mut HeaderMap, target: &mut Target) {
        self.clone().into_apply(headers, target);
    }

    /// Apply this mutation by **value**, moving its owned strings into `headers`/`target` — no copy of
    /// the (possibly secret) value. This is how the interceptor applies the `Vec<Mutation>` it owns
    /// from a [`Verdict::Allow`], which is consumed exactly once.
    pub fn into_apply(self, headers: &mut HeaderMap, target: &mut Target) {
        match self {
            // `Zeroizing<String>` derefs to `String`, but `set` takes `impl Into<String>`, so the
            // inner value is moved out and re-wrapped by the map. No copy: `Zeroizing` is a newtype,
            // and the guard it drops after the move holds an empty `String`.
            Mutation::SetHeader { name, value } => headers.set(&name, take_inner(value)),
            Mutation::StripHeader { name } => {
                headers.remove(&name);
            }
            Mutation::RewritePath { path } => target.path = take_inner(path),
            Mutation::AddQueryParam { name, value } => {
                // Percent-encode both name and value (RFC 3986 query-component escaping). The value
                // is a real credential on the `QueryParam` inject path, so a raw `&`/`=`/`#`/`+`/space
                // would otherwise split it into bogus parameters — a broken credential and a leak of
                // the fragment after the delimiter.
                if !target.query.is_empty() {
                    target.query.push('&');
                }
                target.query.push_str(&percent_encode_query(&name));
                target.query.push('=');
                target.query.push_str(&percent_encode_query(&value));
            }
            Mutation::StripQueryParam { name } => {
                target.query = strip_query_param(&target.query, &name);
            }
        }
    }
}

/// Move the `String` out of a `Zeroizing<String>` without copying its bytes.
fn take_inner(mut value: Zeroizing<String>) -> String {
    std::mem::take(&mut *value)
}

/// Remove every `name=…` pair from a query string, returning what remains.
fn strip_query_param(query: &str, name: &str) -> String {
    query
        .split('&')
        .filter(|pair| {
            if pair.is_empty() {
                return false;
            }
            let key = pair.split_once('=').map_or(*pair, |(key, _)| key);
            decode_query_key(key) != name
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Decode one query-string key: `+` becomes a space and `%XX` becomes its byte, case-insensitively.
fn decode_query_key(key: &str) -> String {
    let bytes = key.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                    (Some(high), Some(low)) => {
                        out.push((high << 4) | low);
                        i += 3;
                    }
                    // Not a valid escape; keep the '%' verbatim.
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The value of one hex digit, upper or lower case; `None` for any other byte.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent-encode a query-string component per RFC 3986: the unreserved set (`A-Z a-z 0-9 - _ . ~`)
/// passes through, everything else is `%XX` with uppercase hex. Hand-rolled (like the vault's SigV4
/// encoder) to keep the boundary types dependency-light; correctness is covered by unit tests.
fn percent_encode_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

impl std::fmt::Debug for Mutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Values MAY be secret (a real credential), so render them [REDACTED]; keep the non-secret
        // name/target so a diagnostic still says *what* was edited.
        match self {
            Mutation::SetHeader { name, .. } => f
                .debug_struct("SetHeader")
                .field("name", name)
                .field("value", &"[REDACTED]")
                .finish(),
            Mutation::StripHeader { name } => {
                f.debug_struct("StripHeader").field("name", name).finish()
            }
            Mutation::RewritePath { .. } => f
                .debug_struct("RewritePath")
                .field("path", &"[REDACTED]")
                .finish(),
            Mutation::AddQueryParam { name, .. } => f
                .debug_struct("AddQueryParam")
                .field("name", name)
                .field("value", &"[REDACTED]")
                .finish(),
            // Carries no value, so there is nothing to redact.
            Mutation::StripQueryParam { name } => f
                .debug_struct("StripQueryParam")
                .field("name", name)
                .finish(),
        }
    }
}

/// The concrete edit target two mutations collide on (see [`Mutation::target_key`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MutationTarget {
    /// A header, keyed by its lowercased name.
    Header(String),
    /// The request path.
    Path,
    /// A query parameter, keyed by its name.
    QueryParam(String),
}

/// Why a request or response was denied — a non-secret, log-safe reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// A host was denied (default-deny allowlist).
    HostDenied(String),
    /// A resolved IP was denied (a policy deny).
    IpDenied(String),
    /// Two mutators tried to edit the same target on one request (fail closed).
    MutationCollision(String),
    /// A credential binding was ambiguous or a phantom mismatched (fail closed).
    Credential(String),
    /// A generic request control denied the exchange.
    ControlDenied(String),
    /// A response breached a configured size/content limit.
    ResponseLimit(String),
    /// The policy decision point did not authorize the exchange. Reached through the
    /// [`EffectInterceptor`](crate::effect::EffectInterceptor) seam, which is the only authorization
    /// authority the boundary has. Names no host/IP (log-safe) and maps to HTTP 403.
    NotAuthorized,
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DenyReason::HostDenied(h) => write!(f, "host denied: {h}"),
            DenyReason::IpDenied(m) => write!(f, "ip denied: {m}"),
            DenyReason::MutationCollision(m) => write!(f, "mutation collision: {m}"),
            DenyReason::Credential(m) => write!(f, "credential denied: {m}"),
            DenyReason::ControlDenied(m) => write!(f, "control denied: {m}"),
            DenyReason::ResponseLimit(m) => write!(f, "response limit: {m}"),
            DenyReason::NotAuthorized => write!(f, "not authorized (default-deny)"),
        }
    }
}

/// The folded result the interceptor acts on: forward with accumulated mutations, or
/// block with a reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Forward, applying the accumulated mutations first.
    Allow {
        /// The mutations to apply, accumulated from every matching `Allow` Control.
        mutations: Vec<Mutation>,
    },
    /// Block, with a non-secret reason.
    Deny {
        /// Why the request/response was denied.
        reason: DenyReason,
    },
}

impl Verdict {
    /// Whether this verdict is a deny.
    pub fn is_deny(&self) -> bool {
        matches!(self, Verdict::Deny { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_debug_redacts_values_but_keeps_names() {
        let m = Mutation::SetHeader {
            name: "Authorization".to_string(),
            value: Zeroizing::new("Bearer sk_live_super_secret".to_string()),
        };
        let rendered = format!("{m:?}");
        assert!(rendered.contains("Authorization"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("sk_live_super_secret"));
    }

    #[test]
    fn set_header_and_strip_collide_on_same_key() {
        let set = Mutation::SetHeader {
            name: "Authorization".to_string(),
            value: Zeroizing::new("x".to_string()),
        };
        let strip = Mutation::StripHeader {
            name: "authorization".to_string(),
        };
        assert_eq!(set.target_key(), strip.target_key());
    }

    #[test]
    fn apply_set_and_strip_and_query() {
        let mut headers = HeaderMap::new();
        headers.append("Authorization", "phantom");
        let mut target = Target::new("api.example.com", 443);

        Mutation::StripHeader {
            name: "authorization".to_string(),
        }
        .apply(&mut headers, &mut target);
        assert!(!headers.contains("authorization"));

        Mutation::SetHeader {
            name: "Authorization".to_string(),
            value: Zeroizing::new("Bearer real".to_string()),
        }
        .apply(&mut headers, &mut target);
        assert_eq!(headers.get("authorization"), Some("Bearer real"));

        Mutation::AddQueryParam {
            name: "api_key".to_string(),
            value: Zeroizing::new("real".to_string()),
        }
        .apply(&mut headers, &mut target);
        assert_eq!(target.query, "api_key=real");

        Mutation::AddQueryParam {
            name: "b".to_string(),
            value: Zeroizing::new("2".to_string()),
        }
        .apply(&mut headers, &mut target);
        assert_eq!(target.query, "api_key=real&b=2");
    }

    /// A credential value with reserved characters must be percent-encoded so it stays a single
    /// query parameter — a raw `&`/`=`/space would otherwise split it and leak the tail.
    #[test]
    fn add_query_param_percent_encodes_reserved_chars() {
        let mut headers = HeaderMap::new();
        let mut target = Target::new("api.example.com", 443);
        Mutation::AddQueryParam {
            name: "api key".to_string(),
            value: Zeroizing::new("abc&def=ghi #x+y".to_string()),
        }
        .apply(&mut headers, &mut target);
        // Name and value are both encoded; the whole thing remains one `k=v` pair.
        assert_eq!(target.query, "api%20key=abc%26def%3Dghi%20%23x%2By");
        // Exactly one '=' delimiter and no stray '&' survives to split the parameter.
        assert_eq!(target.query.matches('=').count(), 1);
        assert!(!target.query.contains('&'));
    }

    /// `StripQueryParam` removes the phantom pair and leaves every other parameter untouched, in
    /// order. Without this the credential swap would append the real secret beside the phantom.
    #[test]
    fn strip_query_param_removes_only_the_named_pair() {
        let mut headers = HeaderMap::new();
        let mut target = Target::new("api.example.com", 443);
        target.query = "city=seattle&api_key=strands_box_phantom&units=metric".to_string();

        Mutation::StripQueryParam {
            name: "api_key".to_string(),
        }
        .apply(&mut headers, &mut target);

        assert_eq!(target.query, "city=seattle&units=metric");
    }

    /// Every occurrence goes, and a valueless key is matched on the key alone.
    #[test]
    fn strip_query_param_removes_repeats_and_valueless_keys() {
        let mut headers = HeaderMap::new();
        let mut target = Target::new("api.example.com", 443);
        target.query = "api_key=one&x=1&api_key&api_key=two".to_string();

        Mutation::StripQueryParam {
            name: "api_key".to_string(),
        }
        .apply(&mut headers, &mut target);

        assert_eq!(target.query, "x=1");
    }

    /// Every spelling that names the same parameter is stripped, because the **workload** chooses the
    /// wire spelling. Uppercase and lowercase hex are equivalent (RFC 3986 §6.2.2.1) and `+` is the
    /// form-encoded space, so matching only one chosen spelling would leave the phantom riding
    /// upstream beside the real secret.
    #[test]
    fn strip_query_param_matches_every_spelling_of_the_name() {
        for (name, query) in [
            // A space: raw, percent-encoded, and the form-encoded `+`.
            ("api key", "api key=strands_box_phantom&x=1"),
            ("api key", "api%20key=strands_box_phantom&x=1"),
            ("api key", "api+key=strands_box_phantom&x=1"),
            // A slash, which `percent_encode_query` writes as uppercase `%2F`.
            ("a/b", "a/b=strands_box_phantom&x=1"),
            ("a/b", "a%2Fb=strands_box_phantom&x=1"),
            ("a/b", "a%2fb=strands_box_phantom&x=1"),
        ] {
            let mut headers = HeaderMap::new();
            let mut target = Target::new("api.example.com", 443);
            target.query = query.to_string();

            Mutation::StripQueryParam {
                name: name.to_string(),
            }
            .apply(&mut headers, &mut target);

            assert_eq!(target.query, "x=1", "name={name:?} query={query:?}");
        }
    }

    /// A different parameter that merely *decodes* near the target is left alone, and a malformed
    /// escape is compared verbatim rather than dropped.
    #[test]
    fn strip_query_param_leaves_other_keys_and_malformed_escapes() {
        let cases = [
            // A distinct key survives.
            ("api_key", "other=1&api_keys=2", "other=1&api_keys=2"),
            // A truncated escape is not a valid encoding of the name, so it is not the name.
            ("a b", "a%2=1&x=2", "a%2=1&x=2"),
            // ...but the same malformed key still compares equal to itself.
            ("a%2", "a%2=1&x=2", "x=2"),
        ];
        for (name, query, expected) in cases {
            let mut headers = HeaderMap::new();
            let mut target = Target::new("api.example.com", 443);
            target.query = query.to_string();

            Mutation::StripQueryParam {
                name: name.to_string(),
            }
            .apply(&mut headers, &mut target);

            assert_eq!(target.query, expected, "name={name:?} query={query:?}");
        }
    }

    /// The full swap: strip then add leaves exactly one parameter, carrying the real secret.
    #[test]
    fn strip_then_add_yields_one_parameter_with_the_real_secret() {
        let mut headers = HeaderMap::new();
        let mut target = Target::new("api.example.com", 443);
        target.query = "api_key=strands_box_phantom&city=seattle".to_string();

        for mutation in [
            Mutation::StripQueryParam {
                name: "api_key".to_string(),
            },
            Mutation::AddQueryParam {
                name: "api_key".to_string(),
                value: Zeroizing::new("wk_live_real".to_string()),
            },
        ] {
            mutation.apply(&mut headers, &mut target);
        }

        assert_eq!(target.query, "city=seattle&api_key=wk_live_real");
        assert_eq!(
            target.query.matches("api_key").count(),
            1,
            "the phantom must not survive beside the real secret"
        );
        assert!(!target.query.contains("strands_box_phantom"));
    }

    /// A strip and an add of the same parameter share one target key — the query twin of the
    /// header swap idiom, which is what lets the collision detector skip the strip half.
    #[test]
    fn add_and_strip_query_param_collide_on_same_key() {
        let add = Mutation::AddQueryParam {
            name: "api_key".to_string(),
            value: Zeroizing::new("x".to_string()),
        };
        let strip = Mutation::StripQueryParam {
            name: "api_key".to_string(),
        };
        assert_eq!(add.target_key(), strip.target_key());
    }

    /// `StripQueryParam` carries no value, so its `Debug` shows the name and redacts nothing.
    #[test]
    fn strip_query_param_debug_shows_the_name() {
        let rendered = format!(
            "{:?}",
            Mutation::StripQueryParam {
                name: "api_key".to_string(),
            }
        );
        assert!(rendered.contains("api_key"));
        assert!(!rendered.contains("REDACTED"));
    }

    /// The unreserved set (`A-Z a-z 0-9 - _ . ~`) passes through untouched.
    #[test]
    fn percent_encode_query_passes_unreserved() {
        assert_eq!(percent_encode_query("Az09-_.~"), "Az09-_.~");
        assert_eq!(percent_encode_query("a/b"), "a%2Fb");
    }
}
