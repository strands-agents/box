//! Credential *reference* types — the pointer to a secret, in either config surface form.

use std::collections::BTreeMap;

use crate::{CredentialError, Result, redact_credential_ref};

/// A parsed credential reference in either config surface form.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Locator {
    /// URI form: a canonical locator string, stored verbatim (e.g. `op://vault/item/field`,
    /// `env://GITHUB_TOKEN`, `file:///etc/token`). The owning source parses its own structure.
    Uri(String),
    /// Structured form: a tagged config block as a map, always carrying a non-empty `source` key
    /// plus the source's named fields (e.g. `{ "source": "aws", "profile": "prod" }`).
    Structured(BTreeMap<String, String>),
}

impl Locator {
    /// Parse a URI-form reference (`op://…`, `env://VAR`, `file:///path`).
    pub fn parse_uri(s: &str) -> Result<Self> {
        match s.split_once("://") {
            Some((scheme, rest)) if !scheme.is_empty() && !rest.is_empty() => {
                Ok(Locator::Uri(s.to_string()))
            }
            _ => Err(CredentialError::Credential(format!(
                "malformed credential reference (expected `scheme://locator`): {:?}",
                redact_credential_ref(s)
            ))),
        }
    }

    /// Build a structured-form reference from a tagged config block.
    pub fn structured(fields: BTreeMap<String, String>) -> Result<Self> {
        match fields.get(SOURCE_TAG) {
            Some(source) if !source.is_empty() => Ok(Locator::Structured(fields)),
            _ => Err(CredentialError::Credential(
                "structured credential reference is missing a non-empty `source` tag".to_string(),
            )),
        }
    }

    /// The routing key the source registry dispatches on: the URI **scheme** (the text before
    /// `://`) for [`Uri`](Self::Uri), or the `source` **tag** for [`Structured`](Self::Structured).
    pub fn scheme(&self) -> &str {
        match self {
            Locator::Uri(s) => s.split_once("://").map_or("", |(scheme, _)| scheme),
            Locator::Structured(fields) => fields.get(SOURCE_TAG).map_or("", String::as_str),
        }
    }
}

/// The reserved structured-form key naming the owning source (the routing tag), e.g. `"aws"`.
const SOURCE_TAG: &str = "source";

impl std::fmt::Debug for Locator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Keep the scheme (the useful routing kind), redact the locator body — a locator can
            // disclose vault/item structure.
            Locator::Uri(s) => f
                .debug_tuple("Uri")
                .field(&redact_credential_ref(s))
                .finish(),
            // Keep the `source` tag (the routing kind); redact every field *value* — a value such as
            // a profile name is disclosure-sensitive.
            Locator::Structured(_) => f
                .debug_struct("Structured")
                .field("source", &self.scheme())
                .field("fields", &"[REDACTED]")
                .finish(),
        }
    }
}

// A `CredentialRef` — a locator paired with the destination it is bound to — lived here until
// 2026-08-07. It was the argument type of the removed `CredentialProcessor::process`, and a
// `RouteSpec` already pairs exactly those two things, so keeping it meant one shape existing
// only to be rebuilt from another on every resolve.

#[cfg(test)]
mod tests {
    use super::*;

    fn structured_fields(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // --- URI form: the v1 canonical-locator sources (op / env / file) --------

    #[test]
    fn parse_uri_accepts_v1_schemes_and_reports_scheme() {
        for (uri, scheme) in [
            ("op://Private/GitHub/token", "op"),
            ("env://GITHUB_TOKEN", "env"),
            ("file:///etc/secret", "file"),
        ] {
            let loc = Locator::parse_uri(uri).unwrap();
            assert_eq!(loc, Locator::Uri(uri.to_string()));
            // The routing key is the scheme; the shared contract never interprets the body.
            assert_eq!(loc.scheme(), scheme);
        }
    }

    #[test]
    fn parse_uri_rejects_malformed() {
        for bad in [
            "",                  // empty
            "GITHUB_TOKEN",      // no scheme separator
            "://orphan",         // empty scheme
            "op://",             // empty locator body
            "no-separator-here", // no `://`
        ] {
            assert!(
                Locator::parse_uri(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    // --- Structured form: the AWS source (source = "aws", profile = ...) -----

    #[test]
    fn structured_accepts_aws_block_and_reports_source() {
        let loc = Locator::structured(structured_fields(&[("source", "aws"), ("profile", "prod")]))
            .unwrap();
        // The `source` tag is the routing key; the AWS source owns validating `profile` later.
        assert_eq!(loc.scheme(), "aws");
        match &loc {
            Locator::Structured(fields) => {
                assert_eq!(fields.get("profile").map(String::as_str), Some("prod"));
            }
            other => panic!("expected Structured, got {other:?}"),
        }
    }

    #[test]
    fn structured_rejects_missing_or_empty_source_tag() {
        // No `source` tag at all.
        assert!(Locator::structured(structured_fields(&[("profile", "prod")])).is_err());
        // Empty map.
        assert!(Locator::structured(BTreeMap::new()).is_err());
        // Present but empty `source`.
        assert!(
            Locator::structured(structured_fields(&[("source", ""), ("profile", "prod")])).is_err()
        );
    }

    // --- Debug redaction: a reference is disclosure-sensitive -----------------

    #[test]
    fn uri_debug_keeps_scheme_hides_body() {
        let loc = Locator::parse_uri("op://Private/GitHub/token").unwrap();
        let rendered = format!("{loc:?}");
        assert!(rendered.contains("op://[REDACTED]"), "got {rendered}");
        // The specific locator body must never survive Debug.
        assert!(!rendered.contains("Private"));
        assert!(!rendered.contains("GitHub"));
    }

    #[test]
    fn structured_debug_keeps_source_hides_field_values() {
        let loc = Locator::structured(structured_fields(&[("source", "aws"), ("profile", "prod")]))
            .unwrap();
        let rendered = format!("{loc:?}");
        // The routing kind survives; the field values (e.g. the profile name) do not.
        assert!(rendered.contains("aws"), "got {rendered}");
        assert!(rendered.contains("[REDACTED]"), "got {rendered}");
        assert!(!rendered.contains("prod"), "got {rendered}");
    }
}
