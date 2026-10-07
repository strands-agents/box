//! Where a credential attaches ([`InjectMode`]) and what stands in for it ([`PhantomToken`]).

use crate::{CredentialError, Result};

/// The prefix a route mints under when it sets no `secret.phantom_prefix`.
pub(crate) const DEFAULT_PHANTOM_PREFIX: &str = "strands_box_";

/// The longest a phantom prefix may be, so the minted token stays bounded.
const PHANTOM_PREFIX_MAX_LEN: usize = 64;

/// The number of CSPRNG bytes behind a phantom token: 256 bits, rendered as 64 lowercase hex chars.
const PHANTOM_ENTROPY_BYTES: usize = 32;

/// Refuse a phantom prefix that is unsafe in a credential location. The unreserved set is safe in a
/// header value, a Basic-auth pair, a query parameter, and an environment variable, so one rule
/// covers every placement; empty and over-long are refused too.
pub(crate) fn check_phantom_prefix(prefix: &str) -> Result<()> {
    if prefix.is_empty() {
        return Err(CredentialError::Credential(
            "a phantom prefix must be non-empty; omit the key for the default prefix".to_string(),
        ));
    }
    if prefix.len() > PHANTOM_PREFIX_MAX_LEN {
        return Err(CredentialError::Credential(format!(
            "a phantom prefix must be at most {PHANTOM_PREFIX_MAX_LEN} characters"
        )));
    }
    if let Some(byte) = prefix.bytes().find(|byte| !is_unreserved(*byte)) {
        return Err(CredentialError::Credential(format!(
            "phantom prefix character {:?} is not one of A-Z, a-z, 0-9, '-', '_', '.', '~'",
            byte as char
        )));
    }
    Ok(())
}

/// Whether `byte` is an RFC 3986 unreserved character.
fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
}

/// The non-secret, unguessable dummy value the vault mints to stand in for a Real_Secret.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PhantomToken(String);

impl PhantomToken {
    /// Mint a fresh Phantom_Token: `prefix` then 64 CSPRNG hex chars. Refuses a prefix
    /// outside the unreserved set or longer than the cap; the entropy lives in the suffix only.
    pub(crate) fn generate(prefix: &str) -> Result<Self> {
        check_phantom_prefix(prefix)?;
        let mut bytes = [0u8; PHANTOM_ENTROPY_BYTES];
        getrandom::fill(&mut bytes).map_err(|e| {
            CredentialError::Credential(format!(
                "failed to draw CSPRNG bytes for a phantom token: {e}"
            ))
        })?;
        let mut token = String::with_capacity(prefix.len() + PHANTOM_ENTROPY_BYTES * 2);
        token.push_str(prefix);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for b in bytes {
            token.push(HEX[(b >> 4) as usize] as char);
            token.push(HEX[(b & 0x0f) as usize] as char);
        }
        Ok(Self(token))
    }

    /// The token as a string slice (`<prefix><64hex>`), for seeding into the workload's environment
    /// or comparing against a phantom observed at interception.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PhantomToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// How a credential is attached to an outbound request — and, in phantom-parse form, how the proxy
/// recognises it on the way in (moved from `egress-proxy` config into `credentials`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InjectMode {
    /// Attach the secret as a header value built from `format`, e.g. `"Bearer {}"`.
    #[non_exhaustive]
    Header {
        /// The header-value template the secret is substituted into (e.g. `"Bearer {}"`).
        format: String,
        /// The header name the value is attached under. `None` means the standard
        /// `Authorization` header (the common bearer/basic case); `Some(name)` names a
        /// non-`Authorization` header such as `x-api-key`.
        header_name: Option<String>,
    },
    /// Attach the secret via HTTP Basic authentication (`Authorization: Basic <base64>`).
    #[non_exhaustive]
    BasicAuth,
    /// Splice the secret into the request URL path using `pattern` (e.g. `"/v1/{}/models"`).
    #[non_exhaustive]
    UrlPath {
        /// The URL-path template the secret is substituted into.
        pattern: String,
    },
    /// Attach the secret as the query parameter named `name` (e.g. `"api_key"`).
    #[non_exhaustive]
    QueryParam {
        /// The query-parameter name the secret is attached under.
        name: String,
    },
}

/// The substitution slot a template must carry exactly once.
const SLOT: &str = "{}";

impl InjectMode {
    /// A header placement: `format` with exactly one `{}`, under `header_name` or `Authorization`.
    pub fn header(format: impl Into<String>, header_name: Option<String>) -> Result<Self> {
        let format = format.into();
        Self::check_one_slot(&format, "a header value template")?;
        if let Some(name) = &header_name
            && (name.is_empty() || !name.bytes().all(is_http_token_byte))
        {
            return Err(CredentialError::Credential(format!(
                "credential header name {name:?} is not an RFC 7230 token"
            )));
        }
        Ok(Self::Header {
            format,
            header_name,
        })
    }

    /// The HTTP Basic placement. Infallible — it carries no operator-supplied value.
    #[must_use]
    pub fn basic_auth() -> Self {
        Self::BasicAuth
    }

    /// A URL-path placement: `pattern` with exactly one `{}`, e.g. `"/v1/{}/models"`.
    pub fn url_path(pattern: impl Into<String>) -> Result<Self> {
        let pattern = pattern.into();
        Self::check_one_slot(&pattern, "a url-path template")?;
        Ok(Self::UrlPath { pattern })
    }

    /// A query-parameter placement under `name`.
    pub fn query_param(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let legal = |byte: u8| byte.is_ascii_alphanumeric() || b"-._~!$'*+".contains(&byte);
        if name.is_empty() || !name.bytes().all(legal) {
            return Err(CredentialError::Credential(format!(
                "credential query-parameter name {name:?} must be non-empty and carry no character \
                 needing encoding in a query key"
            )));
        }
        Ok(Self::QueryParam { name })
    }

    /// The variant's name, for an error that has to say which placements disagree.
    pub(crate) fn placement_name(&self) -> &'static str {
        match self {
            Self::Header { .. } => "header",
            Self::BasicAuth => "basic_auth",
            Self::UrlPath { .. } => "url_path",
            Self::QueryParam { .. } => "query_param",
        }
    }

    /// Exactly one `{}` — not zero (the secret would never be substituted) and not two (only the
    /// first is filled, so the rest reaches the wire as a literal).
    fn check_one_slot(template: &str, what: &str) -> Result<()> {
        match template.matches(SLOT).count() {
            1 => Ok(()),
            found => Err(CredentialError::Credential(format!(
                "{what} must contain exactly one `{SLOT}` for the secret; {template:?} has {found}"
            ))),
        }
    }
}

/// Whether `byte` is legal in an RFC 7230 token (a header or parameter name).
fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minted phantom has the `<prefix><64hex>` form — the prefix plus exactly 64
    /// lowercase hex chars of 256-bit CSPRNG entropy. The default prefix is `strands_box_`.
    #[test]
    fn phantom_token_has_prefixed_64hex_form() {
        for prefix in [DEFAULT_PHANTOM_PREFIX, "sk-ant-"] {
            let token = PhantomToken::generate(prefix).unwrap();
            let s = token.as_str();
            assert!(s.starts_with(prefix), "got {s}");
            let hex = s.strip_prefix(prefix).unwrap();
            assert_eq!(hex.len(), 64, "256 bits → 64 hex chars: {s}");
            assert!(
                hex.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "expected lowercase hex: {s}"
            );
        }
    }

    /// A prefix outside the unreserved set, empty, or over-long is refused at mint.
    #[test]
    fn an_unsafe_phantom_prefix_is_refused() {
        let over_long = "a".repeat(65);
        for prefix in ["", "sk ant", "sk\r\nant", "sk/ant", over_long.as_str()] {
            let err =
                PhantomToken::generate(prefix).expect_err("an unsafe prefix must not mint a token");
            assert!(!err.is_soft(), "{prefix:?} must fail closed");
        }
        assert!(PhantomToken::generate("sk-ant-").is_ok());
    }

    /// A header template without exactly one slot is refused at construction.
    #[test]
    fn a_header_template_needs_exactly_one_slot() {
        for template in ["Bearer", "", "Bearer {} {}", "{}{}"] {
            let err = InjectMode::header(template, None)
                .expect_err("a template that cannot carry the secret is refused");
            assert!(!err.is_soft(), "{template:?} must fail closed");
        }
        assert!(InjectMode::header("Bearer {}", None).is_ok());
        assert!(
            InjectMode::header("{}", None).is_ok(),
            "a raw-value header is valid"
        );
    }

    /// A header name must be an RFC 7230 token.
    #[test]
    fn a_header_name_must_be_a_token() {
        for name in ["", "X-Bad\r\nInjected", "has space", "colon:name"] {
            let err = InjectMode::header("{}", Some(name.to_string()))
                .expect_err("a non-token header name is refused");
            assert!(!err.is_soft(), "{name:?} must fail closed");
        }
        assert!(InjectMode::header("{}", Some("x-api-key".to_string())).is_ok());
    }

    /// A url-path pattern needs exactly one slot too.
    #[test]
    fn a_url_path_pattern_needs_exactly_one_slot() {
        assert!(InjectMode::url_path("/v1/models").is_err());
        assert!(InjectMode::url_path("/v1/{}/{}").is_err());
        assert!(InjectMode::url_path("/v1/{}/models").is_ok());
    }

    /// An empty query-parameter name attached the real secret under the empty key.
    #[test]
    fn a_query_parameter_name_must_be_a_non_empty_token() {
        for name in ["", " ", "a=b", "a&b"] {
            let err =
                InjectMode::query_param(name).expect_err("a non-token parameter name is refused");
            assert!(!err.is_soft(), "{name:?} must fail closed");
        }
        assert!(InjectMode::query_param("api_key").is_ok());
    }

    /// Two draws are distinct — the generator does not repeat (unguessable, unique).
    #[test]
    fn phantom_tokens_are_distinct() {
        let a = PhantomToken::generate(DEFAULT_PHANTOM_PREFIX).unwrap();
        let b = PhantomToken::generate(DEFAULT_PHANTOM_PREFIX).unwrap();
        assert_ne!(a, b, "two CSPRNG draws must differ");
    }

    #[test]
    fn inject_mode_variants_construct_and_compare() {
        let header = InjectMode::header("Bearer {}".to_string(), None).unwrap();
        let path = InjectMode::url_path("/v1/{}/models".to_string()).unwrap();
        let query = InjectMode::query_param("api_key".to_string()).unwrap();
        // Distinct variants are unequal; a clone round-trips.
        assert_ne!(header, InjectMode::basic_auth());
        assert_ne!(path, query);
        assert_eq!(header.clone(), header);
        // The shape fields are readable (Debug is safe — no secret in an InjectMode).
        assert!(format!("{header:?}").contains("Bearer {}"));
    }
}
