//! `env://VAR` — read a secret from a process environment variable.

use std::env;

use zeroize::Zeroizing;

use crate::sources::SecretSource;
use crate::sources::uri_reference;
use crate::{CredentialError, Locator, Result, Secret, redact_credential_ref};

/// The scheme this source claims.
const SCHEME: &str = "env";

/// Environment variable names `env://` refuses to read (case-insensitive).
const DENYLIST: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_CREDENTIAL_EXPIRATION",
    "AWS_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
];

/// Reads secrets from process environment variables (`env://VAR`).
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct EnvSource;

impl EnvSource {
    /// Construct the source.
    pub(crate) fn new() -> Self {
        Self
    }

    /// Whether `name` is denylisted (case-insensitive), so `env://` can't read a sensitive host
    /// variable. Exposed for tests; the denylist itself is a private safety floor.
    fn is_denied(name: &str) -> bool {
        DENYLIST.iter().any(|d| d.eq_ignore_ascii_case(name))
    }
}

impl SecretSource for EnvSource {
    fn scheme(&self) -> &'static str {
        SCHEME
    }

    fn fetch(&self, loc: &Locator) -> Result<Secret> {
        // Own the parse: env:// takes a URI-form reference whose body is the variable name.
        let reference = uri_reference(loc, SCHEME)?;
        let var = reference
            .strip_prefix("env://")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                CredentialError::Credential(format!(
                    "malformed env:// reference (expected `env://VAR`): {:?}",
                    redact_credential_ref(reference)
                ))
            })?;

        // Fail closed on a denylisted name — never let env:// read a sensitive host variable. The
        // variable *name* is not itself a secret, but redact the reference in the message anyway so
        // diagnostics stay uniform with the rest of the crate.
        if Self::is_denied(var) {
            return Err(CredentialError::Credential(format!(
                "env:// refuses to read the sensitive environment variable named in {:?}",
                redact_credential_ref(reference)
            )));
        }

        // An absent variable is a soft miss: this one route is skipped, the vault still comes up.
        // `var_os` + a UTF-8 check keeps a non-UTF-8 value from panicking (unlike `env::var`, which
        // maps both absence and non-UTF-8 into the same error); a present-but-invalid value is a
        // hard error, not a silent skip.
        match env::var_os(var) {
            None => Err(CredentialError::SecretNotFound(redact_credential_ref(
                reference,
            ))),
            Some(value) => match value.into_string() {
                // The content rule is `Secret`'s, not this source's: an exported-but-empty variable
                // is refused here rather than becoming a bound credential
                // (docs/design/decisions.md#an-unusable-secret-value-is-unrepresentable).
                Ok(s) => Secret::new(Zeroizing::new(s), reference),
                Err(_) => Err(CredentialError::Credential(format!(
                    "environment variable named in {:?} is not valid UTF-8",
                    redact_credential_ref(reference)
                ))),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env-var tests mutate real process state, so give each its own uniquely-named variable to
    // avoid cross-test interference (tests can run in parallel).
    fn locator(uri: &str) -> Locator {
        Locator::parse_uri(uri).expect("test URI is well-formed")
    }

    #[test]
    fn reads_a_present_variable() {
        let name = "STRANDS_TEST_ENV_PRESENT";
        // SAFETY: single-threaded within this test; the variable name is unique to it.
        unsafe { env::set_var(name, "gh-token-value") };
        let got = EnvSource::new()
            .fetch(&locator(&format!("env://{name}")))
            .unwrap();
        assert_eq!(got.as_str(), "gh-token-value");
        unsafe { env::remove_var(name) };
    }

    #[test]
    fn missing_variable_is_a_soft_miss() {
        let name = "STRANDS_TEST_ENV_DEFINITELY_UNSET";
        // Ensure it is unset regardless of ambient environment.
        unsafe { env::remove_var(name) };
        let err = EnvSource::new()
            .fetch(&locator(&format!("env://{name}")))
            .unwrap_err();
        assert!(
            err.is_soft(),
            "a missing env var must be a soft SecretNotFound"
        );
        // The error carries only the redacted reference, never the variable name.
        assert_eq!(
            err.to_string(),
            "no secret found for credential reference: env://[REDACTED]"
        );
    }

    #[test]
    fn denylisted_name_is_refused_hard() {
        // Even if the sensitive variable is actually set, env:// must refuse to read it.
        // SAFETY: unique to this test's assertion; removed immediately after.
        unsafe { env::set_var("AWS_SECRET_ACCESS_KEY", "should-never-be-read") };
        let err = EnvSource::new()
            .fetch(&locator("env://AWS_SECRET_ACCESS_KEY"))
            .unwrap_err();
        unsafe { env::remove_var("AWS_SECRET_ACCESS_KEY") };
        assert!(
            !err.is_soft(),
            "a denylisted name must fail closed, not soft-skip"
        );
        // The refusal must not echo the (real) secret value.
        assert!(!err.to_string().contains("should-never-be-read"));
    }

    #[test]
    fn denylist_is_case_insensitive() {
        assert!(EnvSource::is_denied("aws_secret_access_key"));
        assert!(EnvSource::is_denied("Aws_Session_Token"));
        assert!(!EnvSource::is_denied("GITHUB_TOKEN"));
    }

    #[test]
    fn empty_variable_name_is_rejected() {
        // `env://` with no VAR never reaches parse_uri (empty body), so build the locator directly.
        let loc = Locator::Uri("env://".to_string());
        let err = EnvSource::new().fetch(&loc).unwrap_err();
        assert!(!err.is_soft());
    }

    #[test]
    fn structured_reference_is_refused() {
        let fields = [("source", "env"), ("var", "GITHUB_TOKEN")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let loc = Locator::structured(fields).unwrap();
        let err = EnvSource::new().fetch(&loc).unwrap_err();
        assert!(
            !err.is_soft(),
            "a structured block to env:// is a hard config error"
        );
    }

    #[test]
    fn scheme_is_env() {
        assert_eq!(EnvSource::new().scheme(), "env");
    }
}
