//! Startup-miss diagnostics and the reference-redaction helper.

use crate::error::{CredentialError, Severity};
use crate::sources::CREDSD_SCHEME;

/// Redact a credential reference for display/audit.
///
/// A `credsd://<environment>` reference keeps its body: the environment is a non-secret routing
/// label the operator authors in cleartext, and the acquisition audit must name it. Every other
/// scheme's body is disclosure-sensitive and is redacted.
pub(crate) fn redact_credential_ref(reference: &str) -> String {
    match reference.split_once("://") {
        Some((scheme, environment)) if scheme == CREDSD_SCHEME => {
            format!("{scheme}://{environment}")
        }
        Some((scheme, _)) if !scheme.is_empty() => format!("{scheme}://[REDACTED]"),
        _ => "[REDACTED]".to_string(),
    }
}

/// A startup-miss diagnostic: one route could not be loaded, but the vault came up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CredentialDiagnostic {
    /// Stable, machine-readable code, e.g. `"secret_not_found"`.
    pub code: String,
    /// Whether the affected route was skipped ([`Severity::Warning`]) or hard-failed.
    pub severity: Severity,
    /// The route (destination prefix) that was skipped — non-secret, safe to log.
    pub route_prefix: String,
    /// The credential reference, **already redacted** for display — never the raw locator/secret.
    pub credential_ref: String,
    /// Human-readable summary of what went wrong.
    pub message: String,
    /// Actionable hint for the operator (e.g. "set GITHUB_TOKEN in the environment").
    pub hint: String,
}

impl CredentialDiagnostic {
    /// Build a diagnostic, deriving `severity` from `error` and redacting `credential_ref` at
    /// construction (via `redact_credential_ref`) so the stored value can never be the raw
    /// locator. This is the only constructor callers should use to record a startup miss, so
    /// redaction is not an easy-to-forget step.
    pub(crate) fn new(
        code: impl Into<String>,
        error: &CredentialError,
        route_prefix: impl Into<String>,
        credential_ref: &str,
        message: impl Into<String>,
        hint: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            severity: error.severity(),
            route_prefix: route_prefix.into(),
            credential_ref: redact_credential_ref(credential_ref),
            message: message.into(),
            hint: hint.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_credential_ref_keeps_scheme_hides_locator() {
        // The source kind survives (useful in a diagnostic); the specific locator does not.
        assert_eq!(
            redact_credential_ref("op://vault/item/field"),
            "op://[REDACTED]"
        );
        assert_eq!(
            redact_credential_ref("env://GITHUB_TOKEN"),
            "env://[REDACTED]"
        );
        assert_eq!(
            redact_credential_ref("file:///etc/secret"),
            "file://[REDACTED]"
        );
        // No scheme (or an empty one) → nothing is assumed safe: redact wholesale.
        assert_eq!(redact_credential_ref("GITHUB_TOKEN"), "[REDACTED]");
        assert_eq!(redact_credential_ref("://orphan"), "[REDACTED]");
    }

    /// A credsd reference keeps its environment: it is a non-secret routing label the audit names,
    /// unlike every other scheme's body.
    #[test]
    fn redact_credential_ref_keeps_the_credsd_environment() {
        assert_eq!(
            redact_credential_ref("credsd://prod-inference"),
            "credsd://prod-inference"
        );
        // The exception is scoped to credsd; a lookalike scheme is still redacted.
        assert_eq!(
            redact_credential_ref("credsdx://secret"),
            "credsdx://[REDACTED]"
        );
    }

    /// A startup miss builds a soft, self-redacting diagnostic — a route is skipped, not fatal.
    #[test]
    fn diagnostic_is_soft_and_self_redacting() {
        let err = CredentialError::SecretNotFound(redact_credential_ref("env://GITHUB_TOKEN"));
        let diag = CredentialDiagnostic::new(
            "secret_not_found",
            &err,
            "api.github.com",
            "env://GITHUB_TOKEN",
            "GITHUB_TOKEN is not set; skipping this route",
            "export GITHUB_TOKEN before starting the vault",
        );
        assert_eq!(diag.severity, Severity::Warning);
        assert_eq!(diag.code, "secret_not_found");
        assert_eq!(diag.route_prefix, "api.github.com");
        // The reference is redacted at construction — the raw var name never survives.
        assert_eq!(diag.credential_ref, "env://[REDACTED]");
        assert!(!diag.credential_ref.contains("GITHUB_TOKEN"));
    }
}
