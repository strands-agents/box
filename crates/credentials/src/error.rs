//! Fail-closed, typed error model for the vault.

/// Fail-closed, typed error model for the vault.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialError {
    /// A credential could not be produced from its backend (**hard**). The generic hard failure,
    /// and the mapping target for an AWS provider-resolution failure — no AWS-specific variant.
    #[error("credential error: {0}")]
    Credential(String),

    /// The secret a route names was absent at startup (**soft**). The route is reported through
    /// [`Opened::skipped`](crate::Opened::skipped) rather than failing the whole vault. Carries the
    /// *redacted* reference, so the error itself never leaks a locator.
    #[error("no secret found for credential reference: {0}")]
    SecretNotFound(String),

    /// The keystore/keyring backend was unreachable (**hard**). Also the mapping target when an AWS
    /// provider chain is unreachable — again, no AWS-specific variant.
    #[error("keystore access failed: {0}")]
    KeystoreAccess(String),

    /// More than one binding matched the destination (**hard**). The vault never guesses; an
    /// ambiguous match is refused so a credential cannot be attached to the wrong host.
    #[error("ambiguous credential match for destination: {0}")]
    Ambiguous(String),

    /// The route's injection type is unknown or unsupported (**hard**). Refused rather than
    /// emitting an unsigned/unauthenticated request.
    #[error("unsupported inject type: {0}")]
    UnsupportedInjectType(String),
}

impl CredentialError {
    /// Whether this failure is **soft**: the affected route is reported through
    /// [`Opened::skipped`](crate::Opened::skipped) and the vault still comes up. Everything else is
    /// **hard** (fail-closed) — the operation is refused, never silently downgraded. Only
    /// [`SecretNotFound`](CredentialError::SecretNotFound) is soft.
    pub fn is_soft(&self) -> bool {
        matches!(self, CredentialError::SecretNotFound(_))
    }

    /// The severity the diagnostic for this error carries: soft failures are a warning (the route is
    /// skipped), hard failures an error.
    pub(crate) fn severity(&self) -> Severity {
        if self.is_soft() {
            Severity::Warning
        } else {
            Severity::Error
        }
    }
}

/// Convenience alias for the crate's fallible operations.
pub type Result<T> = std::result::Result<T, CredentialError>;

/// Severity of a startup diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Severity {
    /// A soft failure — the affected route was skipped, but the vault came up.
    Warning,
    /// A hard failure.
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact_credential_ref;

    #[test]
    fn error_display_never_leaks_and_is_fail_closed() {
        // Every variant's Display renders only non-secret context — a destination, an inject-type
        // name, or an already-redacted reference — never secret material.
        assert_eq!(
            CredentialError::Credential("provider chain unreachable".into()).to_string(),
            "credential error: provider chain unreachable"
        );
        assert_eq!(
            CredentialError::SecretNotFound(redact_credential_ref("env://GITHUB_TOKEN"))
                .to_string(),
            "no secret found for credential reference: env://[REDACTED]"
        );
        assert_eq!(
            CredentialError::KeystoreAccess("keyring locked".into()).to_string(),
            "keystore access failed: keyring locked"
        );
        assert_eq!(
            CredentialError::Ambiguous("api.github.com".into()).to_string(),
            "ambiguous credential match for destination: api.github.com"
        );
        assert_eq!(
            CredentialError::UnsupportedInjectType("Header".into()).to_string(),
            "unsupported inject type: Header"
        );
    }

    /// The whole reason for one enum: soft (SecretNotFound → skip route) vs hard (fail-closed).
    #[test]
    fn soft_vs_hard_classification() {
        // Soft: a missing secret skips one route, the vault still comes up.
        let soft = CredentialError::SecretNotFound(redact_credential_ref("op://vault/gh/token"));
        assert!(soft.is_soft());
        assert_eq!(soft.severity(), Severity::Warning);

        // Hard (fail-closed): ambiguity and unknown inject type are refusals, not skips.
        for hard in [
            CredentialError::Ambiguous("api.github.com".into()),
            CredentialError::UnsupportedInjectType("Header".into()),
            CredentialError::Credential("x".into()),
            CredentialError::KeystoreAccess("x".into()),
        ] {
            assert!(!hard.is_soft(), "{hard:?} must be hard (fail-closed)");
            assert_eq!(hard.severity(), Severity::Error);
        }
    }
}
