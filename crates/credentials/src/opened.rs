//! What [`Vault::open`] returns: the vault plus its two startup obligations.
//!
//! [`Vault::open`]: crate::Vault::open

use crate::{CredentialDiagnostic, DestinationPattern, PhantomToken, Vault};

/// A minted Phantom_Token paired with the destination it stands in for.
#[derive(Debug, Clone)]
pub struct Phantom {
    destination: DestinationPattern,
    token: PhantomToken,
}

impl Phantom {
    pub(crate) fn new(destination: DestinationPattern, token: PhantomToken) -> Self {
        Self { destination, token }
    }

    /// The destination pattern whose credential this phantom stands in for.
    pub fn destination(&self) -> &DestinationPattern {
        &self.destination
    }

    /// The token itself (`<prefix><64hex>`, default prefix `strands_box_`), for seeding into the
    /// workload's environment.
    pub fn token(&self) -> &str {
        self.token.as_str()
    }
}

/// One route the vault could not load, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    diagnostic: CredentialDiagnostic,
}

impl Skipped {
    pub(crate) fn new(diagnostic: CredentialDiagnostic) -> Self {
        Self { diagnostic }
    }

    /// The destination that was skipped — non-secret, safe to log.
    pub fn destination(&self) -> &str {
        &self.diagnostic.route_prefix
    }

    /// The stable, machine-readable code, e.g. `"secret_not_found"`.
    pub fn code(&self) -> &str {
        &self.diagnostic.code
    }

    /// A human-readable summary of what went wrong.
    pub fn message(&self) -> &str {
        &self.diagnostic.message
    }

    /// An actionable hint for the operator.
    pub fn hint(&self) -> &str {
        &self.diagnostic.hint
    }
}

impl std::fmt::Display for Skipped {
    /// `code: message (hint)` — the line three call sites used to build by hand.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{code}: {message} ({hint})",
            code = self.code(),
            message = self.message(),
            hint = self.hint()
        )
    }
}

/// The outcome of [`Vault::open`](crate::Vault::open): the vault and its two
/// startup obligations.
#[must_use = "the vault, its phantoms, and its skipped routes are all startup obligations"]
#[derive(Debug)]
pub struct Opened {
    vault: Vault,
    phantoms: Vec<Phantom>,
    skipped: Vec<Skipped>,
}

impl Opened {
    pub(crate) fn new(vault: Vault, phantoms: Vec<Phantom>, skipped: Vec<Skipped>) -> Self {
        Self {
            vault,
            phantoms,
            skipped,
        }
    }

    /// One phantom per opaque route the vault resolved, in declaration order.
    pub fn phantoms(&self) -> &[Phantom] {
        &self.phantoms
    }

    /// One entry per route whose secret was absent. Empty when every route loaded, and always empty
    /// when the config declared [`require_every_route`](crate::VaultConfig::require_every_route) —
    /// that switch turns a skip into a hard error instead.
    pub fn skipped(&self) -> &[Skipped] {
        &self.skipped
    }

    /// Take the vault, discarding the startup reports.
    pub fn into_vault(self) -> Vault {
        self.vault
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CredentialError;

    fn diagnostic() -> CredentialDiagnostic {
        CredentialDiagnostic::new(
            "secret_not_found",
            &CredentialError::SecretNotFound("env://[REDACTED]".to_string()),
            "api.github.com",
            "env://GITHUB_TOKEN",
            "GITHUB_TOKEN is not set; skipping this route",
            "export GITHUB_TOKEN before starting the vault",
        )
    }

    /// `Display` renders the `code: message (hint)` line the call sites used to duplicate, and never
    /// leaks the reference body.
    #[test]
    fn skipped_display_is_the_one_line_callers_used_to_build() {
        let skipped = Skipped::new(diagnostic());
        let rendered = skipped.to_string();
        assert_eq!(
            rendered,
            "secret_not_found: GITHUB_TOKEN is not set; skipping this route \
             (export GITHUB_TOKEN before starting the vault)"
        );
        assert_eq!(skipped.destination(), "api.github.com");
    }

    /// A phantom pairs a non-secret token with the destination it stands in for.
    #[test]
    fn phantom_exposes_its_destination_and_token() {
        let token = PhantomToken::generate(crate::DEFAULT_PHANTOM_PREFIX).unwrap();
        let phantom = Phantom::new(
            DestinationPattern::parse("api.github.com").unwrap(),
            token.clone(),
        );
        assert_eq!(phantom.token(), token.as_str());
        assert!(phantom.token().starts_with("strands_box_"));
        assert_eq!(
            phantom.destination(),
            &DestinationPattern::parse("api.github.com").unwrap()
        );
    }
}
