//! [`Backend`] — where a secret comes from, and the one way to dereference a locator.

use zeroize::Zeroizing;

use crate::sources::{EnvSource, FileSource, OnePasswordSource, SecretSource, SourceRegistry};
use crate::{CredentialError, Locator, Result, Secret};

/// The structured-config routing tag the AWS source owns. A locator carrying it resolves to
/// structured session credentials, so it is refused by [`Backend::resolve`].
const AWS_SCHEME: &str = "aws";

/// Which compiled source set a [`Backend`] is.
#[derive(Debug)]
enum Profile {
    /// The local source set (`env://` / `file://` / `op://`), plus structured AWS.
    Local {
        /// The opaque-secret sources, routed by [`Locator::scheme`].
        registry: SourceRegistry,
    },
}

/// Where secrets are fetched from — the compiled swap point, chosen by a named constructor.
#[derive(Debug)]
pub struct Backend {
    profile: Profile,
}

impl Backend {
    /// The local source set: `env://`, `file://`, and `op://`.
    #[must_use]
    pub fn local() -> Self {
        let mut registry = SourceRegistry::new();
        for source in [
            Box::new(EnvSource::new()) as Box<dyn SecretSource>,
            Box::new(FileSource::new()),
            Box::new(OnePasswordSource::new()),
        ] {
            registry
                .register(source)
                .expect("the local sources use distinct schemes");
        }
        Self {
            profile: Profile::Local { registry },
        }
    }

    /// Register an additional [`SecretSource`], returning the backend for chaining.
    #[cfg(test)]
    pub(crate) fn with_source(mut self, source: Box<dyn SecretSource>) -> Result<Self> {
        match &mut self.profile {
            Profile::Local { registry } => registry.register(source)?,
        }
        Ok(self)
    }

    /// Dereference `locator` to its plaintext secret, wiped on drop.
    pub fn resolve(&self, locator: &Locator) -> Result<Zeroizing<String>> {
        // Structured material cannot be a single secret string. Refuse before routing, so the caller
        // needs no knowledge of `CredentialMaterial` to be protected from the confusion.
        if locator.scheme() == AWS_SCHEME {
            return Err(CredentialError::Credential(
                "an aws:// reference resolves to structured session credentials for SigV4 signing, \
                 not a single secret; declare it as a signed route instead"
                    .to_string(),
            ));
        }

        // The value has passed `Secret::new`, so this caller gets the content refusal without
        // holding the crate-internal type: `resolve` is `pub` and has an out-of-crate consumer (the
        // ingress front door), so it cannot return one
        // (docs/design/decisions.md#an-unusable-secret-value-is-unrepresentable).
        self.resolve_secret(locator).map(Secret::into_inner)
    }

    /// The same dereference, keeping the [`Secret`] wrapper — the vault's own load path
    /// (docs/design/decisions.md#an-unusable-secret-value-is-unrepresentable).
    pub(crate) fn resolve_secret(&self, locator: &Locator) -> Result<Secret> {
        if locator.scheme() == AWS_SCHEME {
            return Err(CredentialError::Credential(
                "an aws:// reference resolves to structured session credentials for SigV4 signing, \
                 not a single secret; declare it as a signed route instead"
                    .to_string(),
            ));
        }

        match &self.profile {
            Profile::Local { registry } => registry.fetch(locator),
        }
    }
}

impl Default for Backend {
    fn default() -> Self {
        Self::local()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default profile resolves an `env://` reference to its plaintext.
    #[test]
    fn local_resolves_an_env_reference() {
        // SAFETY (test): the variable is namespaced to this test and removed before it returns.
        unsafe { std::env::set_var("BACKEND_LOCAL_TOKEN", "resolved-secret") };
        let secret = Backend::local()
            .resolve(&Locator::parse_uri("env://BACKEND_LOCAL_TOKEN").unwrap())
            .expect("a set variable resolves");
        assert_eq!(secret.as_str(), "resolved-secret");
        // SAFETY (test): as above.
        unsafe { std::env::remove_var("BACKEND_LOCAL_TOKEN") };
    }

    /// An `aws://` locator is refused rather than resolved to a string.
    #[test]
    fn structured_aws_reference_is_refused() {
        let err = Backend::local()
            .resolve(&Locator::parse_uri("aws://prod").unwrap())
            .expect_err("aws:// is structured, not opaque");
        assert!(!err.is_soft(), "a structured reference must fail closed");
        assert!(
            err.to_string().contains("signed route"),
            "the error should say what to do instead: {err}"
        );
    }

    /// A scheme no compiled source claims fails closed — never a guessed fallback.
    #[test]
    fn unclaimed_scheme_fails_closed() {
        let err = Backend::local()
            .resolve(&Locator::parse_uri("vault://kv/box/key").unwrap())
            .expect_err("no source claims `vault`");
        assert!(!err.is_soft());
        // The scheme is a non-secret source *kind*, so it may appear; the locator body may not.
        let msg = err.to_string();
        assert!(msg.contains("vault"), "got {msg}");
        assert!(!msg.contains("box/key"), "locator body leaked: {msg}");
    }

    /// An absent secret is the crate's one soft failure, so the vault's load path can skip
    /// that route while a single-secret caller can still treat it as fatal.
    #[test]
    fn absent_secret_is_soft() {
        let err = Backend::local()
            .resolve(&Locator::parse_uri("env://BACKEND_DEFINITELY_UNSET").unwrap())
            .expect_err("an unset variable does not resolve");
        assert!(err.is_soft(), "a genuinely absent secret is the soft miss");
    }

    /// A second source claiming a registered scheme is refused, so no source is silently shadowed.
    #[test]
    fn duplicate_scheme_is_refused() {
        let dup = Backend::local().with_source(Box::new(EnvSource::new()));
        assert!(dup.is_err(), "`env` is already claimed by the local set");
    }
}
