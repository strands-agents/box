//! Credential **sources** — where a secret is fetched from, and the table that routes to one.
//!
//! [`RouteSpec`]: crate::RouteSpec

use std::collections::HashMap;

use crate::{CredentialError, Locator, Result, Secret};

mod aws;
mod aws_profile;
mod credsd;
mod env;
mod file;
mod op;

pub(crate) use aws::{
    AmbientFallbackPolicy, AwsAcquisition, AwsResolution, AwsSource, credsd_session_credentials,
    sign_request,
};
pub(crate) use credsd::{CREDSD_SCHEME, CredsdClient, resolve_credsd_socket};
pub(crate) use env::EnvSource;
pub(crate) use file::FileSource;
pub(crate) use op::OnePasswordSource;

/// Return the raw URI-form reference string (`scheme://body`) for a URI-form locator.
pub(crate) fn uri_reference<'a>(loc: &'a Locator, scheme: &str) -> Result<&'a str> {
    match loc {
        Locator::Uri(s) => Ok(s.as_str()),
        Locator::Structured(_) => Err(CredentialError::Credential(format!(
            "{scheme}:// source expects a URI-form reference, not a structured block"
        ))),
    }
}

/// A credential *source*: the extension point for *where* a static secret is fetched from.
pub(crate) trait SecretSource: Send + Sync {
    /// The routing key this source handles — the URI scheme or structured `source` tag, e.g.
    /// `"env"`, `"file"`, `"op"`. The registry dispatches by comparing this against
    /// [`Locator::scheme`]. It is `&'static str` (not `&str`) so it stays object-safe and
    /// so a source's identity is a compile-time constant.
    fn scheme(&self) -> &'static str;

    /// Parse+validate the locator and fetch the secret as a [`Secret`]
    /// (docs/design/decisions.md#an-unusable-secret-value-is-unrepresentable).
    fn fetch(&self, loc: &Locator) -> Result<Secret>;
}

/// A scheme→source registry: routes a reference to the source whose [`scheme`](SecretSource::scheme)
/// matches, then calls its [`fetch`](SecretSource::fetch).
#[derive(Default)]
pub(crate) struct SourceRegistry {
    sources: HashMap<&'static str, Box<dyn SecretSource>>,
}

impl SourceRegistry {
    /// An empty registry. Register the v1 sources (`env` / `file` / `op`) — and any deferred ones —
    /// with [`register`](Self::register).
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Register `source` under its own [`scheme`](SecretSource::scheme).
    pub(crate) fn register(&mut self, source: Box<dyn SecretSource>) -> Result<()> {
        let scheme = source.scheme();
        if self.sources.contains_key(scheme) {
            return Err(CredentialError::Credential(format!(
                "duplicate credential source registered for scheme {scheme:?}"
            )));
        }
        self.sources.insert(scheme, source);
        Ok(())
    }

    /// Whether a source is registered for `scheme` (the routing key, not a full reference).
    #[cfg(test)]
    pub(crate) fn contains(&self, scheme: &str) -> bool {
        self.sources.contains_key(scheme)
    }

    /// Route `loc` to the source whose scheme matches [`Locator::scheme`], and fetch.
    pub(crate) fn fetch(&self, loc: &Locator) -> Result<Secret> {
        let scheme = loc.scheme();
        match self.sources.get(scheme) {
            Some(source) => source.fetch(loc),
            None => Err(CredentialError::Credential(format!(
                "no credential source registered for scheme {scheme:?}"
            ))),
        }
    }
}

impl std::fmt::Debug for SourceRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Sources hold no secret material, but list only their (non-secret) schemes so the output
        // stays a stable, useful audit line regardless of the boxed implementations.
        let mut schemes: Vec<&&'static str> = self.sources.keys().collect();
        schemes.sort_unstable();
        f.debug_struct("SourceRegistry")
            .field("schemes", &schemes)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal source used to prove object-safety, registration, and routing without any real
    /// backend. `fetch` echoes a canned secret so the registry's dispatch is what's under test.
    struct StubSource {
        scheme: &'static str,
        secret: &'static str,
    }

    impl SecretSource for StubSource {
        fn scheme(&self) -> &'static str {
            self.scheme
        }

        fn fetch(&self, _loc: &Locator) -> Result<Secret> {
            Secret::new(
                zeroize::Zeroizing::new(self.secret.to_string()),
                "test://stub",
            )
        }
    }

    /// A source that always reports a soft miss, to prove the registry propagates the source's own
    /// error variant unchanged (rather than remapping it).
    struct MissingSource;

    impl SecretSource for MissingSource {
        fn scheme(&self) -> &'static str {
            "env"
        }

        fn fetch(&self, _loc: &Locator) -> Result<Secret> {
            Err(CredentialError::SecretNotFound(
                crate::redact_credential_ref("env://GITHUB_TOKEN"),
            ))
        }
    }

    fn registry_with(sources: Vec<Box<dyn SecretSource>>) -> SourceRegistry {
        let mut reg = SourceRegistry::new();
        for s in sources {
            reg.register(s).expect("test sources use distinct schemes");
        }
        reg
    }

    /// The trait is object-safe (a `Box<dyn SecretSource>` compiles and is callable) and the
    /// registry routes a reference to the source whose `scheme()` matches, then calls `fetch()`.
    #[test]
    fn registry_routes_to_matching_source_by_scheme() {
        let reg = registry_with(vec![
            Box::new(StubSource {
                scheme: "env",
                secret: "env-secret",
            }),
            Box::new(StubSource {
                scheme: "file",
                secret: "file-secret",
            }),
        ]);

        // A `Uri` reference routes on its scheme prefix …
        let env_ref = Locator::parse_uri("env://GITHUB_TOKEN").unwrap();
        assert_eq!(reg.fetch(&env_ref).unwrap().as_str(), "env-secret");

        let file_ref = Locator::parse_uri("file:///etc/token").unwrap();
        assert_eq!(reg.fetch(&file_ref).unwrap().as_str(), "file-secret");
    }

    /// A structured reference routes on its `source` tag, exactly like a URI scheme — the registry
    /// treats both surface forms uniformly.
    #[test]
    fn registry_routes_structured_reference_by_source_tag() {
        let reg = registry_with(vec![Box::new(StubSource {
            scheme: "aws",
            secret: "aws-secret",
        })]);

        let fields = [("source", "aws"), ("profile", "prod")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let aws_ref = Locator::structured(fields).unwrap();
        assert_eq!(reg.fetch(&aws_ref).unwrap().as_str(), "aws-secret");
    }

    /// An unclaimed scheme is a hard, fail-closed error — never a guess or a silent skip.
    #[test]
    fn registry_fails_closed_on_unregistered_scheme() {
        let reg = registry_with(vec![Box::new(StubSource {
            scheme: "env",
            secret: "x",
        })]);

        let op_ref = Locator::parse_uri("op://Private/GitHub/token").unwrap();
        let err = reg.fetch(&op_ref).unwrap_err();
        assert!(!err.is_soft(), "an unroutable reference must fail closed");
        // The scheme (a non-secret source kind) may appear; the locator body must not.
        let msg = err.to_string();
        assert!(msg.contains("op"), "got {msg}");
        assert!(!msg.contains("Private"), "locator body leaked: {msg}");
    }

    /// Registering a second source for an already-claimed scheme is refused (fail-closed), so a
    /// source can never be silently shadowed.
    #[test]
    fn register_rejects_duplicate_scheme() {
        let mut reg = SourceRegistry::new();
        reg.register(Box::new(StubSource {
            scheme: "env",
            secret: "first",
        }))
        .unwrap();

        let dup = reg.register(Box::new(StubSource {
            scheme: "env",
            secret: "second",
        }));
        assert!(dup.is_err(), "duplicate scheme must be rejected");
        assert!(!dup.unwrap_err().is_soft());

        // The first source is untouched — the duplicate did not shadow it.
        let env_ref = Locator::parse_uri("env://X").unwrap();
        assert_eq!(reg.fetch(&env_ref).unwrap().as_str(), "first");
    }

    /// The registry propagates the source's own error variant unchanged — a soft miss stays soft.
    #[test]
    fn registry_propagates_source_error_unchanged() {
        let reg = registry_with(vec![Box::new(MissingSource)]);
        let env_ref = Locator::parse_uri("env://GITHUB_TOKEN").unwrap();
        let err = reg.fetch(&env_ref).unwrap_err();
        assert!(err.is_soft(), "a source's soft miss must stay soft");
    }

    #[test]
    fn contains_reports_registered_schemes() {
        let reg = registry_with(vec![Box::new(StubSource {
            scheme: "env",
            secret: "x",
        })]);
        assert!(reg.contains("env"));
        assert!(!reg.contains("op"));
    }

    /// `Debug` lists only the (non-secret) schemes and never reaches into a source's material.
    #[test]
    fn registry_debug_lists_schemes_only() {
        let reg = registry_with(vec![
            Box::new(StubSource {
                scheme: "file",
                secret: "top-secret-value",
            }),
            Box::new(StubSource {
                scheme: "env",
                secret: "another-secret",
            }),
        ]);
        let rendered = format!("{reg:?}");
        assert!(rendered.contains("env"), "got {rendered}");
        assert!(rendered.contains("file"), "got {rendered}");
        assert!(
            !rendered.contains("secret-value"),
            "secret leaked: {rendered}"
        );
    }
}
