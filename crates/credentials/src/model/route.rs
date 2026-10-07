//! [`RouteSpec`] — the unresolved config-input shape the loader consumes.

use crate::{
    CredentialError, DEFAULT_PHANTOM_PREFIX, DestinationPattern, InjectMode, Locator, Result,
    check_phantom_prefix,
};

/// The `credential_ref` a signed AWS route carries: a placeholder, never dereferenced.
pub(crate) const AWS_SENTINEL_REF: &str = "aws-signed://route";

/// How strictly the vault checks the Phantom_Token before it attaches the Real_Secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PhantomCheck {
    /// Fail closed when the observed placeholder is absent or does not match the binding.
    #[default]
    Strict,
    /// Warn but attach the Real_Secret when the observed placeholder is absent or does not match.
    Advisory,
}

/// Which of the two credential shapes a route is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteKind {
    /// A single secret attached at one location, standing behind a Phantom_Token.
    Opaque {
        /// How the real (vault-resolved) secret is attached to the outbound request.
        inject: InjectMode,
        /// Where the harness has **already placed** the Phantom_Token, so the vault can recognise and
        /// strip it before attaching the real secret. MAY differ from `inject`.
        harness: InjectMode,
        /// How strictly the vault checks the placeholder before it attaches the secret.
        phantom_check: PhantomCheck,
        /// The literal prefix the minted Phantom_Token carries, before its 64 hex chars.
        phantom_prefix: String,
    },
    /// A SigV4-signed AWS route: signed into several headers, so it has no single inject location and
    /// no phantom is minted for it.
    SignedAws {
        /// The structured AWS config block (`source = "aws"`, optional `profile`), interpreted by the
        /// AWS source at signing time.
        config: Locator,
    },
}

/// One unresolved route declaration [`Vault::open`](crate::Vault::open) consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSpec {
    /// Which outbound requests this route applies to (host + path pattern).
    destination: DestinationPattern,
    /// The pointer to the secret this route attaches (either surface form).
    credential_ref: Locator,
    /// Which credential shape this route is.
    kind: RouteKind,
}

impl RouteSpec {
    /// An **opaque** route: one secret, attached at one location, standing behind a Phantom_Token.
    #[must_use]
    pub fn opaque(
        destination: DestinationPattern,
        credential_ref: Locator,
        inject: InjectMode,
    ) -> Self {
        Self {
            destination,
            credential_ref,
            kind: RouteKind::Opaque {
                harness: inject.clone(),
                inject,
                phantom_check: PhantomCheck::Strict,
                phantom_prefix: DEFAULT_PHANTOM_PREFIX.to_string(),
            },
        }
    }

    /// A signed **AWS route** from a destination and its structured AWS config block.
    #[must_use]
    pub fn signed_aws(destination: DestinationPattern, config: Locator) -> Self {
        Self {
            destination,
            credential_ref: Locator::Uri(AWS_SENTINEL_REF.to_string()),
            kind: RouteKind::SignedAws { config },
        }
    }

    /// Declare that the harness places the Phantom_Token somewhere other than where the real secret
    /// attaches.
    pub fn harness_location(mut self, mode: InjectMode) -> Result<Self> {
        if let RouteKind::Opaque {
            harness, inject, ..
        } = &mut self.kind
        {
            if std::mem::discriminant(&mode) != std::mem::discriminant(inject) {
                return Err(CredentialError::Credential(format!(
                    "the harness places the placeholder as {} but the credential attaches as {}: \
                     the vault would look for the phantom somewhere it was never placed",
                    mode.placement_name(),
                    inject.placement_name()
                )));
            }
            *harness = mode;
        }
        Ok(self)
    }

    /// Set how strictly the vault checks this route's Phantom_Token; a signed route ignores it.
    #[must_use]
    pub fn phantom_check(mut self, mode: PhantomCheck) -> Self {
        if let RouteKind::Opaque { phantom_check, .. } = &mut self.kind {
            *phantom_check = mode;
        }
        self
    }

    /// Set the literal prefix this route's minted Phantom_Token carries; a signed route ignores it.
    /// Refuses a prefix that is empty, over-long, or outside the unreserved character set.
    pub fn phantom_prefix(mut self, prefix: impl Into<String>) -> Result<Self> {
        let prefix = prefix.into();
        check_phantom_prefix(&prefix)?;
        if let RouteKind::Opaque { phantom_prefix, .. } = &mut self.kind {
            *phantom_prefix = prefix;
        }
        Ok(self)
    }

    /// Which outbound requests this route governs.
    pub fn destination(&self) -> &DestinationPattern {
        &self.destination
    }

    /// The pointer to this route's secret. Crate-internal: a locator is disclosure-sensitive, and no
    /// consumer needs to read back what it declared.
    pub(crate) fn credential_ref(&self) -> &Locator {
        &self.credential_ref
    }

    /// Which credential shape this route is.
    pub(crate) fn kind(&self) -> &RouteKind {
        &self.kind
    }

    /// A non-secret, log-safe label for this route's destination, for a startup diagnostic.
    pub(crate) fn destination_display(&self) -> String {
        self.destination.as_written()
    }

    /// The route's credential reference rendered for a diagnostic. The reference is disclosure-
    /// sensitive, so this reuses the locator's own redacting `Debug` (scheme kept, body hidden); the
    /// diagnostic constructor redacts again, so no raw locator can reach a log.
    pub(crate) fn reference_display(&self) -> String {
        // The redacting Debug renders e.g. `Uri("op://[REDACTED]")`; extract the inner redacted form
        // so the diagnostic's own `redact_credential_ref` sees a `scheme://…` shape it can key on.
        match &self.credential_ref {
            Locator::Uri(s) => s.clone(),
            Locator::Structured(_) => {
                format!("{}://structured", self.credential_ref.scheme())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Locator;

    fn a_ref() -> Locator {
        Locator::parse_uri("env://GITHUB_TOKEN").unwrap()
    }

    fn header(format: &str) -> InjectMode {
        InjectMode::header(format.to_string(), None).unwrap()
    }

    /// An opaque route defaults its harness location to the inject location — the common
    /// case, where the workload presents the phantom exactly where the real secret will go.
    #[test]
    fn opaque_defaults_harness_location_to_inject() {
        let spec = RouteSpec::opaque(
            DestinationPattern::parse("*.github.com").unwrap(),
            a_ref(),
            header("Bearer {}"),
        );
        match spec.kind() {
            RouteKind::Opaque {
                inject,
                harness,
                phantom_check,
                phantom_prefix,
            } => {
                assert_eq!(inject, harness, "the default is one location, used twice");
                assert_eq!(
                    *phantom_check,
                    PhantomCheck::Strict,
                    "an opaque route defaults to the fail-closed check"
                );
                assert_eq!(
                    phantom_prefix, DEFAULT_PHANTOM_PREFIX,
                    "an opaque route defaults to the strands_box_ prefix"
                );
            }
            other => panic!("expected an opaque route, got {other:?}"),
        }
        assert_eq!(spec.credential_ref(), &a_ref());
    }

    /// A divergent harness location is recorded without disturbing the inject location.
    #[test]
    fn harness_location_overrides_only_the_placeholder_location() {
        let spec = RouteSpec::opaque(
            DestinationPattern::parse("*.github.com").unwrap(),
            a_ref(),
            header("Bearer {}"),
        )
        .harness_location(header("token {}"))
        .expect("two header placements differ only in their details");

        match spec.kind() {
            RouteKind::Opaque {
                inject, harness, ..
            } => {
                assert_eq!(inject, &header("Bearer {}"));
                assert_eq!(harness, &header("token {}"));
            }
            other => panic!("expected an opaque route, got {other:?}"),
        }
    }

    /// The phantom-check builder overrides only the mode, leaving the placements intact.
    #[test]
    fn phantom_check_builder_sets_advisory_mode() {
        let spec = RouteSpec::opaque(
            DestinationPattern::parse("*.github.com").unwrap(),
            a_ref(),
            header("Bearer {}"),
        )
        .phantom_check(PhantomCheck::Advisory);

        match spec.kind() {
            RouteKind::Opaque {
                inject,
                harness,
                phantom_check,
                ..
            } => {
                assert_eq!(inject, harness, "the placements are untouched");
                assert_eq!(*phantom_check, PhantomCheck::Advisory);
            }
            other => panic!("expected an opaque route, got {other:?}"),
        }
    }

    /// The phantom-prefix builder sets the minted prefix, and refuses an unsafe one.
    #[test]
    fn phantom_prefix_builder_sets_the_prefix_and_refuses_unsafe() {
        let spec = RouteSpec::opaque(
            DestinationPattern::parse("*.anthropic.com").unwrap(),
            a_ref(),
            header("Bearer {}"),
        )
        .phantom_prefix("sk-ant-")
        .expect("an unreserved prefix is accepted");
        match spec.kind() {
            RouteKind::Opaque { phantom_prefix, .. } => assert_eq!(phantom_prefix, "sk-ant-"),
            other => panic!("expected an opaque route, got {other:?}"),
        }

        let err = RouteSpec::opaque(
            DestinationPattern::parse("*.anthropic.com").unwrap(),
            a_ref(),
            header("Bearer {}"),
        )
        .phantom_prefix("sk ant")
        .expect_err("a space is outside the unreserved set");
        assert!(!err.is_soft(), "an unsafe prefix fails closed");
    }

    /// The phantom-prefix builder is a no-op on a signed route: it mints no phantom.
    #[test]
    fn phantom_prefix_is_a_no_op_on_a_signed_route() {
        let config = Locator::structured(
            [("source", "aws")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
        .unwrap();
        let spec = RouteSpec::signed_aws(
            DestinationPattern::parse("*.amazonaws.com").unwrap(),
            config,
        );
        let refined = spec
            .clone()
            .phantom_prefix("sk-ant-")
            .expect("a signed route accepts and ignores a prefix");
        assert_eq!(refined, spec, "a signed route has no phantom to prefix");
    }

    /// The phantom-check builder is a no-op on a signed route: there is no placeholder to check.
    #[test]
    fn phantom_check_is_a_no_op_on_a_signed_route() {
        let config = Locator::structured(
            [("source", "aws")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
        .unwrap();
        let spec = RouteSpec::signed_aws(
            DestinationPattern::parse("*.amazonaws.com").unwrap(),
            config,
        );
        let refined = spec.clone().phantom_check(PhantomCheck::Advisory);
        assert_eq!(refined, spec, "a signed route has no placeholder to check");
    }

    /// A harness placement of a different KIND than the inject placement is refused.
    #[test]
    fn a_harness_of_a_different_kind_than_the_inject_is_refused() {
        let err = RouteSpec::opaque(
            DestinationPattern::parse("*.github.com").unwrap(),
            a_ref(),
            header("Bearer {}"),
        )
        .harness_location(InjectMode::url_path("/v1/{}/models").unwrap())
        .expect_err("a url_path harness cannot serve a header inject");

        assert!(!err.is_soft(), "a mismatched pair fails closed");
        let message = err.to_string();
        assert!(
            message.contains("url_path") && message.contains("header"),
            "the error names both placements: {message}"
        );
    }

    /// The signed constructor takes **no** inject mode — a signed route has no single
    /// injection location, and the type is what makes that unrepresentable rather than re-validated.
    #[test]
    fn signed_aws_carries_the_config_block_and_no_inject_location() {
        let config = Locator::structured(
            [("source", "aws"), ("profile", "prod")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
        .unwrap();
        let spec = RouteSpec::signed_aws(
            DestinationPattern::parse("*.amazonaws.com").unwrap(),
            config,
        );

        match spec.kind() {
            RouteKind::SignedAws { config } => assert_eq!(config.scheme(), "aws"),
            other => panic!("expected a signed route, got {other:?}"),
        }
        // Clone + equality round-trip (every component derives Eq).
        assert_eq!(spec.clone(), spec);
    }

    /// `harness_location` on a signed route is a no-op: there is no placeholder to find, so the value
    /// is dropped rather than stored somewhere nothing reads it.
    #[test]
    fn harness_location_is_a_no_op_on_a_signed_route() {
        let config = Locator::structured(
            [("source", "aws")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
        .unwrap();
        let spec = RouteSpec::signed_aws(
            DestinationPattern::parse("*.amazonaws.com").unwrap(),
            config,
        );
        let refined = spec
            .clone()
            .harness_location(InjectMode::basic_auth())
            .expect("a signed route accepts and ignores a harness location");
        assert_eq!(refined, spec, "a signed route has no placeholder location");
    }

    /// The spec is only a pointer — its `Debug` must not leak the locator body (it derives from the
    /// redacting `Locator` Debug).
    #[test]
    fn spec_debug_does_not_leak_locator_body() {
        let spec = RouteSpec::opaque(
            DestinationPattern::parse("api.github.com").unwrap(),
            Locator::parse_uri("op://Private/GitHub/token").unwrap(),
            InjectMode::basic_auth(),
        );
        let rendered = format!("{spec:?}");
        assert!(!rendered.contains("Private"), "got {rendered}");
        assert!(rendered.contains("op://[REDACTED]"), "got {rendered}");
    }
}
