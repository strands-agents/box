//! [`VaultConfig`] — the one config value [`Vault::open`] takes.
//!
//! [`Vault::open`]: crate::Vault::open

use std::path::PathBuf;

use crate::sources::{AmbientFallbackPolicy, AwsExecutionRoleResolver};
use crate::{Backend, RouteSpec};

/// How a route that cannot be resolved is treated at open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MissingRoutePolicy {
    /// Report an unresolvable route through [`Opened::skipped`](crate::Opened::skipped) and bring the
    /// vault up without it.
    Skip,
    /// Treat any unresolvable route as a hard failure, aborting the open.
    Refuse,
}

/// The declaration a [`Vault`](crate::Vault) is opened from.
#[derive(Debug)]
pub struct VaultConfig {
    /// Where secrets are fetched from.
    backend: Backend,
    /// The tenant every credential in the opened vault belongs to.
    tenant: String,
    /// The declared routes, in declaration order.
    routes: Vec<RouteSpec>,
    /// Whether an unresolvable route is skipped or fatal.
    missing: MissingRoutePolicy,
    /// Whether a signed route may fall back to the ambient AWS provider chain.
    ambient: AmbientFallbackPolicy,
    /// The `credsd` socket a `credsd://` route connects to. `None` means the default
    /// resolution: `CREDSD_SOCKET`, else the platform default path.
    credsd_socket: Option<PathBuf>,
    /// The box-supplied resolver for the host execution-role tokens (`aws://@instance-role`,
    /// `aws://@container-role`). `None` means a route naming such a token fails closed, rather than
    /// substitute an ambient identity.
    aws_execution_role_resolver: Option<AwsExecutionRoleResolver>,
}

impl VaultConfig {
    /// A config for `tenant`, resolving secrets through `backend`, with no routes yet.
    #[must_use]
    pub fn new(backend: Backend, tenant: impl Into<String>) -> Self {
        Self {
            backend,
            tenant: tenant.into(),
            routes: Vec::new(),
            missing: MissingRoutePolicy::Skip,
            ambient: AmbientFallbackPolicy::default(),
            credsd_socket: None,
            aws_execution_role_resolver: None,
        }
    }

    /// Supply the resolver the box built from the AWS SDK for the host execution-role tokens.
    ///
    /// With no resolver, a route that names `aws://@instance-role` or `aws://@container-role` is a
    /// hard failure, never an ambient substitute.
    #[must_use]
    pub fn aws_execution_role_resolver(mut self, resolver: AwsExecutionRoleResolver) -> Self {
        self.aws_execution_role_resolver = Some(resolver);
        self
    }

    /// Declare the `credsd` socket every `credsd://` route in this vault connects to.
    ///
    /// A caller with no path leaves the default resolution in force: `CREDSD_SOCKET`, else the
    /// platform default. A relative resolved path is refused when the vault opens.
    #[must_use]
    pub fn credsd_socket(mut self, path: impl Into<PathBuf>) -> Self {
        self.credsd_socket = Some(path.into());
        self
    }

    /// Require every signed AWS route to declare a scoped profile: a route with none is a hard failure
    /// at signing time rather than a request signed from the host's ambient credential chain.
    #[must_use]
    pub fn require_scoped_aws_profile(mut self) -> Self {
        self.ambient = AmbientFallbackPolicy::Deny;
        self
    }

    /// Declare one route.
    #[must_use]
    pub fn route(mut self, route: RouteSpec) -> Self {
        self.routes.push(route);
        self
    }

    /// Declare every route at once, from any iterator of routes.
    #[must_use]
    pub fn routes(mut self, routes: impl IntoIterator<Item = RouteSpec>) -> Self {
        self.routes.extend(routes);
        self
    }

    /// Require that **every** declared route resolves: an absent secret aborts the open instead of
    /// being reported as skipped.
    #[must_use]
    pub fn require_every_route(mut self) -> Self {
        self.missing = MissingRoutePolicy::Refuse;
        self
    }

    /// Split into the parts `open` consumes.
    pub(crate) fn into_parts(self) -> VaultParts {
        VaultParts {
            backend: self.backend,
            tenant: self.tenant,
            routes: self.routes,
            missing: self.missing,
            ambient: self.ambient,
            credsd_socket: self.credsd_socket,
            aws_execution_role_resolver: self.aws_execution_role_resolver,
        }
    }
}

/// The parts [`Vault::open`](crate::Vault::open) consumes from a [`VaultConfig`]. A struct, not a
/// tuple, because the parts outgrew a readable tuple.
pub(crate) struct VaultParts {
    pub(crate) backend: Backend,
    pub(crate) tenant: String,
    pub(crate) routes: Vec<RouteSpec>,
    pub(crate) missing: MissingRoutePolicy,
    pub(crate) ambient: AmbientFallbackPolicy,
    pub(crate) credsd_socket: Option<PathBuf>,
    pub(crate) aws_execution_role_resolver: Option<AwsExecutionRoleResolver>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DestinationPattern, InjectMode, Locator};

    fn route(dest: &str) -> RouteSpec {
        RouteSpec::opaque(
            DestinationPattern::parse(dest).unwrap(),
            Locator::parse_uri("env://T").unwrap(),
            InjectMode::basic_auth(),
        )
    }

    /// The default is the soft tier: an absent secret is reported, not fatal.
    #[test]
    fn default_policy_skips_a_missing_route() {
        let parts = VaultConfig::new(Backend::local(), "tenant-a")
            .route(route("api.github.com"))
            .into_parts();
        assert_eq!(parts.tenant, "tenant-a");
        assert_eq!(parts.routes.len(), 1);
        assert_eq!(parts.missing, MissingRoutePolicy::Skip);
    }

    /// `require_every_route` flips the switch the supervisors need.
    #[test]
    fn require_every_route_refuses_a_missing_route() {
        let parts = VaultConfig::new(Backend::local(), "t")
            .require_every_route()
            .into_parts();
        assert_eq!(parts.missing, MissingRoutePolicy::Refuse);
    }

    /// The ambient-fallback default is allowed-with-warning; the switch tightens it to Deny.
    #[test]
    fn require_scoped_aws_profile_denies_ambient_fallback() {
        let default = VaultConfig::new(Backend::local(), "t").into_parts();
        assert_eq!(default.ambient, AmbientFallbackPolicy::AllowWithWarning);

        let tightened = VaultConfig::new(Backend::local(), "t")
            .require_scoped_aws_profile()
            .into_parts();
        assert_eq!(tightened.ambient, AmbientFallbackPolicy::Deny);
    }

    /// The credsd socket defaults to absent (default resolution) and the builder retains a path.
    #[test]
    fn credsd_socket_defaults_absent_and_is_retained_when_set() {
        let default = VaultConfig::new(Backend::local(), "t").into_parts();
        assert_eq!(
            default.credsd_socket, None,
            "an unset socket means default resolution"
        );

        let set = VaultConfig::new(Backend::local(), "t")
            .credsd_socket("/var/run/credsd/credsd.sock")
            .into_parts();
        assert_eq!(
            set.credsd_socket.as_deref(),
            Some(std::path::Path::new("/var/run/credsd/credsd.sock"))
        );
    }

    /// The execution-role resolver defaults to absent and the builder retains one.
    #[test]
    fn aws_execution_role_resolver_defaults_absent_and_is_retained_when_set() {
        let default = VaultConfig::new(Backend::local(), "t").into_parts();
        assert!(
            default.aws_execution_role_resolver.is_none(),
            "no resolver means an execution-role token fails closed"
        );

        let set = VaultConfig::new(Backend::local(), "t")
            .aws_execution_role_resolver(crate::AwsExecutionRoleResolver::new(|_kind| {
                Err(crate::CredentialError::Credential("unused".into()))
            }))
            .into_parts();
        assert!(set.aws_execution_role_resolver.is_some());
    }

    /// `routes` is `route` in bulk — the two produce the same declaration.
    #[test]
    fn bulk_routes_matches_repeated_route_calls() {
        let one = VaultConfig::new(Backend::local(), "t")
            .route(route("a.example.com"))
            .route(route("b.example.com"))
            .into_parts()
            .routes;
        let many = VaultConfig::new(Backend::local(), "t")
            .routes([route("a.example.com"), route("b.example.com")])
            .into_parts()
            .routes;
        assert_eq!(one, many);
    }
}
