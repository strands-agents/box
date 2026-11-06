//! The tenant-keyed [`Vault`] — one startup door and two request-leg verbs.

use std::path::{Path, PathBuf};

use crate::attach::{Attachment, Inbound, Outbound, Redactions};
use crate::config::MissingRoutePolicy;
use crate::model::RouteKind;
use crate::sources::{AmbientFallbackPolicy, CREDSD_SCHEME, resolve_credsd_socket};
use crate::{
    Backend, CredentialDiagnostic, CredentialError, Destination, DestinationPattern, InjectMode,
    Locator, Opened, Phantom, PhantomCheck, PhantomToken, RequestId, Result, RouteSpec, Secret,
    Skipped, VaultConfig,
};

/// The correlation id the eager load uses for its audit records.
const LOAD_CORRELATION: &str = "credential-store-load";

/// The `cmd://` scheme, refused at open because no request-time capture path is wired.
const CMD_SCHEME: &str = "cmd";

/// The deferred-mint scheme an operator config could once name.
const OAUTH2_SCHEME: &str = "oauth2";

/// One resolved opaque binding: the secret, how it attaches, and the phantom standing in for it.
pub(crate) struct OpaqueBinding {
    /// How the real secret attaches to the outbound request.
    inject: InjectMode,
    /// Where the harness placed the phantom, so it can be recognised and stripped.
    harness: InjectMode,
    /// The resolved secret, wiped on drop and validated at construction
    /// (docs/design/decisions.md#an-unusable-secret-value-is-unrepresentable).
    secret: Secret,
    /// The phantom minted to stand in for this secret.
    phantom: PhantomToken,
    /// How strictly `swap_phantom` checks the placeholder before it attaches the secret.
    phantom_check: PhantomCheck,
}

impl OpaqueBinding {
    /// How the real secret attaches to the outbound request.
    pub(crate) fn inject(&self) -> &InjectMode {
        &self.inject
    }

    /// Where the harness placed the phantom, so it can be recognised and stripped.
    pub(crate) fn harness(&self) -> &InjectMode {
        &self.harness
    }

    /// The resolved plaintext. `pub(crate)` and nothing more, so no accessor for it exists
    /// outside the crate.
    pub(crate) fn secret(&self) -> &str {
        self.secret.as_str()
    }

    /// The resolved secret itself, for the response leg's scan.
    pub(crate) fn secret_value(&self) -> &Secret {
        &self.secret
    }

    /// The phantom minted to stand in for this secret (non-secret, unguessable).
    pub(crate) fn phantom(&self) -> &str {
        self.phantom.as_str()
    }

    /// How strictly `swap_phantom` checks the placeholder before attaching the secret.
    pub(crate) fn phantom_check(&self) -> PhantomCheck {
        self.phantom_check
    }
}

impl std::fmt::Debug for OpaqueBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Non-secret routing fields print in the clear; the plaintext renders `[REDACTED]`. The
        // phantom is non-secret, so it prints — a diagnostic can pair it with the secret it stands for.
        f.debug_struct("OpaqueBinding")
            .field("inject", &self.inject)
            .field("harness", &self.harness)
            .field("secret", &"[REDACTED]")
            .field("phantom", &self.phantom)
            .field("phantom_check", &self.phantom_check)
            .finish()
    }
}

/// The loaded credential set for one tenant.
#[derive(Debug)]
pub struct Vault {
    /// The tenant every binding here belongs to. Held for the vault's lifetime and never consulted
    /// while matching — isolation is by instance.
    tenant: String,
    /// destination pattern → resolved opaque binding.
    opaque: Vec<(DestinationPattern, OpaqueBinding)>,
    /// destination pattern → the structured AWS config a signed route signs with.
    signed_aws: Vec<(DestinationPattern, Locator)>,
    /// The backend, retained because a signed route resolves its credentials per request (they
    /// expire), unlike an opaque secret which is resolved once at open.
    backend: Backend,
    /// Whether a signed route may fall back to the ambient AWS provider chain when it declares no
    /// scoped profile. Held here because the resolve happens per request, so the policy has to outlive
    /// the open that chose it.
    ambient_policy: AmbientFallbackPolicy,
    /// The acquisition-audit sink. Every resolve emits one record through it, success or
    /// failure; the default discards, since the shared L2 lane does not exist yet.
    emitter: Box<dyn crate::Emitter>,
    /// The resolved absolute `credsd` socket a `credsd://` route connects to, retained because the
    /// resolve happens per request. `Some` only when a `credsd://` route was declared.
    credsd_socket: Option<PathBuf>,
}

impl Vault {
    /// Resolve every declared route and open the vault.
    pub fn open(config: VaultConfig) -> Result<Opened> {
        Self::open_with_emitter(config, Box::new(crate::audit::DiscardingEmitter))
    }

    /// [`open`](Self::open) with the audit sink supplied, so a test can observe that every resolve
    /// emits exactly one record. The public entry point injects the discarding sink; when the shared L2
    /// audit lane lands it is substituted here rather than added as a new path.
    fn open_with_emitter(config: VaultConfig, emitter: Box<dyn crate::Emitter>) -> Result<Opened> {
        let (backend, tenant, routes, missing, ambient_policy, credsd_socket_config) =
            config.into_parts();
        let mut vault = Self {
            tenant,
            opaque: Vec::new(),
            signed_aws: Vec::new(),
            backend,
            ambient_policy,
            emitter,
            credsd_socket: None,
        };
        // A `credsd://` route needs a socket, resolved and validated absolute once here — a relative
        // path is a configuration error the vault refuses at open, not a runtime failure.
        let mut declares_credsd = false;
        let mut phantoms = Vec::new();
        let mut skipped = Vec::new();
        // Every minted phantom, to enforce vault-wide uniqueness: a collision is a
        // fail-closed error, never two credentials sharing one placeholder.
        let mut seen_phantoms = std::collections::HashSet::new();

        for route in &routes {
            // Refuse before dispatching, so no branch can claim a route first and leave an unsupported
            // field unread.
            Self::refuse_unsupported(route)?;

            let (inject, harness, phantom_check, phantom_prefix) = match route.kind() {
                // A signed route carries a config block resolved at use, not a secret held here.
                RouteKind::SignedAws { config } => {
                    if config.scheme() == CREDSD_SCHEME {
                        declares_credsd = true;
                    }
                    vault
                        .signed_aws
                        .push((route.destination().clone(), config.clone()));
                    continue;
                }
                RouteKind::Opaque {
                    inject,
                    harness,
                    phantom_check,
                    phantom_prefix,
                } => (
                    inject.clone(),
                    harness.clone(),
                    *phantom_check,
                    phantom_prefix.clone(),
                ),
            };

            match vault.resolve_secret(route) {
                Ok(secret) => {
                    // Mint a unique phantom for the resolved secret. Generation failure or a
                    // vault-wide collision fails closed — never a weak or duplicated value.
                    let phantom = PhantomToken::generate(&phantom_prefix)?;
                    if !seen_phantoms.insert(phantom.as_str().to_string()) {
                        return Err(CredentialError::Credential(
                            "phantom-token collision across the vault; refusing to bind two \
                             credentials to one placeholder"
                                .to_string(),
                        ));
                    }
                    phantoms.push(Phantom::new(route.destination().clone(), phantom.clone()));
                    vault.opaque.push((
                        route.destination().clone(),
                        OpaqueBinding {
                            inject,
                            harness,
                            secret,
                            phantom,
                            phantom_check,
                        },
                    ));
                }
                // A genuinely absent secret is the one soft failure — unless the caller asked for no
                // soft tier, in which case it is fatal like everything else.
                Err(err) if err.is_soft() && missing == MissingRoutePolicy::Skip => {
                    skipped.push(Skipped::new(CredentialDiagnostic::new(
                        "secret_not_found",
                        &err,
                        route.destination_display(),
                        &route.reference_display(),
                        format!("{err}"),
                        "ensure the referenced secret exists before opening the vault",
                    )));
                }
                Err(err) if err.is_soft() => {
                    // `require_every_route`: name the destination, since the caller wanted no skips.
                    return Err(CredentialError::Credential(format!(
                        "{destination} declares a credential that did not resolve ({err}), and \
                         every route is required: the destination would stay reachable with no \
                         credential attached",
                        destination = route.destination_display(),
                    )));
                }
                Err(err) => return Err(err),
            }
        }

        if declares_credsd {
            vault.credsd_socket = Some(resolve_credsd_socket(credsd_socket_config.as_deref())?);
        }

        Ok(Opened::new(vault, phantoms, skipped))
    }

    /// Refuse a route naming a credential this vault has no way to produce.
    fn refuse_unsupported(route: &RouteSpec) -> Result<()> {
        let scheme = route.credential_ref().scheme();
        let unsupported = match scheme {
            CMD_SCHEME => Some("request-time capture is not wired"),
            OAUTH2_SCHEME => Some("no token-exchange lifecycle is wired"),
            _ => None,
        };
        if let Some(reason) = unsupported {
            return Err(CredentialError::Credential(format!(
                "{destination} names a `{scheme}://` credential, which this vault cannot produce: \
                 {reason}, so the route would send an uncredentialed request. Use an `env://`, \
                 `file://`, or `op://` reference instead.",
                destination = route.destination_display(),
            )));
        }
        Ok(())
    }

    /// Resolve one opaque route's secret through the backend, auditing the attempt.
    fn resolve_secret(&self, route: &RouteSpec) -> Result<Secret> {
        let locator = route.credential_ref();
        let request_id = RequestId::new(LOAD_CORRELATION);
        crate::audit_resolve(
            self.emitter.as_ref(),
            &self.tenant,
            locator.scheme(),
            &route.reference_display(),
            &request_id,
            || self.backend.resolve_secret(locator),
        )
    }

    /// The tenant this vault is bound to. Read by the acquisition audit, which is what makes a record
    /// attributable — with isolation by instance, the tenant is not recoverable from anything else on
    /// the record. Never consulted while matching a destination.
    pub(crate) fn tenant_label(&self) -> &str {
        &self.tenant
    }

    /// The audit sink, for the per-request signing resolve in `legs`.
    pub(crate) fn emitter(&self) -> &dyn crate::Emitter {
        self.emitter.as_ref()
    }

    /// The ambient-fallback policy a signed route's credentials are resolved under.
    pub(crate) fn ambient_policy(&self) -> AmbientFallbackPolicy {
        self.ambient_policy
    }

    /// The resolved `credsd` socket, for the per-request credsd resolve in `legs`. `Some` whenever a
    /// `credsd://` route was declared.
    pub(crate) fn credsd_socket(&self) -> Option<&Path> {
        self.credsd_socket.as_deref()
    }

    /// Report a non-fatal operator-facing condition.
    pub(crate) fn warn(&self, message: &str) {
        eprintln!(
            "strands-box credentials [{tenant}]: {message}",
            tenant = self.tenant
        );
    }

    /// What must be edited on `req` before it goes upstream, or `None` when this vault governs no
    /// credential for its destination.
    pub fn attach_for(&self, req: Outbound<'_>) -> Result<Option<Attachment>> {
        // A signed AWS binding first: it is signed in-boundary and never phantom-swapped, because
        // nothing was minted to match.
        if let Some(config) = Self::first_match(&self.signed_aws, &req.destination) {
            return self.sign_aws(config, &req).map(Some);
        }
        match self.resolve_opaque(&req.destination)? {
            Some(binding) => self.swap_phantom(binding, &req).map(Some),
            None => Ok(None),
        }
    }

    /// Scan `res` for an injected secret and return the redactions needed, or `None` when nothing is
    /// bound for its destination or nothing leaked.
    pub fn redact_leaks(&self, res: Inbound<'_>) -> Option<Redactions> {
        // An ambiguous binding is not a fault on the response leg: there is nothing to attach, so the
        // conservative move is to scan nothing rather than fail a response already received.
        let binding = self.resolve_opaque(&res.destination).ok()??;
        Redactions::scan(&res, binding.secret_value())
    }

    /// Resolve the opaque binding for `dest`, failing closed on ambiguity.
    fn resolve_opaque(&self, dest: &Destination<'_>) -> Result<Option<&OpaqueBinding>> {
        let mut matched = self
            .opaque
            .iter()
            .filter(|(pattern, _)| pattern.matches(dest))
            .map(|(_, binding)| binding);

        let first = matched.next();
        match (first, matched.next()) {
            (None, _) => Ok(None),
            (Some(binding), None) => Ok(Some(binding)),
            (Some(_), Some(_)) => Err(CredentialError::Ambiguous(format!(
                "{host}:{port}{path} matched more than one credential binding — \
                 narrow the bindings so each destination matches exactly one",
                host = dest.host,
                port = dest.port,
                path = dest.path,
            ))),
        }
    }

    /// The first binding in `table` whose pattern matches `dest`.
    fn first_match<'a, T>(
        table: &'a [(DestinationPattern, T)],
        dest: &Destination<'_>,
    ) -> Option<&'a T> {
        table
            .iter()
            .find(|(pattern, _)| pattern.matches(dest))
            .map(|(_, value)| value)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::sources::SecretSource;

    // --- test helpers --------------------------------------------------------

    /// A source that resolves every `test://` reference to one fixed secret.
    #[derive(Debug)]
    struct FixedSource(&'static str);

    impl SecretSource for FixedSource {
        fn scheme(&self) -> &'static str {
            "test"
        }
        fn fetch(&self, _loc: &Locator) -> Result<Secret> {
            Secret::new(zeroize::Zeroizing::new(self.0.to_string()), "test://stub")
        }
    }

    /// A source whose secret is always absent — the crate's one soft failure.
    #[derive(Debug)]
    struct MissingSource;

    impl SecretSource for MissingSource {
        fn scheme(&self) -> &'static str {
            "test"
        }
        fn fetch(&self, _loc: &Locator) -> Result<Secret> {
            Err(CredentialError::SecretNotFound(
                "test://[REDACTED]".to_string(),
            ))
        }
    }

    /// A source that fails hard, to prove a non-soft failure aborts the open.
    #[derive(Debug)]
    struct BrokenSource;

    impl SecretSource for BrokenSource {
        fn scheme(&self) -> &'static str {
            "test"
        }
        fn fetch(&self, _loc: &Locator) -> Result<Secret> {
            Err(CredentialError::Credential("provider unreachable".into()))
        }
    }

    fn backend_with(source: Box<dyn SecretSource>) -> Backend {
        Backend::local()
            .with_source(source)
            .expect("`test` is not claimed by the local set")
    }

    fn header_mode() -> InjectMode {
        InjectMode::header("Bearer {}".to_string(), None).unwrap()
    }

    fn a_ref() -> Locator {
        Locator::parse_uri("test://token").unwrap()
    }

    fn opaque_route(dest: &str) -> RouteSpec {
        RouteSpec::opaque(
            DestinationPattern::parse(dest).unwrap(),
            a_ref(),
            header_mode(),
        )
    }

    fn aws_config(profile: &str) -> Locator {
        let fields: BTreeMap<String, String> = [("source", "aws"), ("profile", profile)]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Locator::structured(fields).unwrap()
    }

    fn dest<'a>(host: &'a str, port: u16, path: &'a str) -> Destination<'a> {
        Destination { host, port, path }
    }

    // --- open ----------------------------------------------------------------

    /// Every resolved route is bound and mints exactly one phantom, and the vault comes up with no
    /// skips.
    #[test]
    fn open_binds_every_resolved_route_and_mints_one_phantom_each() {
        let opened = Vault::open(
            VaultConfig::new(backend_with(Box::new(FixedSource("s3cret"))), "tenant-a")
                .route(opaque_route("api.github.com"))
                .route(opaque_route("api.stripe.com")),
        )
        .expect("both routes resolve");

        assert_eq!(opened.phantoms().len(), 2);
        assert!(opened.skipped().is_empty());
        let tokens: Vec<&str> = opened.phantoms().iter().map(Phantom::token).collect();
        assert_ne!(
            tokens[0], tokens[1],
            "two secrets sharing one phantom would let either be swapped for the other"
        );
    }

    /// A phantom names the destination it stands in for, so a supervisor can seed it correctly.
    #[test]
    fn each_phantom_names_its_destination() {
        let opened = Vault::open(
            VaultConfig::new(backend_with(Box::new(FixedSource("x"))), "t")
                .route(opaque_route("api.github.com")),
        )
        .unwrap();
        assert_eq!(
            opened.phantoms()[0].destination(),
            &DestinationPattern::parse("api.github.com").unwrap()
        );
    }

    /// A soft miss is reported and skipped: the vault still comes up.
    #[test]
    fn open_soft_miss_skips_the_route_and_still_opens() {
        let opened = Vault::open(
            VaultConfig::new(backend_with(Box::new(MissingSource)), "t")
                .route(opaque_route("api.github.com")),
        )
        .expect("a soft miss must not fail the open");

        assert_eq!(opened.skipped().len(), 1);
        assert_eq!(opened.skipped()[0].code(), "secret_not_found");
        assert_eq!(opened.skipped()[0].destination(), "api.github.com");
        assert!(
            opened.phantoms().is_empty(),
            "a skipped route has no secret, so it must mint no phantom"
        );
        // The skip is loggable: the reference body never survives into it.
        assert!(!opened.skipped()[0].to_string().contains("token"));
    }

    /// `require_every_route` turns that same soft miss into a hard failure, naming the destination.
    #[test]
    fn require_every_route_makes_a_soft_miss_fatal() {
        let err = Vault::open(
            VaultConfig::new(backend_with(Box::new(MissingSource)), "t")
                .route(opaque_route("api.github.com"))
                .require_every_route(),
        )
        .expect_err("the caller asked for no soft tier");

        assert!(!err.is_soft());
        let msg = err.to_string();
        assert!(msg.contains("api.github.com"), "got {msg}");
        assert!(
            msg.contains("no credential attached"),
            "the error should say what the consequence is: {msg}"
        );
    }

    /// A hard failure aborts the open rather than bringing the vault up with a gap.
    #[test]
    fn open_hard_failure_aborts() {
        let err = Vault::open(
            VaultConfig::new(backend_with(Box::new(BrokenSource)), "t")
                .route(opaque_route("api.github.com")),
        )
        .expect_err("a provider failure is hard");
        assert!(!err.is_soft());
    }

    /// A `cmd://` route is refused at open, not registered.
    #[test]
    fn open_refuses_a_cmd_route() {
        let route = RouteSpec::opaque(
            DestinationPattern::parse("api.github.com").unwrap(),
            Locator::parse_uri("cmd://gh auth token").unwrap(),
            header_mode(),
        );
        let err = Vault::open(
            VaultConfig::new(backend_with(Box::new(FixedSource("x"))), "t").route(route),
        )
        .expect_err("a cmd:// route must be refused");

        assert!(!err.is_soft());
        let msg = err.to_string();
        assert!(msg.contains("cmd://"), "got {msg}");
        assert!(msg.contains("api.github.com"), "the route is named: {msg}");
    }

    /// One refused route aborts the whole open — never a partial vault with the bad route missing.
    #[test]
    fn one_refused_route_aborts_the_whole_open() {
        let bad = RouteSpec::opaque(
            DestinationPattern::parse("api.bad.com").unwrap(),
            Locator::parse_uri("cmd://whoami").unwrap(),
            header_mode(),
        );
        let err = Vault::open(
            VaultConfig::new(backend_with(Box::new(FixedSource("x"))), "t")
                .route(opaque_route("api.github.com"))
                .route(bad),
        )
        .expect_err("the cmd:// route poisons the whole open");
        assert!(err.to_string().contains("cmd://"));
    }

    /// A signed route mints no phantom: nothing is placed for the vault to match.
    #[test]
    fn open_mints_no_phantom_for_a_signed_route() {
        let opened = Vault::open(
            VaultConfig::new(backend_with(Box::new(FixedSource("x"))), "t").route(
                RouteSpec::signed_aws(
                    DestinationPattern::parse("*.amazonaws.com").unwrap(),
                    aws_config("prod"),
                ),
            ),
        )
        .expect("a signed route registers without resolving");

        assert!(opened.phantoms().is_empty());
        assert!(opened.skipped().is_empty());
    }

    /// A signed route resolves nothing at open — proven by opening one against a backend that would
    /// fail hard if it were consulted. Session credentials expire, so they are resolved per request.
    #[test]
    fn a_signed_route_does_not_resolve_at_open() {
        let opened = Vault::open(
            VaultConfig::new(backend_with(Box::new(BrokenSource)), "t").route(
                RouteSpec::signed_aws(
                    DestinationPattern::parse("*.amazonaws.com").unwrap(),
                    aws_config("prod"),
                ),
            ),
        )
        .expect("a signed route must not touch the backend at open");
        assert!(opened.phantoms().is_empty());
    }

    // --- audit ---------------------------------------------------------------

    /// A successful resolve emits exactly one record, carrying the redacted reference.
    #[test]
    fn a_successful_resolve_emits_one_redacted_record() {
        let recorder = Recorder::new();
        let opened = Vault::open_with_emitter(
            VaultConfig::new(backend_with(Box::new(FixedSource("s3cret"))), "t")
                .route(opaque_route("api.github.com")),
            Box::new(recorder.clone()),
        )
        .unwrap();
        assert_eq!(opened.phantoms().len(), 1);

        let records = recorder.records();
        assert_eq!(records.len(), 1, "one resolve, one record");
        assert!(records[0].ok, "the resolve succeeded");
        assert_eq!(records[0].source, "test");
        // The reference is redacted at construction; the secret never enters the record.
        assert!(records[0].credential_ref.contains("[REDACTED]"));
        assert!(!records[0].credential_ref.contains("token"));
    }

    /// A *failed* resolve is audited too — failing to acquire a credential is itself
    /// security-relevant, so a silent failure would be the gap.
    #[test]
    fn a_failed_resolve_is_audited_too() {
        let recorder = Recorder::new();
        let opened = Vault::open_with_emitter(
            VaultConfig::new(backend_with(Box::new(MissingSource)), "t")
                .route(opaque_route("api.github.com")),
            Box::new(recorder.clone()),
        )
        .unwrap();
        assert_eq!(opened.skipped().len(), 1);

        let records = recorder.records();
        assert_eq!(records.len(), 1);
        assert!(!records[0].ok, "the record must show the failure");
    }

    // --- tenant isolation ----------------------------------------------------

    #[test]
    fn vault_holds_its_tenant_for_lifetime() {
        let opened = Vault::open(
            VaultConfig::new(backend_with(Box::new(FixedSource("x"))), "tenant-a")
                .route(opaque_route("api.github.com")),
        )
        .unwrap();
        assert_eq!(opened.into_vault().tenant_label(), "tenant-a");
    }

    /// Two vaults for two tenants share nothing. Isolation is by instance, so B's vault simply
    /// has no binding for A's destination.
    #[test]
    fn cross_tenant_no_bleed() {
        let a = Vault::open(
            VaultConfig::new(backend_with(Box::new(FixedSource("a-secret"))), "tenant-a")
                .route(opaque_route("api.github.com")),
        )
        .unwrap()
        .into_vault();
        let b = Vault::open(
            VaultConfig::new(backend_with(Box::new(FixedSource("b-secret"))), "tenant-b")
                .route(opaque_route("api.stripe.com")),
        )
        .unwrap()
        .into_vault();

        // Each vault answers only for its own destination.
        assert!(
            b.resolve_opaque(&dest("api.github.com", 443, "/"))
                .unwrap()
                .is_none(),
            "tenant B must not hold tenant A's binding"
        );
        assert!(
            a.resolve_opaque(&dest("api.github.com", 443, "/"))
                .unwrap()
                .is_some()
        );
    }

    // --- fail-closed ambiguity ----------------------------------------------

    /// Two matching bindings fail closed rather than the vault guessing which secret to attach.
    #[test]
    fn ambiguous_binding_fails_closed() {
        let vault = Vault::open(
            VaultConfig::new(backend_with(Box::new(FixedSource("x"))), "t")
                .route(opaque_route("*.github.com"))
                .route(opaque_route("api.github.com")),
        )
        .unwrap()
        .into_vault();

        let err = vault
            .resolve_opaque(&dest("api.github.com", 443, "/"))
            .expect_err("two bindings match");
        assert!(matches!(err, CredentialError::Ambiguous(_)));
        assert!(!err.is_soft());
    }

    #[test]
    fn zero_matches_is_none() {
        let vault = Vault::open(
            VaultConfig::new(backend_with(Box::new(FixedSource("x"))), "t")
                .route(opaque_route("api.github.com")),
        )
        .unwrap()
        .into_vault();
        assert!(
            vault
                .resolve_opaque(&dest("other.example.com", 443, "/"))
                .unwrap()
                .is_none()
        );
    }

    /// A `{:?}` of the whole vault must not print a resolved secret.
    #[test]
    fn vault_debug_never_prints_a_secret() {
        let vault = Vault::open(
            VaultConfig::new(
                backend_with(Box::new(FixedSource("super-secret-value"))),
                "t",
            )
            .route(opaque_route("api.github.com")),
        )
        .unwrap()
        .into_vault();

        let rendered = format!("{vault:?}");
        assert!(
            !rendered.contains("super-secret-value"),
            "secret leaked through the vault's Debug: {rendered}"
        );
        assert!(rendered.contains("[REDACTED]"), "got {rendered}");
    }

    // --- the audit recorder --------------------------------------------------

    use std::sync::{Arc, Mutex};

    /// An emitter that retains every record, so a test can assert one-record-per-resolve.
    #[derive(Debug, Clone)]
    struct Recorder(Arc<Mutex<Vec<crate::audit::CredentialAcquire>>>);

    impl Recorder {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Vec::new())))
        }
        fn records(&self) -> Vec<crate::audit::CredentialAcquire> {
            self.0
                .lock()
                .expect("the recorder mutex is not poisoned")
                .clone()
        }
    }

    impl crate::Emitter for Recorder {
        fn emit(&self, record: crate::audit::CredentialAcquire) {
            self.0
                .lock()
                .expect("the recorder mutex is not poisoned")
                .push(record);
        }
    }
}
