//! The tenant-keyed [`Vault`] for credential attachment and response redaction.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::attach::{Attachment, Inbound, Outbound, Redactions};
use crate::config::MissingRoutePolicy;
use crate::model::RouteKind;
use crate::rotating::{CachedToken, Clock, RotatingToken, TokenSource};

use crate::sources::{
    AmbientFallbackPolicy, AwsCredentialProvider, CREDSD_SCHEME, CredsdClient, credsd_access_token,
    default_aws_provider, is_bare_aws_default_chain, resolve_credsd_socket,
};
use crate::{
    Backend, CredentialDiagnostic, CredentialError, Destination, DestinationPattern, InjectMode,
    Locator, Opened, Phantom, PhantomCheck, PhantomToken, RequestId, ResponseRedactor, Result,
    RouteSpec, Secret, Skipped, VaultConfig,
};

/// The correlation id the eager load uses for its audit records.
const LOAD_CORRELATION: &str = "credential-store-load";

/// The `cmd://` scheme, refused at open because no request-time capture path is wired.
pub(crate) const CMD_SCHEME: &str = "cmd";

/// The deferred-mint scheme an operator config could once name.
pub(crate) const OAUTH2_SCHEME: &str = "oauth2";

/// Bindings of one credsd reference share its current acquisition within this vault.
#[derive(Clone)]
enum BoundSecret {
    Fixed(Secret),
    Rotating(Arc<RotatingToken>),
}

impl BoundSecret {
    fn attach(
        &self,
        inject: &InjectMode,
        attachment: &mut Attachment,
        paired: bool,
    ) -> Result<Option<ResponseRedactor>> {
        let acquired;
        let secret = match self {
            Self::Fixed(secret) => secret,
            Self::Rotating(_) if !paired => {
                return Err(CredentialError::Credential(
                    "a rotating credential requires a paired response redactor".into(),
                ));
            }
            Self::Rotating(token) => {
                acquired = token.acquire()?;
                acquired.as_ref()
            }
        };
        Ok(attach_fixed(secret, inject, attachment, paired))
    }
}

/// Attach `secret`, with a scrubber for it when the caller keeps one.
fn attach_fixed(
    secret: &Secret,
    inject: &InjectMode,
    attachment: &mut Attachment,
    paired: bool,
) -> Option<ResponseRedactor> {
    crate::legs::attach_secret(inject, secret.as_str(), attachment);
    paired.then(|| ResponseRedactor::new(secret))
}

/// One resolved opaque binding: the secret, how it attaches, and the phantom standing in for it.
pub(crate) struct OpaqueBinding {
    /// How the real secret attaches to the outbound request.
    inject: InjectMode,
    /// Where the harness placed the phantom, so it can be recognised and stripped.
    harness: InjectMode,
    /// The resolved secret, wiped on drop and validated at construction
    /// (docs/design/decisions.md#an-unusable-secret-value-is-unrepresentable).
    secret: BoundSecret,
    /// The phantom minted to stand in for this secret.
    phantom: PhantomToken,
    /// How strictly `swap_phantom` checks the placeholder before it attaches the secret.
    phantom_check: PhantomCheck,
}

impl OpaqueBinding {
    pub(crate) fn attach(
        &self,
        attachment: &mut Attachment,
        paired: bool,
    ) -> Result<Option<ResponseRedactor>> {
        self.secret.attach(&self.inject, attachment, paired)
    }

    /// Where the harness placed the phantom, so it can be recognised and stripped.
    pub(crate) fn harness(&self) -> &InjectMode {
        &self.harness
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

/// One resolved box-owned binding: the real secret and where the box attaches it. No phantom is
/// minted, because the workload never presents a placeholder for it.
struct BoxOwnedBinding {
    /// How the real secret attaches to the outbound request.
    inject: InjectMode,
    /// The resolved secret, wiped on drop and validated at construction. A box-owned route never
    /// reads a credsd token, so it holds a fixed secret.
    secret: Secret,
}

impl std::fmt::Debug for BoxOwnedBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxOwnedBinding")
            .field("inject", &self.inject)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// One strip-phantom binding: where the placeholder is, so the vault strips it before the request
/// egresses. It holds no secret: nothing is attached, only stripped.
#[derive(Debug)]
pub(crate) struct StripBinding {
    /// Where the harness placed the placeholder, so it is stripped before the request goes upstream.
    harness: InjectMode,
}

impl StripBinding {
    pub(crate) fn harness(&self) -> &InjectMode {
        &self.harness
    }
}

/// A signed-AWS route's resolved form: its config locator and an optional explicit `(service,
/// region)` to sign under (a re-routed backend whose host carries no derivable scope).
type SignedAwsRoute = (Locator, Option<(String, String)>);

/// The loaded credential set for one tenant.
#[derive(Debug)]
pub struct Vault {
    /// The tenant every binding here belongs to. Held for the vault's lifetime and never consulted
    /// while matching — isolation is by instance.
    tenant: String,
    /// destination pattern → resolved opaque binding.
    opaque: Vec<(DestinationPattern, OpaqueBinding)>,
    /// destination pattern → resolved box-owned binding (a credential the box attaches itself).
    box_owned: Vec<(DestinationPattern, BoxOwnedBinding)>,
    /// destination pattern → strip-phantom binding (strip the placeholder, attach nothing).
    strip: Vec<(DestinationPattern, StripBinding)>,
    /// destination pattern → the structured AWS config a signed route signs with.
    signed_aws: Vec<(DestinationPattern, SignedAwsRoute)>,
    /// The backend that resolves fixed secrets at open.
    backend: Backend,
    /// Whether a signed route may fall back to the ambient AWS provider chain when it declares no
    /// scoped profile. Held here because the resolve happens per request, so the policy has to outlive
    /// the open that chose it.
    ambient_policy: AmbientFallbackPolicy,
    /// The AWS credential provider a signed route resolves through. Defaults to the process-wide
    /// shared SDK worker; a test injects a fake. An injectable field, so signing runs through the
    /// vault rather than a hardcoded global, which both restores the end-to-end `sign_aws` test seam
    /// and lets `open` validate the chain eagerly.
    aws_provider: Arc<dyn AwsCredentialProvider>,
    /// The acquisition-audit sink. Every resolve emits one record through it, success or
    /// failure; the default discards, since the shared L2 lane does not exist yet.
    emitter: Arc<dyn crate::Emitter>,
    /// The resolved absolute `credsd` socket a `credsd://` route connects to, retained because the
    /// resolve happens per request. `Some` only when a `credsd://` route was declared.
    credsd_socket: Option<PathBuf>,
}

impl Vault {
    /// Resolve every declared route and open the vault.
    pub fn open(config: VaultConfig) -> Result<Opened> {
        Self::open_with(
            config,
            Box::new(crate::audit::DiscardingEmitter),
            default_aws_provider(),
        )
    }

    /// [`open`](Self::open) with the audit sink supplied, so a test can observe that every resolve
    /// emits exactly one record. The public entry point injects the discarding sink; when the shared L2
    /// audit lane lands it is substituted here rather than added as a new path.
    #[cfg(test)]
    fn open_with_emitter(config: VaultConfig, emitter: Box<dyn crate::Emitter>) -> Result<Opened> {
        Self::open_with(config, emitter, default_aws_provider())
    }

    /// [`open`](Self::open) with the AWS provider injected, so a test drives the real signing and
    /// eager-validate paths through a fake provider rather than the live SDK chain.
    #[cfg(test)]
    pub(crate) fn open_with_aws_provider(
        config: VaultConfig,
        aws_provider: Arc<dyn AwsCredentialProvider>,
    ) -> Result<Opened> {
        Self::open_with(
            config,
            Box::new(crate::audit::DiscardingEmitter),
            aws_provider,
        )
    }

    /// The one open path: resolve every route, then eagerly validate a bare `aws://` chain.
    fn open_with(
        config: VaultConfig,
        emitter: Box<dyn crate::Emitter>,
        aws_provider: Arc<dyn AwsCredentialProvider>,
    ) -> Result<Opened> {
        let (backend, tenant, routes, missing, ambient_policy, credsd_socket_config) =
            config.into_parts();
        let mut vault = Self {
            tenant,
            opaque: Vec::new(),
            box_owned: Vec::new(),
            strip: Vec::new(),
            signed_aws: Vec::new(),
            backend,
            ambient_policy,
            aws_provider,
            emitter: Arc::from(emitter),
            credsd_socket: None,
        };
        // A `credsd://` route needs a socket, resolved and validated absolute once here — a relative
        // path is a configuration error the vault refuses at open, not a runtime failure. It is
        // resolved before any route, because an opaque `credsd://` route reads its token at open.
        let declares_credsd = routes.iter().any(|route| match route.kind() {
            RouteKind::SignedAws { config, .. } => config.scheme() == CREDSD_SCHEME,
            _ => route.credential_ref().scheme() == CREDSD_SCHEME,
        });
        if declares_credsd {
            vault.credsd_socket = Some(resolve_credsd_socket(credsd_socket_config.as_deref())?);
        }
        let mut phantoms = Vec::new();
        let mut skipped = Vec::new();
        // Every minted phantom, to enforce vault-wide uniqueness: a collision is a
        // fail-closed error, never two credentials sharing one placeholder.
        let mut seen_phantoms = std::collections::HashSet::new();
        // The phantom each credential minted, keyed by its reference and prefix. Routes that name
        // one credential share its phantom, so one placeholder works at every destination it serves.
        let mut minted: Vec<(Locator, String, PhantomToken)> = Vec::new();
        // Each `credsd://` token this open read, keyed by its reference, so every route that names
        // one token reads it once.
        let mut credsd_tokens: Vec<(Locator, BoundSecret)> = Vec::new();

        // Mint a unique phantom, failing closed on a vault-wide collision. The caller records the
        // per-destination `phantoms` mapping, so a shared phantom is recorded at each host it serves.
        let mut mint = |prefix: &str| -> Result<PhantomToken> {
            let phantom = PhantomToken::generate(prefix)?;
            if !seen_phantoms.insert(phantom.as_str().to_string()) {
                return Err(CredentialError::Credential(
                    "phantom-token collision across the vault; refusing to bind two credentials to \
                     one placeholder"
                        .to_string(),
                ));
            }
            Ok(phantom)
        };

        for route in &routes {
            // Refuse before dispatching, so no branch can claim a route first and leave an unsupported
            // field unread.
            Self::refuse_unsupported(route)?;

            match route.kind() {
                // A signed route carries a config block resolved at use, not a secret held here.
                RouteKind::SignedAws { config, scope } => {
                    vault
                        .signed_aws
                        .push((route.destination().clone(), (config.clone(), scope.clone())));
                }
                // A strip-phantom route mints a placeholder (so a workload harness has one) and
                // resolves NO real secret. The strip at request time is unconditional.
                RouteKind::StripPhantom {
                    harness,
                    phantom_prefix,
                } => {
                    let phantom = mint(phantom_prefix)?;
                    phantoms.push(Phantom::new(route.destination().clone(), phantom));
                    vault.strip.push((
                        route.destination().clone(),
                        StripBinding {
                            harness: harness.clone(),
                        },
                    ));
                }
                // An opaque route resolves a real secret and mints a phantom to stand in for it.
                RouteKind::Opaque {
                    inject,
                    harness,
                    phantom_check,
                    phantom_prefix,
                } => {
                    if let Some(secret) = Self::classify_resolve(
                        vault.resolve_secret_once(route, &mut credsd_tokens),
                        route,
                        missing,
                        &mut skipped,
                    )? {
                        // Routes naming one credential (by reference and prefix) share one phantom,
                        // so a single placeholder works at every destination the credential serves.
                        // A new credential mints one (which records its per-destination mapping); a
                        // shared one reuses the token and records this destination's mapping too.
                        let phantom = match minted.iter().find(|(locator, prefix, _)| {
                            locator == route.credential_ref() && prefix == phantom_prefix
                        }) {
                            Some((_, _, phantom)) => {
                                let phantom = phantom.clone();
                                phantoms.push(Phantom::new(
                                    route.destination().clone(),
                                    phantom.clone(),
                                ));
                                phantom
                            }
                            None => {
                                let phantom = mint(phantom_prefix)?;
                                phantoms.push(Phantom::new(
                                    route.destination().clone(),
                                    phantom.clone(),
                                ));
                                minted.push((
                                    route.credential_ref().clone(),
                                    phantom_prefix.clone(),
                                    phantom.clone(),
                                ));
                                phantom
                            }
                        };
                        vault.opaque.push((
                            route.destination().clone(),
                            OpaqueBinding {
                                inject: inject.clone(),
                                harness: harness.clone(),
                                secret,
                                phantom,
                                phantom_check: *phantom_check,
                            },
                        ));
                    }
                }
                // A box-owned route resolves a real secret and attaches it itself, with no phantom.
                RouteKind::BoxOwned { inject } => {
                    if let Some(secret) = Self::classify_resolve(
                        vault.resolve_secret(route),
                        route,
                        missing,
                        &mut skipped,
                    )? {
                        vault.box_owned.push((
                            route.destination().clone(),
                            BoxOwnedBinding {
                                inject: inject.clone(),
                                secret,
                            },
                        ));
                    }
                }
            }
        }

        // Eagerly validate the bare default chain at open, so a broken chain (an unreadable profile,
        // an SSO-only default, a stuck `credential_process` within the resolve timeout) fails at
        // `box run` rather than on the first signed request. Only when a bare `aws://` route exists
        // and ambient fallback is allowed: a named-profile-only vault, a `credsd://` vault, or one
        // under `require_scoped_aws_profile` does no resolve at open, so a box that never signs a
        // bare route forces no credentials to exist. The resolve primes the shared provider cache,
        // `audit_aws_resolve` emits the one prepare-step record, and the vault warns once here for each
        // bare route.
        if vault.ambient_policy != AmbientFallbackPolicy::Deny
            && let Some(locator) = vault
                .signed_aws
                .iter()
                .find_map(|(_, (loc, _))| is_bare_aws_default_chain(loc).then(|| loc.clone()))
        {
            let resolution = vault.audit_aws_resolve(&locator)?;
            if let Some(warning) = resolution.acquisition.warning() {
                for (pattern, (route, _)) in &vault.signed_aws {
                    if is_bare_aws_default_chain(route) {
                        vault.warn_at_open(&format!(
                            "aws:// for {} {warning}",
                            pattern.as_written()
                        ));
                    }
                }
            }
        }

        Ok(Opened::new(vault, phantoms, skipped))
    }

    /// Classify a secret resolution: `Ok(Some)` is a resolved secret, `Ok(None)` a soft miss under
    /// the skip policy (recorded in `skipped`), and `Err` a hard failure. Shared by the opaque and
    /// box-owned routes, which both resolve a real secret.
    fn classify_resolve<T>(
        result: Result<T>,
        route: &RouteSpec,
        missing: MissingRoutePolicy,
        skipped: &mut Vec<Skipped>,
    ) -> Result<Option<T>> {
        match result {
            Ok(secret) => Ok(Some(secret)),
            // A genuinely absent secret is the one soft failure — unless the caller asked for no soft
            // tier, in which case it is fatal like everything else.
            Err(err) if err.is_soft() && missing == MissingRoutePolicy::Skip => {
                skipped.push(Skipped::new(CredentialDiagnostic::new(
                    "secret_not_found",
                    &err,
                    route.destination_display(),
                    &route.reference_display(),
                    format!("{err}"),
                    "ensure the referenced secret exists before opening the vault",
                )));
                Ok(None)
            }
            Err(err) if err.is_soft() => Err(CredentialError::Credential(format!(
                "{destination} declares a credential that did not resolve ({err}), and every route \
                 is required: the destination would stay reachable with no credential attached",
                destination = route.destination_display(),
            ))),
            Err(err) => Err(err),
        }
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

    /// Resolve an opaque route at open, sharing one acquisition and refresh lock per credsd reference.
    fn resolve_secret_once(
        &self,
        route: &RouteSpec,
        read: &mut Vec<(Locator, BoundSecret)>,
    ) -> Result<BoundSecret> {
        let locator = route.credential_ref();
        if let Some((_, secret)) = read.iter().find(|(earlier, _)| earlier == locator) {
            return Ok(secret.clone());
        }
        crate::audit_resolve(
            self.emitter.as_ref(),
            &self.tenant,
            locator.scheme(),
            &route.reference_display(),
            &RequestId::new(LOAD_CORRELATION),
            || {
                if locator.scheme() != CREDSD_SCHEME {
                    let secret = self.backend.resolve_secret(locator)?;
                    return Ok(BoundSecret::Fixed(secret));
                }
                let credential = crate::legs::credsd_credential(locator)?;
                let (secret, expires_at) = self.read_credsd_token(credential)?;
                let binding = match expires_at {
                    Some(expiry) => {
                        let source = TokenSource {
                            credential: credential.to_owned(),
                            socket: self.credsd_socket().map(Path::to_path_buf).ok_or_else(|| {
                                CredentialError::KeystoreAccess(format!(
                                    "no credsd socket was resolved for credential {credential:?}"
                                ))
                            })?,
                            tenant: self.tenant.clone(),
                            emitter: Arc::clone(&self.emitter),
                            clock: Clock::current(),
                            read_wait: crate::rotating::read_wait_limit(),
                        };
                        let first = CachedToken::new(secret, &expiry, source.clock.now()).map_err(
                            |failure| CredentialError::Credential(failure.message(credential)),
                        )?;
                        BoundSecret::Rotating(RotatingToken::new(source, first))
                    }
                    None => BoundSecret::Fixed(secret),
                };
                read.push((locator.clone(), binding.clone()));
                Ok(binding)
            },
        )
    }

    /// Resolve one route's secret through the backend, auditing the attempt. The backend has no
    /// credsd source, so a box-owned `credsd://` route is refused here.
    fn resolve_secret(&self, route: &RouteSpec) -> Result<Secret> {
        let locator = route.credential_ref();
        crate::audit_resolve(
            self.emitter.as_ref(),
            &self.tenant,
            locator.scheme(),
            &route.reference_display(),
            &RequestId::new(LOAD_CORRELATION),
            || self.backend.resolve_secret(locator),
        )
    }

    fn read_credsd_token(&self, credential: &str) -> Result<(Secret, Option<String>)> {
        let socket = self.credsd_socket().ok_or_else(|| {
            CredentialError::KeystoreAccess(format!(
                "no credsd socket was resolved for credential {credential:?}"
            ))
        })?;
        let token = credsd_access_token(&CredsdClient::new(socket.to_path_buf()), credential)?;
        Ok((token.token, token.expires_at))
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

    /// The AWS provider a signed route resolves through, for the per-request signing resolve in
    /// `legs`. A cheap `Arc` clone of the shared provider (or a test's injected fake).
    pub(crate) fn aws_provider(&self) -> Arc<dyn AwsCredentialProvider> {
        self.aws_provider.clone()
    }

    /// The resolved `credsd` socket, for the per-request credsd resolve in `legs`. `Some` whenever a
    /// `credsd://` route was declared.
    pub(crate) fn credsd_socket(&self) -> Option<&Path> {
        self.credsd_socket.as_deref()
    }

    /// Report a non-fatal operator-facing condition.
    pub(crate) fn warn(&self, message: &str) {
        warn_operator(&self.tenant, message);
        #[cfg(test)]
        CAPTURED_WARNINGS.with(|warnings| warnings.borrow_mut().push(message.to_string()));
    }

    /// Report, once for this process, a condition that holds for every request this vault serves.
    fn warn_at_open(&self, message: &str) {
        if !first_warning(message) {
            return;
        }
        let line = diagnostics::diag!(text B0602, "{message}");
        let _ = std::io::Write::write_all(&mut diagnostics::stderr().lock(), line.as_bytes());
        #[cfg(test)]
        CAPTURED_WARNINGS.with(|warnings| warnings.borrow_mut().push(line.trim_end().to_string()));
    }

    /// Return request edits, refusing rotating credentials that require [`Self::attach_with_redactor`].
    pub fn attach_for(&self, req: Outbound<'_>) -> Result<Option<Attachment>> {
        Ok(self.attach(req, false)?.map(|(attachment, _)| attachment))
    }

    /// Return edits with a scrubber for the attached token or a matching fixed secret.
    pub fn attach_with_redactor(
        &self,
        req: Outbound<'_>,
    ) -> Result<Option<(Attachment, Option<ResponseRedactor>)>> {
        let Some((attachment, redactor)) = self.attach(req, true)? else {
            return Ok(None);
        };
        // Signing and stripping can take precedence over a fixed secret that still needs scrubbing.
        let redactor = redactor.or_else(|| self.response_redactor(req.destination));
        Ok(Some((attachment, redactor)))
    }

    fn attach(
        &self,
        req: Outbound<'_>,
        paired: bool,
    ) -> Result<Option<(Attachment, Option<ResponseRedactor>)>> {
        // A signed AWS binding first: it is signed in-boundary and never phantom-swapped, because
        // nothing was minted to match.
        if let Some((config, scope)) = Self::first_match(&self.signed_aws, &req.destination) {
            return Ok(Some((self.sign_aws(config, scope.as_ref(), &req)?, None)));
        }
        // A re-route composes two edits on one destination (one credential authority, so one control):
        // a strip-phantom binding removes the workload's placeholder, and a box-owned binding attaches
        // the box's own token. On the same header the strip runs first, so the backend token wins and
        // no placeholder rides upstream. Either may be absent.
        let strip = Self::first_match(&self.strip, &req.destination);
        let box_owned = Self::first_match(&self.box_owned, &req.destination);
        if strip.is_some() || box_owned.is_some() {
            let mut attachment = Attachment::new();
            if let Some(binding) = strip {
                crate::legs::strip_phantom(binding, &mut attachment)?;
            }
            let redactor = box_owned.and_then(|binding| {
                attach_fixed(&binding.secret, &binding.inject, &mut attachment, paired)
            });
            return Ok(Some((attachment, redactor)));
        }
        match self.resolve_opaque(&req.destination)? {
            Some(binding) => self.swap_phantom(binding, &req, paired).map(Some),
            None => Ok(None),
        }
    }

    /// Scan for the fixed secret bound to this destination, if any.
    pub fn redact_leaks(&self, res: Inbound<'_>) -> Option<Redactions> {
        Redactions::scan(&res, self.response_secret(&res.destination)?)
    }

    /// Create a scrubber for a fixed secret, or use [`Self::attach_with_redactor`] for a rotating token.
    pub fn response_redactor(&self, destination: Destination<'_>) -> Option<ResponseRedactor> {
        Some(ResponseRedactor::new(self.response_secret(&destination)?))
    }

    fn response_secret(&self, destination: &Destination<'_>) -> Option<&Secret> {
        if let Some(owner) = Self::first_match(&self.box_owned, destination) {
            return Some(&owner.secret);
        }
        match &self.resolve_opaque(destination).ok()??.secret {
            BoundSecret::Fixed(secret) => Some(secret),
            BoundSecret::Rotating(_) => None,
        }
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

/// Report a non-fatal condition to the operator, naming the vault's tenant.
pub(crate) fn warn_operator(tenant: &str, message: &str) {
    diagnostics::diag!(B0602, "credentials [{tenant}]: {message}");
    #[cfg(test)]
    CAPTURED_OPERATOR_WARNINGS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push((tenant.to_string(), message.to_string()));
}

/// Every operator warning this test process reported, with its tenant, from any thread.
#[cfg(test)]
pub(crate) static CAPTURED_OPERATOR_WARNINGS: std::sync::Mutex<Vec<(String, String)>> =
    std::sync::Mutex::new(Vec::new());

/// Whether `line` is the first time this process prints it.
fn first_warning(line: &str) -> bool {
    static PRINTED: std::sync::Mutex<std::collections::BTreeSet<String>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());
    PRINTED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(line.to_string())
}

#[cfg(test)]
thread_local! {
    /// Warnings the vault emitted on this thread, so a test can observe a warning without capturing
    /// stderr. Drained by [`drain_captured_warnings`]. Hermetic: a test injects a
    /// fake AWS provider, so `warn` runs on the test thread and never reaches the SDK worker.
    static CAPTURED_WARNINGS: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Take and clear the warnings captured on this thread (test-only).
#[cfg(test)]
pub(crate) fn drain_captured_warnings() -> Vec<String> {
    CAPTURED_WARNINGS.with(|warnings| std::mem::take(&mut *warnings.borrow_mut()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

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

    fn opaque_route_for(dest: &str, reference: &str) -> RouteSpec {
        RouteSpec::opaque(
            DestinationPattern::parse(dest).unwrap(),
            Locator::parse_uri(reference).unwrap(),
            header_mode(),
        )
    }

    /// Every resolved route is bound and two credentials mint two phantoms, and the vault comes up
    /// with no skips.
    #[test]
    fn open_binds_every_resolved_route_and_mints_one_phantom_each() {
        let opened = Vault::open(
            VaultConfig::new(backend_with(Box::new(FixedSource("s3cret"))), "tenant-a")
                .route(opaque_route_for("api.github.com", "test://github"))
                .route(opaque_route_for("api.stripe.com", "test://stripe")),
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

    /// Routes that name one credential share one phantom, so one placeholder works at each host.
    #[test]
    fn routes_that_name_one_credential_share_one_phantom() {
        let vault_for = |second: &str| {
            Vault::open(
                VaultConfig::new(backend_with(Box::new(FixedSource("s3cret"))), "t")
                    .route(opaque_route_for("management.example.dev", "test://key"))
                    .route(opaque_route_for("runtime.example.dev", second)),
            )
            .unwrap()
        };

        let shared = vault_for("test://key");
        let tokens: Vec<&str> = shared.phantoms().iter().map(Phantom::token).collect();
        assert_eq!(tokens.len(), 2, "one phantom entry per route");
        assert_eq!(tokens[0], tokens[1], "one credential, one placeholder");

        let distinct = vault_for("test://other");
        let tokens: Vec<&str> = distinct.phantoms().iter().map(Phantom::token).collect();
        assert_ne!(
            tokens[0], tokens[1],
            "two credentials sharing one phantom would let either be swapped for the other"
        );
    }

    /// One credential with two phantom prefixes mints two phantoms: each carries its own prefix.
    #[test]
    fn one_credential_with_two_prefixes_mints_two_phantoms() {
        let route = |dest: &str, prefix: &str| {
            opaque_route_for(dest, "test://key")
                .phantom_prefix(prefix.to_string())
                .unwrap()
        };
        let opened = Vault::open(
            VaultConfig::new(backend_with(Box::new(FixedSource("s3cret"))), "t")
                .route(route("a.example.dev", "sk-a-"))
                .route(route("b.example.dev", "sk-b-")),
        )
        .unwrap();
        let tokens: Vec<&str> = opened.phantoms().iter().map(Phantom::token).collect();
        assert!(tokens[0].starts_with("sk-a-") && tokens[1].starts_with("sk-b-"));
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

    /// An AWS provider that fails hard if it is ever consulted — proves whether `open` resolved.
    #[derive(Debug)]
    struct FailingAwsProvider;

    impl AwsCredentialProvider for FailingAwsProvider {
        fn provide(&self, _profile: Option<&str>) -> Result<crate::AwsSessionCredentials> {
            Err(CredentialError::KeystoreAccess(
                "the chain is broken".to_string(),
            ))
        }
    }

    /// A bare `aws://` route is eagerly validated at open, so a broken chain fails `box run` rather
    /// than the first signed request. The failing provider turns that eager resolve into a hard
    /// error; `aws_config("")` is the bare form (`is_bare_aws_default_chain` holds).
    #[test]
    fn a_broken_bare_aws_chain_fails_the_open() {
        let error = Vault::open_with_aws_provider(
            VaultConfig::new(backend_with(Box::new(BrokenSource)), "t").route(
                RouteSpec::signed_aws(
                    DestinationPattern::parse("*.amazonaws.com").unwrap(),
                    aws_config(""),
                ),
            ),
            Arc::new(FailingAwsProvider),
        )
        .expect_err("a broken bare chain must fail the open");
        assert!(
            !error.is_soft(),
            "a broken bare chain is a hard open failure: {error:?}"
        );
    }

    /// Only a bare route is eagerly validated. A named-profile-only vault does no resolve at open, so
    /// a box that never signs a bare route forces no credentials to exist — proven by a provider that
    /// would fail hard if it were consulted.
    #[test]
    fn a_named_profile_only_vault_does_not_resolve_at_open() {
        let opened = Vault::open_with_aws_provider(
            VaultConfig::new(backend_with(Box::new(BrokenSource)), "t").route(
                RouteSpec::signed_aws(
                    DestinationPattern::parse("*.amazonaws.com").unwrap(),
                    aws_config("prod"),
                ),
            ),
            Arc::new(FailingAwsProvider),
        )
        .expect("a named-profile-only vault must not resolve at open");
        assert!(
            opened.phantoms().is_empty(),
            "a signed route mints no phantom"
        );
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

    #[test]
    fn response_redactor_preserves_destination_binding_and_outlives_the_vault() {
        let vault = Vault::open(
            VaultConfig::new(backend_with(Box::new(FixedSource("private-value"))), "t")
                .route(opaque_route("api.example.com:443/v1/chat")),
        )
        .unwrap()
        .into_vault();

        for destination in [
            dest("other.example.com", 443, "/v1/chat"),
            dest("api.example.com", 80, "/v1/chat"),
            dest("api.example.com", 443, "/v1/chatbot"),
        ] {
            assert!(vault.response_redactor(destination).is_none());
        }
        let mut redactor = vault
            .response_redactor(dest("API.EXAMPLE.COM", 443, "/v1/chat/completions"))
            .unwrap();
        drop(vault);
        assert_eq!(
            redactor.redact_header("private-value").unwrap(),
            "[REDACTED]"
        );
        assert!(redactor.push(b"private-").is_empty());
        let mut redacted = redactor.push(b"value");
        redacted.extend(redactor.finish());
        assert_eq!(redacted, b"[REDACTED]");
    }

    #[test]
    fn an_ambiguous_response_has_no_streaming_redactor() {
        let vault = Vault::open(
            VaultConfig::new(backend_with(Box::new(FixedSource("private-value"))), "t")
                .route(opaque_route("*.example.com"))
                .route(opaque_route("api.example.com")),
        )
        .unwrap()
        .into_vault();
        assert!(
            vault
                .response_redactor(dest("api.example.com", 443, "/"))
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

    // --- credsd token routes -------------------------------------------------

    fn credsd_answering_once(name: &str, response: String) -> PathBuf {
        credsd_answering(name, [response])
    }

    fn credsd_answering<const N: usize>(name: &str, responses: [String; N]) -> PathBuf {
        credsd_answering_with(name, responses, |_| {})
    }

    /// A fake daemon returning successive acquisitions at a socket unique to this test.
    fn credsd_answering_with<const N: usize>(
        name: &str,
        responses: [String; N],
        mut before_reply: impl FnMut(usize) + Send + 'static,
    ) -> PathBuf {
        use std::io::{BufRead, Write};
        let path =
            std::env::temp_dir().join(format!("credsd-vault-{name}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind the socket");
        std::thread::spawn(move || {
            for (index, response) in responses.into_iter().enumerate() {
                let (mut stream, _) = listener.accept().expect("accept one connection");
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut request = Vec::new();
                let _ = reader.read_until(b'\n', &mut request);
                before_reply(index);
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        path
    }

    /// An `access_token` reply, with `expires_at` as written (a JSON string or `null`).
    fn token_reply(expires_at: &str) -> String {
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"credential\":\"gh\",\"material\":{{\"type\":\"access_token\",\"token\":\"ghp_vault_example\",\"token_type\":\"Bearer\"}},\"expires_at\":{expires_at}}}}}\n"
        )
    }

    /// An opaque `credsd://` route on `host`, attached as a bearer token.
    fn credsd_token_route(host: &str) -> RouteSpec {
        RouteSpec::opaque(
            DestinationPattern::parse(host).unwrap(),
            Locator::parse_uri("credsd://github").unwrap(),
            InjectMode::header("Bearer {}", None).unwrap(),
        )
    }

    fn token_request(headers: &[(String, String)]) -> Outbound<'_> {
        Outbound {
            destination: dest("first.example.com", 443, "/"),
            method: "GET",
            url: "https://first.example.com/",
            query: "",
            headers,
            body: &[],
        }
    }

    #[test]
    fn stripping_preserves_the_response_check_for_an_overlapping_fixed_secret() {
        let host = "first.example.com";
        let vault = Vault::open(
            VaultConfig::new(backend_with(Box::new(FixedSource("fixed-token"))), "t")
                .route(opaque_route(host))
                .route(RouteSpec::strip_phantom(
                    DestinationPattern::parse(host).unwrap(),
                    header_mode(),
                )),
        )
        .unwrap()
        .into_vault();
        let (attachment, redactor) = vault
            .attach_with_redactor(token_request(&[]))
            .unwrap()
            .unwrap();
        assert!(attachment.set_headers().next().is_none());
        assert_eq!(
            redactor.unwrap().redact_header("fixed-token").as_deref(),
            Some("[REDACTED]")
        );
    }

    /// A JSON-RPC error reply carrying the credsd domain `code`.
    fn error_reply(code: &str) -> String {
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{{\"code\":-32000,\"message\":\"sensitive\",\"data\":{{\"code\":\"{code}\"}}}}}}\n"
        )
    }

    /// The token-route binding a vault holds for `host`.
    fn rotating_token(vault: &Vault, host: &str) -> Arc<RotatingToken> {
        match &vault
            .resolve_opaque(&dest(host, 443, "/"))
            .unwrap()
            .unwrap()
            .secret
        {
            BoundSecret::Rotating(token) => Arc::clone(token),
            BoundSecret::Fixed(_) => panic!("an expiring token rotates"),
        }
    }

    fn attached(vault: &Vault, request: Outbound<'_>) -> String {
        let (attachment, _) = vault.attach_with_redactor(request).unwrap().unwrap();
        attachment
            .set_headers()
            .next()
            .unwrap()
            .1
            .as_str()
            .to_owned()
    }

    #[test]
    fn credsd_refresh_is_shared_audited_backed_off_and_pins_each_response() {
        let clock = crate::rotating::tests::ManualClock::install();
        let second =
            token_reply(r#""2099-01-01T00:00:00Z""#).replace("ghp_vault_example", "second-token");
        let socket = credsd_answering(
            "rotate",
            [
                token_reply(r#""1970-01-01T00:01:40Z""#),
                token_reply("null").replace("Bearer", "sensitive-token-type"),
                token_reply(r#""invalid-sensitive-expiry""#),
                token_reply("null"),
                token_reply(r#""1970-01-01T00:00:00Z""#),
                error_reply("CREDENTIAL_NOT_FOUND"),
                error_reply("CONFIG_DRIFTED"),
                error_reply("PROVIDER_UNAVAILABLE"),
                // The daemon closes the connection with no answer.
                String::new(),
                second,
            ],
        );
        let recorder = Recorder::new();
        let opened = Vault::open_with_emitter(
            VaultConfig::new(Backend::local(), "t")
                .credsd_socket(socket.clone())
                .route(credsd_token_route("first.example.com"))
                .route(credsd_token_route("second.example.com")),
            Box::new(recorder.clone()),
        )
        .unwrap();
        let phantom = opened.phantoms()[0].token().to_owned();
        let vault = opened.into_vault();
        let headers = [("authorization".into(), format!("Bearer {phantom}"))];
        let request = token_request(&headers);
        let (original, redactor) = vault.attach_with_redactor(request).unwrap().unwrap();
        assert_eq!(
            original.set_headers().next().unwrap().1.as_str(),
            "Bearer ghp_vault_example"
        );
        // Past the first token's expiry, so each failed refresh refuses rather than serving it.
        clock.set(100);
        assert!(
            vault
                .attach_for(request)
                .unwrap_err()
                .to_string()
                .contains("paired")
        );
        assert!(vault.response_redactor(request.destination).is_none());

        // A missing placeholder cannot provoke an acquisition.
        assert!(
            vault
                .attach_with_redactor(Outbound {
                    headers: &[],
                    ..request
                })
                .is_err()
        );
        assert_eq!(recorder.records().len(), 1);
        // Each failure keeps its reason, and the next read waits 1, 2, 4, 8, then at most 10 seconds.
        for (at, next, reason) in [
            (100, 101, "no usable bearer token"),
            (101, 103, "invalid expires_at"),
            (103, 107, "no expires_at"),
            (107, 115, "expired token"),
            (115, 125, "has no credential"),
            (125, 135, "`creds revalidate`"),
            (135, 145, "provider is unavailable"),
            (145, 155, "closed the connection"),
        ] {
            clock.set(at);
            let refusal = vault.attach_with_redactor(request).unwrap_err().to_string();
            assert!(refusal.contains(reason), "at {at}: {refusal}");
            assert!(!refusal.contains("ghp_vault_example"));
            assert!(!refusal.contains("sensitive"), "{refusal}");
            let reads = recorder.records().len();
            // Until the wait ends, a request is refused without reaching the daemon.
            for during in [at, next - 1] {
                clock.set(during);
                assert!(vault.attach_with_redactor(request).is_err());
                assert_eq!(recorder.records().len(), reads, "backed off at {during}");
            }
        }

        clock.set(155);
        let start = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for index in 0..8 {
                let req = if index % 2 == 0 {
                    request
                } else {
                    Outbound {
                        destination: dest("second.example.com", 443, "/"),
                        url: "https://second.example.com/",
                        ..request
                    }
                };
                let (vault, start) = (&vault, &start);
                scope.spawn(move || {
                    start.wait();
                    let (next, scrubber) = vault.attach_with_redactor(req).unwrap().unwrap();
                    assert_eq!(
                        next.set_headers().next().unwrap().1.as_str(),
                        "Bearer second-token"
                    );
                    assert_eq!(
                        scrubber.unwrap().redact_header("second-token").as_deref(),
                        Some("[REDACTED]")
                    );
                });
            }
        });
        let records = recorder.records();
        assert_eq!(
            records.iter().map(|r| r.ok).collect::<Vec<_>>(),
            [
                true, false, false, false, false, false, false, false, false, true
            ]
        );
        assert!(
            records
                .iter()
                .all(|r| r.source == "credsd" && r.credential_ref == "credsd://github")
        );
        assert_eq!(records[0].request_id, RequestId::new(LOAD_CORRELATION));
        assert!(
            records[1..]
                .iter()
                .all(|r| r.request_id == RequestId::new("credential-store-refresh"))
        );
        // Rotation cannot affect a response still in flight.
        let mut redactor = redactor.unwrap();
        let mut body = redactor.push(b"ghp_vault");
        body.extend(redactor.push(b"_example"));
        body.extend(redactor.finish());
        assert_eq!(body, b"[REDACTED]");
        std::fs::remove_file(&socket).unwrap();
    }

    /// An early refresh runs off the request path: a request in the refresh window attaches the
    /// still-valid token while the read is outstanding, and a failed read only delays the next one.
    #[test]
    fn early_credsd_refresh_runs_in_the_background_and_keeps_serving() {
        use std::sync::mpsc::channel;

        let timeout = Duration::from_secs(5);
        let (refresh_started, refresh_seen) = channel();
        let (reply_to_refresh, await_reply) = channel();
        let socket = credsd_answering_with(
            "refresh-overlap",
            [
                token_reply(r#""1970-01-01T01:00:00Z""#),
                error_reply("PROVIDER_UNAVAILABLE"),
                token_reply(r#""1970-01-01T02:00:00Z""#)
                    .replace("ghp_vault_example", "replacement-token"),
            ],
            move |index| {
                if index == 1 {
                    refresh_started.send(()).unwrap();
                    await_reply
                        .recv_timeout(timeout)
                        .expect("release failed reply");
                }
            },
        );
        let clock = crate::rotating::tests::ManualClock::install();
        let recorder = Recorder::new();
        let opened = Vault::open_with_emitter(
            VaultConfig::new(Backend::local(), "t")
                .credsd_socket(socket.clone())
                .route(credsd_token_route("first.example.com")),
            Box::new(recorder.clone()),
        )
        .unwrap();
        let headers = [(
            "authorization".into(),
            format!("Bearer {}", opened.phantoms()[0].token()),
        )];
        let vault = opened.into_vault();
        let token = rotating_token(&vault, "first.example.com");
        let request = token_request(&headers);
        clock.set(3539);
        assert_eq!(attached(&vault, request), "Bearer ghp_vault_example");
        assert_eq!(recorder.records().len(), 1, "no read before the window");

        // The first request in the window starts the read and still attaches at once.
        clock.set(3540);
        assert_eq!(attached(&vault, request), "Bearer ghp_vault_example");
        refresh_seen
            .recv_timeout(timeout)
            .expect("refresh reaches daemon");
        // While the daemon has not answered, another request attaches without waiting on it.
        assert_eq!(attached(&vault, request), "Bearer ghp_vault_example");
        reply_to_refresh.send(()).unwrap();
        token.wait_settled();
        assert_eq!(recorder.records().len(), 2);

        // Within the retry delay the original token serves with no daemon read.
        clock.set(3540);
        assert_eq!(attached(&vault, request), "Bearer ghp_vault_example");
        token.wait_settled();
        assert_eq!(recorder.records().len(), 2);

        // After it, the next request starts another read and gets the replacement once it lands.
        clock.set(3541);
        assert_eq!(attached(&vault, request), "Bearer ghp_vault_example");
        token.wait_settled();
        assert_eq!(attached(&vault, request), "Bearer replacement-token");
        assert_eq!(
            recorder
                .records()
                .iter()
                .map(|record| record.ok)
                .collect::<Vec<_>>(),
            [true, false, true]
        );
        drop(clock);
        let _ = std::fs::remove_file(&socket);
    }

    /// Every request with no valid token, including the one that starts the read, waits for it only
    /// up to its limit, so a daemon that never answers hangs no request.
    #[test]
    fn a_request_waiting_on_a_stuck_read_is_refused_at_its_limit() {
        use std::sync::mpsc::channel;

        let timeout = Duration::from_secs(5);
        let (read_started, read_seen) = channel();
        let (release_read, await_release) = channel::<()>();
        let socket = credsd_answering_with(
            "stuck-read",
            [
                token_reply(r#""1970-01-01T00:01:40Z""#),
                token_reply(r#""2099-01-01T00:00:00Z""#).replace("ghp_vault_example", "late-token"),
            ],
            move |index| {
                if index == 1 {
                    read_started.send(()).unwrap();
                    let _ = await_release.recv_timeout(timeout);
                }
            },
        );
        let clock = crate::rotating::tests::ManualClock::install();
        crate::rotating::tests::TEST_READ_WAIT.set(Some(Duration::from_millis(200)));
        let opened = Vault::open(
            VaultConfig::new(Backend::local(), "t")
                .credsd_socket(socket.clone())
                .route(credsd_token_route("first.example.com")),
        )
        .unwrap();
        crate::rotating::tests::TEST_READ_WAIT.set(None);
        let headers = [(
            "authorization".into(),
            format!("Bearer {}", opened.phantoms()[0].token()),
        )];
        let vault = opened.into_vault();
        let request = token_request(&headers);
        clock.set(100);
        let shared = &vault;
        let rotating = rotating_token(&vault, "first.example.com");
        std::thread::scope(|scope| {
            let (answered, answer) = channel();
            // The first request after expiry starts the read; it and a second request that joins it
            // are both refused at the limit while credsd holds the read.
            for _ in 0..2 {
                let answered = answered.clone();
                scope.spawn(move || {
                    let _ = answered.send(shared.attach_with_redactor(request).map(|_| ()));
                });
            }
            read_seen
                .recv_timeout(timeout)
                .expect("the read reaches credsd");
            for _ in 0..2 {
                let refusal = answer
                    .recv_timeout(timeout)
                    .expect("each request is answered at its limit")
                    .unwrap_err()
                    .to_string();
                assert!(refusal.contains("did not answer"), "{refusal}");
            }
            release_read.send(()).unwrap();
        });
        rotating.wait_settled();
        assert_eq!(attached(&vault, request), "Bearer late-token");
        drop(clock);
        let _ = std::fs::remove_file(&socket);
    }

    /// A failed read is retried no later than the token's expiry, however long the backoff has
    /// grown, and a success restarts the backoff at its first wait.
    #[test]
    fn a_failed_read_is_due_by_expiry_and_backoff_restarts_after_success() {
        let clock = crate::rotating::tests::ManualClock::install();
        let token = |expires_at: &str, value: &str| {
            token_reply(&format!("\"{expires_at}\"")).replace("ghp_vault_example", value)
        };
        let socket = credsd_answering(
            "retry-by-expiry",
            [
                token("1970-01-01T00:01:40Z", "first-token"),
                error_reply("PROVIDER_UNAVAILABLE"),
                error_reply("PROVIDER_UNAVAILABLE"),
                error_reply("PROVIDER_UNAVAILABLE"),
                error_reply("PROVIDER_UNAVAILABLE"),
                error_reply("PROVIDER_UNAVAILABLE"),
                token("1970-01-01T00:16:40Z", "second-token"),
                error_reply("PROVIDER_UNAVAILABLE"),
                token("2099-01-01T00:00:00Z", "third-token"),
            ],
        );
        let recorder = Recorder::new();
        let opened = Vault::open_with_emitter(
            VaultConfig::new(Backend::local(), "t")
                .credsd_socket(socket.clone())
                .route(credsd_token_route("first.example.com")),
            Box::new(recorder.clone()),
        )
        .unwrap();
        let headers = [(
            "authorization".into(),
            format!("Bearer {}", opened.phantoms()[0].token()),
        )];
        let vault = opened.into_vault();
        let rotating = rotating_token(&vault, "first.example.com");
        let request = token_request(&headers);
        // Early reads fail at 80, 81, 83, 87, and 95; the fifth backoff, 10 s, would end past expiry
        // at 100.
        for at in [80, 81, 83, 87, 95] {
            clock.set(at);
            assert_eq!(attached(&vault, request), "Bearer first-token");
            rotating.wait_settled();
        }
        assert_eq!(recorder.records().len(), 6);
        clock.set(100);
        assert_eq!(attached(&vault, request), "Bearer second-token");
        // The next failure waits the first 1 s again, not the grown backoff.
        clock.set(1000);
        assert!(vault.attach_with_redactor(request).is_err());
        clock.set(1001);
        assert_eq!(attached(&vault, request), "Bearer third-token");
        assert_eq!(recorder.records().len(), 9);
        drop(clock);
        let _ = std::fs::remove_file(&socket);
    }

    /// A daemon that needs the operator to sign in again is reported once for each run of failed
    /// reads, and each refusal names the remedy.
    #[test]
    fn credsd_reauthentication_is_reported_once_per_failure_run() {
        let clock = crate::rotating::tests::ManualClock::install();
        let socket = credsd_answering(
            "reauth",
            [
                token_reply(r#""1970-01-01T00:01:40Z""#),
                error_reply("REAUTH_REQUIRED"),
                error_reply("REAUTH_REQUIRED"),
                token_reply(r#""1970-01-01T00:16:40Z""#),
                error_reply("REAUTH_REQUIRED"),
            ],
        );
        let tenant = "reauth-tenant";
        let opened = Vault::open(
            VaultConfig::new(Backend::local(), tenant)
                .credsd_socket(socket.clone())
                .route(credsd_token_route("first.example.com")),
        )
        .unwrap();
        let headers = [(
            "authorization".into(),
            format!("Bearer {}", opened.phantoms()[0].token()),
        )];
        let vault = opened.into_vault();
        let rotating = rotating_token(&vault, "first.example.com");
        let request = token_request(&headers);
        let reports = || {
            CAPTURED_OPERATOR_WARNINGS
                .lock()
                .unwrap()
                .iter()
                .filter(|(from, message)| from == tenant && message.contains("re-authentication"))
                .count()
        };

        // While the first report is blocked on stderr, another request is still answered.
        clock.set(100);
        let (report_started, report_seen) = std::sync::mpsc::channel();
        let (release_report, await_release) = std::sync::mpsc::channel::<()>();
        let shared = &vault;
        *crate::rotating::tests::BEFORE_REPORT.lock().unwrap() = Some((
            tenant.to_string(),
            Box::new(move || {
                report_started.send(()).unwrap();
                let _ = await_release.recv_timeout(Duration::from_secs(5));
            }),
        ));
        std::thread::scope(|scope| {
            let reporting = scope.spawn(move || shared.attach_with_redactor(request).map(|_| ()));
            report_seen
                .recv_timeout(Duration::from_secs(5))
                .expect("the re-authentication report starts");
            let (answered, answer) = std::sync::mpsc::channel();
            scope.spawn(move || answered.send(shared.attach_with_redactor(request).is_err()));
            assert_eq!(
                answer.recv_timeout(Duration::from_secs(2)),
                Ok(true),
                "a request waits on no report"
            );
            release_report.send(()).unwrap();
            assert!(reporting.join().unwrap().is_err());
        });
        for (at, reported) in [(100, 1), (105, 1)] {
            clock.set(at);
            let refusal = vault.attach_with_redactor(request).unwrap_err().to_string();
            assert!(
                refusal.contains("`creds login --credential github`"),
                "{refusal}"
            );
            rotating.wait_settled();
            assert_eq!(reports(), reported, "at {at}");
        }
        clock.set(115);
        assert_eq!(attached(&vault, request), "Bearer ghp_vault_example");
        // A success ends the run, so the next failure is reported again.
        clock.set(1000);
        assert!(vault.attach_with_redactor(request).is_err());
        rotating.wait_settled();
        assert_eq!(reports(), 2);
        drop(clock);
        let _ = std::fs::remove_file(&socket);
    }

    /// A token with no expiry opens with no warning.
    #[test]
    fn a_credsd_token_that_never_expires_opens_with_no_warning() {
        drain_captured_warnings();
        let socket = credsd_answering_once("forever", token_reply("null"));
        let _opened = Vault::open(
            VaultConfig::new(Backend::local(), "t")
                .credsd_socket(socket.clone())
                .route(credsd_token_route("forever.example.com"))
                .require_every_route(),
        )
        .expect("the token route opens");
        assert!(
            drain_captured_warnings().is_empty(),
            "a token that never expires needs no warning"
        );
        let _ = std::fs::remove_file(&socket);
    }

    /// A token route whose environment serves AWS credentials fails the open, so no route loads
    /// with a credential it cannot attach.
    #[test]
    fn a_credsd_token_route_that_reads_aws_credentials_fails_the_open() {
        let socket = credsd_answering_once(
            "aws",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"material\":{\"type\":\"session_credentials\",\"access_key_id\":\"ASIAX\",\"secret_access_key\":\"vaultSecretExample\",\"session_token\":\"tok\"}}}\n".to_string(),
        );
        let error = Vault::open(
            VaultConfig::new(Backend::local(), "t")
                .credsd_socket(socket.clone())
                .route(credsd_token_route("aws.example.com")),
        )
        .expect_err("AWS material is no token");
        let message = error.to_string();
        assert!(
            message.contains("session_credentials") && message.contains("access_token"),
            "{message}"
        );
        assert!(
            !message.contains("vaultSecretExample"),
            "no material: {message}"
        );
        let _ = std::fs::remove_file(&socket);
    }

    /// Every route that names one credsd token shares one read: the fake daemon answers one
    /// connection, so a second read would fail the open.
    #[test]
    fn routes_that_name_one_credsd_token_read_it_once() {
        let socket = credsd_answering_once("shared", token_reply("null"));
        let recorder = Recorder::new();
        let opened = Vault::open_with_emitter(
            VaultConfig::new(Backend::local(), "t")
                .credsd_socket(socket.clone())
                .route(credsd_token_route("first.example.com"))
                .route(credsd_token_route("second.example.com"))
                .require_every_route(),
            Box::new(recorder.clone()),
        )
        .expect("both routes open on one read");
        assert_eq!(recorder.records().len(), 1, "one read, one record");
        let phantoms = opened.phantoms();
        assert_eq!(phantoms.len(), 2);
        assert_eq!(
            phantoms[0].token(),
            phantoms[1].token(),
            "one token, one placeholder"
        );
        let _ = std::fs::remove_file(&socket);
    }

    /// A box-owned `credsd://` route is refused at open: only an opaque route reads a credsd token,
    /// and no daemon is contacted for it.
    #[test]
    fn a_box_owned_credsd_route_is_refused() {
        let socket = std::env::temp_dir().join(format!(
            "credsd-vault-box-owned-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket);
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind the socket");
        listener
            .set_nonblocking(true)
            .expect("a nonblocking listener");
        let error = Vault::open(
            VaultConfig::new(Backend::local(), "t")
                .credsd_socket(socket.clone())
                .route(RouteSpec::box_owned(
                    DestinationPattern::parse("api.github.com").unwrap(),
                    Locator::parse_uri("credsd://github").unwrap(),
                    InjectMode::header("Bearer {}", None).unwrap(),
                )),
        )
        .expect_err("a box-owned credsd route has no source");
        assert!(
            error
                .to_string()
                .contains("no credential source registered for scheme \"credsd\""),
            "{error}"
        );
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "no daemon is contacted"
        );
        let _ = std::fs::remove_file(&socket);
    }
}
