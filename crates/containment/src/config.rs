//! Complete configuration for one containment application.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ContainmentError;
use crate::model::{
    BackendOverride, IpcMode, Network, Operation, PathGrant, PreparedFilesystemPath,
    ProcessInfoMode, Scope, SignalMode, WriteProtection,
};

type Result<T> = std::result::Result<T, ContainmentError>;

/// Complete configuration for containing one process.
///
/// **This is the wire format, and there is no second type describing it.** Each field validates
/// itself on load — a `PathGrant` re-resolves its own path and refuses its own illegal cell, and
/// `network` runs the same port checks [`Self::set_network`] does — so loading a crafted payload
/// meets every refusal a caller meets. A missing key is an error except for an additive wire field
/// that has an explicit default.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentConfig {
    paths: Vec<PathGrant>,
    identity_requirements: Vec<WriteProtection>,
    write_protections: Vec<WriteProtection>,
    #[serde(deserialize_with = "deserialize_validated_network")]
    network: Network,
    process: Process,
    backend_override: BackendOverride,
    /// The home this caller resolved its `~/`-relative grants against, added to the floor's anchors.
    #[serde(deserialize_with = "deserialize_stated_home")]
    operator_home: Option<PathBuf>,
    /// Credential-store grants that may pass the credential floor.
    #[serde(default)]
    credential_store_grants: Vec<CredentialStoreGrant>,
    /// Subtrees a leaf may test for existence and read metadata over, never content; credential
    /// stores beneath them stay refused. Empty for the agent box.
    #[serde(default, deserialize_with = "deserialize_canonical_paths")]
    discovery_roots: Vec<PathBuf>,
    /// Subtrees excluded from discovery even when they lie under a discovery root — the box's own
    /// state, so a leaf cannot stat this box's private state or a sibling box's. An explicit grant
    /// beneath one (the CA trust bundle) still applies. Empty for the agent box.
    #[serde(default, deserialize_with = "deserialize_canonical_paths")]
    discovery_denies: Vec<PathBuf>,
    /// Whether the leaf renders `(allow process-exec*)` in addition to its exec literals, and a
    /// `file-map-executable` allow over its writable grants. False for the agent box.
    #[serde(default)]
    broad_exec: bool,
    /// Whether the process may reach the host services a bundled JS/Node runtime touches at startup:
    /// `getifaddrs` (the `net.*` sysctls it reads and the routing socket it opens) and `getpwuid`
    /// (identity resolution via `opendirectoryd`). Leaf-only; the agent box never sets it. It grants
    /// read-only host information, identity lookup, and a routing socket — never egress (the profile's
    /// `(deny network*)` still stands and AF_INET/AF_UNIX are unaffected).
    #[serde(default)]
    runtime_services: bool,
}

/// One credential-store floor exception, tied to its matching path grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialStoreGrant {
    path: PathBuf,
    operation: Operation,
}

/// What the contained process may observe or affect about other processes.
///
/// One group rather than three loose fields, so the model and the wire are the same shape.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Process {
    pub(crate) signals: SignalMode,
    pub(crate) info: ProcessInfoMode,
    pub(crate) ipc: IpcMode,
}

impl ContainmentConfig {
    /// Create a deny-by-default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            paths: Vec::new(),
            identity_requirements: Vec::new(),
            write_protections: Vec::new(),
            network: Network::Blocked,
            process: Process::default(),
            backend_override: BackendOverride::None,
            operator_home: None,
            credential_store_grants: Vec::new(),
            discovery_roots: Vec::new(),
            discovery_denies: Vec::new(),
            broad_exec: false,
            runtime_services: false,
        }
    }

    /// State the home this caller resolved its `~/`-relative grants against, as an absolute path.
    ///
    /// It joins the passwd-database anchor rather than replacing it, so a caller naming the wrong
    /// home widens the refusal set and can never narrow it. One home is stated, so a second call
    /// replaces the first; the passwd anchor is unaffected either way. A path that is not absolute is
    /// refused when the floor runs.
    #[must_use]
    pub fn anchored_at(mut self, operator_home: impl AsRef<Path>) -> Self {
        let home = operator_home.as_ref();
        // Canonical, to match both the passwd anchor and a grant's own identity.
        self.operator_home = Some(home.canonicalize().unwrap_or_else(|_| home.to_path_buf()));
        self
    }

    /// Let a leaf test existence and read metadata across `path`, never its content, so a contained
    /// tool can probe for optional config without a fatal refusal. Credential stores beneath `path`
    /// stay refused. Leaf-only; the agent box never calls this. macOS renders it; Linux defers.
    #[must_use]
    pub fn allow_discovery(mut self, path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        self.discovery_roots
            .push(path.canonicalize().unwrap_or_else(|_| path.to_path_buf()));
        self
    }

    /// Exclude `path` from discovery even under a discovery root, so a leaf cannot test existence or
    /// read metadata across it — the box's own `.strands-box` state. An explicit grant beneath it
    /// still applies. Leaf-only; macOS renders it, and only when discovery is active.
    #[must_use]
    pub fn deny_discovery(mut self, path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        self.discovery_denies
            .push(path.canonicalize().unwrap_or_else(|_| path.to_path_buf()));
        self
    }

    /// Let a leaf `exec` any reachable binary (`process-exec*`, in addition to its exec literals) and
    /// load what it compiles in its writable grants. Leaf-only and macOS-only; the agent box never
    /// calls this.
    #[must_use]
    pub fn allow_broad_exec(mut self) -> Self {
        self.broad_exec = true;
        self
    }

    /// Let the process reach the host services a bundled JS/Node runtime touches at startup:
    /// `getifaddrs` (the `net.*` sysctls and a routing socket) and `getpwuid` (identity resolution
    /// via `opendirectoryd`). A contained leaf running such a runtime calls both
    /// before any workload code and dies with no diagnostic without them. Leaf-only; the agent box
    /// never calls this. Read-only host info, identity lookup, and a routing socket — never egress.
    /// macOS renders it; Linux defers.
    #[must_use]
    pub fn allow_runtime_services(mut self) -> Self {
        self.runtime_services = true;
        self
    }

    /// Whether the runtime-services grant was made.
    pub(crate) fn runtime_services(&self) -> bool {
        self.runtime_services
    }

    /// Resolve one existing filesystem path before an authorization decision.
    pub fn prepare_filesystem_path(path: impl AsRef<Path>) -> Result<PreparedFilesystemPath> {
        PreparedFilesystemPath::new(path)
    }

    /// Authorize one operation at one scope on one path.
    ///
    /// Refuses an illegal pair, and refuses a scope that disagrees with the filesystem. A path
    /// needing read and write takes two calls.
    pub fn allow(
        mut self,
        path: impl AsRef<Path>,
        operation: Operation,
        scope: Scope,
    ) -> Result<Self> {
        require_authorizing(operation)?;
        self.paths.push(PathGrant::new(path, operation, scope)?);
        Ok(self)
    }

    /// Refuse one path, a whole tree at `Root` scope or one file at `File` scope, whatever any grant
    /// says.
    ///
    /// The path need not exist.
    /// `docs/design/decisions.md#a-denial-is-an-operation-not-a-second-list` holds why.
    pub fn refuse(mut self, path: impl AsRef<Path>, scope: Scope) -> Result<Self> {
        self.paths.push(PathGrant::denial(path, scope)?);
        Ok(self)
    }

    /// Authorize an already-resolved identity without looking it up again.
    pub fn allow_prepared(
        mut self,
        path: PreparedFilesystemPath,
        operation: Operation,
        scope: Scope,
    ) -> Result<Self> {
        require_authorizing(operation)?;
        self.paths
            .push(PathGrant::from_prepared(path, operation, scope)?);
        Ok(self)
    }

    /// Authorize one exact credential-store path and its matching floor exception.
    pub fn allow_credential_store(
        mut self,
        path: impl AsRef<Path>,
        operation: Operation,
        scope: Scope,
    ) -> Result<Self> {
        if !matches!(operation, Operation::Read | Operation::Write) {
            return Err(ContainmentError::ConfigValidation(format!(
                "a credential-store grant must be Read or Write, not {operation:?}"
            )));
        }
        let path = path.as_ref();
        if !crate::floors::credential_store_exception_path(path, self.operator_home.as_deref())? {
            return Err(ContainmentError::ConfigValidation(format!(
                "a credential-store grant must name an exact credential-store path: {}",
                path.display()
            )));
        }
        let grant = PathGrant::new(path, operation, scope)?;
        if !crate::floors::credential_store_exception_path(
            &grant.resolved,
            self.operator_home.as_deref(),
        )? {
            return Err(ContainmentError::ConfigValidation(format!(
                "a credential-store grant resolves outside every credential store: {}",
                grant.resolved.display()
            )));
        }
        if !crate::floors::credential_store_grant_stays_in_store(
            &grant,
            self.operator_home.as_deref(),
        )? {
            return Err(ContainmentError::ConfigValidation(format!(
                "a credential-store grant resolves into a different store: {} -> {}",
                grant.original.display(),
                grant.resolved.display()
            )));
        }
        self.credential_store_grants.push(CredentialStoreGrant {
            path: grant.resolved.clone(),
            operation,
        });
        self.paths.push(grant);
        Ok(self)
    }

    /// Deny writes to one opened regular file; a backend can allow metadata and existence checks or deny execution.
    pub fn protect_write(mut self, path: impl AsRef<Path>, opened: &std::fs::File) -> Result<Self> {
        let protection = WriteProtection::new(path, opened)?;
        if self
            .write_protections
            .iter()
            .any(|existing| existing.path() == protection.path())
        {
            return Err(ContainmentError::ConflictingGrants {
                reason: format!("{} is write-protected twice", protection.path().display()),
            });
        }
        self.write_protections.push(protection);
        Ok(self)
    }

    /// Require one opened regular file to keep its path and identity; a backend can allow metadata and existence checks.
    pub fn require_file_identity(
        mut self,
        path: impl AsRef<Path>,
        opened: &std::fs::File,
    ) -> Result<Self> {
        let requirement = WriteProtection::new(path, opened)?;
        if self
            .identity_requirements
            .iter()
            .any(|existing| existing.path() == requirement.path())
        {
            return Err(ContainmentError::ConflictingGrants {
                reason: format!(
                    "{} has two identity requirements",
                    requirement.path().display()
                ),
            });
        }
        self.identity_requirements.push(requirement);
        Ok(self)
    }

    /// Set the network mode after validating every concrete port.
    pub fn set_network(mut self, network: Network) -> Result<Self> {
        validate_network(&network)?;
        self.network = network;
        Ok(self)
    }

    /// Set the signal-isolation mode.
    #[must_use]
    pub fn set_signal_mode(mut self, mode: SignalMode) -> Self {
        self.process.signals = mode;
        self
    }

    /// Set the process-information visibility mode.
    #[must_use]
    pub fn set_process_info_mode(mut self, mode: ProcessInfoMode) -> Self {
        self.process.info = mode;
        self
    }

    /// Set the IPC mode.
    #[must_use]
    pub fn set_ipc_mode(mut self, mode: IpcMode) -> Self {
        self.process.ipc = mode;
        self
    }

    /// Select an explicit backend-specific mechanism override.
    #[must_use]
    pub fn with_backend_override(mut self, backend_override: BackendOverride) -> Self {
        self.backend_override = backend_override;
        self
    }

    /// Every grant pair that renders and that the caller should disclose before it applies.
    #[must_use]
    pub fn warnings(&self) -> Vec<crate::floors::ContainmentWarning> {
        crate::floors::warnings(self)
    }

    /// Serialize this complete containment request as strict, full-fidelity JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|error| {
            ContainmentError::ConfigValidation(format!(
                "failed to serialize containment config: {error}"
            ))
        })
    }

    /// Load a complete containment request from strict JSON, revalidating all of it.
    ///
    /// A refusal this crate raised travels as the parse error's own text, because serde wraps one
    /// rather than carrying its type. Reported verbatim, so an operator reads the drift or the
    /// illegal cell rather than "invalid value".
    pub fn from_json(json: &str) -> Result<Self> {
        let config: Self = serde_json::from_str(json).map_err(|error| {
            ContainmentError::ConfigValidation(format!(
                "failed to parse containment config: {error}"
            ))
        })?;
        config.validate_credential_store_grants()?;
        config.validate_discovery()?;
        Ok(config)
    }

    /// Each discovery root must lie at or under the operator home, so a crafted config cannot open
    /// existence and metadata beyond the home posture `allow_discovery` produces. A discovery deny
    /// only subtracts, so it needs no upper bound.
    fn validate_discovery(&self) -> Result<()> {
        if self.discovery_roots.is_empty() {
            return Ok(());
        }
        let Some(home) = self.operator_home.as_deref() else {
            return Err(ContainmentError::ConfigValidation(
                "a discovery root needs a stated operator home to bound it".to_string(),
            ));
        };
        for root in &self.discovery_roots {
            if !root.starts_with(home) {
                return Err(ContainmentError::ConfigValidation(format!(
                    "a discovery root must lie at or under the operator home {}: {}",
                    home.display(),
                    root.display()
                )));
            }
        }
        Ok(())
    }

    /// Every entry that refuses rather than authorizes, in the order the caller stated it.
    pub(crate) fn refusals(&self) -> Vec<&PathGrant> {
        self.paths
            .iter()
            .filter(|granted| granted.operation == Operation::Deny)
            .collect()
    }

    /// Every entry that authorizes, which is every backend's grant set.
    pub(crate) fn authorizations(&self) -> Vec<&PathGrant> {
        self.paths
            .iter()
            .filter(|granted| granted.operation != Operation::Deny)
            .collect()
    }

    /// What the workload may reach on the network.
    #[must_use]
    pub fn network(&self) -> &Network {
        &self.network
    }

    /// Signal-isolation mode.
    #[must_use]
    pub fn signal_mode(&self) -> SignalMode {
        self.process.signals
    }

    /// Process-information visibility mode.
    #[must_use]
    pub fn process_info_mode(&self) -> ProcessInfoMode {
        self.process.info
    }

    /// IPC mode.
    #[must_use]
    pub fn ipc_mode(&self) -> IpcMode {
        self.process.ipc
    }

    /// Backend-specific mechanism override.
    #[must_use]
    pub fn backend_override(&self) -> &BackendOverride {
        &self.backend_override
    }

    pub(crate) fn write_protections(&self) -> &[WriteProtection] {
        &self.write_protections
    }

    pub(crate) fn identity_requirements(&self) -> &[WriteProtection] {
        &self.identity_requirements
    }

    /// The home this caller stated it resolved its `~/`-relative grants against.
    pub(crate) fn operator_home(&self) -> Option<&Path> {
        self.operator_home.as_deref()
    }

    /// Subtrees a leaf may test for existence and read metadata over (never content).
    pub(crate) fn discovery_roots(&self) -> &[PathBuf] {
        &self.discovery_roots
    }

    /// Subtrees excluded from discovery even under a discovery root (the box's own state).
    pub(crate) fn discovery_denies(&self) -> &[PathBuf] {
        &self.discovery_denies
    }

    /// Whether the leaf renders broad `process-exec*` and a `file-map-executable` allow over its writable grants.
    pub(crate) fn broad_exec(&self) -> bool {
        self.broad_exec
    }

    /// Whether this exact grant lies at or under its credential-store floor exception.
    pub(crate) fn credential_store_exempts(&self, granted: &PathGrant) -> bool {
        self.credential_store_exception_covers(granted)
            && crate::floors::credential_store_exception_path(
                &granted.original,
                self.operator_home.as_deref(),
            )
            .unwrap_or(false)
            && crate::floors::credential_store_grant_stays_in_store(
                granted,
                self.operator_home.as_deref(),
            )
            .unwrap_or(false)
    }

    fn credential_store_exception_covers(&self, granted: &PathGrant) -> bool {
        self.credential_store_grants.iter().any(|exception| {
            exception.operation == granted.operation
                && granted.resolved.starts_with(&exception.path)
        })
    }

    /// Every grant in one cell, which is one operation at one scope.
    ///
    /// One definition, because two callers had a closure each: this check, and the Seatbelt
    /// renderer's own expressibility pass.
    pub(crate) fn grants_in(&self, operation: Operation, scope: Scope) -> Vec<&PathGrant> {
        self.paths
            .iter()
            .filter(|granted| granted.operation == operation && granted.scope == scope)
            .collect()
    }

    /// Revalidate every absolute caller spelling against its prepared identity.
    ///
    /// The one floor that touches the filesystem, so it runs last.
    ///
    /// `pub(crate)` because each backend re-runs it at its own last safe point, which is this crate's
    /// stated pattern: validate at the façade, then again where the rule is built.
    pub(crate) fn require_live_path_identities(&self) -> Result<()> {
        for granted in &self.paths {
            granted.validate_live_identity()?;
        }
        self.require_live_file_identities()
    }

    pub(crate) fn require_live_file_identities(&self) -> Result<()> {
        for required in &self.identity_requirements {
            required.validate_live_identity()?;
        }
        for protected in &self.write_protections {
            protected.validate_live_identity()?;
        }
        Ok(())
    }

    fn validate_credential_store_grants(&self) -> Result<()> {
        for (index, exception) in self.credential_store_grants.iter().enumerate() {
            if !exception.path.is_absolute() {
                return Err(ContainmentError::ConfigValidation(format!(
                    "credential-store grant path must be absolute: {}",
                    exception.path.display()
                )));
            }
            if !matches!(exception.operation, Operation::Read | Operation::Write) {
                return Err(ContainmentError::ConfigValidation(format!(
                    "credential-store grant must be Read or Write, not {:?}",
                    exception.operation
                )));
            }
            if !crate::floors::credential_store_exception_path(
                &exception.path,
                self.operator_home.as_deref(),
            )? {
                return Err(ContainmentError::ConfigValidation(format!(
                    "credential-store grant path does not name a credential store: {}",
                    exception.path.display()
                )));
            }
            if self.credential_store_grants[..index].contains(exception) {
                return Err(ContainmentError::ConfigValidation(format!(
                    "credential-store grant is duplicated for {} with operation {:?}",
                    exception.path.display(),
                    exception.operation
                )));
            }
            let Some(granted) = self.paths.iter().find(|granted| {
                granted.resolved == exception.path && granted.operation == exception.operation
            }) else {
                return Err(ContainmentError::ConfigValidation(format!(
                    "credential-store grant for {} with operation {:?} has no matching path grant",
                    exception.path.display(),
                    exception.operation
                )));
            };
            if !crate::floors::credential_store_exception_path(
                &granted.original,
                self.operator_home.as_deref(),
            )? {
                return Err(ContainmentError::ConfigValidation(format!(
                    "credential-store grant uses a non-exact original path: {}",
                    granted.original.display()
                )));
            }
            if !crate::floors::credential_store_grant_stays_in_store(
                granted,
                self.operator_home.as_deref(),
            )? {
                return Err(ContainmentError::ConfigValidation(format!(
                    "credential-store grant switches stores: {} -> {}",
                    granted.original.display(),
                    granted.resolved.display()
                )));
            }
        }
        for granted in &self.paths {
            if self.credential_store_exception_covers(granted) {
                if !crate::floors::credential_store_exception_path(
                    &granted.original,
                    self.operator_home.as_deref(),
                )? {
                    return Err(ContainmentError::ConfigValidation(format!(
                        "credential-store grant covers a non-exact original path: {}",
                        granted.original.display()
                    )));
                }
                if !crate::floors::credential_store_grant_stays_in_store(
                    granted,
                    self.operator_home.as_deref(),
                )? {
                    return Err(ContainmentError::ConfigValidation(format!(
                        "credential-store grant covers a path from another store: {} -> {}",
                        granted.original.display(),
                        granted.resolved.display()
                    )));
                }
            }
        }
        self.validate_platform_credential_grants()
    }

    pub(crate) fn validate_platform_credential_grants(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        for writable in self
            .credential_store_grants
            .iter()
            .filter(|grant| grant.operation == Operation::Write)
        {
            if !self
                .credential_store_grants
                .iter()
                .any(|grant| grant.operation == Operation::Read && grant.path == writable.path)
            {
                return Err(ContainmentError::ConfigValidation(format!(
                    "credential-store write grant must have a read grant on Linux: {}",
                    writable.path.display()
                )));
            }
        }
        Ok(())
    }
}

impl Default for ContainmentConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Read a `Network` and run the same checks the builder does.
///
/// A field hook rather than a wire twin for the enum: the shape is identical, and only the ports need
/// judging.
fn deserialize_validated_network<'de, D>(deserializer: D) -> std::result::Result<Network, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let network = Network::deserialize(deserializer)?;
    validate_network(&network).map_err(serde::de::Error::custom)?;
    Ok(network)
}

/// Deserialize the stated home, keeping the key required and refusing a spelling that is not one.
///
/// A relative anchor would resolve against the applying process's own working directory, so the
/// anchor set would depend on where the trampoline was started
/// (docs/design/decisions.md#the-configuration-is-its-own-wire-format).
fn deserialize_stated_home<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<PathBuf>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let home = Option::<PathBuf>::deserialize(deserializer)?;
    if let Some(home) = home.as_deref() {
        require_absolute_home(home).map_err(serde::de::Error::custom)?;
    }
    Ok(home)
}

/// Canonicalize each discovery path on load, so a config read from JSON matches the seatbelt subpath
/// checks the way the `allow_discovery`/`deny_discovery` builders do — a non-canonical entry cannot
/// silently miss the tree it guards
/// (docs/design/decisions.md#a-leaf-discovers-existence-and-metadata-content-stays-gated). A path
/// that does not resolve is kept as authored, as the builders keep it.
fn deserialize_canonical_paths<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<PathBuf>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let paths = Vec::<PathBuf>::deserialize(deserializer)?;
    paths
        .into_iter()
        .map(|path| {
            if !path.is_absolute() {
                return Err(serde::de::Error::custom(format!(
                    "a discovery path must be absolute, so it does not resolve against the applying \
                     process's own working directory: {}",
                    path.display()
                )));
            }
            Ok(path.canonicalize().unwrap_or(path))
        })
        .collect()
}

/// Refuse `Operation::Deny` from an authorizing verb, so a denial has one constructor.
///
/// `refuse` takes the lexical route a denial needs and refuses a `..` component; reaching `Deny`
/// through `allow` would take neither.
fn require_authorizing(operation: Operation) -> Result<()> {
    if operation == Operation::Deny {
        return Err(ContainmentError::UnsupportedCapability {
            capability: "Operation::Deny through an authorizing verb: state a denial with `refuse`"
                .to_string(),
            backend: "vocabulary".to_string(),
        });
    }
    Ok(())
}

/// Refuse a stated home that is not an absolute path.
fn require_absolute_home(home: &Path) -> Result<()> {
    if home.as_os_str().is_empty() || !home.is_absolute() {
        return Err(ContainmentError::ConfigValidation(format!(
            "the stated operator home must be an absolute path, so the floor's anchors do not depend \
             on a working directory: {}",
            home.display()
        )));
    }
    Ok(())
}

fn validate_network(network: &Network) -> Result<()> {
    if let Network::Localhost { connect, listen } = network {
        // Not `InvalidPort`: there is no port 0 here, the list is simply empty, and an
        // "invalid port 0" diagnostic points an operator at the wrong defect.
        if connect.is_empty() {
            return Err(ContainmentError::ConflictingGrants {
                reason:
                    "Localhost names no port to connect to, so the workload would reach nothing"
                        .to_string(),
            });
        }
        for port in connect {
            validate_port("connect", *port)?;
        }
        // Two grants naming one port is one grant, so the config would state a boundary the
        // profile does not carry. Refused rather than folded, because the caller meant two
        // services and got one.
        for (index, port) in connect.iter().enumerate() {
            if connect[..index].contains(port) {
                return Err(ContainmentError::ConflictingGrants {
                    reason: format!(
                        "two of the composition's localhost ports are both {port}; two services \
                         cannot share one port"
                    ),
                });
            }
        }
        for port in listen {
            validate_port("listen", *port)?;
        }
    }
    Ok(())
}

fn validate_port(field: &'static str, port: u16) -> Result<()> {
    if port == 0 {
        return Err(ContainmentError::InvalidPort { field, port });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn prepared_path_preserves_the_authorized_identity_and_original_spelling() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let original = temp.path().join("requested");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, &original).unwrap();

        let prepared = ContainmentConfig::prepare_filesystem_path(&original).unwrap();
        assert_eq!(prepared.resolved_path(), target.canonicalize().unwrap());

        let config = ContainmentConfig::new()
            .allow_prepared(prepared, Operation::Read, Scope::Root)
            .unwrap();
        let granted = &config.authorizations()[0];
        assert_eq!(granted.original, original);
        assert_eq!(granted.resolved, target.canonicalize().unwrap());
        assert!(granted.is_directory());
    }

    /// The scope a caller asks for is the scope validation applies, so a directory scope cannot be
    /// satisfied by a file and vice versa.
    #[test]
    fn a_grant_is_validated_against_the_scope_it_asks_for() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().canonicalize().unwrap();
        let file = directory.join("agent.sock");
        std::fs::write(&file, "").unwrap();

        for scope in [Scope::Dir, Scope::Root] {
            let config = ContainmentConfig::new()
                .allow(&directory, Operation::Read, scope)
                .unwrap();
            assert_eq!(config.authorizations()[0].scope, scope);
            assert_eq!(config.authorizations()[0].resolved, directory);

            assert!(
                matches!(
                    ContainmentConfig::new().allow(&file, Operation::Read, scope),
                    Err(ContainmentError::ExpectedDirectory(_))
                ),
                "a file must not satisfy {scope:?}"
            );
        }

        assert!(matches!(
            ContainmentConfig::new().allow(&directory, Operation::Connect, Scope::File),
            Err(ContainmentError::ExpectedFile(_))
        ));
    }

    /// **Every illegal cell an authorizing verb can state is refused by the vocabulary**, so no
    /// backend sees a pair it cannot render.
    ///
    /// Seven of the eight refusals are here. The `Deny` row is not reachable through `allow` at
    /// all — it refuses that operation outright — and
    /// `profile_conformance.rs::a_refusal_at_dir_scope_is_refused_and_file_scope_names_one_file`
    /// pins it through the verb that does state one.
    #[test]
    fn the_illegal_cells_are_refused_before_a_backend_sees_them() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().canonicalize().unwrap();
        let file = directory.join("program");
        std::fs::write(&file, "").unwrap();

        // A denial has one constructor, so an authorizing verb refuses the operation at every scope.
        for scope in [Scope::File, Scope::Dir, Scope::Root] {
            assert!(
                ContainmentConfig::new()
                    .allow(&directory, Operation::Deny, scope)
                    .is_err(),
                "a denial must be stated with `refuse`, never through `allow` at {scope:?} scope"
            );
        }

        for (path, operation, scope) in [
            (directory.as_path(), Operation::Exec, Scope::Dir),
            (file.as_path(), Operation::List, Scope::File),
            (directory.as_path(), Operation::List, Scope::Dir),
            (directory.as_path(), Operation::Write, Scope::Dir),
            (directory.as_path(), Operation::Connect, Scope::Dir),
            (directory.as_path(), Operation::Connect, Scope::Root),
            (file.as_path(), Operation::Metadata, Scope::File),
        ] {
            let refusal = ContainmentConfig::new()
                .allow(path, operation, scope)
                .expect_err("{operation:?} at {scope:?} is not a legal cell");
            assert!(
                matches!(refusal, ContainmentError::UnsupportedCapability { .. }),
                "{operation:?} at {scope:?}: {refusal:?}"
            );
        }

        for (operation, scope) in [
            (Operation::Exec, Scope::File),
            (Operation::Read, Scope::File),
            (Operation::Write, Scope::File),
            (Operation::Connect, Scope::File),
        ] {
            ContainmentConfig::new()
                .allow(&file, operation, scope)
                .unwrap_or_else(|e| panic!("{operation:?} at {scope:?} is legal: {e:?}"));
        }
        for operation in [Operation::Exec, Operation::List] {
            ContainmentConfig::new()
                .allow(&directory, operation, Scope::Root)
                .unwrap_or_else(|e| panic!("{operation:?} at Root is legal: {e:?}"));
        }
    }

    /// Read and write on one path is two grants, so neither mode hides inside the other.
    #[test]
    fn read_and_write_on_one_path_are_two_grants() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().canonicalize().unwrap();

        let config = ContainmentConfig::new()
            .allow(&directory, Operation::Read, Scope::Root)
            .unwrap()
            .allow(&directory, Operation::Write, Scope::Root)
            .unwrap();

        assert_eq!(config.authorizations().len(), 2);
        assert_eq!(config.authorizations()[0].operation, Operation::Read);
        assert_eq!(config.authorizations()[1].operation, Operation::Write);
    }

    #[test]
    fn credential_store_exceptions_round_trip_and_old_json_defaults_to_none() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let store = home_path.join(".aws");
        std::fs::create_dir(&store).expect("a credential store");

        let config = ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow_credential_store(&store, Operation::Read, Scope::Root)
            .expect("an exact credential-store grant");
        let json = config.to_json().expect("the config serializes");
        let restored = ContainmentConfig::from_json(&json).expect("the config reloads");
        assert!(restored.credential_store_exempts(restored.authorizations()[0]));

        let mut old: serde_json::Value = serde_json::from_str(&json).expect("the config is JSON");
        old.as_object_mut()
            .expect("the config is an object")
            .remove("credential_store_grants");
        let restored = ContainmentConfig::from_json(
            &serde_json::to_string(&old).expect("the old config serializes"),
        )
        .expect("the additive field defaults when absent");
        assert!(!restored.credential_store_exempts(restored.authorizations()[0]));
    }

    #[test]
    fn a_serialized_exception_must_have_its_matching_credential_grant() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let store = home_path.join(".aws");
        std::fs::create_dir(&store).expect("a credential store");
        let config = ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow_credential_store(&store, Operation::Read, Scope::Root)
            .expect("an exact credential-store grant");
        let mut json: serde_json::Value =
            serde_json::from_str(&config.to_json().expect("the config serializes"))
                .expect("the config is JSON");
        json["paths"] = serde_json::json!([]);

        let error = ContainmentConfig::from_json(
            &serde_json::to_string(&json).expect("the crafted config serializes"),
        )
        .expect_err("an exception cannot travel without its grant");
        assert!(
            error.to_string().contains("no matching path grant"),
            "the refusal names the detached exception: {error}"
        );
    }

    #[test]
    fn a_serialized_exception_refuses_a_non_exact_original_alias() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let store = home_path.join(".aws");
        std::fs::create_dir(&store).expect("a credential store");
        let alias = home_path.join("alias");
        std::os::unix::fs::symlink(&store, &alias).expect("an alias to the credential store");
        let config = ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow(&store, Operation::Read, Scope::Root)
            .expect("the exact path grant")
            .allow(&alias, Operation::Read, Scope::Root)
            .expect("the ordinary vocabulary accepts the alias");
        let mut json: serde_json::Value =
            serde_json::from_str(&config.to_json().expect("the config serializes"))
                .expect("the config is JSON");
        json["credential_store_grants"] = serde_json::json!([{
            "path": store.canonicalize().expect("the store resolves"),
            "operation": "read"
        }]);

        let error = ContainmentConfig::from_json(
            &serde_json::to_string(&json).expect("the crafted config serializes"),
        )
        .expect_err("an alias is not exact punch-hole consent");
        assert!(
            error
                .to_string()
                .contains("covers a non-exact original path"),
            "the refusal names the alias: {error}"
        );
    }

    #[test]
    fn only_an_exact_credential_path_can_receive_an_exception() {
        let home = tempfile::tempdir().expect("an operator home");
        let ordinary = home.path().join("ordinary");
        std::fs::create_dir(&ordinary).expect("an ordinary directory");

        let error = ContainmentConfig::new()
            .anchored_at(home.path())
            .allow_credential_store(&ordinary, Operation::Read, Scope::Root)
            .expect_err("an ordinary path is not a credential-store exception");
        assert!(
            error.to_string().contains("exact credential-store path"),
            "the refusal names the required shape: {error}"
        );
    }

    #[test]
    fn a_credential_symlink_cannot_exempt_an_ordinary_target() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let store = home_path.join(".aws");
        std::fs::create_dir(&store).expect("a credential store");
        let ordinary = home_path.join("ordinary");
        std::fs::write(&ordinary, "ordinary").expect("an ordinary file");
        let route = store.join("credential");
        std::os::unix::fs::symlink(&ordinary, &route).expect("a route outside the store");

        let error = ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow_credential_store(&route, Operation::Read, Scope::File)
            .expect_err("the exception must follow the credential identity");
        assert!(
            error.to_string().contains("resolves outside"),
            "the refusal names the escaped identity: {error}"
        );
    }

    #[test]
    fn a_credential_symlink_cannot_switch_stores() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let aws = home_path.join(".aws");
        let ssh = home_path.join(".ssh");
        std::fs::create_dir(&aws).expect("an AWS store");
        std::fs::create_dir(&ssh).expect("an SSH store");
        let ssh_key = ssh.join("id_rsa");
        std::fs::write(&ssh_key, "key").expect("an SSH credential");
        let route = aws.join("credentials");
        std::os::unix::fs::symlink(&ssh_key, &route).expect("a cross-store route");

        let error = ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow_credential_store(&route, Operation::Read, Scope::File)
            .expect_err("one credential-store consent cannot expose another");
        assert!(
            error.to_string().contains("different store"),
            "the refusal names the store switch: {error}"
        );
    }

    #[test]
    fn a_credential_symlink_chain_cannot_leave_and_reenter_its_store() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let aws = home_path.join(".aws");
        let ssh = home_path.join(".ssh");
        std::fs::create_dir(&aws).expect("an AWS store");
        std::fs::create_dir(&ssh).expect("an SSH store");
        let credential = aws.join("credentials");
        std::fs::write(&credential, "secret").expect("an AWS credential");
        let hop = ssh.join("hop");
        std::os::unix::fs::symlink("../.aws/credentials", &hop)
            .expect("a route back to the AWS store");
        let route = aws.join("route");
        std::os::unix::fs::symlink("../.ssh/hop", &route).expect("a route through the SSH store");

        let error = ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow_credential_store(&route, Operation::Read, Scope::File)
            .expect_err("one credential-store consent cannot expose another traversal node");
        assert!(
            error.to_string().contains("different store"),
            "the refusal names the store switch: {error}"
        );
    }

    #[test]
    fn a_serialized_exception_cannot_switch_stores() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let aws = home_path.join(".aws");
        let ssh = home_path.join(".ssh");
        std::fs::create_dir(&aws).expect("an AWS store");
        std::fs::create_dir(&ssh).expect("an SSH store");
        let ssh_key = ssh.join("id_rsa");
        std::fs::write(&ssh_key, "key").expect("an SSH credential");
        let route = aws.join("credentials");
        std::os::unix::fs::symlink(&ssh_key, &route).expect("a cross-store route");
        let config = ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow(&route, Operation::Read, Scope::File)
            .expect("the ordinary grant records both identities");
        let mut json: serde_json::Value =
            serde_json::from_str(&config.to_json().expect("the config serializes"))
                .expect("the config is JSON");
        json["credential_store_grants"] = serde_json::json!([{
            "path": ssh_key.canonicalize().expect("the SSH key resolves"),
            "operation": "read"
        }]);

        let error = ContainmentConfig::from_json(
            &serde_json::to_string(&json).expect("the crafted config serializes"),
        )
        .expect_err("the wire exception cannot switch stores");
        assert!(
            error.to_string().contains("switches stores"),
            "the refusal names the store switch: {error}"
        );
    }

    #[test]
    fn a_serialized_exception_cannot_leave_and_reenter_its_store() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let aws = home_path.join(".aws");
        let ssh = home_path.join(".ssh");
        std::fs::create_dir(&aws).expect("an AWS store");
        std::fs::create_dir(&ssh).expect("an SSH store");
        let credential = aws.join("credentials");
        std::fs::write(&credential, "secret").expect("an AWS credential");
        let hop = ssh.join("hop");
        std::os::unix::fs::symlink("../.aws/credentials", &hop)
            .expect("a route back to the AWS store");
        let route = aws.join("route");
        std::os::unix::fs::symlink("../.ssh/hop", &route).expect("a route through the SSH store");
        let config = ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow(&route, Operation::Read, Scope::File)
            .expect("the ordinary grant records the traversal nodes");
        let mut json: serde_json::Value =
            serde_json::from_str(&config.to_json().expect("the config serializes"))
                .expect("the config is JSON");
        json["credential_store_grants"] = serde_json::json!([{
            "path": credential.canonicalize().expect("the credential resolves"),
            "operation": "read"
        }]);

        let error = ContainmentConfig::from_json(
            &serde_json::to_string(&json).expect("the crafted config serializes"),
        )
        .expect_err("the wire exception cannot cross a second credential store");
        assert!(
            error.to_string().contains("switches stores"),
            "the refusal names the store switch: {error}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn serialized_credential_write_requires_the_same_read_grant_on_linux() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let cache = home_path.join(".aws/sso/cache");
        std::fs::create_dir_all(&cache).expect("a credential cache");
        let config = ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow_credential_store(&cache, Operation::Write, Scope::Root)
            .expect("the builder can receive grants in either order");

        let error = ContainmentConfig::from_json(&config.to_json().expect("the config serializes"))
            .expect_err("the complete Linux config must state its read authority");
        assert!(
            error
                .to_string()
                .contains("must have a read grant on Linux"),
            "the refusal names the missing operation: {error}"
        );
    }

    #[test]
    fn the_network_refuses_every_zero_port() {
        fn assert_invalid_port(network: Network, expected_field: &'static str) {
            let refusal = ContainmentConfig::new()
                .set_network(network)
                .expect_err("port 0 is never a port");
            assert!(
                matches!(refusal, ContainmentError::InvalidPort { field, port: 0 } if field == expected_field),
                "{refusal:?}"
            );
        }

        assert_invalid_port(Network::localhost().connect(0), "connect");
        assert_invalid_port(Network::localhost().connect(8080).connect(0), "connect");
        assert_invalid_port(Network::localhost().connect(8080).listen(0), "listen");
    }

    /// Two localhost services cannot share one port, so a config claiming they do is refused.
    #[test]
    fn two_of_the_connect_ports_may_not_be_the_same() {
        let refusal = ContainmentConfig::new()
            .set_network(Network::localhost().connect(8080).connect(8080))
            .expect_err("one port cannot be two services");
        assert!(
            matches!(refusal, ContainmentError::ConflictingGrants { .. }),
            "{refusal:?}"
        );
    }

    /// **Naming no port at all is refused**, so `Localhost` always names what it reaches.
    ///
    /// The refusal is `ConflictingGrants` rather than `InvalidPort`, because there is no port 0 to
    /// report — the earlier shape told an operator to fix a port that was never named.
    #[test]
    fn an_empty_connect_list_is_refused() {
        let refusal = ContainmentConfig::new()
            .set_network(Network::localhost())
            .expect_err("Localhost with no port reaches nothing");
        assert!(
            matches!(refusal, ContainmentError::ConflictingGrants { .. }),
            "{refusal:?}"
        );
        assert!(
            refusal.to_string().contains("no port"),
            "the refusal must name the actual defect: {refusal}"
        );
    }

    /// The builder is additive, and grant order is the wire contract on Linux.
    #[test]
    fn from_json_refuses_a_discovery_root_outside_the_operator_home() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        // A crafted config whose discovery root is the filesystem root, not the operator home:
        // `allow_discovery` never produces this, and load must refuse it.
        let json = ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow_discovery("/")
            .to_json()
            .expect("the config serializes");
        let error = ContainmentConfig::from_json(&json)
            .expect_err("a discovery root outside the operator home is refused");
        assert!(
            error.to_string().contains("at or under the operator home"),
            "{error}"
        );
    }

    #[test]
    fn from_json_refuses_a_relative_discovery_path() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let sub = home_path.join("sub");
        std::fs::create_dir(&sub).expect("a discovery subtree");
        let json = ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow_discovery(&sub)
            .to_json()
            .expect("the config serializes");
        // Rewrite only the discovery root to a relative spelling the wire format must refuse; the
        // operator home keeps its own absolute spelling.
        let tampered = json.replace(
            &serde_json::to_string(&sub).expect("the subtree encodes"),
            "\"relative/discovery\"",
        );
        assert_ne!(tampered, json, "the discovery root was rewritten");
        let error = ContainmentConfig::from_json(&tampered)
            .expect_err("a relative discovery path is refused");
        assert!(error.to_string().contains("must be absolute"), "{error}");
    }

    /// A discovery root that resolves outside the home, or that has no stated home, is refused on load.
    #[cfg(unix)]
    #[test]
    fn from_json_refuses_a_discovery_root_outside_the_home() {
        let home = tempfile::tempdir().expect("an operator home");
        let home_path = home.path().canonicalize().expect("the home resolves");
        let sub = home_path.join("sub");
        std::fs::create_dir(&sub).expect("a discovery subtree");
        let link = home_path.join("to-root");
        std::os::unix::fs::symlink("/", &link).expect("a link to the filesystem root");
        let json = ContainmentConfig::new()
            .anchored_at(&home_path)
            .allow_discovery(&sub)
            .to_json()
            .expect("the config serializes");
        let tampered = json.replace(
            &serde_json::to_string(&sub).expect("the subtree encodes"),
            &serde_json::to_string(&link).expect("the link encodes"),
        );
        assert_ne!(tampered, json, "the discovery root was rewritten");
        let error = ContainmentConfig::from_json(&tampered)
            .expect_err("a discovery root that resolves to the filesystem root is refused");
        assert!(
            error.to_string().contains("at or under the operator home"),
            "{error}"
        );

        let homeless = ContainmentConfig::new()
            .allow_discovery(&sub)
            .to_json()
            .expect("the config serializes");
        assert!(
            homeless.contains("\"operator_home\": null"),
            "the config states no home: {homeless}"
        );
        let error = ContainmentConfig::from_json(&homeless)
            .expect_err("a discovery root with no stated home is refused");
        assert!(
            error.to_string().contains("needs a stated operator home"),
            "{error}"
        );
    }

    #[test]
    fn the_connect_ports_keep_their_grant_order() {
        let config = ContainmentConfig::new()
            .set_network(
                Network::localhost()
                    .connect(8080)
                    .connect(33085)
                    .listen(3000),
            )
            .expect("localhost");
        assert_eq!(
            config.network(),
            &Network::Localhost {
                connect: vec![8080, 33085],
                listen: vec![3000],
            }
        );
    }
}
