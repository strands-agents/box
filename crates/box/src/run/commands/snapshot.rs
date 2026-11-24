//! Original command pins exported to a fresh, trusted compiler without reloading authority.
use std::collections::BTreeSet;
use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{ConfiguredCommand, ConfiguredCommands, FileState};
use crate::error::{BoxError, ConfigError};
use crate::record::layout::resolved_through_links;

const VERSION: u32 = 1;
const MAX_COMMANDS: usize = 4096;
const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;

/// Implementations must bound the request and response and fail on owner loss or timeout.
/// The digest binds the descriptor index to the exact original manifest, including every role.
pub(crate) trait OwnerVerifier: Send + Sync {
    fn verify(&self, descriptor: u32, manifest_digest: [u8; 32]) -> Result<(), BoxError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DescriptorKind {
    ReadOnly,
    Path,
    Execute,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DescriptorSnapshot {
    pub(crate) index: u32,
    kind: DescriptorKind,
    identity: (u64, u64),
    state: FileState,
}

impl DescriptorSnapshot {
    #[cfg(test)]
    pub(crate) fn capture(index: u32, file: &File) -> Result<Self, BoxError> {
        let metadata = file
            .metadata()
            .map_err(|error| invalid(error.to_string()))?;
        if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
            return Err(invalid("descriptor must pin an executable regular file"));
        }
        Ok(Self {
            index,
            kind: descriptor_kind(file)?,
            identity: (metadata.dev(), metadata.ino()),
            state: FileState::of(&metadata),
        })
    }

    pub(crate) fn identity(&self) -> (u64, u64) {
        self.identity
    }

    pub(crate) fn links(&self) -> u64 {
        self.state.links
    }

    /// Ownership IDs can be translated in a child user namespace. The original owner checks them.
    fn verify_replica(&self, file: &File) -> Result<(), BoxError> {
        let metadata = file
            .metadata()
            .map_err(|error| invalid(error.to_string()))?;
        if !metadata.is_file()
            || (metadata.dev(), metadata.ino()) != self.identity
            || metadata.nlink() != self.state.links
            || metadata.mode() != self.state.mode
            || descriptor_kind(file)? != self.kind
        {
            return Err(invalid(
                "received descriptor does not match its original identity, type, mode, or link count",
            ));
        }
        // SAFETY: this reads flags of the live received descriptor.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
            return Err(invalid(
                "received authority descriptor must be close-on-exec",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn verify_owner(&self, file: &File) -> Result<(), BoxError> {
        self.verify_replica(file)?;
        let metadata = file
            .metadata()
            .map_err(|error| invalid(error.to_string()))?;
        if FileState::of(&metadata) != self.state {
            return Err(invalid(
                "original descriptor metadata changed after snapshot export",
            ));
        }
        Ok(())
    }
}

fn descriptor_kind(file: &File) -> Result<DescriptorKind, BoxError> {
    // SAFETY: this reads flags of a live descriptor without reopening its path.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(invalid(std::io::Error::last_os_error().to_string()));
    }
    #[cfg(target_os = "linux")]
    if flags & libc::O_PATH != 0 {
        return Ok(DescriptorKind::Path);
    }
    #[cfg(target_os = "macos")]
    if flags & libc::O_EXEC != 0 {
        return Ok(DescriptorKind::Execute);
    }
    if flags & libc::O_ACCMODE == libc::O_RDONLY {
        Ok(DescriptorKind::ReadOnly)
    } else {
        Err(invalid("authority descriptor must not permit writes"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteSnapshot {
    path: PathBuf,
    resolved: PathBuf,
    links: Vec<PathBuf>,
}

impl RouteSnapshot {
    fn capture(path: &Path) -> Result<Self, BoxError> {
        let (resolved, links) =
            resolved_through_links(path).map_err(|error| invalid(error.to_string()))?;
        Ok(Self {
            path: path.to_path_buf(),
            resolved,
            links,
        })
    }

    fn verify(&self) -> Result<(), BoxError> {
        let now = Self::capture(&self.path)?;
        if now != *self {
            return Err(invalid(format!(
                "configured command route {} changed",
                self.path.display()
            )));
        }
        Ok(())
    }
}

/// The imported object's state check stays in the original owner's credential context.
pub(crate) struct ReplicaVerifier {
    descriptor: DescriptorSnapshot,
    manifest_digest: [u8; 32],
    owner: Arc<dyn OwnerVerifier>,
    routes: Vec<RouteSnapshot>,
}

impl std::fmt::Debug for ReplicaVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReplicaVerifier")
            .field("descriptor", &self.descriptor.index)
            .finish_non_exhaustive()
    }
}

impl ReplicaVerifier {
    pub(crate) fn new(
        descriptor: DescriptorSnapshot,
        manifest_digest: [u8; 32],
        owner: Arc<dyn OwnerVerifier>,
    ) -> Self {
        Self {
            descriptor,
            manifest_digest,
            owner,
            routes: Vec::new(),
        }
    }

    pub(crate) fn verify(&self, file: &File) -> Result<(), BoxError> {
        self.descriptor.verify_replica(file)?;
        self.owner
            .verify(self.descriptor.index, self.manifest_digest)?;
        for route in &self.routes {
            route.verify()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    Tool,
    SecretSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandSnapshot {
    role: Role,
    label: String,
    table: String,
    path: PathBuf,
    invoked: PathBuf,
    routes: Vec<PathBuf>,
    links: Vec<PathBuf>,
    route_snapshots: Vec<RouteSnapshot>,
    identity: (u64, u64),
    loaded: FileState,
    needs_alias_scan: bool,
    descriptor: DescriptorSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    version: u32,
    commands: Vec<CommandSnapshot>,
}

#[cfg(test)]
pub(crate) struct Export {
    pub(crate) manifest: Manifest,
    pub(crate) descriptors: Vec<File>,
    pub(crate) owner: Arc<Owner>,
}

#[cfg(test)]
pub(crate) struct Owner {
    objects: Vec<Arc<ConfiguredCommand>>,
    descriptors: Vec<DescriptorSnapshot>,
    manifest_digest: [u8; 32],
}

#[cfg(test)]
impl Owner {
    pub(crate) fn verify(
        &self,
        descriptor: u32,
        manifest_digest: [u8; 32],
    ) -> Result<(), BoxError> {
        if manifest_digest != self.manifest_digest {
            return Err(invalid(
                "command manifest differs from the original owner's snapshot",
            ));
        }
        let index = descriptor as usize;
        let command = self
            .objects
            .get(index)
            .ok_or_else(|| invalid("unknown original command descriptor"))?;
        self.descriptors[index].verify_owner(&command.opened)?;
        if !command.unchanged_owner_state() {
            return Err(super::refusal(
                &command.table,
                &command.path,
                "changed in the original owner's identity context",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
impl OwnerVerifier for Owner {
    fn verify(&self, descriptor: u32, manifest_digest: [u8; 32]) -> Result<(), BoxError> {
        Self::verify(self, descriptor, manifest_digest)
    }
}

#[cfg(test)]
impl ConfiguredCommands {
    pub(crate) fn export_snapshot(self: &Arc<Self>) -> Result<Export, BoxError> {
        let mut commands = Vec::new();
        let mut files = Vec::new();
        let mut objects = Vec::new();
        for (role, entries) in [
            (Role::Tool, &self.tools),
            (Role::SecretSource, &self.sources),
        ] {
            for (label, command) in entries {
                if command.verification.is_some() {
                    return Err(invalid(
                        "a compiler replica cannot export original command authority",
                    ));
                }
                command.verify()?;
                let descriptor =
                    DescriptorSnapshot::capture(commands.len() as u32, &command.opened)?;
                let route_snapshots = command
                    .routes
                    .iter()
                    .map(|path| RouteSnapshot::capture(path))
                    .collect::<Result<Vec<_>, _>>()?;
                if role == Role::SecretSource
                    && !route_snapshots
                        .iter()
                        .any(|route| route.links == command.links)
                {
                    return Err(invalid(
                        "secret source's original symbolic-link route changed",
                    ));
                }
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                let needs_alias_scan = command.needs_alias_scan;
                #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                let needs_alias_scan = false;
                commands.push(CommandSnapshot {
                    role,
                    label: label.clone(),
                    table: command.table.clone(),
                    path: command.path.clone(),
                    invoked: command.invoked.clone(),
                    routes: command.routes.clone(),
                    links: command.links.clone(),
                    route_snapshots,
                    identity: command.identity,
                    loaded: command.loaded,
                    needs_alias_scan,
                    descriptor,
                });
                files.push(
                    command
                        .opened
                        .try_clone()
                        .map_err(|error| invalid(error.to_string()))?,
                );
                objects.push(Arc::clone(command));
            }
        }
        let manifest = Manifest {
            version: VERSION,
            commands,
        };
        manifest.validate()?;
        let manifest_digest = digest(&manifest)?;
        let descriptors = manifest
            .commands
            .iter()
            .map(|command| command.descriptor.clone())
            .collect();
        let owner = Arc::new(Owner {
            objects,
            descriptors,
            manifest_digest,
        });
        Ok(Export {
            manifest,
            descriptors: files,
            owner,
        })
    }
}

impl Manifest {
    pub(crate) fn descriptor_count(&self) -> usize {
        self.commands.len()
    }

    pub(crate) fn validate(&self) -> Result<(), BoxError> {
        if self.version != VERSION || self.commands.len() > MAX_COMMANDS {
            return Err(invalid(
                "unsupported command snapshot version or descriptor count",
            ));
        }
        let mut roles = BTreeSet::new();
        for (index, command) in self.commands.iter().enumerate() {
            let table = match command.role {
                Role::Tool => format!("[tool.{}]", command.label),
                Role::SecretSource => format!("[secret-source.{}]", command.label),
            };
            if command.label.is_empty()
                || command.table != table
                || !roles.insert((command.role, command.label.clone()))
                || command.descriptor.index as usize != index
                || command.identity != command.descriptor.identity()
                || command.loaded.links == 0
                || command.routes.is_empty()
                || command.routes.len() > 128
                || command.route_snapshots.len() != command.routes.len()
                || !command.routes.contains(&command.invoked)
                || command.links.len() > 40
            {
                return Err(invalid(
                    "invalid or duplicate command role, route, or descriptor index",
                ));
            }
            for path in std::iter::once(&command.path)
                .chain(std::iter::once(&command.invoked))
                .chain(&command.routes)
                .chain(&command.links)
            {
                validate_path(path)?;
            }
            for (path, route) in command.routes.iter().zip(&command.route_snapshots) {
                if path != &route.path || route.resolved != command.path || route.links.len() > 40 {
                    return Err(invalid(
                        "command route snapshot does not match its original path",
                    ));
                }
                validate_path(&route.resolved)?;
                for link in &route.links {
                    validate_path(link)?;
                }
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            if command.needs_alias_scan {
                return Err(invalid(
                    "command alias enforcement is unavailable on this platform",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn import(
        self,
        descriptors: Vec<File>,
        owner: Arc<dyn OwnerVerifier>,
    ) -> Result<ConfiguredCommands, BoxError> {
        self.validate()?;
        if descriptors.len() != self.descriptor_count() {
            return Err(invalid(
                "command descriptor count does not match its manifest",
            ));
        }
        let manifest_digest = digest(&self)?;
        let mut result = ConfiguredCommands::default();
        for (entry, opened) in self.commands.into_iter().zip(descriptors) {
            let mut verification =
                ReplicaVerifier::new(entry.descriptor, manifest_digest, Arc::clone(&owner));
            verification.routes = entry.route_snapshots;
            let command = Arc::new(ConfiguredCommand {
                table: entry.table,
                path: entry.path,
                invoked: entry.invoked,
                routes: entry.routes,
                links: entry.links,
                opened,
                identity: entry.identity,
                loaded: entry.loaded,
                verification: Some(verification),
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                needs_alias_scan: entry.needs_alias_scan,
            });
            command.verify()?;
            match entry.role {
                Role::Tool => {
                    result.tools.insert(entry.label, command);
                }
                Role::SecretSource => {
                    result.sources.insert(entry.label, command);
                }
            }
        }
        Ok(result)
    }
}

pub(crate) fn digest(value: &impl Serialize) -> Result<[u8; 32], BoxError> {
    let bytes = serde_json::to_vec(value).map_err(|error| invalid(error.to_string()))?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(invalid(
            "authority snapshot exceeds its private transport limit",
        ));
    }
    Ok(Sha256::digest(bytes).into())
}

pub(crate) fn validate_path(path: &Path) -> Result<(), BoxError> {
    use std::os::unix::ffi::OsStrExt as _;
    if !path.is_absolute() || path.as_os_str().as_bytes().contains(&0) {
        return Err(invalid(
            "authority snapshot paths must be absolute and contain no NUL",
        ));
    }
    Ok(())
}

pub(crate) fn invalid(reason: impl Into<String>) -> BoxError {
    ConfigError::Process {
        table: "[storage.compiler]".into(),
        reason: reason.into(),
    }
    .into()
}

#[cfg(test)]
mod tests;
