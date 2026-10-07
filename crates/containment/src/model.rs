//! Containment value types and private grant records.

use serde::{Deserialize, Serialize};

use crate::error::ContainmentError;
use std::fs::File;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, ContainmentError>;

/// What may be done to a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Run one file, or any program under a directory; renders a metadata read and never contents.
    Exec,
    /// Read bytes from a file, or the entry names of a directory.
    Read,
    /// Enumerate a directory's entries and every directory's beneath it, and never a file's bytes.
    List,
    /// Write, create, remove, rename, or truncate, including symlinks.
    Write,
    /// `connect(2)` to a pathname AF_UNIX socket. Never `bind(2)`.
    Connect,
    /// Stat it. Never its bytes, and never a directory's entry names.
    Metadata,
    /// Reach nothing here, one file or a whole tree, whatever any other entry says.
    Deny,
}

/// How far a grant reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// This leaf, and nothing else.
    File,
    /// This directory's own entry. **Not its contents.**
    Dir,
    /// This directory and every descendant.
    Root,
}

impl Scope {
    /// Whether this scope names a directory.
    #[must_use]
    pub(crate) const fn is_directory(self) -> bool {
        matches!(self, Self::Dir | Self::Root)
    }
}

/// Whether an operation may be granted at a scope, and why not when it may not.
///
/// Thirteen cells are legal. The eight refusals are the vocabulary's own, so a backend never sees
/// a pair it cannot render.
pub(crate) const fn cell_refusal(operation: Operation, scope: Scope) -> Option<&'static str> {
    match (operation, scope) {
        (Operation::Exec, Scope::File | Scope::Root)
        | (Operation::Read, Scope::File | Scope::Dir | Scope::Root)
        | (Operation::List, Scope::Root)
        | (Operation::Write, Scope::File | Scope::Root)
        | (Operation::Connect, Scope::File)
        | (Operation::Metadata, Scope::Dir | Scope::Root)
        | (Operation::Deny, Scope::File | Scope::Root) => None,
        (Operation::Exec, Scope::Dir) => Some("a directory has no bytes to execute"),
        (Operation::List, Scope::File) => Some("a file has no entries to enumerate"),
        (Operation::List, Scope::Dir) => {
            Some("one directory's own entries are Read at Dir scope; List reaches the whole tree")
        }
        (Operation::Write, Scope::Dir) => {
            Some("writing a directory's entries is a grant on its children, not on itself")
        }
        (Operation::Connect, Scope::Dir | Scope::Root) => {
            Some("a socket grant names one existing file")
        }
        (Operation::Metadata, Scope::File) => {
            Some("a file's metadata comes with the exec or read grant that names it")
        }
        (Operation::Deny, Scope::Dir) => Some(
            "a denial subtracts one file or a whole tree; a directory's own entry alone would \
             leave its contents reachable",
        ),
    }
}

/// One existing filesystem path resolved before an authorization decision.
///
/// The token that stops a second lookup: prepare once, read [`Self::resolved_path`], then hand the
/// same value to `allow_prepared`. It is [`PathGrant`] before an operation is attached.
#[derive(Debug)]
pub struct PreparedFilesystemPath {
    original: PathBuf,
    resolved: PathBuf,
    is_file: bool,
}

impl PreparedFilesystemPath {
    pub(crate) fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let original = absolute_path(path)?;
        let resolved = canonicalize_existing(&original)?;
        let is_file = !resolved.is_dir();
        Ok(Self {
            original,
            resolved,
            is_file,
        })
    }

    /// The canonical identity policy should authorize.
    #[must_use]
    pub fn resolved_path(&self) -> &Path {
        &self.resolved
    }

    /// What the filesystem says this path is, which a grant's scope must agree with.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        !self.is_file
    }
}

/// One opened regular file whose identity must remain unavailable to writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "WriteProtectionWire")]
pub(crate) struct WriteProtection {
    path: PathBuf,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl WriteProtection {
    pub(crate) fn new(path: impl AsRef<Path>, opened: &File) -> Result<Self> {
        let path = canonicalize_existing(&absolute_path(path.as_ref())?)?;
        let opened_metadata = opened.metadata().map_err(|source| {
            ContainmentError::ConfigValidation(format!(
                "cannot inspect the opened write-protected file {}: {source}",
                path.display()
            ))
        })?;
        if !opened_metadata.is_file() {
            return Err(ContainmentError::ExpectedFile(path));
        }
        #[cfg(unix)]
        if opened_metadata.nlink() != 1 {
            return Err(ContainmentError::ConfigValidation(format!(
                "write-protected file {} has {} hard links, so one pathname cannot protect the \
                 opened object",
                path.display(),
                opened_metadata.nlink()
            )));
        }
        let protected = Self {
            path,
            #[cfg(unix)]
            device: opened_metadata.dev(),
            #[cfg(unix)]
            inode: opened_metadata.ino(),
        };
        protected.validate_live_identity()?;
        Ok(protected)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn device(&self) -> u64 {
        self.device
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn inode(&self) -> u64 {
        self.inode
    }

    pub(crate) fn validate_live_identity(&self) -> Result<()> {
        let canonical = canonicalize_existing(&self.path)?;
        if canonical != self.path {
            return Err(ContainmentError::ConfigValidation(format!(
                "write-protected file canonical path changed before apply: recorded={}, current={}",
                self.path.display(),
                canonical.display()
            )));
        }
        let metadata = std::fs::metadata(&self.path).map_err(|source| {
            ContainmentError::ConfigValidation(format!(
                "cannot inspect write-protected file {}: {source}",
                self.path.display()
            ))
        })?;
        if !metadata.is_file() {
            return Err(ContainmentError::ExpectedFile(self.path.clone()));
        }
        #[cfg(unix)]
        if metadata.dev() != self.device || metadata.ino() != self.inode || metadata.nlink() != 1 {
            return Err(ContainmentError::ConfigValidation(format!(
                "write-protected file identity changed before apply: {}",
                self.path.display()
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteProtectionWire {
    path: PathBuf,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl TryFrom<WriteProtectionWire> for WriteProtection {
    type Error = ContainmentError;

    fn try_from(wire: WriteProtectionWire) -> Result<Self> {
        require_absolute("write-protected", &wire.path)?;
        let protected = Self {
            path: wire.path,
            #[cfg(unix)]
            device: wire.device,
            #[cfg(unix)]
            inode: wire.inode,
        };
        protected.validate_live_identity()?;
        Ok(protected)
    }
}

/// What the contained process may reach on the network.
///
/// The wire form is this enum, and `ContainmentConfig` validates every port on load.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Network {
    /// Nothing is reachable.
    #[default]
    Blocked,
    /// Unrestricted. No enforcement.
    AllowAll,
    /// Outbound restricted to localhost. Nothing else is reachable.
    Localhost {
        /// Ports the workload may connect to, in grant order. On Linux one listening descriptor is
        /// handed out per port in this order, because one `recvmsg` carries one descriptor and
        /// that order is the wire contract. An empty list or a duplicate is refused.
        connect: Vec<u16>,
        /// Ports the workload may bind. Empty by default. The Linux namespace backend refuses a
        /// non-empty list: it has no lowering for an inbound bind.
        listen: Vec<u16>,
    },
}

impl Network {
    /// Outbound restricted to localhost, reaching nothing until a port is named.
    #[must_use]
    pub fn localhost() -> Self {
        Self::Localhost {
            connect: Vec::new(),
            listen: Vec::new(),
        }
    }

    /// Add a localhost port the workload may connect to.
    #[must_use]
    pub fn connect(mut self, port: u16) -> Self {
        if let Self::Localhost { connect, .. } = &mut self {
            connect.push(port);
        }
        self
    }

    /// Add a port the workload may bind.
    #[must_use]
    pub fn listen(mut self, port: u16) -> Self {
        if let Self::Localhost { listen, .. } = &mut self {
            listen.push(port);
        }
        self
    }
}

/// Signal delivery mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalMode {
    /// Signals only to self and processes in the same containment domain.
    #[default]
    Isolated,
    /// Signals to any process (unrestricted).
    AllowAll,
}

/// Process info visibility mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessInfoMode {
    /// Process info only for self and processes in the same containment domain.
    #[default]
    Isolated,
    /// Process info for all processes.
    AllowAll,
}

/// IPC mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcMode {
    /// Only shared memory IPC allowed.
    #[default]
    SharedMemoryOnly,
    /// Full IPC (shared memory + mach ports + etc).
    Full,
}

/// This path with its deepest existing ancestor canonicalized and the absent remainder re-attached.
///
/// `canonicalize` fails outright on an absent leaf, and a rule spelled as authored matches nothing
/// when an ancestor is a link — so neither the raw path nor a failed resolve is usable for a denial.
fn canonical_with_absent_tail(path: &Path) -> PathBuf {
    let mut absent: Vec<std::ffi::OsString> = Vec::new();
    let mut existing = path.to_path_buf();
    loop {
        if let Ok(canonical) = existing.canonicalize() {
            let mut resolved = canonical;
            for component in absent.iter().rev() {
                resolved.push(component);
            }
            return resolved;
        }
        match (
            existing.file_name().map(std::ffi::OsStr::to_os_string),
            existing.parent(),
        ) {
            (Some(name), Some(parent)) if parent != existing => {
                absent.push(name);
                existing = parent.to_path_buf();
            }
            // Nothing on the path exists, so the authored spelling is the best identity available.
            _ => return path.to_path_buf(),
        }
    }
}

/// One operation, at one scope, on one path. Files, directories and sockets alike.
///
/// Deserializing goes through [`PathGrantWire`], so a loaded grant re-resolves its own path and
/// re-runs every refusal a builder call makes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "PathGrantWire")]
pub(crate) struct PathGrant {
    /// The absolute caller spelling before symlink resolution.
    pub(crate) original: PathBuf,
    /// The canonicalized grant target (symlinks in the path resolved).
    pub(crate) resolved: PathBuf,
    /// What may be done.
    pub(crate) operation: Operation,
    /// How far it reaches.
    pub(crate) scope: Scope,
    /// Every node a lookup of this grant traverses, resolved once when the grant is built.
    #[serde(skip)]
    nodes: Vec<PathBuf>,
}

impl PathGrant {
    /// Refuse one path, a whole tree at `Root` scope or one file at `File` scope, whether or not it
    /// exists yet.
    ///
    /// **A denial is the one entry that need not exist.** Every authorization is canonicalized and
    /// refused when absent, because a grant on a path that is not there grants nothing and says so
    /// nowhere. A denial is the opposite: `~/.codex` is commonly absent on a machine that has never
    /// run Codex, and skipping the subtraction there would leave a grant enclosing its future
    /// location unsubtracted — so an absent path is named rather than dropped. macOS renders a deny
    /// on an absent path perfectly well, and the Linux view creates the mountpoint.
    ///
    /// The identity is the deepest existing ancestor canonicalized, with the remainder re-attached,
    /// because Seatbelt matches a path whose ancestor components are already resolved.
    pub(crate) fn denial(path: impl AsRef<Path>, scope: Scope) -> Result<Self> {
        if let Some(reason) = cell_refusal(Operation::Deny, scope) {
            return Err(ContainmentError::UnsupportedCapability {
                capability: format!("denial at {scope:?} scope: {reason}"),
                backend: "vocabulary".to_string(),
            });
        }
        let original = absolute_path(path.as_ref())?;
        // `..` survives `absolute`, and the lexical resolve below cannot answer it, so the entry
        // would render a rule the kernel never matches: a denial that refuses nothing.
        if original
            .components()
            .any(|component| component == std::path::Component::ParentDir)
        {
            return Err(ContainmentError::ConfigValidation(format!(
                "refused path must not contain `..`: {}",
                original.display()
            )));
        }
        let resolved = canonical_with_absent_tail(&original);
        // A file refusal on a directory would deny the entry and leave its contents reachable, so
        // the one kind that exists is checked; an absent path is accepted at either scope.
        if scope == Scope::File && resolved.is_dir() {
            return Err(ContainmentError::ExpectedFile(original));
        }
        let mut granted = Self {
            original,
            resolved,
            operation: Operation::Deny,
            scope,
            nodes: Vec::new(),
        };
        granted.nodes = granted.walk_traversal_nodes();
        Ok(granted)
    }

    /// Authorize one operation at one scope, reconciling the authored scope with the filesystem.
    pub(crate) fn new(path: impl AsRef<Path>, operation: Operation, scope: Scope) -> Result<Self> {
        Self::from_prepared(PreparedFilesystemPath::new(path)?, operation, scope)
    }

    pub(crate) fn from_prepared(
        path: PreparedFilesystemPath,
        operation: Operation,
        scope: Scope,
    ) -> Result<Self> {
        if let Some(reason) = cell_refusal(operation, scope) {
            return Err(ContainmentError::UnsupportedCapability {
                capability: format!(
                    "{operation:?} at {scope:?} on {}: {reason}",
                    path.original.display()
                ),
                backend: "vocabulary".to_string(),
            });
        }
        // The authored scope against what the filesystem says, both spelled the same way.
        if scope.is_directory() != path.is_directory() {
            return Err(if path.is_directory() {
                ContainmentError::ExpectedFile(path.original)
            } else {
                ContainmentError::ExpectedDirectory(path.original)
            });
        }
        // Built empty and then filled, so the walk reads `reachable_paths` for its seed and the two
        // answers cannot drift apart.
        let mut granted = Self {
            original: path.original,
            resolved: path.resolved,
            operation,
            scope,
            nodes: Vec::new(),
        };
        granted.nodes = granted.walk_traversal_nodes();
        Ok(granted)
    }

    /// Whether this grant names a directory.
    pub(crate) const fn is_directory(&self) -> bool {
        self.scope.is_directory()
    }

    /// The paths this grant must be reachable at: its resolved identity, and the caller's own
    /// spelling when that differs.
    pub(crate) fn reachable_paths(&self) -> Vec<PathBuf> {
        if self.original == self.resolved {
            return vec![self.resolved.clone()];
        }
        vec![self.resolved.clone(), self.original.clone()]
    }

    /// Every node a lookup of this grant traverses, resolved once when the grant was built.
    pub(crate) fn traversal_paths(&self) -> Vec<PathBuf> {
        self.nodes.clone()
    }

    /// Walk the chain once: [`Self::reachable_paths`], the caller's spelling parent-canonical, and
    /// each link node between the two ends.
    ///
    /// A grant whose parent is canonical and which holds no link, or one, gives back exactly
    /// [`Self::reachable_paths`].
    fn walk_traversal_nodes(&self) -> Vec<PathBuf> {
        let mut nodes = self.reachable_paths();
        let record = |node: PathBuf, nodes: &mut Vec<PathBuf>| {
            if !nodes.contains(&node) {
                nodes.push(node);
            }
        };

        record(parent_canonical(&self.original), &mut nodes);

        let mut current = self.original.clone();
        for _ in 0..MAXIMUM_LINK_HOPS {
            let Ok(target) = std::fs::read_link(&current) else {
                break;
            };
            current = match current.parent() {
                Some(parent) if target.is_relative() => parent.join(&target),
                _ => target,
            };
            let node = parent_canonical(&current);
            if node == self.resolved {
                break;
            }
            record(node, &mut nodes);
        }
        nodes
    }

    /// Re-resolve the caller spelling immediately before apply.
    pub(crate) fn validate_live_identity(&self) -> Result<()> {
        // **A denial re-checks its identity without requiring the path to be there.** It may name a
        // path that does not exist, and it renders the same rule either way; what still matters is
        // that the identity has not moved under it, which the lexical resolve answers.
        if self.operation == Operation::Deny {
            let live = canonical_with_absent_tail(&self.original);
            if live != self.resolved {
                return Err(ContainmentError::ConfigValidation(format!(
                    "refused path changed before apply: original={}, recorded resolved={}, \
                     current resolved={}",
                    self.original.display(),
                    self.resolved.display(),
                    live.display(),
                )));
            }
            if self.scope == Scope::File && live.is_dir() {
                return Err(ContainmentError::ExpectedFile(self.original.clone()));
            }
            return Ok(());
        }
        let live = PreparedFilesystemPath::new(&self.original)?;
        if live.resolved != self.resolved || live.is_directory() != self.is_directory() {
            return Err(ContainmentError::ConfigValidation(format!(
                "filesystem grant changed before apply: original={}, recorded resolved={}, \
                 current resolved={}, recorded kind={}, current kind={}",
                self.original.display(),
                self.resolved.display(),
                live.resolved.display(),
                if self.is_directory() {
                    "directory"
                } else {
                    "file"
                },
                if live.is_directory() {
                    "directory"
                } else {
                    "file"
                },
            )));
        }
        let live_nodes = self.walk_traversal_nodes();
        if live_nodes != self.nodes {
            return Err(ContainmentError::ConfigValidation(format!(
                "the nodes a lookup of {} traverses changed before apply: recorded {} of them, \
                 and {} now",
                self.original.display(),
                self.nodes.len(),
                live_nodes.len(),
            )));
        }
        Ok(())
    }
}

/// A grant as it arrives on the wire, before any of it is trusted.
///
/// `resolved` travels so loading can detect drift: the path is canonicalized again here, and a
/// different answer means the filesystem changed under a grant somebody already approved.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PathGrantWire {
    original: PathBuf,
    resolved: PathBuf,
    operation: Operation,
    scope: Scope,
}

impl TryFrom<PathGrantWire> for PathGrant {
    type Error = ContainmentError;

    fn try_from(wire: PathGrantWire) -> Result<Self> {
        require_absolute("granted original", &wire.original)?;
        require_absolute("granted resolved", &wire.resolved)?;
        // **A denial re-validates on its own terms.** It may name a path that does not exist, so
        // routing it through the authorizing constructor would refuse on load the very entry the
        // caller stated deliberately — and the drift check below still holds it to one identity.
        let granted = if wire.operation == Operation::Deny {
            Self::denial(&wire.original, wire.scope)?
        } else {
            Self::new(&wire.original, wire.operation, wire.scope)?
        };
        if granted.resolved != wire.resolved {
            return Err(ContainmentError::ConfigValidation(format!(
                "granted path canonical path drifted while loading config: \
                 serialized resolved={}, actual resolved={}",
                wire.resolved.display(),
                granted.resolved.display(),
            )));
        }
        Ok(granted)
    }
}

/// Refuse a relative path on the wire, because it would mean whatever the loader's cwd happens to be.
fn require_absolute(label: &str, path: &Path) -> Result<()> {
    if path.is_absolute() {
        return Ok(());
    }
    Err(ContainmentError::ConfigValidation(format!(
        "{label} path must be absolute: {}",
        path.display()
    )))
}

fn canonicalize_existing(path: &Path) -> Result<PathBuf> {
    path.canonicalize().map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            ContainmentError::PathNotFound(path.to_path_buf())
        } else {
            ContainmentError::PathCanonicalization {
                path: path.to_path_buf(),
                source,
            }
        }
    })
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    std::path::absolute(path).map_err(|source| ContainmentError::PathCanonicalization {
        path: path.to_path_buf(),
        source,
    })
}

/// How many links one lookup may traverse before this crate stops walking.
const MAXIMUM_LINK_HOPS: usize = 40;

/// The path with a canonical parent and its own final component.
fn parent_canonical(path: &Path) -> PathBuf {
    let Some(parent) = path.parent() else {
        return path.to_path_buf();
    };
    let Some(name) = path.file_name() else {
        return path.to_path_buf();
    };
    match parent.canonicalize() {
        Ok(canonical) => canonical.join(name),
        Err(_) => path.to_path_buf(),
    }
}

/// Backend-specific overrides that only make sense for one enforcement mechanism.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BackendOverride {
    /// No backend-specific overrides — use each backend's defaults.
    #[default]
    None,
    /// macOS Seatbelt backend.
    Seatbelt {
        /// Whether Seatbelt extension tokens are enabled.
        extensions_enabled: bool,
    },
}
