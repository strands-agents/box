//! Where one box's files live, organized by what the workload can reach.
//!
//! | Child | Workload access | Holds |
//! |---|---|---|
//! | `bin/` | execute | the Shell aliases, one exec literal each |
//! | `run/` | connect | the broker socket: `box.sock`, for every interpreter |
//! | `trust/` | read | the proxy's public CA certificate |
//! | `private/` | **none** | the record, the policy, the caches, the lock and the live record |
//!
//! **There is one root, and it is a box's own**. A second, machine-level root sited a daemon
//! serving N boxes; with the `run` process owning its box, every path a box needs is under that
//! box's root, and the lock proving who owns it is one of them.

use std::fs::OpenOptions;
use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd as _, FromRawFd as _, IntoRawFd as _};

use crate::error::{BoxError, ConfigError, DaemonError, HistoryFound, Internal, LayoutError};
use crate::record::config::Record;

#[cfg(target_os = "linux")]
mod mount;

#[cfg(target_os = "linux")]
pub(crate) fn prepare_mount_inspection() -> std::io::Result<()> {
    mount::prepare()
}

/// The platform's usable `sun_path`, measured on macOS rather than taken from the docs.
///
/// This is the whole guard on socket-path length. The box name used to spend the budget, because it
/// was a path component of a Box-sited root; a caller now supplies `box_dir`, so the budget is spent
/// by a path Box does not choose and the refusal is the only thing that bounds it.
pub(crate) const BROKER_SOCKET_PATH_LIMIT: usize = 103;

/// The workload's `PATH`, executed and never read.
const BIN_DIRECTORY: &str = "bin";

/// Where the shim binds the socket the workload connects to.
const RUN_DIRECTORY: &str = "run";

/// The proxy's public CA certificate, read and never written.
const TRUST_DIRECTORY: &str = "trust";
const TRUST_CERTIFICATE_FILE: &str = "cert.pem";

/// Everything no profile placeholder names.
pub(crate) const PRIVATE_DIRECTORY: &str = "private";

/// The mode that marks a recoverable first-record write.
const FIRST_USE_PRIVATE_MODE: u32 = 0o1700;

/// This box's own telemetry, below [`PRIVATE_DIRECTORY`].
const TELEMETRY_DIRECTORY: &str = "telemetry";

/// The one file the default target appends to.
const TELEMETRY_FILE: &str = "records.jsonl";

/// The box root's children, in the order this module creates them.
const BOX_ROOT_CHILDREN: [&str; 4] = [
    BIN_DIRECTORY,
    RUN_DIRECTORY,
    TRUST_DIRECTORY,
    PRIVATE_DIRECTORY,
];

/// The record `configure` writes and every other verb reads.
pub(crate) const RECORD_FILE: &str = "box.toml";
const PRIVATE_COMMIT_FILE: &str = "configured";
const PENDING_RECORD_FILE: &str = "box.toml.pending";

#[cfg(any(target_os = "linux", target_os = "macos"))]
static DIRECTORY_ENUMERATION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The policy text, copied by `configure` rather than referenced.
pub(crate) const POLICY_FILE: &str = "policy.dw";

/// The Dogwood database, below [`PRIVATE_DIRECTORY`].
const DOGWOOD_DATABASE_FILE: &str = "dogwood.redb";

/// Where a local MCP server is started, under `private/`.
const MCP_WORKING_DIRECTORY: &str = "mcp";

/// Records which installed image the placed aliases were copied from.
const ALIAS_STAMP_FILE: &str = "alias-image.stamp";

/// The lock that serializes `configure` against itself and against `start`.
const LOCK_FILE: &str = ".lock";

/// A record of what is live: the daemon's pid at the machine root, one box's port in a box.
const LIVE_FILE: &str = "live.json";

/// The daemon's own directory, under the operator's state directory.
const MACHINE_DIRECTORY: &str = "strands-box";

/// Where the state directory sits when `XDG_STATE_HOME` is unset.
const STATE_HOME_FALLBACK: [&str; 2] = [".local", "state"];

/// Per-run containment configs, named by the digest the trampoline verifies.
const CONTAINMENT_DIRECTORY: &str = "containment";

/// The verified trampoline image, named by its content digest.
const TRAMPOLINE_DIRECTORY: &str = "trampoline";

// `run/broker/protocol.rs` owns the two alias name lists, because it is the one module the separate
// `strands-box-sock-alias` binary can `#[path]`-include — so it cannot import from here, and one
use crate::run::broker::protocol::{BROKER_SOCKET, PYTHON_ALIAS_NAMES, SHELL_ALIAS_NAMES};

/// One box's filesystem: the root, and every path computed from it.
#[derive(Debug, Clone)]
pub(crate) struct BoxRoot {
    /// The caller-selected box directory spelling.
    root: PathBuf,

    /// The operator home used for portable policy reporting.
    operator_home: PathBuf,

    /// The generated box identity, or a legacy locator before a record is open.
    name: String,

    /// The opened directory identity that keeps the caller-selected root pinned.
    root_handle: Option<Arc<std::fs::File>>,

    /// The opened directory identity that keeps private state pinned.
    private_handle: Option<Arc<std::fs::File>>,

    /// The opened private directory left by an interrupted first record write.
    first_use_private: Option<FirstUsePrivate>,

    /// Whether opening found one completed private record.
    configured: bool,

    /// Whether a committed record existed before this process opened the root.
    committed_before_open: bool,
}

/// The exclusive lock that serializes first use of a caller-owned directory.
pub(crate) struct RootLock {
    handle: Arc<std::fs::File>,
}

#[derive(Debug, Clone)]
struct FirstUsePrivate {
    handle: Arc<std::fs::File>,
    record: Option<Arc<std::fs::File>>,
}

struct RecoverablePrivateState {
    record: Option<Arc<std::fs::File>>,
}

/// What the commit marker says about the record beside it.
enum CommittedRecord {
    Absent,
    Committed { box_id: String },
    Mismatch { stored: String, found: String },
    Unreadable(ConfigError),
}

/// A record's persisted identity: its box id, and the text the commit marker holds.
struct RecordIdentity {
    box_id: String,
    text: String,
}

enum OpenedState {
    Fresh,
    Interrupted(FirstUsePrivate),
    Configured {
        box_id: String,
        private: Arc<std::fs::File>,
    },
}

impl Drop for RootLock {
    fn drop(&mut self) {
        // SAFETY: flock only takes a descriptor this File owns.
        unsafe { libc::flock(self.handle.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl BoxRoot {
    /// Create the box rooted at `root`, whatever sited it.
    #[cfg(test)]
    pub(crate) fn create_at(root: PathBuf, name: &str) -> Result<Self, BoxError> {
        create_private_directory(&root)?;
        for child in BOX_ROOT_CHILDREN {
            create_private_directory(&root.join(child))?;
        }

        let root_handle = Arc::new(open_directory_without_following(&root).map_err(|source| {
            LayoutError::ReadDirectory {
                path: root.clone(),
                source,
            }
        })?);
        let private_path = root.join(PRIVATE_DIRECTORY);
        let private_handle = Arc::new(open_child_directory(
            root_handle.as_ref(),
            PRIVATE_DIRECTORY,
            &private_path,
        )?);
        let layout = Self {
            root,
            operator_home: canonical(&operator_home_directory()?),
            name: name.to_string(),
            root_handle: Some(root_handle),
            private_handle: Some(private_handle),
            first_use_private: None,
            configured: false,
            committed_before_open: false,
        };
        for directory in [
            layout.containment_directory(),
            layout.trampoline_directory(),
            layout.mcp_working_directory(),
        ] {
            create_private_directory(&directory)?;
        }
        Ok(layout)
    }

    /// Open a caller-created box directory and create only Box-owned children.
    ///
    /// `run` takes the lock, so this borrows nothing an unlocked caller could act on.
    #[cfg(test)]
    pub(crate) fn open_directory(path: &Path) -> Result<Self, BoxError> {
        Ok(Self::open_directory_inner(path, false)?.0)
    }

    /// Open and exclusively lock a caller-created box directory.
    pub(crate) fn lock_directory(path: &Path) -> Result<(Self, RootLock), BoxError> {
        let (root, lock) = Self::open_directory_inner(path, true)?;
        Ok((root, lock.expect("an exclusive open returns its lock")))
    }

    fn open_directory_inner(
        path: &Path,
        exclusive: bool,
    ) -> Result<(Self, Option<RootLock>), BoxError> {
        Self::open_directory_inner_with(path, exclusive, || {})
    }

    fn open_directory_inner_with(
        path: &Path,
        exclusive: bool,
        before_open: impl FnOnce(),
    ) -> Result<(Self, Option<RootLock>), BoxError> {
        before_open();
        let handle = match open_directory_without_following(path) {
            Ok(handle) => handle,
            #[cfg(unix)]
            Err(source)
                if matches!(
                    source.raw_os_error(),
                    Some(libc::ELOOP) | Some(libc::ENOTDIR)
                ) =>
            {
                return Err(LayoutError::NotADirectory {
                    path: path.to_path_buf(),
                }
                .into());
            }
            Err(source) => {
                return Err(LayoutError::Create {
                    path: path.to_path_buf(),
                    source,
                }
                .into());
            }
        };
        let metadata = handle.metadata().map_err(|source| LayoutError::Create {
            path: path.to_path_buf(),
            source,
        })?;
        if !metadata.is_dir() {
            return Err(LayoutError::NotADirectory {
                path: path.to_path_buf(),
            }
            .into());
        }
        #[cfg(unix)]
        {
            if metadata.uid() != unsafe { libc::geteuid() } {
                return Err(LayoutError::UnsafeDirectory {
                    path: path.to_path_buf(),
                    reason: "it is not owned by the current user".to_string(),
                }
                .into());
            }
            if metadata.permissions().mode() & 0o777 != 0o700 {
                return Err(LayoutError::UnsafeDirectory {
                    path: path.to_path_buf(),
                    reason: "its mode is not 0700".to_string(),
                }
                .into());
            }
        }

        #[cfg(unix)]
        {
            let current =
                std::fs::symlink_metadata(path).map_err(|source| LayoutError::Create {
                    path: path.to_path_buf(),
                    source,
                })?;
            if current.file_type().is_symlink()
                || metadata.dev() != current.dev()
                || metadata.ino() != current.ino()
            {
                return Err(LayoutError::UnsafeDirectory {
                    path: path.to_path_buf(),
                    reason: "its identity changed while Box opened it".to_string(),
                }
                .into());
            }
        }
        let root = path.to_path_buf();

        let handle = Arc::new(handle);
        let root_lock = if exclusive {
            // SAFETY: flock only takes a descriptor this File owns.
            let result = unsafe { libc::flock(handle.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                let source = std::io::Error::last_os_error();
                return match source.raw_os_error() {
                    Some(libc::EWOULDBLOCK) => Err(DaemonError::Busy.into()),
                    _ => Err(DaemonError::Lock {
                        path: root.clone(),
                        source,
                    }
                    .into()),
                };
            }
            Some(RootLock {
                handle: Arc::clone(&handle),
            })
        } else {
            None
        };

        let (identity, private_handle, first_use_private, configured) =
            match inspect_opened_state(&handle, &root)? {
                OpenedState::Fresh => (String::new(), None, None, false),
                OpenedState::Interrupted(private) => (
                    String::new(),
                    Some(Arc::clone(&private.handle)),
                    Some(private),
                    false,
                ),
                OpenedState::Configured { box_id, private } => (box_id, Some(private), None, true),
            };

        let layout = Self {
            root,
            operator_home: canonical(&operator_home_directory()?),
            name: identity,
            root_handle: Some(handle),
            private_handle,
            first_use_private,
            configured,
            committed_before_open: configured,
        };
        if layout.broker_socket().as_os_str().as_encoded_bytes().len() > BROKER_SOCKET_PATH_LIMIT {
            return Err(LayoutError::UnsafeDirectory {
                path: path.to_path_buf(),
                reason: "its broker socket path exceeds the platform limit".to_string(),
            }
            .into());
        }
        layout.verify_identity()?;
        Ok((layout, root_lock))
    }

    /// Create the Box-owned layout after the caller-owned directory passes contract validation.
    pub(crate) fn initialize(&mut self) -> Result<(), BoxError> {
        self.verify_identity()?;
        for child in BOX_ROOT_CHILDREN {
            self.create_directory_on_identity(&self.root.join(child))?;
        }
        for directory in [
            self.containment_directory(),
            self.trampoline_directory(),
            self.mcp_working_directory(),
        ] {
            self.create_directory_on_identity(&directory)?;
        }
        self.verify_identity()
    }

    /// Commit the first record before the remaining Box layout.
    pub(crate) fn initialize_first_use(&mut self, record: &Record) -> Result<(), BoxError> {
        let text = record.to_toml()?;
        let private = match self.first_use_private.clone() {
            Some(private) => private,
            None => self.create_first_use_private()?,
        };
        self.private_handle = Some(Arc::clone(&private.handle));
        private.verify_before_record(self)?;
        let record_file = private.write_record(self, &text)?;
        private.verify_binding(self)?;
        private.finish(self, &record_file)?;
        self.first_use_private = None;
        self.configured = true;
        self.initialize()
    }

    fn create_first_use_private(&self) -> Result<FirstUsePrivate, BoxError> {
        self.verify_identity()?;
        let root = self
            .root_handle
            .as_deref()
            .ok_or_else(|| LayoutError::UnsafeDirectory {
                path: self.root.clone(),
                reason: "the caller-owned directory is not open".to_string(),
            })?;
        if !first_use_contents(root, &self.root, false)? {
            return Err(LayoutError::UnsafeDirectory {
                path: self.root.clone(),
                reason: "its first-use contents changed after Box validated it".to_string(),
            }
            .into());
        }
        let handle = Arc::new(create_child_directory(
            root,
            PRIVATE_DIRECTORY,
            &self.private_directory(),
            FIRST_USE_PRIVATE_MODE,
        )?);
        let private = FirstUsePrivate {
            handle,
            record: None,
        };
        Ok(private)
    }

    /// Read the existing identity, or generate one for first use.
    pub(crate) fn settle_identity(&mut self) -> Result<(), BoxError> {
        self.verify_identity()?;
        if self.configured {
            return Ok(());
        }
        if self.root_handle.is_some() {
            if self.name.is_empty() {
                self.name = new_box_identity()?;
            }
            return self.verify_identity();
        }
        let path = self.record();
        match std::fs::read_to_string(&path) {
            Ok(text) => self.name = Record::parse(&text, &path)?.box_id,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.name = new_box_identity()?;
            }
            Err(source) => return Err(ConfigError::Read { path, source }.into()),
        }
        self.verify_identity()
    }

    pub(crate) fn is_configured(&self) -> bool {
        self.configured
    }

    /// The box root itself.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// The generated identity, or the legacy lifecycle locator before it is settled.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn box_id(&self) -> &str {
        assert!(!self.name.is_empty(), "the box identity must be settled");
        &self.name
    }

    /// The operator home this box was created under, derived from the root rather than read.
    pub(crate) fn operator_home(&self) -> Option<&Path> {
        Some(&self.operator_home)
    }

    /// The workload's `PATH`: execute-only, holding the Shell aliases.
    pub(crate) fn bin_directory(&self) -> PathBuf {
        self.root.join(BIN_DIRECTORY)
    }

    /// Every Shell alias path, one per conventional shell name.
    pub(crate) fn all_aliases(
        &self,
        servers: &[crate::record::config::mcp::McpServer],
    ) -> Vec<PathBuf> {
        self.shell_aliases()
            .into_iter()
            .chain(self.python_aliases())
            .chain(self.mcp_aliases(servers))
            .collect()
    }

    pub(crate) fn shell_aliases(&self) -> Vec<PathBuf> {
        let bin = self.bin_directory();
        SHELL_ALIAS_NAMES
            .iter()
            .map(|name| bin.join(name))
            .collect()
    }

    /// Every Python alias path, one per name a harness might resolve.
    pub(crate) fn mcp_aliases(
        &self,
        servers: &[crate::record::config::mcp::McpServer],
    ) -> Vec<PathBuf> {
        let directory = self.bin_directory();
        servers
            .iter()
            .map(|server| directory.join(server.program()))
            .collect()
    }

    pub(crate) fn python_aliases(&self) -> Vec<PathBuf> {
        let bin = self.bin_directory();
        PYTHON_ALIAS_NAMES
            .iter()
            .map(|name| bin.join(name))
            .collect()
    }

    /// Where the trusted process binds its sockets.
    pub(crate) fn run_directory(&self) -> PathBuf {
        self.root.join(RUN_DIRECTORY)
    }

    /// The broker's socket, which the workload connects to and never binds.
    pub(crate) fn broker_socket(&self) -> PathBuf {
        self.run_directory().join(BROKER_SOCKET)
    }

    /// Bind the broker socket through the retained run-directory identity.
    pub(crate) fn bind_broker_listener(&self) -> std::io::Result<std::os::unix::net::UnixListener> {
        self.verify_identity().map_err(box_error_as_io)?;
        let run = self
            .open_directory_handle(&self.run_directory())
            .map_err(box_error_as_io)?;
        let listener = bind_unix_listener_at(&run, std::ffi::OsStr::new(BROKER_SOCKET))?;
        self.verify_identity().map_err(box_error_as_io)?;
        Ok(listener)
    }

    /// Where the proxy writes its ephemeral CA's public certificate.
    pub(crate) fn trust_directory(&self) -> PathBuf {
        self.root.join(TRUST_DIRECTORY)
    }

    /// Create the public trust certificate through the retained trust-directory identity.
    pub(crate) fn open_trust_certificate(&self) -> Result<std::fs::File, BoxError> {
        self.verify_identity()?;
        let path = self.trust_directory().join(TRUST_CERTIFICATE_FILE);
        self.remove_file(&path)?;
        let file = match self.identity_anchor(&path)? {
            Some((anchor, relative)) => open_relative_with_mode(
                anchor,
                relative,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            ),
            None => OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path),
        }
        .map_err(|source| LayoutError::Create {
            path: path.clone(),
            source,
        })?;
        let metadata = file
            .metadata()
            .map_err(|source| LayoutError::ReadDirectory {
                path: path.clone(),
                source,
            })?;
        if !record_metadata_is_safe(&metadata) {
            return Err(LayoutError::UnsafeDirectory {
                path,
                reason: "it is not one private certificate inode".to_string(),
            }
            .into());
        }
        self.verify_identity()?;
        Ok(file)
    }

    /// Where this box's own telemetry lands when no target names a destination.
    pub(crate) fn telemetry_directory(&self) -> PathBuf {
        self.private_directory().join(TELEMETRY_DIRECTORY)
    }

    /// The default file destination: one file per box, appended across runs.
    pub(crate) fn telemetry_file(&self) -> PathBuf {
        self.telemetry_directory().join(TELEMETRY_FILE)
    }

    /// Open the default telemetry file through the retained private directory.
    pub(crate) fn open_telemetry_file(&self) -> Result<std::fs::File, BoxError> {
        self.verify_identity()?;
        let path = self.telemetry_file();
        let file = match self.identity_anchor(&path)? {
            Some((anchor, relative)) => open_relative_with_mode(
                anchor,
                relative,
                libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
                0o600,
            ),
            None => OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&path),
        }
        .map_err(|source| LayoutError::Create {
            path: path.clone(),
            source,
        })?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| LayoutError::Create {
                path: path.clone(),
                source,
            })?;
        let metadata = file
            .metadata()
            .map_err(|source| LayoutError::ReadDirectory {
                path: path.clone(),
                source,
            })?;
        if !record_metadata_is_safe(&metadata) {
            return Err(LayoutError::UnsafeDirectory {
                path,
                reason: "it is not one private telemetry inode".to_string(),
            }
            .into());
        }
        self.verify_identity()?;
        Ok(file)
    }

    /// Where the alias image's stamp is written, so staleness costs one `stat`.
    pub(crate) fn alias_stamp(&self) -> PathBuf {
        self.private_directory().join(ALIAS_STAMP_FILE)
    }

    /// Private to this module: eleven accessors below join a filename onto it, and each of those
    /// is the named way to reach that file. Public, it invited a caller to join a name itself and
    /// bypass the accessor — and the record, the policy, and the lock all live under here.
    fn private_directory(&self) -> PathBuf {
        self.root.join(PRIVATE_DIRECTORY)
    }

    /// The record `configure` writes: version, name, and the egress bindings.
    pub(crate) fn record(&self) -> PathBuf {
        self.private_directory().join(RECORD_FILE)
    }

    /// The policy text, copied at `configure` and opened by both the box and the
    /// shim.
    pub(crate) fn policy(&self) -> PathBuf {
        self.private_directory().join(POLICY_FILE)
    }

    /// The durable Dogwood database.
    pub(crate) fn dogwood_database(&self) -> PathBuf {
        self.private_directory().join(DOGWOOD_DATABASE_FILE)
    }

    /// The lock that one run holds through teardown.
    pub(crate) fn lock(&self) -> PathBuf {
        self.private_directory().join(LOCK_FILE)
    }

    /// Open this box's ownership lock through the retained private directory.
    pub(crate) fn open_lock_file(&self, create: bool) -> Result<Option<std::fs::File>, BoxError> {
        self.open_private_state_file(&self.lock(), create)
    }

    /// Refuse a box whose record, as committed before this run, and durable history disagree about
    /// whether it has run.
    pub(crate) fn verify_history_matches_record(&self) -> Result<(), BoxError> {
        self.verify_identity()?;
        let history = self.dogwood_database();
        let found = match self.open_file_on_identity(&history, libc::O_RDONLY) {
            Ok(file) => match file
                .metadata()
                .map_err(|source| LayoutError::ReadDirectory {
                    path: history.clone(),
                    source,
                })?
                .len()
            {
                0 => HistoryFound::Empty,
                bytes => HistoryFound::Present { bytes },
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HistoryFound::Absent,
            Err(source) => {
                return Err(LayoutError::ReadDirectory {
                    path: history,
                    source,
                }
                .into());
            }
        };
        match (self.committed_before_open, found) {
            (true, HistoryFound::Present { .. })
            | (false, HistoryFound::Absent | HistoryFound::Empty) => Ok(()),
            (committed, found) => Err(Internal::HistoryDisagreesWithRecord {
                committed,
                history,
                found,
            }
            .into()),
        }
    }

    /// Open the durable history file through the retained private directory.
    pub(crate) fn open_dogwood_database(&self) -> Result<std::fs::File, BoxError> {
        Ok(self
            .open_private_state_file(&self.dogwood_database(), true)?
            .expect("creating a private state file returns one file"))
    }

    /// This box's live record: the port it is served on, while it is loaded.
    pub(crate) fn live_record(&self) -> PathBuf {
        self.private_directory().join(LIVE_FILE)
    }

    /// Where per-run containment configs land.
    pub(crate) fn mcp_working_directory(&self) -> PathBuf {
        self.private_directory().join(MCP_WORKING_DIRECTORY)
    }

    pub(crate) fn containment_directory(&self) -> PathBuf {
        self.private_directory().join(CONTAINMENT_DIRECTORY)
    }

    /// The containment config for `digest`.
    pub(crate) fn containment_config(&self, digest: &str) -> PathBuf {
        self.containment_directory().join(format!("{digest}.json"))
    }

    /// Where the verified trampoline image is cached.
    fn trampoline_directory(&self) -> PathBuf {
        self.private_directory().join(TRAMPOLINE_DIRECTORY)
    }

    /// The cached trampoline image for `digest`.
    pub(crate) fn trampoline_image(&self, digest: &str) -> PathBuf {
        self.trampoline_directory().join(format!("{digest}.bin"))
    }

    /// Open the directory that holds validated trampoline images.
    pub(crate) fn open_trampoline_cache(&self) -> Result<std::fs::File, BoxError> {
        self.verify_identity()?;
        let private =
            self.private_handle
                .as_deref()
                .ok_or_else(|| LayoutError::UnsafeDirectory {
                    path: self.private_directory(),
                    reason: "the private directory is not open".to_string(),
                })?;
        let path = self.trampoline_directory();
        let cache = open_child_directory(private, TRAMPOLINE_DIRECTORY, &path)?;
        let metadata = cache
            .metadata()
            .map_err(|source| LayoutError::ReadDirectory {
                path: path.clone(),
                source,
            })?;
        if !private_directory_metadata_is_safe(&metadata)
            || private_directory_mode(&metadata) != 0o700
            || !same_mount(private, &cache, &self.private_directory(), &path)?
        {
            return Err(LayoutError::UnsafeDirectory {
                path,
                reason: "it is not one private cache directory".to_string(),
            }
            .into());
        }
        self.verify_identity()?;
        Ok(cache)
    }

    /// Open the local MCP working directory through the retained private directory.
    pub(crate) fn open_mcp_working_directory(&self) -> Result<std::fs::File, BoxError> {
        let working_directory = self.mcp_working_directory();
        self.open_directory_handle(&working_directory)
    }

    /// Re-create one directory inside this box at mode 0700.
    pub(crate) fn create_child_directory(&self, path: &Path) -> Result<(), BoxError> {
        self.verify_identity()?;
        if !path.starts_with(&self.root) {
            return Err(LayoutError::NotADirectory {
                path: path.to_path_buf(),
            }
            .into());
        }
        self.create_directory_on_identity(path)?;
        self.verify_identity()
    }

    /// Whether one path below this root exists on the opened directory identity.
    pub(crate) fn path_exists(&self, path: &Path) -> Result<bool, BoxError> {
        self.verify_identity()?;
        let result = match self.open_file_on_identity(path, libc::O_RDONLY) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(LayoutError::ReadDirectory {
                path: path.to_path_buf(),
                source,
            }
            .into()),
        };
        self.verify_identity()?;
        result
    }

    /// List one Box-owned directory through its retained identity.
    pub(crate) fn directory_entry_names(
        &self,
        path: &Path,
    ) -> Result<Vec<std::ffi::OsString>, BoxError> {
        self.verify_identity()?;
        let directory = self
            .open_file_on_identity(path, libc::O_RDONLY | libc::O_DIRECTORY)
            .map_err(|source| LayoutError::ReadDirectory {
                path: path.to_path_buf(),
                source,
            })?;
        let entries = directory_entries(&directory, path)?;
        self.verify_identity()?;
        Ok(entries)
    }

    /// Open one Box-owned directory through its retained identity.
    pub(crate) fn open_directory_handle(&self, path: &Path) -> Result<std::fs::File, BoxError> {
        self.verify_identity()?;
        let directory = self
            .open_file_on_identity(path, libc::O_RDONLY | libc::O_DIRECTORY)
            .map_err(|source| LayoutError::ReadDirectory {
                path: path.to_path_buf(),
                source,
            })?;
        self.verify_identity()?;
        Ok(directory)
    }

    /// Remove every file in one Box-owned directory.
    pub(crate) fn clear_directory(&self, path: &Path) -> Result<(), BoxError> {
        for entry in self.directory_entry_names(path)? {
            let _ = self.remove_file(&path.join(entry));
        }
        Ok(())
    }

    /// Place one source file below this Box through its retained identity.
    pub(crate) fn install_file(
        &self,
        source: &Path,
        destination: &Path,
        mode: u32,
    ) -> Result<(), BoxError> {
        self.verify_identity()?;
        let Some((anchor, relative)) = self.identity_anchor(destination)? else {
            return install_file_at_path(source, destination, mode).map_err(|source| {
                LayoutError::Create {
                    path: destination.to_path_buf(),
                    source,
                }
                .into()
            });
        };
        install_relative_file(anchor, relative, source, mode).map_err(|source| {
            BoxError::from(LayoutError::Create {
                path: destination.to_path_buf(),
                source,
            })
        })?;
        self.verify_identity()
    }

    fn create_directory_on_identity(&self, path: &Path) -> Result<(), BoxError> {
        let Some((anchor, relative)) = self.identity_anchor(path)? else {
            return create_private_directory(path);
        };
        ensure_relative_directory(anchor, relative, path)?;
        Ok(())
    }

    fn open_file_on_identity(
        &self,
        path: &Path,
        flags: libc::c_int,
    ) -> std::io::Result<std::fs::File> {
        let Some((anchor, relative)) = self.identity_anchor(path).map_err(box_error_as_io)? else {
            return OpenOptions::new().read(true).open(path);
        };
        open_relative(anchor, relative, flags)
    }

    fn open_private_state_file(
        &self,
        path: &Path,
        create: bool,
    ) -> Result<Option<std::fs::File>, BoxError> {
        self.verify_identity()?;
        let opened = match self.identity_anchor(path)? {
            Some((anchor, relative)) => open_relative_with_mode(
                anchor,
                relative,
                libc::O_RDWR | if create { libc::O_CREAT } else { 0 },
                0o600,
            ),
            None => OpenOptions::new()
                .read(true)
                .write(true)
                .create(create)
                .truncate(false)
                .open(path),
        };
        let file = match opened {
            Ok(file) => file,
            Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(source) => {
                return Err(LayoutError::Create {
                    path: path.to_path_buf(),
                    source,
                }
                .into());
            }
        };
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| LayoutError::Create {
                path: path.to_path_buf(),
                source,
            })?;
        let metadata = file
            .metadata()
            .map_err(|source| LayoutError::ReadDirectory {
                path: path.to_path_buf(),
                source,
            })?;
        if !record_metadata_is_safe(&metadata) {
            return Err(LayoutError::UnsafeDirectory {
                path: path.to_path_buf(),
                reason: "it is not one private state inode".to_string(),
            }
            .into());
        }
        self.verify_identity()?;
        Ok(Some(file))
    }

    fn identity_anchor<'a>(
        &'a self,
        path: &'a Path,
    ) -> Result<Option<(&'a std::fs::File, &'a Path)>, BoxError> {
        let Some(root) = self.root_handle.as_deref() else {
            return Ok(None);
        };
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|_| LayoutError::NotADirectory {
                path: path.to_path_buf(),
            })?;
        if relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(LayoutError::NotADirectory {
                path: path.to_path_buf(),
            }
            .into());
        }
        if let Some(private) = self.private_handle.as_deref()
            && let Ok(private_relative) = relative.strip_prefix(PRIVATE_DIRECTORY)
        {
            return Ok(Some((private, private_relative)));
        }
        Ok(Some((root, relative)))
    }

    /// Read one UTF-8 file below this root from the opened directory identity.
    pub(crate) fn read_text(&self, path: &Path) -> Result<String, BoxError> {
        self.verify_identity()?;
        let result = self
            .open_file_on_identity(path, libc::O_RDONLY)
            .and_then(read_file_to_string)
            .map_err(|source| {
                ConfigError::Read {
                    path: path.to_path_buf(),
                    source,
                }
                .into()
            });
        self.verify_identity()?;
        result
    }

    /// Read one file below this root from the opened directory identity.
    pub(crate) fn read_bytes(&self, path: &Path) -> Result<Vec<u8>, BoxError> {
        self.verify_identity()?;
        let result = self
            .open_file_on_identity(path, libc::O_RDONLY)
            .and_then(|mut file| {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                Ok(bytes)
            })
            .map_err(|source| {
                BoxError::from(LayoutError::ReadDirectory {
                    path: path.to_path_buf(),
                    source,
                })
            });
        self.verify_identity()?;
        result
    }

    /// Remove one file below this root from the opened directory identity.
    pub(crate) fn remove_file(&self, path: &Path) -> Result<(), BoxError> {
        self.verify_identity()?;
        let result = match self.identity_anchor(path)? {
            Some((anchor, relative)) => remove_relative_file(anchor, relative),
            None => std::fs::remove_file(path),
        };
        let result = match result {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(LayoutError::Remove {
                path: path.to_path_buf(),
                source,
            }
            .into()),
        };
        self.verify_identity()?;
        result
    }

    /// Read the stored record.
    pub(crate) fn read_record(&self) -> Result<crate::record::config::Record, BoxError> {
        self.verify_identity()?;
        let path = self.record();
        let record = match &self.private_handle {
            Some(private) => {
                let record = open_child_file(private, RECORD_FILE, &path)?;
                let metadata = record
                    .metadata()
                    .map_err(|source| LayoutError::ReadDirectory {
                        path: path.clone(),
                        source,
                    })?;
                if !record_metadata_is_safe(&metadata)
                    || !same_mount(private, &record, &self.private_directory(), &path)?
                {
                    return Err(LayoutError::UnsafeDirectory {
                        path,
                        reason: "it is not one private record inode".to_string(),
                    }
                    .into());
                }
                read_record_file(&record, &path)?
            }
            None => {
                let text = self.read_text(&path)?;
                crate::record::config::Record::parse(&text, &path)?
            }
        };
        self.verify_identity()?;
        Ok(record)
    }

    /// Read the stored policy text, or `None` when the box was configured without
    /// one.
    pub(crate) fn read_policy(&self) -> Result<Option<String>, BoxError> {
        self.verify_identity()?;
        let path = self.policy();
        let result = match self.open_file_on_identity(&path, libc::O_RDONLY) {
            Ok(file) => read_file_to_string(file).map(Some).map_err(|source| {
                ConfigError::PolicyRead {
                    path: path.clone(),
                    source,
                }
                .into()
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(ConfigError::PolicyRead { path, source }.into()),
        };
        self.verify_identity()?;
        result
    }

    /// Write `contents` to `path` at `mode`, replacing whatever was there.
    pub(crate) fn write_private_file(
        &self,
        path: &Path,
        contents: &str,
        mode: u32,
    ) -> Result<(), BoxError> {
        self.write_private_opened_file(path, contents, mode)?;
        Ok(())
    }

    /// Write one private file and retain the installed filesystem identity.
    pub(crate) fn write_private_opened_file(
        &self,
        path: &Path,
        contents: &str,
        mode: u32,
    ) -> Result<std::fs::File, BoxError> {
        self.verify_identity()?;
        let opened = match self.identity_anchor(path)? {
            Some((anchor, relative)) => {
                write_relative_opened_file(anchor, relative, path, contents.as_bytes(), mode)?
            }
            None => write_private_opened_file(path, contents, mode)?,
        };
        self.verify_identity()?;
        Ok(opened)
    }

    /// Replace the private record and bind its installed identity to the commit marker.
    pub(crate) fn write_committed_record(&self, contents: &str) -> Result<(), BoxError> {
        self.write_committed_record_with(contents, || {})
    }

    fn write_committed_record_with(
        &self,
        contents: &str,
        before_install: impl FnOnce(),
    ) -> Result<(), BoxError> {
        self.verify_identity()?;
        let private = self
            .private_handle
            .as_ref()
            .ok_or_else(|| LayoutError::UnsafeDirectory {
                path: self.private_directory(),
                reason: "the private directory is not open".to_string(),
            })?;
        let pending_path = self.private_directory().join(PENDING_RECORD_FILE);
        let pending = Arc::new(write_relative_opened_file(
            private,
            Path::new(PENDING_RECORD_FILE),
            &pending_path,
            contents.as_bytes(),
            0o600,
        )?);
        let binding = FirstUsePrivate {
            handle: Arc::clone(private),
            record: None,
        };
        binding.verify_named_file_binding(
            PENDING_RECORD_FILE,
            &pending_path,
            &pending,
            "the pending record identity changed before commit",
        )?;
        private.sync_all().map_err(|source| LayoutError::Create {
            path: self.private_directory(),
            source,
        })?;
        let commit = binding.write_commit(self, &pending)?;
        binding.verify_named_file_binding(
            PENDING_RECORD_FILE,
            &pending_path,
            &pending,
            "the pending record identity changed before install",
        )?;
        binding.verify_commit_binding(self, &pending, &commit)?;
        before_install();
        rename_child_file(private, PENDING_RECORD_FILE, RECORD_FILE, &self.record())?;
        binding.verify_record_binding(self, &pending)?;
        binding.verify_commit_binding(self, &pending, &commit)
    }

    fn verify_identity(&self) -> Result<(), BoxError> {
        let Some(handle) = &self.root_handle else {
            return Ok(());
        };
        #[cfg(unix)]
        {
            let opened = handle
                .metadata()
                .map_err(|source| LayoutError::ReadDirectory {
                    path: self.root.clone(),
                    source,
                })?;
            let current = std::fs::symlink_metadata(&self.root).map_err(|source| {
                LayoutError::ReadDirectory {
                    path: self.root.clone(),
                    source,
                }
            })?;
            if current.file_type().is_symlink()
                || opened.dev() != current.dev()
                || opened.ino() != current.ino()
            {
                return Err(LayoutError::UnsafeDirectory {
                    path: self.root.clone(),
                    reason: "its identity changed after Box validated it".to_string(),
                }
                .into());
            }
            if let Some(private) = &self.private_handle {
                verify_private_binding(handle, private, &self.root, &self.private_directory())?;
            }
        }
        Ok(())
    }
}

fn new_box_identity() -> Result<String, BoxError> {
    let mut bytes = [0_u8; 8];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|source| LayoutError::Create {
            path: PathBuf::from("/dev/urandom"),
            source,
        })?;
    let mut text = String::from("box-");
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    Ok(text)
}

/// Write `contents` to `path` at `mode`, replacing whatever was there.
#[cfg(unix)]
pub(crate) fn open_without_following(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(unix)]
fn open_directory_without_following(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(unix))]
fn open_directory_without_following(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// Without `O_NOFOLLOW` there is no refusal to make, so this is a plain open.
#[cfg(not(unix))]
pub(crate) fn open_without_following(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

fn write_private_opened_file(
    path: &Path,
    contents: &str,
    mode: u32,
) -> Result<std::fs::File, BoxError> {
    let directory = path.parent().ok_or_else(|| LayoutError::NotADirectory {
        path: path.to_path_buf(),
    })?;
    static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let (staging, mut file) = loop {
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let staging = directory.join(format!(
            ".{}.{}.{sequence}.tmp",
            path.file_name()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or("record"),
            std::process::id()
        ));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&staging)
        {
            Ok(file) => break (staging, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(LayoutError::Create {
                    path: staging,
                    source,
                }
                .into());
            }
        }
    };
    file.write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| file.set_permissions(std::fs::Permissions::from_mode(mode)))
        .and_then(|()| file.seek(std::io::SeekFrom::Start(0)).map(|_| ()))
        .map_err(|source| LayoutError::Create {
            path: staging.clone(),
            source,
        })?;
    std::fs::rename(staging, path).map_err(|source| LayoutError::Create {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(file)
}

fn box_error_as_io(error: BoxError) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

fn read_file_to_string(mut file: std::fs::File) -> std::io::Result<String> {
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
}

#[cfg(unix)]
fn ensure_relative_directory(
    anchor: &std::fs::File,
    relative: &Path,
    reported: &Path,
) -> Result<(), BoxError> {
    let mut parent = anchor
        .try_clone()
        .map_err(|source| LayoutError::ReadDirectory {
            path: reported.to_path_buf(),
            source,
        })?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(LayoutError::NotADirectory {
                path: reported.to_path_buf(),
            }
            .into());
        };
        parent = ensure_child_directory(&parent, name, reported)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_relative_directory(
    _anchor: &std::fs::File,
    _relative: &Path,
    reported: &Path,
) -> Result<(), BoxError> {
    Err(LayoutError::UnsafeDirectory {
        path: reported.to_path_buf(),
        reason: "this platform cannot create through an opened directory".to_string(),
    }
    .into())
}

#[cfg(unix)]
fn ensure_child_directory(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    reported: &Path,
) -> Result<std::fs::File, BoxError> {
    let name = c_name(name).map_err(|source| LayoutError::Create {
        path: reported.to_path_buf(),
        source,
    })?;
    // SAFETY: name is one valid component and mkdirat uses the retained parent.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == -1 {
        let source = std::io::Error::last_os_error();
        if source.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(LayoutError::Create {
                path: reported.to_path_buf(),
                source,
            }
            .into());
        }
    }
    let directory = open_child_name(
        parent,
        name.as_c_str(),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
    .map_err(|source| LayoutError::Create {
        path: reported.to_path_buf(),
        source,
    })?;
    let metadata = directory
        .metadata()
        .map_err(|source| LayoutError::ReadDirectory {
            path: reported.to_path_buf(),
            source,
        })?;
    if !private_directory_metadata_is_safe(&metadata) {
        return Err(LayoutError::UnsafeDirectory {
            path: reported.to_path_buf(),
            reason: "it is not a private directory owned by the current user".to_string(),
        }
        .into());
    }
    directory
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(|source| LayoutError::Create {
            path: reported.to_path_buf(),
            source,
        })?;
    Ok(directory)
}

#[cfg(unix)]
fn open_relative(
    anchor: &std::fs::File,
    relative: &Path,
    flags: libc::c_int,
) -> std::io::Result<std::fs::File> {
    if relative.as_os_str().is_empty() {
        return anchor.try_clone();
    }
    let (parent, name) = open_relative_parent(anchor, relative)?;
    let name = c_name(&name)?;
    open_child_name(
        &parent,
        name.as_c_str(),
        flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
}

#[cfg(unix)]
fn open_relative_with_mode(
    anchor: &std::fs::File,
    relative: &Path,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<std::fs::File> {
    let (parent, name) = open_relative_parent(anchor, relative)?;
    let name = c_name(&name)?;
    // SAFETY: name is one valid component and openat returns one owned descriptor.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if descriptor == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned one fresh descriptor.
    Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
}

#[cfg(not(unix))]
fn open_relative_with_mode(
    _anchor: &std::fs::File,
    _relative: &Path,
    _flags: libc::c_int,
    _mode: libc::mode_t,
) -> std::io::Result<std::fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "this platform cannot open through a directory descriptor",
    ))
}

#[cfg(not(unix))]
fn open_relative(
    _anchor: &std::fs::File,
    _relative: &Path,
    _flags: libc::c_int,
) -> std::io::Result<std::fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "this platform cannot open through a directory descriptor",
    ))
}

#[cfg(unix)]
fn open_relative_parent(
    anchor: &std::fs::File,
    relative: &Path,
) -> std::io::Result<(std::fs::File, std::ffi::OsString)> {
    let mut components = relative.components().peekable();
    let mut parent = anchor.try_clone()?;
    while let Some(component) = components.next() {
        let std::path::Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path is not relative to the opened directory",
            ));
        };
        if components.peek().is_none() {
            return Ok((parent, name.to_os_string()));
        }
        let name = c_name(name)?;
        parent = open_child_name(
            &parent,
            name.as_c_str(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "path does not name a child",
    ))
}

#[cfg(unix)]
fn remove_relative_file(anchor: &std::fs::File, relative: &Path) -> std::io::Result<()> {
    let (parent, name) = open_relative_parent(anchor, relative)?;
    let name = c_name(&name)?;
    // SAFETY: name is one valid component and unlinkat uses the retained parent.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn remove_relative_file(_anchor: &std::fs::File, _relative: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "this platform cannot unlink through a directory descriptor",
    ))
}

#[cfg(unix)]
fn install_relative_file(
    anchor: &std::fs::File,
    relative: &Path,
    source: &Path,
    mode: u32,
) -> std::io::Result<()> {
    let (parent, name) = open_relative_parent(anchor, relative)?;
    let destination = c_name(&name)?;
    // SAFETY: destination is one valid component below the retained parent.
    let _ = unsafe { libc::unlinkat(parent.as_raw_fd(), destination.as_ptr(), 0) };
    let source_name = c_name(source.as_os_str())?;
    // SAFETY: both path arguments are valid C strings and destination is below the retained parent.
    if unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source_name.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
            0,
        )
    } == 0
    {
        return Ok(());
    }
    let link_error = std::io::Error::last_os_error();
    if link_error.raw_os_error() != Some(libc::EXDEV) {
        return Err(link_error);
    }
    let mut source = open_without_following(source)?;
    let expected = source.metadata()?.len();
    let mut destination_file = open_child_name_with_mode(
        &parent,
        destination.as_c_str(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        mode as libc::mode_t,
    )?;
    let copied = std::io::copy(&mut source, &mut destination_file)?;
    if copied != expected {
        return Err(std::io::Error::other(format!(
            "copied {copied} of {expected} bytes"
        )));
    }
    destination_file
        .flush()
        .and_then(|()| destination_file.sync_all())?;
    destination_file.set_permissions(std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn install_relative_file(
    _anchor: &std::fs::File,
    _relative: &Path,
    _source: &Path,
    _mode: u32,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "this platform cannot install through a directory descriptor",
    ))
}

fn install_file_at_path(source: &Path, destination: &Path, mode: u32) -> std::io::Result<()> {
    let _ = std::fs::remove_file(destination);
    match std::fs::hard_link(source, destination) {
        Ok(()) => return Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {}
        Err(error) => return Err(error),
    }
    let mut source = open_without_following(source)?;
    let expected = source.metadata()?.len();
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(destination)?;
    let copied = std::io::copy(&mut source, &mut destination_file)?;
    if copied != expected {
        return Err(std::io::Error::other(format!(
            "copied {copied} of {expected} bytes"
        )));
    }
    destination_file
        .flush()
        .and_then(|()| destination_file.sync_all())?;
    destination_file.set_permissions(std::fs::Permissions::from_mode(mode))
}

#[cfg(unix)]
fn write_relative_opened_file(
    anchor: &std::fs::File,
    relative: &Path,
    reported: &Path,
    contents: &[u8],
    mode: u32,
) -> Result<std::fs::File, BoxError> {
    let (parent, name) =
        open_relative_parent(anchor, relative).map_err(|source| LayoutError::Create {
            path: reported.to_path_buf(),
            source,
        })?;
    static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let (staging_name, descriptor) = loop {
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let staging = std::ffi::OsString::from(format!(
            ".{}.{}.{sequence}.tmp",
            name.to_string_lossy(),
            std::process::id()
        ));
        let staging_name = c_name(&staging).map_err(|source| LayoutError::Create {
            path: reported.to_path_buf(),
            source,
        })?;
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                staging_name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        };
        if descriptor != -1 {
            break (staging_name, descriptor);
        }
        let source = std::io::Error::last_os_error();
        if source.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(LayoutError::Create {
                path: reported.to_path_buf(),
                source,
            }
            .into());
        }
    };
    // SAFETY: openat returned one fresh descriptor.
    let mut file = unsafe { std::fs::File::from_raw_fd(descriptor) };
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .and_then(|()| file.set_permissions(std::fs::Permissions::from_mode(mode)))
        .and_then(|()| file.seek(std::io::SeekFrom::Start(0)).map(|_| ()))
        .map_err(|source| LayoutError::Create {
            path: reported.to_path_buf(),
            source,
        })?;
    let name = c_name(&name).map_err(|source| LayoutError::Create {
        path: reported.to_path_buf(),
        source,
    })?;
    // SAFETY: both names are valid components below the retained parent.
    if unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            staging_name.as_ptr(),
            parent.as_raw_fd(),
            name.as_ptr(),
        )
    } == -1
    {
        let source = std::io::Error::last_os_error();
        return Err(LayoutError::Create {
            path: reported.to_path_buf(),
            source,
        }
        .into());
    }
    Ok(file)
}

#[cfg(not(unix))]
fn write_relative_opened_file(
    _anchor: &std::fs::File,
    _relative: &Path,
    reported: &Path,
    _contents: &[u8],
    _mode: u32,
) -> Result<std::fs::File, BoxError> {
    Err(LayoutError::UnsafeDirectory {
        path: reported.to_path_buf(),
        reason: "this platform cannot write through a directory descriptor".to_string(),
    }
    .into())
}

#[cfg(unix)]
fn c_name(name: &std::ffi::OsStr) -> std::io::Result<std::ffi::CString> {
    std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains NUL",
        )
    })
}

#[cfg(unix)]
fn open_child_name(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
    flags: libc::c_int,
) -> std::io::Result<std::fs::File> {
    // SAFETY: name is one valid C string and openat returns one owned descriptor.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned one fresh descriptor.
    Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn open_child_name_with_mode(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<std::fs::File> {
    // SAFETY: name is one valid C string and openat returns one owned descriptor.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags,
            mode as libc::c_uint,
        )
    };
    if descriptor == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned one fresh descriptor.
    Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn bind_unix_listener_at(
    directory: &std::fs::File,
    name: &std::ffi::OsStr,
) -> std::io::Result<std::os::unix::net::UnixListener> {
    let name = name.as_bytes();
    // SAFETY: a zeroed sockaddr_un is valid after its family and path are set below.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if name.len() + 1 > address.sun_path.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the broker socket name is too long",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (destination, source) in address.sun_path.iter_mut().zip(name.iter().copied()) {
        *destination = source as libc::c_char;
    }
    let address_length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + name.len() + 1;
    #[cfg(target_os = "macos")]
    {
        address.sun_len = u8::try_from(address_length).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the broker socket address is too long",
            )
        })?;
    }

    // SAFETY: socket returns one fresh descriptor or -1.
    let descriptor = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if descriptor == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: socket returned one fresh descriptor.
    let socket = unsafe { std::fs::File::from_raw_fd(descriptor) };
    // SAFETY: fcntl reads and updates flags on the socket descriptor.
    let descriptor_flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFD) };
    if descriptor_flags == -1
        || unsafe {
            libc::fcntl(
                socket.as_raw_fd(),
                libc::F_SETFD,
                descriptor_flags | libc::FD_CLOEXEC,
            )
        } == -1
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fork duplicates this process; the child calls only system calls before _exit.
    let child = unsafe { libc::fork() };
    if child == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if child == 0 {
        // SAFETY: these descriptors and pointers were prepared before fork.
        unsafe {
            let mut failure = 0;
            if libc::fchdir(directory.as_raw_fd()) == -1 {
                failure = *errno_slot();
            }
            if failure == 0
                && libc::bind(
                    socket.as_raw_fd(),
                    std::ptr::from_ref(&address).cast::<libc::sockaddr>(),
                    address_length as libc::socklen_t,
                ) == -1
            {
                failure = *errno_slot();
            }
            if failure == 0
                && libc::fchmodat(directory.as_raw_fd(), address.sun_path.as_ptr(), 0o600, 0) == -1
            {
                failure = *errno_slot();
            }
            if failure == 0 && libc::listen(socket.as_raw_fd(), 128) == -1 {
                failure = *errno_slot();
            }
            libc::_exit(failure.clamp(0, u8::MAX.into()));
        }
    }

    let mut status = 0;
    loop {
        // SAFETY: child is the pid returned by fork and status points to live storage.
        if unsafe { libc::waitpid(child, &mut status, 0) } != -1 {
            break;
        }
        let source = std::io::Error::last_os_error();
        if source.kind() != std::io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
    if !libc::WIFEXITED(status) {
        return Err(std::io::Error::other(
            "the broker socket binding child failed",
        ));
    }
    let failure = libc::WEXITSTATUS(status);
    if failure != 0 {
        return Err(std::io::Error::from_raw_os_error(failure));
    }
    let descriptor = socket.into_raw_fd();
    // SAFETY: ownership moves from File to UnixListener.
    Ok(unsafe { std::os::unix::net::UnixListener::from_raw_fd(descriptor) })
}

fn inspect_opened_state(
    root: &std::fs::File,
    reported_root: &Path,
) -> Result<OpenedState, BoxError> {
    let entries = directory_entries(root, reported_root)?;
    if first_use_contents(root, reported_root, false)? {
        return Ok(OpenedState::Fresh);
    }
    if !entries
        .iter()
        .any(|entry| entry == std::ffi::OsStr::new(PRIVATE_DIRECTORY))
    {
        return Err(no_valid_private_record(reported_root));
    }
    let reported_private = reported_root.join(PRIVATE_DIRECTORY);
    let handle = Arc::new(open_child_directory(
        root,
        PRIVATE_DIRECTORY,
        &reported_private,
    )?);
    let metadata = handle
        .metadata()
        .map_err(|source| LayoutError::ReadDirectory {
            path: reported_private.clone(),
            source,
        })?;
    if !private_directory_metadata_is_safe(&metadata)
        || !same_mount(root, &handle, reported_root, &reported_private)?
    {
        return Err(no_valid_private_record(reported_root));
    }

    let mode = private_directory_mode(&metadata);
    if mode != 0o700 && mode != FIRST_USE_PRIVATE_MODE {
        return Err(no_valid_private_record(reported_root));
    }
    if mode == FIRST_USE_PRIVATE_MODE && !first_use_contents(root, reported_root, true)? {
        return Err(no_valid_private_record(reported_root));
    }
    match committed_record(&handle, &reported_private)? {
        CommittedRecord::Committed { box_id } if mode == 0o700 => Ok(OpenedState::Configured {
            box_id,
            private: handle,
        }),
        CommittedRecord::Committed { .. } => Err(no_valid_private_record(reported_root)),
        CommittedRecord::Mismatch { stored, found } => {
            Err(record_identity_mismatch(reported_root, &stored, &found))
        }
        CommittedRecord::Unreadable(error) => Err(error.into()),
        CommittedRecord::Absent => {
            let Some(recoverable) = recoverable_private_state(&handle, &reported_private)? else {
                return Err(no_valid_private_record(reported_root));
            };
            Ok(OpenedState::Interrupted(FirstUsePrivate {
                handle,
                record: recoverable.record,
            }))
        }
    }
}

fn first_use_contents(
    root: &std::fs::File,
    reported_root: &Path,
    private_created: bool,
) -> Result<bool, BoxError> {
    let entries = directory_entries(root, reported_root)?;
    let only_private = entries
        .iter()
        .all(|entry| private_created && entry == PRIVATE_DIRECTORY);
    Ok(only_private && private_created == entries.iter().any(|entry| entry == PRIVATE_DIRECTORY))
}

fn no_valid_private_record(root: &Path) -> BoxError {
    LayoutError::UnsafeDirectory {
        path: root.to_path_buf(),
        reason: "it is not empty and contains no valid private record".to_string(),
    }
    .into()
}

fn record_identity_mismatch(root: &Path, stored: &str, found: &str) -> BoxError {
    LayoutError::UnsafeDirectory {
        path: root.to_path_buf(),
        reason: format!(
            "its record identity is {}, but the committed record has identity {}. Delete the box \
             directory to start again.",
            stored.trim_end(),
            found.trim_end()
        ),
    }
    .into()
}

impl FirstUsePrivate {
    fn verify_before_record(&self, root: &BoxRoot) -> Result<(), BoxError> {
        self.verify_binding(root)?;
        let root_handle =
            root.root_handle
                .as_deref()
                .ok_or_else(|| LayoutError::UnsafeDirectory {
                    path: root.root.clone(),
                    reason: "the caller-owned directory is not open".to_string(),
                })?;
        if !first_use_contents(root_handle, &root.root, true)? {
            return Err(LayoutError::UnsafeDirectory {
                path: root.root.clone(),
                reason: "its first-use contents changed before the record write".to_string(),
            }
            .into());
        }
        let Some(recoverable) = recoverable_private_state(&self.handle, &root.private_directory())?
        else {
            return Err(LayoutError::UnsafeDirectory {
                path: root.private_directory(),
                reason: "its first-use contents changed before the record write".to_string(),
            }
            .into());
        };
        let record = recoverable.record;
        if !same_optional_file_identity(self.record.as_deref(), record.as_deref())? {
            return Err(LayoutError::UnsafeDirectory {
                path: root.private_directory(),
                reason: "its record identity changed before the first write".to_string(),
            }
            .into());
        }
        Ok(())
    }

    fn write_record(&self, root: &BoxRoot, contents: &str) -> Result<Arc<std::fs::File>, BoxError> {
        self.verify_before_record(root)?;
        let record = match &self.record {
            Some(record) => Arc::clone(record),
            None => Arc::new(create_child_file(
                &self.handle,
                RECORD_FILE,
                &root.record(),
                0o600,
            )?),
        };
        let metadata = record
            .metadata()
            .map_err(|source| LayoutError::ReadDirectory {
                path: root.record(),
                source,
            })?;
        if !record_metadata_is_safe(&metadata)
            || !same_mount(
                &self.handle,
                &record,
                &root.private_directory(),
                &root.record(),
            )?
        {
            return Err(LayoutError::UnsafeDirectory {
                path: root.record(),
                reason: "it is not one private record inode".to_string(),
            }
            .into());
        }
        record.set_len(0).map_err(|source| LayoutError::Create {
            path: root.record(),
            source,
        })?;
        let mut writer = record.as_ref();
        writer
            .seek(std::io::SeekFrom::Start(0))
            .and_then(|_| writer.write_all(contents.as_bytes()))
            .and_then(|()| writer.sync_all())
            .map_err(|source| LayoutError::Create {
                path: root.record(),
                source,
            })?;
        self.verify_binding(root)?;
        let current = open_child_file(&self.handle, RECORD_FILE, &root.record())?;
        if !same_file_identity(
            &record
                .metadata()
                .map_err(|source| LayoutError::ReadDirectory {
                    path: root.record(),
                    source,
                })?,
            &current
                .metadata()
                .map_err(|source| LayoutError::ReadDirectory {
                    path: root.record(),
                    source,
                })?,
        ) {
            return Err(LayoutError::UnsafeDirectory {
                path: root.record(),
                reason: "its identity changed during the first write".to_string(),
            }
            .into());
        }
        let box_id = read_record_file(&record, &root.record())?.box_id;
        if box_id != root.box_id() {
            return Err(LayoutError::UnsafeDirectory {
                path: root.record(),
                reason: "its identity does not match the opened box".to_string(),
            }
            .into());
        }
        Ok(record)
    }

    fn verify_binding(&self, root: &BoxRoot) -> Result<(), BoxError> {
        root.verify_identity()?;
        let Some(private) = &root.private_handle else {
            return Err(LayoutError::UnsafeDirectory {
                path: root.private_directory(),
                reason: "the private directory is not open".to_string(),
            }
            .into());
        };
        if !same_file_identity(
            &self
                .handle
                .metadata()
                .map_err(|source| LayoutError::ReadDirectory {
                    path: root.private_directory(),
                    source,
                })?,
            &private
                .metadata()
                .map_err(|source| LayoutError::ReadDirectory {
                    path: root.private_directory(),
                    source,
                })?,
        ) {
            return Err(LayoutError::UnsafeDirectory {
                path: root.private_directory(),
                reason: "the private directory handle changed".to_string(),
            }
            .into());
        }
        Ok(())
    }

    fn finish(&self, root: &BoxRoot, record: &std::fs::File) -> Result<(), BoxError> {
        self.finish_with(root, record, || {})
    }

    fn finish_with(
        &self,
        root: &BoxRoot,
        record: &std::fs::File,
        after_mode_change: impl FnOnce(),
    ) -> Result<(), BoxError> {
        self.verify_binding(root)?;
        self.verify_record_binding(root, record)?;
        self.handle
            .set_permissions(std::fs::Permissions::from_mode(0o700))
            .map_err(|source| LayoutError::Create {
                path: root.private_directory(),
                source,
            })?;
        after_mode_change();
        let commit = self.write_commit(root, record)?;
        self.verify_binding(root)?;
        self.verify_record_binding(root, record)?;
        self.verify_commit_binding(root, record, &commit)
    }

    fn write_commit(
        &self,
        root: &BoxRoot,
        record: &std::fs::File,
    ) -> Result<std::fs::File, BoxError> {
        let path = root.private_directory().join(PRIVATE_COMMIT_FILE);
        let text = record_identity(record, &root.record())??.text;
        let commit = write_relative_opened_file(
            &self.handle,
            Path::new(PRIVATE_COMMIT_FILE),
            &path,
            text.as_bytes(),
            0o600,
        )?;
        let metadata = commit
            .metadata()
            .map_err(|source| LayoutError::ReadDirectory {
                path: path.clone(),
                source,
            })?;
        if !record_metadata_is_safe(&metadata)
            || !same_mount(&self.handle, &commit, &root.private_directory(), &path)?
        {
            return Err(LayoutError::UnsafeDirectory {
                path,
                reason: "it is not one private commit inode".to_string(),
            }
            .into());
        }
        self.handle
            .sync_all()
            .map_err(|source| LayoutError::Create { path, source })?;
        Ok(commit)
    }

    fn verify_commit_binding(
        &self,
        root: &BoxRoot,
        record: &std::fs::File,
        commit: &std::fs::File,
    ) -> Result<(), BoxError> {
        let path = root.private_directory().join(PRIVATE_COMMIT_FILE);
        let current = open_child_file(&self.handle, PRIVATE_COMMIT_FILE, &path)?;
        let expected_metadata = commit
            .metadata()
            .map_err(|source| LayoutError::ReadDirectory {
                path: path.clone(),
                source,
            })?;
        let current_metadata = current
            .metadata()
            .map_err(|source| LayoutError::ReadDirectory {
                path: path.clone(),
                source,
            })?;
        if !record_metadata_is_safe(&expected_metadata)
            || !record_metadata_is_safe(&current_metadata)
            || !same_file_identity(&expected_metadata, &current_metadata)
            || !commit_matches(&self.handle, record, &root.private_directory())?
            || !child_path_matches(&self.handle, PRIVATE_COMMIT_FILE, &path, commit)?
        {
            return Err(LayoutError::UnsafeDirectory {
                path,
                reason: "the record commit identity changed".to_string(),
            }
            .into());
        }
        Ok(())
    }

    fn verify_record_binding(
        &self,
        root: &BoxRoot,
        record: &std::fs::File,
    ) -> Result<(), BoxError> {
        self.verify_named_file_binding(
            RECORD_FILE,
            &root.record(),
            record,
            "its identity changed before the record commit finished",
        )
    }

    fn verify_named_file_binding(
        &self,
        name: &str,
        path: &Path,
        expected: &std::fs::File,
        reason: &str,
    ) -> Result<(), BoxError> {
        let current = open_child_file(&self.handle, name, path)?;
        let expected_metadata =
            expected
                .metadata()
                .map_err(|source| LayoutError::ReadDirectory {
                    path: path.to_path_buf(),
                    source,
                })?;
        let current_metadata = current
            .metadata()
            .map_err(|source| LayoutError::ReadDirectory {
                path: path.to_path_buf(),
                source,
            })?;
        if !record_metadata_is_safe(&expected_metadata)
            || !record_metadata_is_safe(&current_metadata)
            || !same_file_identity(&expected_metadata, &current_metadata)
        {
            return Err(LayoutError::UnsafeDirectory {
                path: path.to_path_buf(),
                reason: reason.to_string(),
            }
            .into());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn verify_private_binding(
    root: &std::fs::File,
    private: &std::fs::File,
    reported_root: &Path,
    reported_private: &Path,
) -> Result<(), BoxError> {
    let current = open_child_directory(root, PRIVATE_DIRECTORY, reported_private)?;
    let expected_metadata = private
        .metadata()
        .map_err(|source| LayoutError::ReadDirectory {
            path: reported_private.to_path_buf(),
            source,
        })?;
    let current_metadata = current
        .metadata()
        .map_err(|source| LayoutError::ReadDirectory {
            path: reported_private.to_path_buf(),
            source,
        })?;
    if !private_directory_metadata_is_safe(&expected_metadata)
        || !matches!(
            private_directory_mode(&expected_metadata),
            0o700 | FIRST_USE_PRIVATE_MODE
        )
        || !same_file_identity(&expected_metadata, &current_metadata)
    {
        return Err(LayoutError::UnsafeDirectory {
            path: reported_private.to_path_buf(),
            reason: "its identity changed after Box validated it".to_string(),
        }
        .into());
    }
    if !same_mount(root, &current, reported_root, reported_private)? {
        return Err(LayoutError::UnsafeDirectory {
            path: reported_private.to_path_buf(),
            reason: "it crosses a mount boundary".to_string(),
        }
        .into());
    }
    Ok(())
}

fn directory_entries(
    directory: &std::fs::File,
    reported: &Path,
) -> Result<Vec<std::ffi::OsString>, BoxError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        with_directory_enumeration_lock(|| {
            let enumeration =
                directory
                    .try_clone()
                    .map_err(|source| LayoutError::ReadDirectory {
                        path: reported.to_path_buf(),
                        source,
                    })?;
            let descriptor = enumeration.into_raw_fd();
            // SAFETY: fdopendir takes ownership of the fresh descriptor.
            let stream = unsafe { libc::fdopendir(descriptor) };
            if stream.is_null() {
                let source = std::io::Error::last_os_error();
                // SAFETY: fdopendir did not take ownership on failure.
                unsafe { libc::close(descriptor) };
                return Err(LayoutError::ReadDirectory {
                    path: reported.to_path_buf(),
                    source,
                }
                .into());
            }
            let mut entries = Vec::new();
            loop {
                // SAFETY: errno_slot returns this thread's errno storage.
                unsafe { *errno_slot() = 0 };
                // SAFETY: stream remains open and is used by this thread only.
                let entry = unsafe { libc::readdir(stream) };
                if entry.is_null() {
                    // SAFETY: errno_slot returns this thread's errno storage.
                    let read_error = unsafe { *errno_slot() };
                    // SAFETY: stream is open and rewinddir returns its shared offset to the start.
                    unsafe { libc::rewinddir(stream) };
                    // SAFETY: closed exactly once after fdopendir took ownership.
                    let close_result = unsafe { libc::closedir(stream) };
                    let close_error = (close_result == -1).then(std::io::Error::last_os_error);
                    if read_error != 0 {
                        return Err(LayoutError::ReadDirectory {
                            path: reported.to_path_buf(),
                            source: std::io::Error::from_raw_os_error(read_error),
                        }
                        .into());
                    }
                    if let Some(source) = close_error {
                        return Err(LayoutError::ReadDirectory {
                            path: reported.to_path_buf(),
                            source,
                        }
                        .into());
                    }
                    return Ok(entries);
                }
                // SAFETY: readdir returned a live dirent with a NUL-terminated d_name.
                let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                if name != b"." && name != b".." {
                    entries.push(std::ffi::OsStr::from_bytes(name).to_os_string());
                }
            }
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = directory;
        Err(LayoutError::UnsafeDirectory {
            path: reported.to_path_buf(),
            reason: "this platform cannot enumerate an opened directory".to_string(),
        }
        .into())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn with_directory_enumeration_lock<T>(operation: impl FnOnce() -> T) -> T {
    let _enumeration_lock = DIRECTORY_ENUMERATION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    operation()
}

#[cfg(target_os = "linux")]
unsafe fn errno_slot() -> *mut libc::c_int {
    // SAFETY: the caller uses this thread's libc errno storage.
    unsafe { libc::__errno_location() }
}

#[cfg(target_os = "macos")]
unsafe fn errno_slot() -> *mut libc::c_int {
    // SAFETY: the caller uses this thread's libc errno storage.
    unsafe { libc::__error() }
}

fn recoverable_private_state(
    private: &std::fs::File,
    reported_private: &Path,
) -> Result<Option<RecoverablePrivateState>, BoxError> {
    let entries: Vec<_> = directory_entries(private, reported_private)?
        .into_iter()
        .filter(|name| !is_commit_staging_file(name))
        .collect();
    if entries.is_empty() {
        return Ok(Some(RecoverablePrivateState { record: None }));
    }
    if entries.iter().any(|name| {
        name != std::ffi::OsStr::new(RECORD_FILE)
            && name != std::ffi::OsStr::new(PRIVATE_COMMIT_FILE)
    }) {
        return Ok(None);
    }
    let has_commit = entries
        .iter()
        .any(|name| name == std::ffi::OsStr::new(PRIVATE_COMMIT_FILE));
    if has_commit {
        let path = reported_private.join(PRIVATE_COMMIT_FILE);
        let commit = open_child_file(private, PRIVATE_COMMIT_FILE, &path)?;
        let metadata = commit
            .metadata()
            .map_err(|source| LayoutError::ReadDirectory {
                path: path.clone(),
                source,
            })?;
        if !record_metadata_is_safe(&metadata)
            || !same_mount(private, &commit, reported_private, &path)?
        {
            return Ok(None);
        }
    }
    if !entries
        .iter()
        .any(|name| name == std::ffi::OsStr::new(RECORD_FILE))
    {
        return Ok(Some(RecoverablePrivateState { record: None }));
    }
    let file = Arc::new(open_child_file(
        private,
        RECORD_FILE,
        &reported_private.join(RECORD_FILE),
    )?);
    let metadata = file
        .metadata()
        .map_err(|source| LayoutError::ReadDirectory {
            path: reported_private.join(RECORD_FILE),
            source,
        })?;
    if !record_metadata_is_safe(&metadata)
        || !same_mount(
            private,
            &file,
            reported_private,
            &reported_private.join(RECORD_FILE),
        )?
    {
        return Ok(None);
    }
    Ok(Some(RecoverablePrivateState { record: Some(file) }))
}

fn is_commit_staging_file(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(sequence) = name
        .strip_prefix(".configured.")
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let mut parts = sequence.split('.');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(process), Some(sequence), None)
            if !process.is_empty()
                && process.bytes().all(|byte| byte.is_ascii_digit())
                && !sequence.is_empty()
                && sequence.bytes().all(|byte| byte.is_ascii_digit())
    )
}

fn committed_record(
    private: &std::fs::File,
    reported_private: &Path,
) -> Result<CommittedRecord, BoxError> {
    let entries = directory_entries(private, reported_private)?;
    if !entries
        .iter()
        .any(|name| name == std::ffi::OsStr::new(PRIVATE_COMMIT_FILE))
    {
        return Ok(CommittedRecord::Absent);
    }
    let commit_path = reported_private.join(PRIVATE_COMMIT_FILE);
    let commit = open_child_file(private, PRIVATE_COMMIT_FILE, &commit_path)?;
    let commit_metadata = commit
        .metadata()
        .map_err(|source| LayoutError::ReadDirectory {
            path: commit_path.clone(),
            source,
        })?;
    if !record_metadata_is_safe(&commit_metadata)
        || !same_mount(private, &commit, reported_private, &commit_path)?
    {
        return Ok(CommittedRecord::Absent);
    }
    let stored = commit_text(&commit, &commit_path)?;
    let mut found = None;
    if entries
        .iter()
        .any(|name| name == std::ffi::OsStr::new(RECORD_FILE))
    {
        let record_path = reported_private.join(RECORD_FILE);
        let record = Arc::new(open_child_file(private, RECORD_FILE, &record_path)?);
        if opened_private_file_is_safe(private, &record, reported_private, &record_path)?
            && child_path_matches(private, RECORD_FILE, &record_path, &record)?
            && child_path_matches(private, PRIVATE_COMMIT_FILE, &commit_path, &commit)?
        {
            match record_identity(&record, &record_path)? {
                Ok(identity) if identity.text == stored => {
                    return Ok(CommittedRecord::Committed {
                        box_id: identity.box_id,
                    });
                }
                identity => found = Some(identity),
            }
        }
    }
    let mismatch = |found: Option<Result<RecordIdentity, ConfigError>>| match found {
        Some(Ok(identity)) => CommittedRecord::Mismatch {
            stored: stored.clone(),
            found: identity.text,
        },
        Some(Err(error)) => CommittedRecord::Unreadable(error),
        None => CommittedRecord::Absent,
    };
    if !entries
        .iter()
        .any(|name| name == std::ffi::OsStr::new(PENDING_RECORD_FILE))
    {
        return Ok(mismatch(found));
    }

    let pending_path = reported_private.join(PENDING_RECORD_FILE);
    let pending = Arc::new(open_child_file(
        private,
        PENDING_RECORD_FILE,
        &pending_path,
    )?);
    if !opened_private_file_is_safe(private, &pending, reported_private, &pending_path)?
        || !child_path_matches(private, PRIVATE_COMMIT_FILE, &commit_path, &commit)?
        || !child_path_matches(private, PENDING_RECORD_FILE, &pending_path, &pending)?
    {
        return Ok(mismatch(found));
    }
    let identity = match record_identity(&pending, &pending_path)? {
        Ok(identity) if identity.text == stored => identity,
        identity => return Ok(mismatch(found.or(Some(identity)))),
    };
    let record_path = reported_private.join(RECORD_FILE);
    rename_child_file(private, PENDING_RECORD_FILE, RECORD_FILE, &record_path)?;
    if !child_path_matches(private, RECORD_FILE, &record_path, &pending)?
        || !child_path_matches(private, PRIVATE_COMMIT_FILE, &commit_path, &commit)?
        || !opened_commit_matches(&commit, &pending, &commit_path)?
    {
        return Ok(CommittedRecord::Absent);
    }
    Ok(CommittedRecord::Committed {
        box_id: identity.box_id,
    })
}

fn commit_matches(
    private: &std::fs::File,
    record: &std::fs::File,
    reported_private: &Path,
) -> Result<bool, BoxError> {
    let path = reported_private.join(PRIVATE_COMMIT_FILE);
    let commit = open_child_file(private, PRIVATE_COMMIT_FILE, &path)?;
    opened_commit_matches(&commit, record, &path)
}

fn opened_commit_matches(
    commit: &std::fs::File,
    record: &std::fs::File,
    path: &Path,
) -> Result<bool, BoxError> {
    let stored = commit_text(commit, path)?;
    Ok(matches!(
        record_identity(record, Path::new(RECORD_FILE))?,
        Ok(identity) if identity.text == stored
    ))
}

fn commit_text(commit: &std::fs::File, path: &Path) -> Result<String, BoxError> {
    let bytes = read_opened_file_bytes(commit, path)?;
    String::from_utf8(bytes).map_err(|_| {
        LayoutError::UnsafeDirectory {
            path: path.to_path_buf(),
            reason: "the record commit is not UTF-8".to_string(),
        }
        .into()
    })
}

fn read_opened_file_bytes(file: &std::fs::File, path: &Path) -> Result<Vec<u8>, BoxError> {
    let mut reader = file
        .try_clone()
        .map_err(|source| LayoutError::ReadDirectory {
            path: path.to_path_buf(),
            source,
        })?;
    let mut bytes = Vec::new();
    reader
        .seek(std::io::SeekFrom::Start(0))
        .and_then(|_| reader.read_to_end(&mut bytes))
        .map_err(|source| LayoutError::ReadDirectory {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(bytes)
}

fn opened_private_file_is_safe(
    private: &std::fs::File,
    file: &std::fs::File,
    reported_private: &Path,
    path: &Path,
) -> Result<bool, BoxError> {
    let metadata = file
        .metadata()
        .map_err(|source| LayoutError::ReadDirectory {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(record_metadata_is_safe(&metadata) && same_mount(private, file, reported_private, path)?)
}

fn child_path_matches(
    private: &std::fs::File,
    name: &str,
    path: &Path,
    expected: &std::fs::File,
) -> Result<bool, BoxError> {
    let current = open_child_file(private, name, path)?;
    let expected_metadata = expected
        .metadata()
        .map_err(|source| LayoutError::ReadDirectory {
            path: path.to_path_buf(),
            source,
        })?;
    let current_metadata = current
        .metadata()
        .map_err(|source| LayoutError::ReadDirectory {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(record_metadata_is_safe(&expected_metadata)
        && record_metadata_is_safe(&current_metadata)
        && same_file_identity(&expected_metadata, &current_metadata))
}

/// The identity of the bytes behind `record`, or why they are not a record.
fn record_identity(
    record: &std::fs::File,
    path: &Path,
) -> Result<Result<RecordIdentity, ConfigError>, BoxError> {
    use sha2::{Digest as _, Sha256};

    let bytes = read_opened_file_bytes(record, path)?;
    let digest = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let parsed = String::from_utf8(bytes)
        .map_err(|error| ConfigError::Read {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
        })
        .and_then(|text| Record::parse(&text, path));
    Ok(parsed.map(|record| RecordIdentity {
        text: format!("{} sha256:{digest}\n", record.box_id),
        box_id: record.box_id,
    }))
}

fn read_record_file(file: &std::fs::File, path: &Path) -> Result<Record, BoxError> {
    let mut reader = file
        .try_clone()
        .map_err(|source| LayoutError::ReadDirectory {
            path: path.to_path_buf(),
            source,
        })?;
    let mut text = String::new();
    reader
        .seek(std::io::SeekFrom::Start(0))
        .and_then(|_| reader.read_to_string(&mut text).map(|_| ()))
        .map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(Record::parse(&text, path)?)
}

#[cfg(unix)]
fn open_child_directory(
    parent: &std::fs::File,
    name: &str,
    reported: &Path,
) -> Result<std::fs::File, BoxError> {
    open_child(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        reported,
    )
}

#[cfg(unix)]
fn rename_child_file(
    parent: &std::fs::File,
    from: &str,
    to: &str,
    reported: &Path,
) -> Result<(), BoxError> {
    let from = std::ffi::CString::new(from).map_err(|_| LayoutError::NotADirectory {
        path: reported.to_path_buf(),
    })?;
    let to = std::ffi::CString::new(to).map_err(|_| LayoutError::NotADirectory {
        path: reported.to_path_buf(),
    })?;
    // SAFETY: both names are valid components below the retained parent.
    if unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
        )
    } == -1
    {
        return Err(LayoutError::Create {
            path: reported.to_path_buf(),
            source: std::io::Error::last_os_error(),
        }
        .into());
    }
    parent.sync_all().map_err(|source| {
        LayoutError::Create {
            path: reported.to_path_buf(),
            source,
        }
        .into()
    })
}

#[cfg(not(unix))]
fn rename_child_file(
    _parent: &std::fs::File,
    _from: &str,
    _to: &str,
    reported: &Path,
) -> Result<(), BoxError> {
    Err(LayoutError::UnsafeDirectory {
        path: reported.to_path_buf(),
        reason: "this platform cannot replace through a directory descriptor".to_string(),
    }
    .into())
}

#[cfg(unix)]
fn create_child_directory(
    parent: &std::fs::File,
    name: &str,
    reported: &Path,
    mode: u32,
) -> Result<std::fs::File, BoxError> {
    let name = std::ffi::CString::new(name).map_err(|_| LayoutError::NotADirectory {
        path: reported.to_path_buf(),
    })?;
    // SAFETY: name is a valid C string and mkdirat uses the retained parent descriptor.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) };
    if result != 0 {
        return Err(LayoutError::Create {
            path: reported.to_path_buf(),
            source: std::io::Error::last_os_error(),
        }
        .into());
    }
    let directory = open_child_directory(
        parent,
        name.to_str().expect("the internal directory name is UTF-8"),
        reported,
    )?;
    directory
        .set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|source| LayoutError::Create {
            path: reported.to_path_buf(),
            source,
        })?;
    Ok(directory)
}

#[cfg(unix)]
fn open_child_file(
    parent: &std::fs::File,
    name: &str,
    reported: &Path,
) -> Result<std::fs::File, BoxError> {
    open_child(
        parent,
        name,
        libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        reported,
    )
}

#[cfg(unix)]
fn create_child_file(
    parent: &std::fs::File,
    name: &str,
    reported: &Path,
    mode: u32,
) -> Result<std::fs::File, BoxError> {
    let name = std::ffi::CString::new(name).map_err(|_| LayoutError::NotADirectory {
        path: reported.to_path_buf(),
    })?;
    // SAFETY: name is a valid C string and the returned descriptor is checked.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if descriptor < 0 {
        return Err(LayoutError::Create {
            path: reported.to_path_buf(),
            source: std::io::Error::last_os_error(),
        }
        .into());
    }
    // SAFETY: openat returned one owned descriptor.
    Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
}

#[cfg(not(unix))]
fn create_child_directory(
    _parent: &std::fs::File,
    _name: &str,
    reported: &Path,
    _mode: u32,
) -> Result<std::fs::File, BoxError> {
    Err(LayoutError::UnsafeDirectory {
        path: reported.to_path_buf(),
        reason: "this platform cannot bind a new child directory identity".to_string(),
    }
    .into())
}

#[cfg(unix)]
fn open_child(
    parent: &std::fs::File,
    name: &str,
    flags: libc::c_int,
    reported: &Path,
) -> Result<std::fs::File, BoxError> {
    let name = std::ffi::CString::new(name).map_err(|_| LayoutError::NotADirectory {
        path: reported.to_path_buf(),
    })?;
    // SAFETY: name is a valid C string and the returned descriptor is checked.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(LayoutError::Create {
            path: reported.to_path_buf(),
            source: std::io::Error::last_os_error(),
        }
        .into());
    }
    // SAFETY: openat returned one owned descriptor.
    Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
}

#[cfg(not(unix))]
fn open_child_directory(
    _parent: &std::fs::File,
    _name: &str,
    reported: &Path,
) -> Result<std::fs::File, BoxError> {
    Err(LayoutError::UnsafeDirectory {
        path: reported.to_path_buf(),
        reason: "this platform cannot bind a child directory identity".to_string(),
    }
    .into())
}

#[cfg(not(unix))]
fn open_child_file(
    _parent: &std::fs::File,
    _name: &str,
    reported: &Path,
) -> Result<std::fs::File, BoxError> {
    Err(LayoutError::UnsafeDirectory {
        path: reported.to_path_buf(),
        reason: "this platform cannot bind a child file identity".to_string(),
    }
    .into())
}

#[cfg(not(unix))]
fn create_child_file(
    _parent: &std::fs::File,
    _name: &str,
    reported: &Path,
    _mode: u32,
) -> Result<std::fs::File, BoxError> {
    Err(LayoutError::UnsafeDirectory {
        path: reported.to_path_buf(),
        reason: "this platform cannot bind a new child file identity".to_string(),
    }
    .into())
}

#[cfg(unix)]
fn private_directory_metadata_is_safe(metadata: &std::fs::Metadata) -> bool {
    metadata.is_dir() && metadata.uid() == unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn private_directory_metadata_is_safe(metadata: &std::fs::Metadata) -> bool {
    metadata.is_dir()
}

#[cfg(unix)]
fn private_directory_mode(metadata: &std::fs::Metadata) -> u32 {
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn private_directory_mode(_metadata: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn record_metadata_is_safe(metadata: &std::fs::Metadata) -> bool {
    metadata.is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.permissions().mode() & 0o777 == 0o600
        && metadata.nlink() == 1
}

#[cfg(not(unix))]
fn record_metadata_is_safe(metadata: &std::fs::Metadata) -> bool {
    metadata.is_file()
}

fn same_optional_file_identity(
    left: Option<&std::fs::File>,
    right: Option<&std::fs::File>,
) -> Result<bool, BoxError> {
    match (left, right) {
        (None, None) => Ok(true),
        (Some(left), Some(right)) => Ok(same_file_identity(
            &left
                .metadata()
                .map_err(|source| LayoutError::ReadDirectory {
                    path: PathBuf::from(RECORD_FILE),
                    source,
                })?,
            &right
                .metadata()
                .map_err(|source| LayoutError::ReadDirectory {
                    path: PathBuf::from(RECORD_FILE),
                    source,
                })?,
        )),
        _ => Ok(false),
    }
}

#[cfg(target_os = "linux")]
fn same_mount(
    left: &std::fs::File,
    right: &std::fs::File,
    left_path: &Path,
    right_path: &Path,
) -> Result<bool, BoxError> {
    Ok(mount_id(left, left_path)? == mount_id(right, right_path)?)
}

#[cfg(target_os = "linux")]
fn mount_id(file: &std::fs::File, reported: &Path) -> Result<u64, BoxError> {
    mount::identity(file)
        .map_err(|source| LayoutError::ReadDirectory {
            path: reported.to_path_buf(),
            source,
        })
        .map_err(Into::into)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn same_mount(
    left: &std::fs::File,
    right: &std::fs::File,
    left_path: &Path,
    right_path: &Path,
) -> Result<bool, BoxError> {
    let left = left
        .metadata()
        .map_err(|source| LayoutError::ReadDirectory {
            path: left_path.to_path_buf(),
            source,
        })?;
    let right = right
        .metadata()
        .map_err(|source| LayoutError::ReadDirectory {
            path: right_path.to_path_buf(),
            source,
        })?;
    Ok(left.dev() == right.dev())
}

#[cfg(not(unix))]
fn same_mount(
    _left: &std::fs::File,
    _right: &std::fs::File,
    _left_path: &Path,
    _right_path: &Path,
) -> Result<bool, BoxError> {
    Ok(false)
}

#[cfg(unix)]
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(_left: &std::fs::Metadata, _right: &std::fs::Metadata) -> bool {
    false
}

/// The operator's state directory, which sites the daemon and grants nothing.
fn state_home() -> Result<PathBuf, BoxError> {
    if let Some(declared) = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from)
        && declared.is_absolute()
    {
        return Ok(declared);
    }
    let mut state = operator_home_directory()?;
    for component in STATE_HOME_FALLBACK {
        state.push(component);
    }
    Ok(state)
}

/// Create a caller-selected box directory that does not exist yet, at mode 0700, when its parent
/// does. An existing directory is left for `open_directory` to judge.
pub(crate) fn create_box_directory_if_absent(path: &Path) -> Result<(), BoxError> {
    if std::fs::symlink_metadata(path).is_ok() {
        return Ok(());
    }
    let parent_exists = path.parent().is_some_and(|parent| parent.is_dir());
    if !parent_exists {
        return Err(LayoutError::Create {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "the box directory's parent does not exist; create it, because Box creates no \
                 directory above the one `box_dir` names",
            ),
        }
        .into());
    }
    create_private_directory(path)
}

/// Trusted machine-level Box state, in every spelling it has.
pub(crate) fn reserved_host_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut push = |path: PathBuf| {
        if !roots.contains(&path) {
            roots.push(path);
        }
    };

    if let Ok(state) = state_home() {
        push(state.join(MACHINE_DIRECTORY));
        if let Ok(canonical) = state.canonicalize() {
            push(canonical.join(MACHINE_DIRECTORY));
        }
    }
    roots
}

/// Refuse a declared `env.HOME` that lies in trusted Box state, or that encloses it.
pub(crate) fn refuse_home_in_box_state(
    home: &Path,
    box_directory: &Path,
    table: &str,
) -> Result<(), BoxError> {
    let mut roots = reserved_host_roots();
    let box_spellings = [box_directory.to_path_buf(), canonical(box_directory)];
    for spelling in &box_spellings {
        if !roots.contains(spelling) {
            roots.push(spelling.clone());
        }
    }
    // Both spellings, because a link laundering an authored path resolves only through its deepest
    // existing ancestor: a home whose leaf is absent still hides one.
    for spelling in [
        home.to_path_buf(),
        resolved_to_its_deepest_existing_ancestor(home),
    ] {
        if roots.iter().any(|root| spelling.starts_with(root)) {
            return Err(home_in_box_state(home, table));
        }
        // The other direction: a home ABOVE the box directory. `Reach` makes a declared home one of
        // its roots and forbids this box's own directory alone, so a home enclosing `box_dir` puts
        // every sibling box's stored policy inside the reachable set.
        if box_spellings
            .iter()
            .any(|box_spelling| box_spelling.starts_with(&spelling))
        {
            return Err(ConfigError::Process {
                table: table.to_string(),
                reason: format!(
                    "`env.HOME` is {}, which encloses the box directory {}. A declared home is \
                     reachable, so a home above the box directory would put this box's own state, \
                     and any sibling box's, inside the reachable set. Name a home beside the box \
                     directory rather than above it, or omit `env.HOME` for the operator's own home",
                    home.display(),
                    box_directory.display()
                ),
            }
            .into());
        }
    }
    Ok(())
}

/// The refusal a home inside trusted Box state carries.
fn home_in_box_state(home: &Path, table: &str) -> BoxError {
    ConfigError::Process {
        table: table.to_string(),
        reason: format!(
            "`env.HOME` is {}, which lies in trusted Box state. The box directory holds \
             `bin`, `run`, `trust`, and `private`, and none of them is a home. Name a \
             directory outside it, or omit `env.HOME` for the operator's own home",
            home.display()
        ),
    }
    .into()
}

/// The operator's home directory, which sites the box root and grants nothing.
pub(crate) fn operator_home_directory() -> Result<PathBuf, BoxError> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| !home.as_os_str().is_empty())
        .ok_or(LayoutError::NoOperatorHome.into())
}

/// Canonicalize the deepest ancestor that exists and re-attach the rest.
pub(crate) fn resolved_to_its_deepest_existing_ancestor(path: &Path) -> PathBuf {
    let mut absent: Vec<std::ffi::OsString> = Vec::new();
    let mut existing = path.to_path_buf();
    loop {
        if let Ok(resolved) = existing.canonicalize() {
            let mut resolved = resolved;
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
            _ => return path.to_path_buf(),
        }
    }
}

/// The canonical spelling of `path`, or the authored one when it does not resolve.
pub(crate) fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// Create `path` at mode 0700, refusing anything already there that is not a
/// directory — including a symlink, which is refused rather than followed.
fn create_private_directory(path: &Path) -> Result<(), BoxError> {
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata =
                std::fs::symlink_metadata(path).map_err(|source| LayoutError::Create {
                    path: path.to_path_buf(),
                    source,
                })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(LayoutError::NotADirectory {
                    path: path.to_path_buf(),
                }
                .into());
            }
        }
        Err(source) => {
            return Err(LayoutError::Create {
                path: path.to_path_buf(),
                source,
            }
            .into());
        }
    }
    set_private_mode(path)
}

#[cfg(unix)]
fn set_private_mode(path: &Path) -> Result<(), BoxError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|source| {
        LayoutError::Create {
            path: path.to_path_buf(),
            source,
        }
        .into()
    })
}

#[cfg(not(unix))]
fn set_private_mode(_path: &Path) -> Result<(), BoxError> {
    Ok(())
}

/// Siting a box for tests in other modules.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// Create a box beside `operator_home`, as a caller-supplied `box_dir` would be.
    pub(crate) fn box_root(operator_home: &Path, name: &str) -> BoxRoot {
        crate::test_support::with_operator_home(operator_home, || {
            let parent = operator_home.join("boxes");
            std::fs::create_dir_all(&parent).expect("create the box directory's parent");
            let parent = parent.canonicalize().expect("canonicalize the parent");
            BoxRoot::create_at(parent.join(name), name).expect("create the box root")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_record(layout: &BoxRoot) -> String {
        valid_record_at(
            layout.root(),
            layout
                .operator_home()
                .expect("the test layout has an operator home"),
            "box-0123456789abcdef",
        )
    }

    fn valid_record_at(root: &Path, _workspace: &Path, box_id: &str) -> String {
        format!(
            "version = {}\n\
             box_id = {:?}\n\
             box_dir = {:?}\n\
             name = \"codex\"\n",
            crate::record::config::RECORD_VERSION,
            box_id,
            root.display().to_string()
        )
    }

    /// Create a box root beside a fixture operator home, as a caller-supplied `box_dir` is.
    ///
    /// The parent is canonicalized before the root is joined onto it, so every derived path
    /// inherits the canonical spelling without the root having to exist yet. On macOS a temporary
    /// directory is reached through a symlink into `/private`, and a grant that disagrees with
    /// what the kernel checks has broken this suite before.
    fn layout(name: &str) -> (BoxRoot, tempfile::TempDir) {
        let operator_home = tempfile::tempdir().unwrap();
        let layout =
            with_operator_home(operator_home.path(), || boxes_parent(operator_home.path()))
                .join(name);
        let layout =
            with_operator_home(operator_home.path(), || BoxRoot::create_at(layout, name)).unwrap();
        (layout, operator_home)
    }

    /// A canonical parent for one caller-selected box directory, created beside `operator_home`.
    fn boxes_parent(operator_home: &Path) -> PathBuf {
        let parent = operator_home.join("boxes");
        std::fs::create_dir_all(&parent).expect("the box directory's parent");
        parent.canonicalize().expect("canonicalize the parent")
    }

    /// Run `body` with `HOME` pointed at `home`.
    fn with_operator_home<T>(home: &Path, body: impl FnOnce() -> T) -> T {
        crate::test_support::with_operator_home(home, body)
    }

    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        path.metadata().unwrap().permissions().mode() & 0o777
    }

    fn children(path: &Path) -> Vec<String> {
        let mut entries: Vec<_> = std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        entries
    }

    fn record_for(layout: &BoxRoot) -> Record {
        let mut record =
            Record::parse(&valid_record(layout), &layout.record()).expect("valid record");
        record.box_id = layout.box_id().to_string();
        record
    }

    #[cfg(unix)]
    fn write_partial_record(private: &Path, contents: &str) {
        use std::os::unix::fs::PermissionsExt as _;

        let path = private.join(RECORD_FILE);
        std::fs::write(&path, contents).expect("interrupted record");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("record mode");
    }

    #[cfg(unix)]
    #[test]
    fn an_interrupted_first_record_write_leaves_the_directory_recoverable() {
        use std::os::unix::fs::PermissionsExt as _;

        for partial in [false, true] {
            let operator_home = tempfile::tempdir().expect("operator home");
            let parent = tempfile::tempdir().expect("box parent");
            let root = parent.path().join("box");
            std::fs::create_dir(&root).expect("caller-owned box directory");
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .expect("private root mode");
            let private = root.join(PRIVATE_DIRECTORY);
            std::fs::create_dir(&private).expect("interrupted private directory");
            std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o1700))
                .expect("private state mode");
            if partial {
                write_partial_record(&private, "version =");
            }

            let mut opened = with_operator_home(operator_home.path(), || {
                BoxRoot::open_directory(&root).expect("interrupted first use recovers")
            });
            assert_eq!(
                children(&root),
                ["private"],
                "opening an interrupted first use must not mutate it"
            );
            assert_eq!(
                children(&private),
                if partial {
                    vec![RECORD_FILE.to_string()]
                } else {
                    Vec::new()
                },
                "opening must retain the exact interrupted record state"
            );
            opened
                .settle_identity()
                .expect("the recovered directory receives an identity");
            let record = record_for(&opened);
            opened
                .initialize_first_use(&record)
                .expect("the retry commits a record and initializes the layout");
            assert_eq!(
                private.metadata().unwrap().permissions().mode() & 0o7777,
                0o700
            );
            assert_eq!(
                Record::parse(
                    &std::fs::read_to_string(private.join(RECORD_FILE)).expect("completed record"),
                    &private.join(RECORD_FILE)
                )
                .expect("record parses")
                .box_id,
                opened.box_id()
            );

            let reopened = with_operator_home(operator_home.path(), || {
                BoxRoot::open_directory(&root).expect("the completed retry reopens")
            });
            assert_eq!(reopened.box_id(), opened.box_id());
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_interrupted_record_does_not_commit_its_identity() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let private = root.join(PRIVATE_DIRECTORY);
        std::fs::create_dir(&private).expect("interrupted private directory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o1700))
            .expect("interrupted private mode");
        let expected = "box-1111111111111111";
        write_partial_record(
            &private,
            &valid_record_at(&root, operator_home.path(), expected),
        );

        let mut opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("completed first record opens")
        });
        assert!(!opened.is_configured());
        opened
            .settle_identity()
            .expect("the retry receives an uncommitted identity");
        assert_ne!(opened.box_id(), expected);
        let retried = opened.box_id().to_string();
        let record = record_for(&opened);
        opened
            .initialize_first_use(&record)
            .expect("first-use completion succeeds");

        assert!(opened.is_configured());
        assert_eq!(children(&root), ["bin", "private", "run", "trust"]);
        let reopened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("completed box reopens")
        });
        assert_eq!(reopened.box_id(), retried);
    }

    #[cfg(unix)]
    #[test]
    fn a_crash_after_mode_change_does_not_commit_the_record() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        let private = root.join(PRIVATE_DIRECTORY);
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        std::fs::create_dir(&private).expect("private directory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
            .expect("configured-looking mode");
        let uncommitted = "box-2222222222222222";
        write_partial_record(
            &private,
            &valid_record_at(&root, operator_home.path(), uncommitted),
        );

        let mut opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("the uncommitted state reopens")
        });
        assert!(!opened.is_configured());
        opened
            .settle_identity()
            .expect("the retry receives a new identity");
        assert_ne!(opened.box_id(), uncommitted);
    }

    #[cfg(unix)]
    #[test]
    fn a_crash_during_commit_staging_leaves_first_use_recoverable() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        let private = root.join(PRIVATE_DIRECTORY);
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        std::fs::create_dir(&private).expect("private directory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
            .expect("configured-looking mode");
        write_partial_record(
            &private,
            &valid_record_at(&root, operator_home.path(), "box-2222222222222222"),
        );
        std::fs::write(private.join(".configured.123.0.tmp"), "partial")
            .expect("partial commit staging");

        let mut opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("the staged commit reopens")
        });
        assert!(!opened.is_configured());
        opened
            .settle_identity()
            .expect("the retry receives a new identity");
        let record = record_for(&opened);
        opened
            .initialize_first_use(&record)
            .expect("the retry commits the record");

        let reopened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("the completed retry reopens")
        });
        assert_eq!(reopened.box_id(), opened.box_id());
    }

    #[cfg(unix)]
    #[test]
    fn a_record_replaced_during_commit_is_refused_when_reopened() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");

        let mut opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("empty first use opens")
        });
        opened.settle_identity().expect("box identity");
        let record = record_for(&opened);
        let private = opened
            .create_first_use_private()
            .expect("first-use private directory");
        opened.private_handle = Some(Arc::clone(&private.handle));
        let written = private
            .write_record(&opened, &record.to_toml().expect("record text"))
            .expect("record write");
        let record_path = opened.record();
        let replacement = valid_record_at(&root, operator_home.path(), "box-ffffffffffffffff");
        private
            .finish_with(&opened, &written, || {
                std::fs::remove_file(&record_path).expect("unlink opened record");
                write_partial_record(&opened.private_directory(), &replacement);
            })
            .expect_err("the replacement record must not be sealed");

        assert_eq!(
            opened
                .private_directory()
                .metadata()
                .expect("private metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        let mut retained = written.as_ref();
        retained
            .seek(std::io::SeekFrom::Start(0))
            .expect("retained record seeks");
        let mut retained_text = String::new();
        retained
            .read_to_string(&mut retained_text)
            .expect("retained record reads");
        assert_eq!(retained_text, record.to_toml().expect("record text"));
        assert_eq!(
            std::fs::read_to_string(&record_path).expect("replacement remains"),
            replacement
        );
        let box_id = opened.box_id().to_string();
        drop(opened);
        let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
            .expect_err("a record swapped under the marker must be refused");
        let message = error.to_string();
        assert!(
            message.contains(&format!(
                "its record identity is {box_id} sha256:{}, but the committed record has \
                 identity box-ffffffffffffffff sha256:{}.",
                sha256_hex(retained_text.as_bytes()),
                sha256_hex(replacement.as_bytes())
            )),
            "the refusal must name the sealed identity and the replacement: {message}"
        );
        assert_eq!(
            std::fs::read_to_string(&record_path).expect("the replacement remains"),
            replacement,
            "the refusal must not re-initialize the replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_crash_after_refresh_commit_completes_the_record_install_on_open() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");

        let mut opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("empty box opens")
        });
        opened.settle_identity().expect("box identity");
        let initial = record_for(&opened);
        opened
            .initialize_first_use(&initial)
            .expect("first use completes");
        let mut updated = initial;
        updated.agent = Some(crate::record::config::process::ProcessSpec {
            command: vec!["/bin/sh".to_string()],
            workspace: None,
            env: std::collections::BTreeMap::from([("REFRESHED".to_string(), "yes".to_string())]),
            filesystem: Default::default(),
            network: None,
        });
        let updated_text = updated.to_toml().expect("updated record");

        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            opened
                .write_committed_record_with(&updated_text, || panic!("simulated crash"))
                .expect("the simulated crash interrupts the write");
        }));
        assert!(interrupted.is_err());
        assert!(
            opened
                .private_directory()
                .join(PENDING_RECORD_FILE)
                .is_file()
        );
        drop(opened);

        let reopened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("the committed refresh recovers")
        });
        assert!(reopened.is_configured());
        assert_eq!(
            reopened
                .read_record()
                .expect("the recovered record reads")
                .agent
                .expect("the refreshed agent")
                .env
                .get("REFRESHED")
                .map(String::as_str),
            Some("yes")
        );
        assert!(
            !reopened
                .private_directory()
                .join(PENDING_RECORD_FILE)
                .exists()
        );
    }

    #[cfg(unix)]
    #[test]
    fn unrecognized_private_content_is_not_removed_as_interrupted_state() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let private = root.join(PRIVATE_DIRECTORY);
        std::fs::create_dir(&private).expect("private directory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o1700))
            .expect("interrupted private mode");
        std::fs::write(private.join("operator-data"), "keep").expect("unrecognized content");

        let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
            .expect_err("unrecognized content must be refused");
        assert!(
            error
                .to_string()
                .contains("contains no valid private record"),
            "{error}"
        );
        assert_eq!(
            std::fs::read_to_string(private.join("operator-data")).expect("content remains"),
            "keep"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_hard_linked_authority_source_is_not_rewritten_as_a_partial_record() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        let authority = parent.path().join("box.toml");
        std::fs::write(&authority, "authority").expect("authority source");
        std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o600))
            .expect("authority mode");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let private = root.join(PRIVATE_DIRECTORY);
        std::fs::create_dir(&private).expect("private directory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o1700))
            .expect("interrupted private mode");
        std::fs::hard_link(&authority, private.join(RECORD_FILE)).expect("hard-linked authority");

        with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
            .expect_err("the hard-linked authority must be refused");
        assert_eq!(
            std::fs::read_to_string(authority).expect("authority remains"),
            "authority"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_established_record_symlink_is_refused_without_following_it() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        let authority = parent.path().join("record.toml");
        std::fs::write(
            &authority,
            valid_record_at(&root, operator_home.path(), "box-2222222222222222"),
        )
        .expect("record source");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let private = root.join(PRIVATE_DIRECTORY);
        std::fs::create_dir(&private).expect("private directory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
            .expect("configured private mode");
        std::os::unix::fs::symlink(&authority, private.join(RECORD_FILE)).expect("record symlink");

        with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
            .expect_err("the record symlink must be refused");
        assert!(authority.exists());
    }

    #[cfg(unix)]
    #[test]
    fn an_established_record_hard_link_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        let authority = parent.path().join("record.toml");
        std::fs::write(
            &authority,
            valid_record_at(&root, operator_home.path(), "box-3333333333333333"),
        )
        .expect("record source");
        std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o600))
            .expect("record mode");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let private = root.join(PRIVATE_DIRECTORY);
        std::fs::create_dir(&private).expect("private directory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
            .expect("configured private mode");
        std::fs::hard_link(&authority, private.join(RECORD_FILE)).expect("record hard link");

        with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
            .expect_err("the record hard link must be refused");
        assert!(authority.exists());
    }

    #[cfg(unix)]
    #[test]
    fn an_established_commit_marker_hard_link_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");

        let mut initial = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("empty box opens")
        });
        initial.settle_identity().expect("box identity");
        let record = record_for(&initial);
        initial
            .initialize_first_use(&record)
            .expect("first use completes");
        let marker = initial.private_directory().join(PRIVATE_COMMIT_FILE);
        std::fs::hard_link(&marker, parent.path().join("marker-alias"))
            .expect("commit marker hard link");
        drop(initial);

        with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
            .expect_err("the commit marker hard link must be refused");
    }

    #[cfg(unix)]
    #[test]
    fn a_commit_marker_hard_link_added_during_refresh_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");

        let mut opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("empty box opens")
        });
        opened.settle_identity().expect("box identity");
        let record = record_for(&opened);
        opened
            .initialize_first_use(&record)
            .expect("first use completes");
        let marker = opened.private_directory().join(PRIVATE_COMMIT_FILE);
        let alias = parent.path().join("marker-alias");

        let error = opened
            .write_committed_record_with(&record.to_toml().expect("record text"), || {
                std::fs::hard_link(&marker, &alias).expect("commit marker hard link");
            })
            .expect_err("the added marker name must be refused");
        assert!(
            error.to_string().contains("commit identity changed"),
            "{error}"
        );
        assert!(alias.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_configured_record_swap_after_inspection_is_refused_without_following_it() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");

        let mut initial = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("empty box opens")
        });
        initial.settle_identity().expect("box identity");
        let expected = initial.box_id().to_string();
        let record = record_for(&initial);
        initial
            .initialize_first_use(&record)
            .expect("first use completes");
        drop(initial);

        let mut opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("configured box opens")
        });
        let private = root.join(PRIVATE_DIRECTORY);
        let replacement = parent.path().join("replacement.toml");
        std::fs::write(
            &replacement,
            valid_record_at(&root, operator_home.path(), "box-4444444444444444"),
        )
        .expect("replacement record");
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600))
            .expect("replacement mode");
        std::fs::rename(private.join(RECORD_FILE), private.join("original.toml"))
            .expect("move opened record");
        std::os::unix::fs::symlink(&replacement, private.join(RECORD_FILE))
            .expect("replacement symlink");

        opened
            .settle_identity()
            .expect("the inspected identity remains settled");
        assert_eq!(opened.box_id(), expected);
        opened
            .read_record()
            .expect_err("the replacement symlink must be refused");
    }

    #[cfg(unix)]
    #[test]
    fn a_record_inserted_after_interrupted_state_was_opened_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let private = root.join(PRIVATE_DIRECTORY);
        std::fs::create_dir(&private).expect("private directory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o1700))
            .expect("interrupted private mode");

        let mut opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("interrupted first use opens")
        });
        opened.settle_identity().expect("box identity");
        let record = record_for(&opened);
        write_partial_record(&private, "inserted");

        opened
            .initialize_first_use(&record)
            .expect_err("the inserted record must be refused");
        assert_eq!(
            std::fs::read_to_string(private.join(RECORD_FILE)).expect("inserted record remains"),
            "inserted"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_partial_record_swap_before_rewrite_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let private = root.join(PRIVATE_DIRECTORY);
        let moved = private.join("moved-record");
        std::fs::create_dir(&private).expect("private directory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o1700))
            .expect("interrupted private mode");
        write_partial_record(&private, "original");

        let mut opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("interrupted first use opens")
        });
        opened.settle_identity().expect("box identity");
        let record = record_for(&opened);
        std::fs::rename(private.join(RECORD_FILE), &moved).expect("move opened record");
        write_partial_record(&private, "replacement");

        opened
            .initialize_first_use(&record)
            .expect_err("the replacement record must be refused");
        assert_eq!(std::fs::read_to_string(moved).unwrap(), "original");
        assert_eq!(
            std::fs::read_to_string(private.join(RECORD_FILE)).unwrap(),
            "replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_root_swap_before_first_record_commit_receives_no_box_state() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        let moved = parent.path().join("moved");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let private = root.join(PRIVATE_DIRECTORY);
        std::fs::create_dir(&private).expect("interrupted private directory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o1700))
            .expect("private state mode");

        let mut opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("interrupted first use opens")
        });
        opened.settle_identity().expect("box identity");
        let record = record_for(&opened);
        std::fs::rename(&root, &moved).expect("move opened root");
        std::fs::create_dir(&root).expect("replacement root");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("replacement mode");

        opened
            .initialize_first_use(&record)
            .expect_err("the replacement root must be refused");
        assert_eq!(children(&root), Vec::<String>::new());
        assert!(!moved.join(PRIVATE_DIRECTORY).join(RECORD_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_private_swap_before_first_record_commit_receives_no_box_state() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let private = root.join(PRIVATE_DIRECTORY);
        let moved = root.join("moved-private");
        std::fs::create_dir(&private).expect("interrupted private directory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o1700))
            .expect("private state mode");

        let mut opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("interrupted first use opens")
        });
        opened.settle_identity().expect("box identity");
        let record = record_for(&opened);
        std::fs::rename(&private, &moved).expect("move opened private directory");
        std::fs::create_dir(&private).expect("replacement private directory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
            .expect("replacement private mode");

        opened
            .initialize_first_use(&record)
            .expect_err("the replacement private directory must be refused");
        assert_eq!(children(&private), Vec::<String>::new());
        assert!(!moved.join(RECORD_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_configured_private_swap_before_state_write_receives_no_box_state() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");

        let mut initial = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("empty box opens")
        });
        initial.settle_identity().expect("box identity");
        let record = record_for(&initial);
        initial
            .initialize_first_use(&record)
            .expect("first use completes");
        drop(initial);

        let opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("configured box opens")
        });
        let private = root.join(PRIVATE_DIRECTORY);
        let moved = root.join("moved-private");
        std::fs::rename(&private, &moved).expect("move opened private directory");
        std::fs::create_dir(&private).expect("replacement private directory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
            .expect("replacement private mode");

        opened
            .write_private_file(&opened.policy(), "permit;", 0o400)
            .expect_err("the replacement private directory must be refused");
        assert_eq!(children(&private), Vec::<String>::new());
        assert!(!moved.join(POLICY_FILE).exists());
        assert!(moved.join(RECORD_FILE).is_file());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn an_open_trampoline_cache_stays_on_the_validated_private_identity() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");

        let mut initial = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("empty box opens")
        });
        initial.settle_identity().expect("box identity");
        let record = record_for(&initial);
        initial
            .initialize_first_use(&record)
            .expect("first use completes");
        drop(initial);

        let opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("configured box opens")
        });
        let cache = opened
            .open_trampoline_cache()
            .expect("the trampoline cache opens");
        let private = root.join(PRIVATE_DIRECTORY);
        let moved = root.join("moved-private");
        std::fs::rename(&private, &moved).expect("move opened private directory");
        std::fs::create_dir(&private).expect("replacement private directory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
            .expect("replacement private mode");

        let mut image =
            create_child_file(&cache, "abc.bin", &opened.trampoline_image("abc"), 0o700)
                .expect("the cache write uses the retained identity");
        image
            .write_all(b"validated image")
            .expect("the image bytes are written");

        assert_eq!(children(&private), Vec::<String>::new());
        assert_eq!(
            std::fs::read_to_string(moved.join(TRAMPOLINE_DIRECTORY).join("abc.bin"))
                .expect("the opened private identity received the image"),
            "validated image"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn different_mount_ids_are_not_one_private_state_mount() {
        let root = tempfile::tempdir().expect("root");
        let root = std::fs::File::open(root.path()).expect("root descriptor");
        let proc = std::fs::File::open("/proc").expect("proc descriptor");

        assert!(
            !same_mount(&root, &proc, Path::new("root"), Path::new("/proc"))
                .expect("mount identities read")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mount_identity_reads_the_descriptor_without_reopening_procfs() {
        let directory = tempfile::tempdir().expect("directory");
        let opened = std::fs::File::open(directory.path()).expect("directory descriptor");
        let expected = mount_id(&opened, directory.path()).expect("mount identity");
        mount_identity_under_syscall_refusals(
            &[
                (libc::SYS_statx, libc::ENOSYS),
                (libc::SYS_openat, libc::EACCES),
                (libc::SYS_openat2, libc::EACCES),
                (libc::SYS_name_to_handle_at, libc::EOPNOTSUPP),
            ],
            true,
            || {
                std::fs::File::open("/proc/self/fdinfo").is_err()
                    && mount_id(&opened, directory.path()).is_ok_and(|actual| actual == expected)
            },
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mount_identity_reads_the_descriptor_when_statx_omits_the_mount_id() {
        let directory = tempfile::tempdir().expect("directory");
        let opened = std::fs::File::open(directory.path()).expect("directory descriptor");
        let expected = mount_id(&opened, directory.path()).expect("mount identity");
        mount_identity_under_syscall_refusals(
            &[
                (libc::SYS_statx, 0),
                (libc::SYS_openat, libc::EACCES),
                (libc::SYS_openat2, libc::EACCES),
                (libc::SYS_name_to_handle_at, libc::EOPNOTSUPP),
            ],
            true,
            || {
                std::fs::File::open("/proc/self/fdinfo").is_err()
                    && mount_id(&opened, directory.path()).is_ok_and(|actual| actual == expected)
            },
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mount_identity_uses_fdinfo_when_file_handles_are_unsupported() {
        let opened = std::fs::File::open("/proc").expect("proc descriptor");
        let expected = mount_id(&opened, Path::new("/proc")).expect("mount identity");
        mount_identity_under_syscall_refusals(
            &[
                (libc::SYS_statx, libc::ENOSYS),
                (libc::SYS_name_to_handle_at, libc::EOPNOTSUPP),
                (libc::SYS_openat, libc::EACCES),
            ],
            true,
            || mount_id(&opened, Path::new("/proc")).is_ok_and(|actual| actual == expected),
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mount_identity_refuses_when_every_route_is_unavailable() {
        let directory = tempfile::tempdir().expect("directory");
        let opened = std::fs::File::open(directory.path()).expect("directory descriptor");
        for error in [libc::EOPNOTSUPP, libc::EOVERFLOW] {
            mount_identity_under_syscall_refusals(
                &[
                    (libc::SYS_statx, libc::ENOSYS),
                    (libc::SYS_name_to_handle_at, error),
                    (libc::SYS_openat, libc::EACCES),
                ],
                false,
                || {
                    crate::run::hardening::Hardening::apply().is_err()
                        && mount_id(&opened, directory.path()).is_err()
                },
            );
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn mount_identity_under_syscall_refusals(
        refusals: &[(libc::c_long, libc::c_int)],
        harden: bool,
        check: impl FnOnce() -> bool,
    ) {
        fn install(refusals: impl Iterator<Item = (libc::c_long, libc::c_int)>) -> bool {
            let mut filter = vec![libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            }];
            for (number, error) in refusals {
                filter.extend([
                    libc::sock_filter {
                        code: 0x15,
                        jt: 0,
                        jf: 1,
                        k: number as u32,
                    },
                    libc::sock_filter {
                        code: 0x06,
                        jt: 0,
                        jf: 0,
                        k: libc::SECCOMP_RET_ERRNO | error as u32,
                    },
                ]);
            }
            filter.push(libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            });
            let program = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_mut_ptr(),
            };
            // SAFETY: the initialized filter changes only the listed syscalls in this child.
            unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program) == 0 }
        }
        // SAFETY: the child installs its own filter and exits without unwinding.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");
        if child == 0 {
            // SAFETY: these scalar operations affect only this forked child.
            let ready = unsafe {
                libc::alarm(10);
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
            };
            let statx_disabled = ready
                && install(
                    refusals
                        .iter()
                        .copied()
                        .filter(|&(number, _)| number == libc::SYS_statx),
                );
            let hardened =
                statx_disabled && (!harden || crate::run::hardening::Hardening::apply().is_ok());
            // SAFETY: PR_GET_DUMPABLE reads this process's scalar flag.
            let memory_protected =
                !harden || unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0;
            let installed = hardened
                && install(
                    refusals
                        .iter()
                        .copied()
                        .filter(|&(number, _)| number != libc::SYS_statx),
                );
            let passed = installed && memory_protected && check();
            // SAFETY: the forked child does not return into the test harness.
            unsafe { libc::_exit(i32::from(!passed)) };
        }
        let mut status = 0;
        // SAFETY: waitpid observes the child created by this test.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "mount identity violated its syscall fallback contract"
        );
    }

    /// The root holds exactly one child per reachability class.
    #[test]
    fn the_box_root_holds_exactly_one_child_per_reachability_class() {
        let (layout, operator_home) = layout("codex");

        assert_eq!(
            layout.root(),
            boxes_parent(operator_home.path()).join("codex"),
            "the root is the directory the caller named, and nothing Box sited for it"
        );
        assert_eq!(mode(layout.root()), 0o700);
        assert_eq!(
            children(layout.root()),
            ["bin", "private", "run", "trust"],
            "one child per reachability class: execute, none, connect, read"
        );
        for child in BOX_ROOT_CHILDREN {
            assert_eq!(
                mode(&layout.root().join(child)),
                0o700,
                "{child} must be private to this user"
            );
        }
    }

    /// Nothing the box owns lives under `$TMPDIR`.
    #[test]
    fn every_path_is_under_the_one_box_root() {
        let (layout, _fixture) = layout("codex");

        for path in [
            &layout.bin_directory(),
            &layout.broker_socket(),
            &layout.trust_directory(),
            &layout.record(),
            &layout.policy(),
            &layout.dogwood_database(),
            &layout.live_record(),
            &layout.containment_config("abc"),
            &layout.trampoline_image("abc"),
        ] {
            assert!(
                path.starts_with(layout.root()),
                "{} escapes the box root",
                path.display()
            );
        }
    }

    /// The workload's `PATH` directory starts empty.
    #[test]
    fn the_executable_directory_starts_empty() {
        let (layout, _fixture) = layout("codex");

        assert_eq!(
            std::fs::read_dir(layout.bin_directory()).unwrap().count(),
            0,
            "bin/ must hold no executable until one is deliberately materialized"
        );
    }

    /// Every alias derives the SAME socket from its own path.
    #[test]
    fn every_alias_derives_the_one_socket_the_shim_binds() {
        let (layout, _fixture) = layout("codex");
        let aliases = layout.shell_aliases();

        assert_eq!(
            aliases.len(),
            SHELL_ALIAS_NAMES.len(),
            "one alias per conventional shell name"
        );
        for name in SHELL_ALIAS_NAMES {
            let expected = layout.bin_directory().join(name);
            assert!(
                aliases.contains(&expected),
                "{name} must be materialized at {}",
                expected.display()
            );
        }

        for alias in &aliases {
            // What the alias itself computes: parent of `bin/<name>` is `bin`, its
            // parent is the box root, then `run/box.sock`.
            let derived = alias
                .parent()
                .and_then(Path::parent)
                .expect("the alias has a grandparent")
                .join(RUN_DIRECTORY)
                .join(BROKER_SOCKET);
            assert_eq!(
                derived,
                layout.broker_socket(),
                "{} must derive exactly the socket the shim binds",
                alias.display()
            );
        }

        // The shim's own image name can never be an alias: one image picks its role
        // by filename, so an alias wearing it would reach serve mode.
        assert!(
            !SHELL_ALIAS_NAMES.contains(&"strands-box-sock-alias"),
            "the shim image's name must never be materialized as an alias"
        );
    }

    /// **A declared home in trusted Box state is refused in every spelling that reaches it**,
    /// including one whose own leaf does not exist yet: resolution walks to the deepest existing
    /// ancestor, so a link on an interior component cannot launder the path.
    #[test]
    fn a_declared_home_in_box_state_is_refused_in_every_spelling() {
        let guard = tempfile::tempdir().expect("an operator home");
        let operator = guard.path().canonicalize().expect("the home resolves");
        // A caller-selected box directory, which is the only shape there is now.
        let box_directory = operator.join("boxes/codex");
        std::fs::create_dir_all(&box_directory).expect("the box directory");
        let link = operator.join("shortcut");
        std::os::unix::fs::symlink(&box_directory, &link).expect("a link to the box directory");

        with_operator_home(&operator, || {
            for refused in [
                box_directory.join("home"),
                // The laundered spelling: the leaf does not exist, so only the ancestor resolves.
                link.join("home"),
                link.join("absent/deeper"),
            ] {
                let error = refuse_home_in_box_state(&refused, &box_directory, "[agent]")
                    .err()
                    .unwrap_or_else(|| panic!("{} must be refused", refused.display()));
                assert!(
                    error.to_string().contains("trusted Box state"),
                    "{}: {error}",
                    refused.display()
                );
            }
            // An ordinary directory beside the box directory stays acceptable.
            refuse_home_in_box_state(&operator.join("agent-home"), &box_directory, "[agent]")
                .expect(
                    "a home outside trusted Box state is accepted: \
                     docs/design/decisions.md#home-is-the-operators-and-the-workspace-is-entered",
                );
        });
    }

    /// **A declared home ABOVE the box directory is refused too**, because `Reach` makes a declared
    /// home one of its roots and forbids this box's own directory alone — so an enclosing home puts
    /// this box's state, and every sibling box's, inside the reachable set.
    ///
    /// A caller-selected `box_dir` has no reserved parent, so `~/boxes` with `box_dir = ~/boxes/a`
    /// was accepted.
    #[cfg(unix)]
    #[test]
    fn a_declared_home_enclosing_the_box_directory_is_refused() {
        let guard = tempfile::tempdir().expect("an operator home");
        let operator = guard.path().canonicalize().expect("the home resolves");
        let box_directory = operator.join("boxes/codex");
        std::fs::create_dir_all(&box_directory).expect("the box directory");
        let link = operator.join("to-boxes");
        std::os::unix::fs::symlink(operator.join("boxes"), &link).expect("a link to the parent");

        with_operator_home(&operator, || {
            for refused in [
                // The immediate parent, which is where a sibling box sits.
                operator.join("boxes"),
                // The operator home, which encloses every box the caller sited under it.
                operator.clone(),
                // The same parent reached through a link, which resolves to it.
                link.clone(),
            ] {
                let error = refuse_home_in_box_state(&refused, &box_directory, "[agent]")
                    .err()
                    .unwrap_or_else(|| panic!("{} must be refused", refused.display()));
                assert!(
                    error.to_string().contains("encloses the box directory"),
                    "the refusal must name why: {}: {error}",
                    refused.display()
                );
            }

            // Two paired positives, or the refusals above would pass on a check that refuses every
            // home under the operator's own.
            refuse_home_in_box_state(&operator.join("boxes-elsewhere"), &box_directory, "[agent]")
                .expect("a sibling of the box directory's parent encloses nothing");
            refuse_home_in_box_state(
                &operator.join("boxes/codex-notes"),
                &box_directory,
                "[agent]",
            )
            .expect(
                "a directory sharing the box directory's prefix is neither inside nor above it",
            );
        });
    }

    /// How many bytes `socket` costs below `enclosing`.
    fn contributed_bytes(socket: &Path, enclosing: &Path) -> usize {
        socket
            .strip_prefix(enclosing)
            .expect("the socket is under the enclosing directory")
            .as_os_str()
            .len()
    }

    /// **What the box adds below `box_dir` is fixed**, so a caller can compute its own budget against
    /// [`BROKER_SOCKET_PATH_LIMIT`]: `run/box.sock` plus the separator joining it, 13 bytes in all.
    ///
    /// This used to measure the longest box NAME against the operator home, which is no longer the
    /// shape: the name sites no path, and a caller supplies `box_dir`. Measuring the overhead is what
    /// is still true, and `a_box_directory_whose_socket_exceeds_the_platform_limit_is_refused` is what
    /// pins the bound itself.
    #[test]
    fn the_broker_socket_costs_a_fixed_overhead_below_the_box_directory() {
        let parent = tempfile::tempdir().expect("a box parent");
        let root = parent.path().canonicalize().unwrap().join("b");
        // `create_at` reads `HOME`, and the build fleet leaves it unset, so this must hold the
        // suite's `HOME` lock rather than read whatever a parallel test left behind.
        let home = tempfile::tempdir().expect("an operator home");
        let layout = with_operator_home(home.path(), || BoxRoot::create_at(root.clone(), "codex"))
            .expect("the box root");

        // `strip_prefix` drops the joining separator, so this is the cost without it.
        let below = contributed_bytes(&layout.broker_socket(), &root);
        assert_eq!(
            below,
            "run/box.sock".len(),
            "the socket sits at <box_dir>/run/box.sock, so the cost below it is that string"
        );
        assert_eq!(
            layout.broker_socket().as_os_str().len() - root.as_os_str().len(),
            "/run/box.sock".len(),
            "and the whole cost a caller must budget for includes the separator"
        );
        assert!(
            below < BROKER_SOCKET_PATH_LIMIT,
            "the overhead alone must leave a caller some budget"
        );
    }

    /// **A `box_dir` whose broker socket would exceed the platform limit is refused at open**, and
    /// the refusal says so.
    ///
    /// This is the only guard on socket-path length now that no Box-sited root spends the budget, and
    /// it had no test: the assertion above it passed while measuring a layout the product never
    /// produces. A socket that does not fit is a box whose aliases cannot connect at all.
    ///
    /// The padding is computed rather than hardcoded, because the temporary directory's own length
    /// differs by platform.
    #[cfg(unix)]
    #[test]
    fn a_box_directory_whose_socket_exceeds_the_platform_limit_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = tempfile::tempdir().expect("a box parent");
        let base = parent.path().canonicalize().expect("the parent resolves");
        let overhead = "/run/box.sock".len();
        // One byte over the limit, counting the separator this component adds.
        let needed = BROKER_SOCKET_PATH_LIMIT + 1 - overhead - base.as_os_str().len() - 1;

        let over = base.join("a".repeat(needed));
        std::fs::create_dir(&over).expect("the over-limit box directory");
        std::fs::set_permissions(&over, std::fs::Permissions::from_mode(0o700)).expect("mode");
        assert_eq!(
            over.join("run").join("box.sock").as_os_str().len(),
            BROKER_SOCKET_PATH_LIMIT + 1,
            "the fixture must sit exactly one byte over, or it proves nothing about the bound"
        );

        // `open_directory` reads `HOME` before it measures the socket, so without the lock this
        // reports `NoOperatorHome` on a host that leaves `HOME` unset and asserts nothing about the
        // bound. It passed once by racing a test that held the lock.
        let home = tempfile::tempdir().expect("an operator home");
        let error = match with_operator_home(home.path(), || BoxRoot::open_directory(&over)) {
            Err(error) => error,
            Ok(_) => panic!("a box whose socket does not fit must be refused"),
        };
        assert!(
            error.to_string().contains("exceeds the platform limit"),
            "the refusal must name the limit: {error}"
        );

        // The paired positive, one byte shorter: without it this passes on a check that refuses
        // every directory.
        let under = base.join("a".repeat(needed - 1));
        std::fs::create_dir(&under).expect("the at-limit box directory");
        std::fs::set_permissions(&under, std::fs::Permissions::from_mode(0o700)).expect("mode");
        assert_eq!(
            under.join("run").join("box.sock").as_os_str().len(),
            BROKER_SOCKET_PATH_LIMIT
        );
        with_operator_home(home.path(), || BoxRoot::open_directory(&under))
            .expect("a socket exactly at the limit is accepted");
    }

    /// A box's live record is private, so the workload cannot read its own port.
    #[test]
    fn the_live_record_is_private_to_the_box() {
        let (layout, _fixture) = layout("codex");

        assert_eq!(
            layout.live_record().parent().unwrap(),
            layout.private_directory()
        );
    }

    /// The Dogwood database has one workload-inaccessible location.
    #[test]
    fn dogwood_database_has_one_private_location() {
        let (layout, _fixture) = layout("codex");

        assert_eq!(
            layout.dogwood_database(),
            layout.private_directory().join("dogwood.redb")
        );
    }

    /// Two runs with different inputs get different containment files.
    #[test]
    fn containment_configs_are_named_by_their_digest() {
        let (layout, _fixture) = layout("codex");

        assert_ne!(
            layout.containment_config("aaaa"),
            layout.containment_config("bbbb")
        );
        assert_eq!(
            layout.containment_config("aaaa"),
            layout.containment_config("aaaa"),
            "the same inputs name the same file, so identical runs share it"
        );
        assert!(
            layout
                .containment_config("aaaa")
                .starts_with(layout.private_directory()),
            "the workload must not be able to read or name its own containment config"
        );
    }

    #[test]
    fn a_private_file_is_written_atomically_at_its_mode() {
        let (layout, _fixture) = layout("codex");

        layout
            .write_private_file(
                &layout.policy(),
                "permit(principal, action, resource);",
                0o400,
            )
            .unwrap();

        assert_eq!(mode(&layout.policy()), 0o400);
        assert_eq!(
            std::fs::read_to_string(layout.policy()).unwrap(),
            "permit(principal, action, resource);"
        );
        // No staging file survives a successful write.
        assert!(
            !children(&layout.private_directory())
                .iter()
                .any(|entry| entry.ends_with(".tmp")),
            "the staging file must be renamed, not left behind"
        );
    }

    /// Rewriting replaces the bytes, which is what `configure` does on a second run.
    #[test]
    fn a_private_file_can_be_rewritten_in_place() {
        let (layout, _fixture) = layout("codex");

        layout
            .write_private_file(&layout.policy(), "first", 0o400)
            .unwrap();
        layout
            .write_private_file(&layout.policy(), "second", 0o400)
            .unwrap();

        assert_eq!(std::fs::read_to_string(layout.policy()).unwrap(), "second");
        assert_eq!(mode(&layout.policy()), 0o400);
    }

    /// A box directory that does not exist cannot be opened, and the failure creates nothing.
    #[test]
    fn opening_an_uncreated_box_directory_fails_and_creates_nothing() {
        let parent = tempfile::tempdir().unwrap();
        let absent = parent.path().join("never-configured");

        // Wrapped, because `open_directory` reads `HOME` to record the operator home. This case
        // happens to fail on the absent path first, but the suite mutates `HOME` under one lock and a
        // test that reads it outside that lock is racing every other test.
        let home = tempfile::tempdir().expect("an operator home");
        with_operator_home(home.path(), || {
            BoxRoot::open_directory(&absent)
                .expect_err("open must refuse a directory that is absent")
        });
        assert!(!absent.exists(), "a failed open must create nothing");
    }

    /// **Box creates no directory above the one `box_dir` names.** A caller who names a path two
    /// levels deep gets a refusal naming the missing parent, rather than a tree Box invented.
    #[test]
    fn a_box_directory_whose_parent_is_absent_is_refused_and_creates_nothing() {
        let parent = tempfile::tempdir().unwrap();
        let absent_parent = parent.path().join("absent");
        let root = absent_parent.join("box");

        let error = create_box_directory_if_absent(&root)
            .expect_err("a box directory below an absent parent must be refused");
        assert!(
            error.to_string().contains("parent does not exist"),
            "the refusal must name what is missing: {error}"
        );
        assert!(!absent_parent.exists(), "no ancestor may be created");

        // The paired positive: with the parent there, the leaf is created at mode 0700.
        std::fs::create_dir(&absent_parent).expect("the parent");
        create_box_directory_if_absent(&root).expect("a leaf below an existing parent is created");
        assert_eq!(mode(&root), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn a_replaced_box_directory_is_refused_before_initialization() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        let moved = parent.path().join("moved");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private mode");

        let mut opened = crate::test_support::with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("directory validates")
        });
        std::fs::rename(&root, &moved).expect("move validated identity");
        std::fs::create_dir(&root).expect("replacement directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private replacement");

        let error = opened
            .initialize()
            .expect_err("the replacement must not receive Box state");
        assert!(error.to_string().contains("identity changed"), "{error}");
        assert_eq!(
            std::fs::read_dir(&root).expect("replacement reads").count(),
            0,
            "the replacement directory must remain empty"
        );
        assert_eq!(
            std::fs::read_dir(&moved)
                .expect("validated identity reads")
                .count(),
            0,
            "Box must create nothing after the pathname changes"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_state_write_refuses_after_a_path_swap() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        let moved = parent.path().join("moved");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private mode");

        let mut opened = crate::test_support::with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("directory validates")
        });
        opened.initialize().expect("Box state initializes");

        std::fs::rename(&root, &moved).expect("move validated identity");
        std::fs::create_dir(&root).expect("replacement directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private replacement");
        let error = opened
            .write_private_file(&opened.policy(), "permit;", 0o400)
            .expect_err("the changed configured identity must be refused");
        assert!(error.to_string().contains("identity changed"), "{error}");
        assert!(
            !moved.join("private/policy.dw").exists(),
            "the refused write must not change the opened directory"
        );
        assert_eq!(
            std::fs::read_dir(&root).expect("replacement reads").count(),
            0,
            "the replacement path must receive no Box state"
        );

        std::fs::remove_dir(&root).expect("remove replacement");
        std::fs::rename(&moved, &root).expect("restore validated identity");
        opened
            .verify_identity()
            .expect("the opened identity is current again");
    }

    #[cfg(unix)]
    #[test]
    fn validation_checks_the_directory_opened_after_a_path_swap() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        let original = parent.path().join("original");
        let replacement = parent.path().join("replacement");
        std::fs::create_dir(&root).expect("private directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private mode");
        std::fs::create_dir(&replacement).expect("replacement directory");
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o755))
            .expect("unsafe replacement mode");

        let error = crate::test_support::with_operator_home(operator_home.path(), || {
            match BoxRoot::open_directory_inner_with(&root, false, || {
                std::fs::rename(&root, &original).expect("move private directory");
                std::fs::rename(&replacement, &root).expect("install unsafe replacement");
            }) {
                Ok(_) => panic!("the opened replacement must be validated"),
                Err(error) => error,
            }
        });

        assert!(
            error.to_string().contains("mode is not 0700"),
            "validation must use the opened descriptor metadata: {error}"
        );
        assert_eq!(
            std::fs::read_dir(&root).expect("replacement reads").count(),
            0,
            "a refused replacement receives no Box state"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn directory_enumeration_uses_the_opened_identity_without_reopening_it() {
        use std::os::unix::fs::PermissionsExt as _;

        const ENTRY_COUNT: usize = 4_096;
        const READER_COUNT: usize = 8;

        let parent = tempfile::tempdir().expect("directory parent");
        let directory = parent.path().join("directory");
        std::fs::create_dir(&directory).expect("directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("readable directory mode");
        let expected: std::collections::BTreeSet<_> = (0..ENTRY_COUNT)
            .map(|entry| std::ffi::OsString::from(format!("entry-{entry}")))
            .collect();
        for entry in 0..ENTRY_COUNT {
            std::fs::write(directory.join(format!("entry-{entry}")), "").expect("directory entry");
        }
        let opened = open_directory_without_following(&directory).expect("opened directory");

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o100))
            .expect("remove pathname read permission");
        let entries: std::collections::BTreeSet<_> = directory_entries(&opened, &directory)
            .expect("enumerate the opened identity")
            .into_iter()
            .collect();
        assert_eq!(
            entries, expected,
            "enumeration must return each expected name"
        );

        let opened = Arc::new(opened);
        let start = Arc::new(std::sync::Barrier::new(READER_COUNT));
        let readers: Vec<_> = (0..READER_COUNT)
            .map(|_| {
                let opened = Arc::clone(&opened);
                let directory = directory.clone();
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    directory_entries(&opened, &directory)
                        .expect("concurrent enumeration")
                        .into_iter()
                        .collect::<std::collections::BTreeSet<_>>()
                })
            })
            .collect();
        for reader in readers {
            assert_eq!(
                reader.join().expect("directory reader"),
                expected,
                "each concurrent enumeration must return every expected name"
            );
        }

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("restore directory mode");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn directory_enumeration_lock_serializes_the_shared_offset_region() {
        const READER_COUNT: usize = 8;

        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pause_first = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let start = Arc::new(std::sync::Barrier::new(READER_COUNT));
        let readers: Vec<_> = (0..READER_COUNT)
            .map(|_| {
                let active = Arc::clone(&active);
                let peak = Arc::clone(&peak);
                let pause_first = Arc::clone(&pause_first);
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    with_directory_enumeration_lock(|| {
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(current, Ordering::SeqCst);
                        if pause_first.swap(false, Ordering::SeqCst) {
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                        active.fetch_sub(1, Ordering::SeqCst);
                    });
                })
            })
            .collect();
        for reader in readers {
            reader.join().expect("directory reader");
        }

        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "only one reader can use the shared directory offset"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_ancestor_symlink_spelling_is_visible_and_cannot_be_retargeted() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let first = parent.path().join("first");
        let second = parent.path().join("second");
        let alias = parent.path().join("alias");
        for directory in [&first, &second] {
            std::fs::create_dir(directory).expect("parent directory");
            let root = directory.join("box");
            std::fs::create_dir(&root).expect("box directory");
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .expect("private mode");
        }
        std::os::unix::fs::symlink(&first, &alias).expect("ancestor symlink");
        let configured = alias.join("box");

        let mut opened = crate::test_support::with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&configured).expect("directory validates")
        });
        opened.initialize().expect("Box state initializes");

        assert_eq!(opened.root(), configured);
        assert_eq!(
            opened.broker_socket(),
            configured.join(RUN_DIRECTORY).join(BROKER_SOCKET)
        );

        std::fs::remove_file(&alias).expect("remove old ancestor");
        std::os::unix::fs::symlink(&second, &alias).expect("retarget ancestor");
        let error = opened
            .verify_identity()
            .expect_err("a retargeted configured spelling must be refused");
        assert!(error.to_string().contains("identity changed"), "{error}");
    }

    /// A configured box opens without being re-created.
    #[test]
    fn opening_a_configured_box_finds_the_same_paths() {
        let operator_home = tempfile::tempdir().unwrap();
        let root = boxes_parent(operator_home.path()).join("codex");

        let created = with_operator_home(operator_home.path(), || {
            let created = BoxRoot::create_at(root.clone(), "codex").unwrap();
            created
                .write_committed_record(&valid_record(&created))
                .unwrap();
            created
        });
        let opened = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
            .expect("a configured directory reopens");

        assert_eq!(opened.root(), created.root());
    }

    /// `configure` twice keeps the root and adds nothing to it.
    #[test]
    fn reconfiguring_adds_no_child() {
        let operator_home = tempfile::tempdir().unwrap();
        let root = boxes_parent(operator_home.path()).join("codex");

        let first = with_operator_home(operator_home.path(), || {
            BoxRoot::create_at(root.clone(), "codex")
        })
        .unwrap();
        let second = with_operator_home(operator_home.path(), || {
            BoxRoot::create_at(root.clone(), "codex")
        })
        .unwrap();

        assert_eq!(second.root(), first.root());
        assert_eq!(
            children(second.root()),
            ["bin", "private", "run", "trust"],
            "a second create adds no child"
        );
    }

    /// Two directories are two boxes, and the directory is what separates them now that no name
    /// sites a root.
    #[test]
    fn distinct_directories_are_distinct_boxes() {
        let operator_home = tempfile::tempdir().unwrap();
        let parent = boxes_parent(operator_home.path());
        let (codex, claude) = with_operator_home(operator_home.path(), || {
            (
                BoxRoot::create_at(parent.join("codex"), "codex").unwrap(),
                BoxRoot::create_at(parent.join("claude"), "claude").unwrap(),
            )
        });

        assert_ne!(codex.root(), claude.root());
        assert_ne!(codex.broker_socket(), claude.broker_socket());
    }

    #[test]
    fn a_symlinked_alias_directory_is_refused() {
        let operator_home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let box_root = boxes_parent(operator_home.path()).join("codex");
        std::fs::create_dir_all(&box_root).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), box_root.join("bin")).unwrap();

        let error = with_operator_home(operator_home.path(), || {
            BoxRoot::create_at(box_root.clone(), "codex")
        })
        .expect_err("a symlinked alias directory must be refused, not followed");

        assert!(
            error.to_string().contains("not a directory"),
            "unexpected error: {error}"
        );
    }

    /// A symlinked `private/` is refused too.
    #[test]
    fn a_symlinked_private_tree_is_refused() {
        let operator_home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let box_root = boxes_parent(operator_home.path()).join("codex");
        std::fs::create_dir_all(&box_root).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), box_root.join("private")).unwrap();

        let error = with_operator_home(operator_home.path(), || {
            BoxRoot::create_at(box_root.clone(), "codex")
        })
        .expect_err("a symlinked private tree must be refused");

        assert!(
            error.to_string().contains("not a directory"),
            "unexpected error: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn broker_binding_uses_the_opened_directory_after_a_path_swap() {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = tempfile::tempdir().expect("broker parent");
        let run = parent.path().join("run");
        let moved = parent.path().join("moved-run");
        std::fs::create_dir(&run).expect("run directory");
        let opened = std::fs::File::open(&run).expect("run descriptor");
        std::fs::rename(&run, &moved).expect("move run directory");
        std::fs::create_dir(&run).expect("replacement run directory");

        let listener = bind_unix_listener_at(&opened, std::ffi::OsStr::new(BROKER_SOCKET))
            .expect("listener binds");
        let socket = moved.join(BROKER_SOCKET);
        let client = std::os::unix::net::UnixStream::connect(&socket)
            .expect("client connects to moved root");
        let (_server, _) = listener.accept().expect("listener accepts");
        drop(client);

        assert!(
            !run.join(BROKER_SOCKET).exists(),
            "the replacement path must receive no socket"
        );
        assert_eq!(
            std::fs::metadata(socket)
                .expect("socket metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    /// **A committed record with no history, or an empty one, is refused, and the check leaves the
    /// file as it finds it.**
    #[cfg(unix)]
    #[test]
    fn a_committed_record_without_a_history_is_refused_and_the_file_is_left_as_found() {
        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let mut opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("an empty box directory opens")
        });
        opened
            .verify_history_matches_record()
            .expect("a box with neither a record nor a history is consistent");
        opened.settle_identity().expect("a first-use identity");
        let record = record_for(&opened);
        opened
            .initialize_first_use(&record)
            .expect("the record commits");
        assert!(opened.is_configured());
        opened
            .verify_history_matches_record()
            .expect("the run that commits the record has no history yet");
        let history = opened.dogwood_database();

        let reopened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("a configured box reopens")
        });
        assert!(reopened.is_configured());
        let refusal = reopened
            .verify_history_matches_record()
            .expect_err("a committed record without a history is refused")
            .to_string();
        assert_eq!(
            refusal,
            format!(
                "policy staging failed: the box record is committed, but the history {} is \
                 absent. Wipe the box directory to start again.",
                history.display()
            )
        );
        assert!(!history.exists(), "the check must not create the history");

        std::fs::write(&history, []).expect("an empty history");
        let refusal = reopened
            .verify_history_matches_record()
            .expect_err("a committed record with an empty history is refused")
            .to_string();
        assert_eq!(
            refusal,
            format!(
                "policy staging failed: the box record is committed, but the history {} is \
                 empty. Wipe the box directory to start again.",
                history.display()
            )
        );
        assert_eq!(
            std::fs::metadata(&history)
                .expect("the history remains")
                .len(),
            0,
            "the check must not grow the history"
        );

        std::fs::write(&history, b"history").expect("a history with bytes");
        reopened
            .verify_history_matches_record()
            .expect("a committed record with a history is consistent");
        assert_eq!(
            std::fs::read(&history).expect("the history remains"),
            b"history"
        );
    }

    /// **A history with bytes under a record that is not committed is refused, and the check leaves
    /// the file as it finds it.**
    #[cfg(unix)]
    #[test]
    fn a_history_without_a_committed_record_is_refused_and_the_file_is_left_as_found() {
        let (layout, _operator_home) = layout("codex");
        assert!(!layout.is_configured());
        let history = layout.dogwood_database();

        std::fs::write(&history, []).expect("an empty history");
        layout
            .verify_history_matches_record()
            .expect("an empty history under no record is a box that has not run");

        std::fs::write(&history, b"history").expect("a history with bytes");
        let refusal = layout
            .verify_history_matches_record()
            .expect_err("a history under no committed record is refused")
            .to_string();
        assert_eq!(
            refusal,
            format!(
                "policy staging failed: the box record is not committed, but the history {} \
                 holds 7 bytes. Wipe the box directory to start again.",
                history.display()
            )
        );
        assert_eq!(
            std::fs::read(&history).expect("the history remains"),
            b"history"
        );
    }

    /// A box whose first use completed, closed, so a later open reads only what is on disk.
    #[cfg(unix)]
    fn configured_box(operator_home: &Path, parent: &Path) -> (PathBuf, String) {
        use std::os::unix::fs::PermissionsExt as _;

        let root = parent.join("box");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let mut opened = with_operator_home(operator_home, || {
            BoxRoot::open_directory(&root).expect("empty box opens")
        });
        opened.settle_identity().expect("box identity");
        let record = record_for(&opened);
        opened
            .initialize_first_use(&record)
            .expect("first use completes");
        let box_id = opened.box_id().to_string();
        drop(opened);
        (root, box_id)
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    }

    /// Copy `source` to `destination` with every mode kept, so the copy differs only in identity.
    #[cfg(unix)]
    fn copy_tree(source: &Path, destination: &Path) {
        let metadata = std::fs::symlink_metadata(source).expect("source metadata");
        if metadata.is_dir() {
            std::fs::create_dir(destination).expect("copied directory");
            for entry in std::fs::read_dir(source).expect("source entries") {
                let entry = entry.expect("source entry");
                copy_tree(&entry.path(), &destination.join(entry.file_name()));
            }
            std::fs::set_permissions(destination, metadata.permissions()).expect("directory mode");
        } else if metadata.is_file() {
            std::fs::copy(source, destination).expect("copied file");
        } else if metadata.file_type().is_symlink() {
            let target = std::fs::read_link(source).expect("link target");
            std::os::unix::fs::symlink(target, destination).expect("copied link");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_configured_box_whose_marker_holds_its_id_and_digest_reopens() {
        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let (root, box_id) = configured_box(operator_home.path(), parent.path());
        let private = root.join(PRIVATE_DIRECTORY);

        let record = std::fs::read(private.join(RECORD_FILE)).expect("the committed record");
        assert_eq!(
            std::fs::read_to_string(private.join(PRIVATE_COMMIT_FILE)).expect("the marker"),
            format!("{box_id} sha256:{}\n", sha256_hex(&record)),
            "the marker must hold the box id and the digest of the committed record"
        );

        let reopened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("a configured box reopens")
        });
        assert!(reopened.is_configured());
        assert_eq!(reopened.box_id(), box_id);
    }

    #[cfg(unix)]
    #[test]
    fn a_record_whose_content_changed_in_place_refuses_and_names_both_identities() {
        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let (root, box_id) = configured_box(operator_home.path(), parent.path());
        let private = root.join(PRIVATE_DIRECTORY);
        let record_path = private.join(RECORD_FILE);
        let inode_before = record_path.metadata().expect("record metadata").ino();
        let stored = std::fs::read_to_string(private.join(PRIVATE_COMMIT_FILE)).expect("marker");

        let replacement = valid_record_at(&root, operator_home.path(), "box-ffffffffffffffff");
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&record_path)
            .and_then(|mut file| file.write_all(replacement.as_bytes()))
            .expect("rewrite the record in place");
        assert_eq!(
            record_path.metadata().expect("record metadata").ino(),
            inode_before,
            "the rewrite must keep the record's inode"
        );

        let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
            .expect_err("a record with other content must be refused");
        let message = error.to_string();
        assert!(message.starts_with("unsafe box directory "), "{message}");
        assert!(
            message.contains(&format!(
                ": its record identity is {}, but the committed record has identity \
                 box-ffffffffffffffff sha256:{}. Delete the box directory to start again.",
                stored.trim_end(),
                sha256_hex(replacement.as_bytes())
            )),
            "{message}"
        );
        assert!(message.contains(&box_id), "{message}");
    }

    #[cfg(unix)]
    #[test]
    fn a_marker_in_the_device_and_inode_form_refuses_with_the_identity_text() {
        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let (root, box_id) = configured_box(operator_home.path(), parent.path());
        let private = root.join(PRIVATE_DIRECTORY);
        let record = std::fs::read(private.join(RECORD_FILE)).expect("the committed record");
        let metadata = private
            .join(RECORD_FILE)
            .metadata()
            .expect("record metadata");
        let legacy = format!("{}:{}\n", metadata.dev(), metadata.ino());
        std::fs::write(private.join(PRIVATE_COMMIT_FILE), &legacy).expect("legacy marker");

        let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
            .expect_err("a marker in the device and inode form must be refused");
        let message = error.to_string();
        assert!(message.starts_with("unsafe box directory "), "{message}");
        assert!(
            message.contains(&format!(
                ": its record identity is {}, but the committed record has identity {box_id} \
                 sha256:{}. Delete the box directory to start again.",
                legacy.trim_end(),
                sha256_hex(&record)
            )),
            "{message}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_record_identity_holds_no_device_or_inode() {
        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let (root, box_id) = configured_box(operator_home.path(), parent.path());
        let private = root.join(PRIVATE_DIRECTORY);
        let metadata = private
            .join(RECORD_FILE)
            .metadata()
            .expect("record metadata");
        let text = std::fs::read_to_string(private.join(PRIVATE_COMMIT_FILE)).expect("marker");

        let line = text
            .strip_suffix('\n')
            .expect("one line ending in a newline");
        let (id, digest) = line
            .split_once(' ')
            .expect("two fields separated by one space");
        assert_eq!(id, box_id, "the first field must be the box id");
        assert_eq!(id.len(), "box-".len() + 16);
        assert!(id.starts_with("box-") && id[4..].bytes().all(|byte| byte.is_ascii_hexdigit()));
        let digest = digest
            .strip_prefix("sha256:")
            .expect("the second field names its algorithm");
        assert_eq!(digest.len(), 64, "the digest must be a SHA-256 in hex");
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(line.matches(':').count(), 1);
        assert_ne!(text, format!("{}:{}\n", metadata.dev(), metadata.ino()));
    }

    #[cfg(unix)]
    #[test]
    fn a_copied_box_directory_with_the_same_bytes_opens_as_the_same_box() {
        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let (root, box_id) = configured_box(operator_home.path(), parent.path());
        let copy = parent.path().join("copy");
        copy_tree(&root, &copy);
        let original = root.join(PRIVATE_DIRECTORY).join(RECORD_FILE);
        let copied = copy.join(PRIVATE_DIRECTORY).join(RECORD_FILE);
        assert_ne!(
            original.metadata().expect("original record").ino(),
            copied.metadata().expect("copied record").ino(),
            "the copy must hold a different record inode"
        );
        assert_eq!(
            std::fs::read(&original).expect("original bytes"),
            std::fs::read(&copied).expect("copied bytes")
        );

        let opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&copy).expect("a copy with the same bytes opens")
        });
        assert!(opened.is_configured());
        assert_eq!(opened.box_id(), box_id);
    }

    #[cfg(unix)]
    #[test]
    fn a_committed_record_that_no_longer_parses_refuses_with_its_own_parse_error() {
        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let (root, box_id) = configured_box(operator_home.path(), parent.path());
        let record_path = root.join(PRIVATE_DIRECTORY).join(RECORD_FILE);
        let stale = valid_record_at(&root, operator_home.path(), &box_id).replacen(
            &format!("version = {}", crate::record::config::RECORD_VERSION),
            "version = 999",
            1,
        );
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&record_path)
            .and_then(|mut file| file.write_all(stale.as_bytes()))
            .expect("rewrite the record in place");

        let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
            .expect_err("a record this build cannot read must be refused");
        let message = error.to_string();
        assert!(
            message.contains("box record is version 999, but this build understands"),
            "the refusal must be the record's own: {message}"
        );
        assert!(!message.contains("no valid private record"), "{message}");
    }

    #[cfg(unix)]
    #[test]
    fn a_pending_record_that_does_not_match_the_marker_is_not_installed() {
        use std::os::unix::fs::PermissionsExt as _;

        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let (root, _) = configured_box(operator_home.path(), parent.path());
        let private = root.join(PRIVATE_DIRECTORY);
        let record_path = private.join(RECORD_FILE);
        let pending_path = private.join(PENDING_RECORD_FILE);
        let stored = std::fs::read_to_string(private.join(PRIVATE_COMMIT_FILE)).expect("marker");

        let replaced = valid_record_at(&root, operator_home.path(), "box-eeeeeeeeeeeeeeee");
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&record_path)
            .and_then(|mut file| file.write_all(replaced.as_bytes()))
            .expect("rewrite the record in place");
        let stray = valid_record_at(&root, operator_home.path(), "box-dddddddddddddddd");
        std::fs::write(&pending_path, &stray).expect("stray pending record");
        std::fs::set_permissions(&pending_path, std::fs::Permissions::from_mode(0o600))
            .expect("pending mode");

        let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
            .expect_err("neither the record nor the pending record matches the marker");
        let message = error.to_string();
        assert!(
            message.contains(&format!(
                "its record identity is {}, but the committed record has identity \
                 box-eeeeeeeeeeeeeeee sha256:{}.",
                stored.trim_end(),
                sha256_hex(replaced.as_bytes())
            )),
            "{message}"
        );
        assert_eq!(
            std::fs::read_to_string(&record_path).expect("the record remains"),
            replaced,
            "the stray pending record must not be installed over the record"
        );
        assert_eq!(
            std::fs::read_to_string(&pending_path).expect("the pending record remains"),
            stray
        );
    }

    /// Reduce a configured box's private directory to its record and its marker alone.
    #[cfg(unix)]
    fn keep_only_record_and_marker(private: &Path) {
        for entry in std::fs::read_dir(private).expect("private entries") {
            let entry = entry.expect("private entry");
            let name = entry.file_name();
            if name == RECORD_FILE || name == PRIVATE_COMMIT_FILE {
                continue;
            }
            if entry.file_type().expect("entry type").is_dir() {
                std::fs::remove_dir_all(entry.path()).expect("remove a generated directory");
            } else {
                std::fs::remove_file(entry.path()).expect("remove a generated file");
            }
        }
        assert_eq!(children(private), [RECORD_FILE, PRIVATE_COMMIT_FILE]);
    }

    #[cfg(unix)]
    fn rewrite_in_place(path: &Path, contents: &str) {
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .and_then(|mut file| file.write_all(contents.as_bytes()))
            .expect("rewrite the record in place");
    }

    #[cfg(unix)]
    #[test]
    fn a_marker_beside_an_edited_record_refuses_without_sibling_directories() {
        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let (root, _) = configured_box(operator_home.path(), parent.path());
        let private = root.join(PRIVATE_DIRECTORY);
        keep_only_record_and_marker(&private);
        let record_path = private.join(RECORD_FILE);
        let marker_path = private.join(PRIVATE_COMMIT_FILE);
        let stored = std::fs::read_to_string(&marker_path).expect("marker");
        let replacement = valid_record_at(&root, operator_home.path(), "box-ffffffffffffffff");
        rewrite_in_place(&record_path, &replacement);

        let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
            .expect_err("a marker beside a record it does not describe must be refused");
        let message = error.to_string();
        assert!(
            message.contains(&format!(
                "its record identity is {}, but the committed record has identity \
                 box-ffffffffffffffff sha256:{}.",
                stored.trim_end(),
                sha256_hex(replacement.as_bytes())
            )),
            "the refusal must name both identities: {message}"
        );
        assert_eq!(
            std::fs::read_to_string(&marker_path).expect("the marker remains"),
            stored,
            "the open must not rewrite the marker"
        );
        assert_eq!(
            std::fs::read_to_string(&record_path).expect("the record remains"),
            replacement,
            "the open must not rewrite the record"
        );
        assert_eq!(
            children(&private),
            [RECORD_FILE, PRIVATE_COMMIT_FILE],
            "the open must not re-initialize the private directory"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_marker_beside_an_unreadable_record_refuses_without_sibling_directories() {
        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let (root, box_id) = configured_box(operator_home.path(), parent.path());
        let private = root.join(PRIVATE_DIRECTORY);
        keep_only_record_and_marker(&private);
        let record_path = private.join(RECORD_FILE);
        let marker_path = private.join(PRIVATE_COMMIT_FILE);
        let stored = std::fs::read_to_string(&marker_path).expect("marker");
        let stale = valid_record_at(&root, operator_home.path(), &box_id).replacen(
            &format!("version = {}", crate::record::config::RECORD_VERSION),
            "version = 999",
            1,
        );
        rewrite_in_place(&record_path, &stale);

        let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
            .expect_err("a marker beside a record this build cannot read must be refused");
        let message = error.to_string();
        assert!(
            message.contains("box record is version 999, but this build understands"),
            "the refusal must be the record's own: {message}"
        );
        assert!(!message.contains("no valid private record"), "{message}");
        assert_eq!(
            std::fs::read_to_string(&marker_path).expect("the marker remains"),
            stored
        );
        assert_eq!(
            std::fs::read_to_string(&record_path).expect("the record remains"),
            stale
        );
        assert_eq!(children(&private), [RECORD_FILE, PRIVATE_COMMIT_FILE]);
    }

    #[cfg(unix)]
    #[test]
    fn a_record_without_a_marker_still_recovers_as_an_interrupted_first_use() {
        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let (root, _) = configured_box(operator_home.path(), parent.path());
        let private = root.join(PRIVATE_DIRECTORY);
        keep_only_record_and_marker(&private);
        std::fs::remove_file(private.join(PRIVATE_COMMIT_FILE)).expect("remove the marker");
        let record_path = private.join(RECORD_FILE);
        let before = std::fs::read_to_string(&record_path).expect("record");

        let opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("a record without a marker is recoverable")
        });
        assert!(
            !opened.is_configured(),
            "a record without a marker must not open as configured"
        );
        assert_eq!(children(&private), [RECORD_FILE]);
        assert_eq!(
            std::fs::read_to_string(&record_path).expect("the record remains"),
            before
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_marker_under_the_first_use_mode_refuses_and_is_not_re_initialized() {
        use std::os::unix::fs::PermissionsExt as _;

        for edited in [true, false] {
            let operator_home = tempfile::tempdir().expect("operator home");
            let parent = tempfile::tempdir().expect("box parent");
            let (root, _) = configured_box(operator_home.path(), parent.path());
            let private = root.join(PRIVATE_DIRECTORY);
            keep_only_record_and_marker(&private);
            for name in ["bin", "run", "trust"] {
                std::fs::remove_dir_all(root.join(name)).expect("remove a layout directory");
            }
            assert_eq!(children(&root), [PRIVATE_DIRECTORY]);
            std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o1700))
                .expect("first-use private mode");
            let record_path = private.join(RECORD_FILE);
            let marker_path = private.join(PRIVATE_COMMIT_FILE);
            let stored = std::fs::read_to_string(&marker_path).expect("marker");
            let record = if edited {
                let replacement =
                    valid_record_at(&root, operator_home.path(), "box-ffffffffffffffff");
                rewrite_in_place(&record_path, &replacement);
                replacement
            } else {
                std::fs::read_to_string(&record_path).expect("record")
            };

            let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
                .expect_err("a marker under the first-use mode must be refused");
            let message = error.to_string();
            if edited {
                assert!(
                    message.contains(&format!(
                        "its record identity is {}, but the committed record has identity \
                         box-ffffffffffffffff sha256:{}.",
                        stored.trim_end(),
                        sha256_hex(record.as_bytes())
                    )),
                    "the refusal must name both identities: {message}"
                );
            } else {
                assert!(
                    message.contains("contains no valid private record"),
                    "a marker that matches its record is not a first-use state: {message}"
                );
            }
            assert_eq!(
                private
                    .metadata()
                    .expect("private metadata")
                    .permissions()
                    .mode()
                    & 0o7777,
                0o1700,
                "the open must not change the private directory mode"
            );
            assert_eq!(
                std::fs::read_to_string(&marker_path).expect("the marker remains"),
                stored
            );
            assert_eq!(
                std::fs::read_to_string(&record_path).expect("the record remains"),
                record
            );
            assert_eq!(children(&private), [RECORD_FILE, PRIVATE_COMMIT_FILE]);
            assert_eq!(children(&root), [PRIVATE_DIRECTORY]);
        }
    }
}
