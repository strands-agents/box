// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use std::collections::HashMap;
#[cfg(unix)]
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::ops::ControlFlow;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::os::*;
use crate::vfs::{self, InodeData, LASH_GID, LASH_UID, Vfs};

/// The most dangling symlinks `resolved_target` replaces in one path.
const MAX_SYMLINK_HOPS: u32 = 40;

/// An outbound HTTP proxy the kernel routes every request through.
///
/// When a [`VfsKernel`] carries one, `http_request` dials the proxy instead of the
/// origin directly, and trusts `ca_pem` for the leaf certificates the proxy forges
/// on interception. This is how an embedder routes the Shell's outbound HTTP through
/// a governed boundary rather than letting the kernel reach the network itself. The
/// kernel still runs its SSRF floor first; the proxy is an *addition*, not a bypass.
#[derive(Clone)]
pub struct EgressProxy {
    /// The proxy URL, for example `http://127.0.0.1:8080`.
    pub target: String,
    /// PEM bytes of the CA the proxy signs its intercept leaves with.
    pub ca_pem: Vec<u8>,
    /// The response header this proxy sets on a refusal it originates itself.
    ///
    /// The proxy forges the origin's leaf certificate, so a refusal it synthesises inside the tunnel
    /// is otherwise indistinguishable from the origin answering with the same status — and a command
    /// that cannot tell them apart reports a refused request as a server response. When set, a
    /// response carrying this header is turned into `PermissionDenied` and never reaches a command
    /// as a response, so the header itself is never rendered. `None` keeps the response as it is.
    pub refusal_header: Option<String>,
}

/// A Kernel backed entirely by the in-memory VFS.
pub struct VfsKernel {
    pub vfs: Arc<Mutex<Vfs>>,
    pub network_enabled: bool,
    /// When set, `http_request` routes through this proxy rather than dialing the
    /// origin directly. `None` keeps the direct-client behaviour.
    pub egress_proxy: Option<EgressProxy>,
    /// When set, `run_script` forwards the source to this interpreter hook. `None`
    /// leaves `run_script` `Unsupported`, so a Shell with no hook refuses a script.
    pub script_interpreter: Option<crate::os::ScriptInterpreter>,
    /// When set, `spawn_host` forwards the binary to this hook.
    pub host_spawner: Option<crate::os::HostSpawner>,
    resolution_generation: Arc<Mutex<u64>>,
    pending_writes: std::sync::Mutex<Vec<PendingWrite>>,
}

/// Chunks a host writer may hold in flight before the writer waits for the drain.
const HOST_WRITER_DEPTH: usize = 64;

/// One file write whose drain task may still be running.
struct PendingWrite {
    path: String,
    writer: tokio::sync::mpsc::WeakSender<bytes::Bytes>,
    drain: tokio::task::JoinHandle<io::Result<()>>,
}

impl VfsKernel {
    pub fn new(vfs: Vfs) -> Self {
        Self {
            vfs: Arc::new(Mutex::new(vfs)),
            network_enabled: true,
            egress_proxy: None,
            script_interpreter: None,
            host_spawner: None,
            resolution_generation: Arc::new(Mutex::new(0)),
            pending_writes: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn track_write(
        &self,
        path: &str,
        writer: tokio::sync::mpsc::WeakSender<bytes::Bytes>,
        drain: tokio::task::JoinHandle<io::Result<()>>,
    ) {
        self.pending_writes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(PendingWrite {
                path: path.to_string(),
                writer,
                drain,
            });
    }

    /// The drains whose writers are all closed, removed from the pending list.
    fn closed_writes(&self) -> Vec<PendingWrite> {
        let mut pending = self
            .pending_writes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (closed, open): (Vec<_>, Vec<_>) = pending
            .drain(..)
            .partition(|write| write.writer.strong_count() == 0);
        *pending = open;
        closed
    }

    fn changed_resolution(generation: &mut u64) {
        *generation = generation.wrapping_add(1);
    }

    fn stale_resolution() -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "filesystem identity changed during effect admission",
        )
    }

    async fn resolution_is_current(&self, path: &Resolved, generation: u64) -> bool {
        if path.generation() != generation {
            return false;
        }
        let vfs = self.vfs.lock().await;
        Self::host_identity(&vfs, path.path(), path.follow()).as_ref() == path.host_identity()
    }

    async fn guard_resolution(
        &self,
        path: &Resolved,
    ) -> io::Result<tokio::sync::MutexGuard<'_, u64>> {
        let generation = self.resolution_generation.lock().await;
        if !self.resolution_is_current(path, *generation).await {
            return Err(Self::stale_resolution());
        }
        Ok(generation)
    }

    /// Resolve `abs_path` to the object an operation will actually act on.
    ///
    /// `abs` only normalizes the *string* — it applies the working directory and folds
    /// `.` and `..`. It does not follow symlinks, so admitting its output would
    /// authorize the link's own name while the operation reads the link's target. A
    /// policy denying a path could then be evaded by reading a symlink to it.
    ///
    /// Operations with follow semantics are therefore admitted on the fully resolved
    /// path. Operations that deliberately do not follow a final symlink — `lstat`,
    /// `read_link`, `remove_file`, and the link side of a pair — keep the unresolved
    /// spelling, because the link itself is the object they act on.
    ///
    /// A path whose leaf does not exist yet — a create, or `mkdir -p` several levels
    /// deep — still has its **existing ancestors** resolved, and the missing tail is
    /// appended to that canonical base. Resolving only the whole path would fall back
    /// to the unresolved spelling for every create, which is exactly the case a
    /// directory symlink exploits: `ln -s /secrets /alias` then writing
    /// `/alias/newfile` must be authorized as `/secrets/newfile`.
    ///
    /// A dangling symlink on the path is replaced by the path it names. A path that has too many
    /// symlinks for `Vfs::resolve` keeps its spelling.
    async fn resolved_target(&self, abs_path: &str) -> String {
        let vfs = self.vfs.lock().await;
        if vfs
            .resolve(abs_path, true)
            .is_err_and(|error| error.to_string() == vfs::SYMLINK_LOOP)
        {
            return abs_path.to_string();
        }
        let mut path = abs_path.to_string();
        for _ in 0..=MAX_SYMLINK_HOPS {
            match Self::resolve_existing_prefix(&vfs, &path) {
                ControlFlow::Break(resolved) => return resolved,
                ControlFlow::Continue(named) => path = named,
            }
        }
        abs_path.to_string()
    }

    /// Canonicalize the existing prefix of `abs_path` and re-append the missing tail.
    ///
    /// Continues with the path a dangling symlink names when the first missing component
    /// is one.
    fn resolve_existing_prefix(vfs: &Vfs, abs_path: &str) -> ControlFlow<String, String> {
        let (canonical, consumed) = vfs.canonicalize_prefix(abs_path);
        let normalized = vfs::normalize(abs_path);
        let mut components = normalized
            .split('/')
            .filter(|component| !component.is_empty())
            .skip(consumed);
        let Some(first) = components.next() else {
            return ControlFlow::Break(canonical);
        };
        let base = canonical.trim_end_matches('/');
        let child = format!("{base}/{first}");
        let dangling = Self::symlink_target(vfs, &child);
        let mut resolved = match &dangling {
            Some(target) if target.starts_with('/') => vfs::normalize(target),
            Some(target) => vfs::normalize(&format!("{base}/{target}")),
            None => child,
        };
        for component in components {
            resolved.push('/');
            resolved.push_str(component);
        }
        match dangling {
            Some(_) => ControlFlow::Continue(resolved),
            None => ControlFlow::Break(resolved),
        }
    }

    /// Whether the entry at `path` is itself a host bind.
    fn is_bind_point(vfs: &Vfs, path: &str) -> bool {
        vfs.resolve(path, false)
            .and_then(|ino| vfs.get(ino))
            .is_ok_and(|inode| {
                matches!(inode.data, InodeData::HostFile(..) | InodeData::HostDir(..))
            })
    }

    /// The refusal for removing or replacing a bind point.
    fn bind_point_busy() -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, "bind mount point is busy")
    }

    /// The target of the symlink at `path`, when the entry there is one.
    fn symlink_target(vfs: &Vfs, path: &str) -> Option<String> {
        let inode = vfs.get(vfs.resolve(path, false).ok()?).ok()?;
        match &inode.data {
            InodeData::Symlink(target) => Some(target.clone()),
            _ => None,
        }
    }

    /// Resolve a path relative to the process cwd, producing an absolute virtual path.
    fn abs(proc: &Process, path: &str) -> String {
        if path.starts_with('/') {
            vfs::normalize(path)
        } else {
            vfs::normalize(&format!("{}/{}", proc.cwd.display(), path))
        }
    }

    /// Check that the user has write permission on the parent directory of `abs_path`.
    fn check_parent_write(vfs: &Vfs, abs_path: &str) -> io::Result<()> {
        let parent = match abs_path.rfind('/') {
            Some(0) | None => "/".to_string(),
            Some(i) => abs_path[..i].to_string(),
        };
        if let Ok(parent_ino) = vfs.resolve(&parent, true)
            && !vfs.check_permission(parent_ino, LASH_UID, LASH_GID, 2)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "permission denied",
            ));
        }
        Ok(())
    }

    /// Check if a VFS path resolves to a host-backed inode (HostFile or HostDir).
    /// If the exact path is a HostFile/HostDir, returns the host path and readonly flag.
    /// If an ancestor is a HostDir, returns the host path with remaining components appended.
    /// For HostDir children, the resolved host path is canonicalized and verified
    /// to remain within the bind mount base to prevent symlink traversal escapes.
    /// Returns (host_path, readonly, canon_base) where canon_base is the
    /// canonicalized bind mount root (used by open_host for fd verification).
    fn resolve_host(vfs: &Vfs, abs_path: &str) -> Option<(PathBuf, bool, PathBuf)> {
        // First try exact match
        if let Ok(ino) = vfs.resolve(abs_path, true)
            && let Ok(inode) = vfs.get(ino)
        {
            match &inode.data {
                InodeData::HostFile(p, ro) | InodeData::HostDir(p, ro) => {
                    let pb = PathBuf::from(p);
                    let base = std::fs::canonicalize(&pb).unwrap_or_else(|_| pb.clone());
                    return Some((pb, *ro, base));
                }
                _ => {}
            }
        }
        // The HostDir ancestor, when there is one, is the longest prefix that resolves.
        let normalized = vfs::normalize(abs_path);
        let components: Vec<&str> = normalized.split('/').filter(|c| !c.is_empty()).collect();
        let resolves = |length: usize| {
            vfs.resolve(&format!("/{}", components[..length].join("/")), true)
                .ok()
        };
        let (mut low, mut high) = (0, components.len());
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            if resolves(middle).is_some() {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        if low > 0
            && let Some(ino) = resolves(low)
            && let Ok(inode) = vfs.get(ino)
            && let InodeData::HostDir(host_base, ro) = &inode.data
        {
            let rest = &components[low..];
            let mut host = PathBuf::from(host_base);
            for c in rest {
                host.push(c);
            }
            // Canonicalize and verify the path stays within the bind mount
            let canon_base =
                std::fs::canonicalize(host_base).unwrap_or_else(|_| PathBuf::from(host_base));
            if let Ok(canon_host) = std::fs::canonicalize(&host) {
                if !canon_host.starts_with(&canon_base) {
                    return None; // symlink escape — block access
                }
                return Some((canon_host, *ro, canon_base));
            }
            // canonicalize failed — check if path is a dangling symlink
            if host.symlink_metadata().is_ok() {
                return None; // dangling symlink pointing outside mount
            }
            // Path truly doesn't exist — verify parent is safe
            if let Some(parent) = host.parent()
                && let Ok(canon_parent) = std::fs::canonicalize(parent)
                && !canon_parent.starts_with(&canon_base)
            {
                return None;
            }
            return Some((host, *ro, canon_base));
        }
        None
    }

    fn resolve_host_for(
        vfs: &Vfs,
        abs_path: &str,
        follow: Follow,
    ) -> Option<(PathBuf, bool, PathBuf)> {
        if follow == Follow::Yes || Self::is_bind_point(vfs, abs_path) {
            return Self::resolve_host(vfs, abs_path);
        }
        let (parent, leaf) = match abs_path.rfind('/') {
            Some(0) => ("/", &abs_path[1..]),
            Some(index) => (&abs_path[..index], &abs_path[index + 1..]),
            None => ("", abs_path),
        };
        if leaf.is_empty() {
            return Self::resolve_host(vfs, abs_path);
        }
        let (host_parent, readonly, base) = Self::resolve_host(vfs, parent)?;
        Some((host_parent.join(leaf), readonly, base))
    }

    fn host_identity(vfs: &Vfs, abs_path: &str, follow: Follow) -> Option<HostIdentity> {
        let (path, _, _) = Self::resolve_host_for(vfs, abs_path, follow)?;
        let parent = path.parent()?.canonicalize().ok()?;
        let parent_metadata = std::fs::metadata(&parent).ok()?;
        let metadata = if follow == Follow::Yes {
            std::fs::metadata(&path)
        } else {
            std::fs::symlink_metadata(&path)
        };
        match metadata {
            Ok(metadata) => Some(HostIdentity::Present {
                path,
                parent,
                #[cfg(unix)]
                device: metadata.dev(),
                #[cfg(unix)]
                inode: metadata.ino(),
                #[cfg(unix)]
                parent_device: parent_metadata.dev(),
                #[cfg(unix)]
                parent_inode: parent_metadata.ino(),
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Some(HostIdentity::Missing {
                path,
                parent,
                #[cfg(unix)]
                parent_device: parent_metadata.dev(),
                #[cfg(unix)]
                parent_inode: parent_metadata.ino(),
            }),
            Err(_) => Some(HostIdentity::Unavailable { path }),
        }
    }

    #[cfg(unix)]
    fn opened_parent(host_path: &Path, expected: &HostIdentity) -> io::Result<(File, CString)> {
        let (identity_path, parent, parent_device, parent_inode) = match expected {
            HostIdentity::Present {
                path,
                parent,
                parent_device,
                parent_inode,
                ..
            }
            | HostIdentity::Missing {
                path,
                parent,
                parent_device,
                parent_inode,
            } => (path, parent, *parent_device, *parent_inode),
            HostIdentity::Unavailable { .. } => return Err(Self::stale_resolution()),
        };
        if identity_path != host_path {
            return Err(Self::stale_resolution());
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(parent)?;
        let metadata = directory.metadata()?;
        if metadata.dev() != parent_device || metadata.ino() != parent_inode {
            return Err(Self::stale_resolution());
        }
        let leaf = host_path.file_name().ok_or_else(Self::stale_resolution)?;
        let leaf = CString::new(leaf.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "host path contains a NUL byte")
        })?;
        Ok((directory, leaf))
    }

    #[cfg(unix)]
    fn open_host_file(
        host_path: &Path,
        flags: &OpenFlags,
        expected: Option<&HostIdentity>,
    ) -> io::Result<File> {
        let expected = expected.ok_or_else(Self::stale_resolution)?;
        let (parent, leaf) = Self::opened_parent(host_path, expected)?;
        let mut open_flags = if flags.write && (flags.read || flags.append) {
            libc::O_RDWR
        } else if flags.write {
            libc::O_WRONLY
        } else {
            libc::O_RDONLY
        };
        open_flags |= libc::O_CLOEXEC | libc::O_NOFOLLOW;
        if flags.create {
            open_flags |= libc::O_CREAT;
        }
        match expected {
            HostIdentity::Present { .. } => {}
            HostIdentity::Missing { .. } => {
                if !flags.create {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "host path does not exist",
                    ));
                }
                open_flags |= libc::O_EXCL;
            }
            HostIdentity::Unavailable { .. } => return Err(Self::stale_resolution()),
        }
        // SAFETY: parent and leaf are owned, valid handles. The returned descriptor is checked.
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                open_flags,
                0o666 as libc::c_uint,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned this owned descriptor and File closes it once.
        let file = unsafe { File::from_raw_fd(descriptor) };
        if let HostIdentity::Present { device, inode, .. } = expected {
            let metadata = file.metadata()?;
            if metadata.dev() != *device || metadata.ino() != *inode {
                return Err(Self::stale_resolution());
            }
        }
        if flags.truncate {
            file.set_len(0)?;
        }
        Ok(file)
    }

    #[cfg(not(unix))]
    fn open_host_file(
        host_path: &Path,
        flags: &OpenFlags,
        _expected: Option<&HostIdentity>,
    ) -> io::Result<File> {
        OpenOptions::new()
            .read(flags.read || flags.append)
            .write(flags.write)
            .create(flags.create)
            .append(flags.append)
            .truncate(flags.truncate)
            .open(host_path)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn open_host(
        &self,
        proc: &mut Process,
        spelled: &str,
        host_path: &std::path::Path,
        flags: &OpenFlags,
        expected: Option<&HostIdentity>,
    ) -> io::Result<Fd> {
        let mut file = Self::open_host_file(host_path, flags, expected)?;
        if flags.read && !flags.write {
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;
            let (tx, rx) = crate::os::pipe(data.len().max(64));
            let _ = tx.send(bytes::Bytes::from(data)).await;
            drop(tx);
            proc.alloc_fd(FdKind::ChannelReader {
                rx,
                buf: Vec::new(),
            })
        } else if flags.write {
            let (tx, rx) = crate::os::pipe(HOST_WRITER_DEPTH);
            let writer = tx.downgrade();
            let fd = proc.alloc_fd(FdKind::ChannelWriter {
                tx,
                limit: Some(WriteLimit::new(0, 0)),
            })?;
            let append = flags.append;
            let drain = tokio::task::spawn_local(async move {
                let mut rx = rx;
                let mut written = if append {
                    file.seek(SeekFrom::End(0))?
                } else {
                    0
                };
                while let Some(chunk) = rx.recv().await {
                    file.write_all(&chunk)?;
                    written += chunk.len() as u64;
                }
                if append {
                    Ok(())
                } else {
                    file.set_len(written)
                }
            });
            self.track_write(spelled, writer, drain);
            Ok(fd)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid open flags",
            ))
        }
    }

    #[cfg(unix)]
    fn unlink_host(
        host_path: &Path,
        expected: Option<&HostIdentity>,
        directory: bool,
    ) -> io::Result<()> {
        let expected = expected.ok_or_else(Self::stale_resolution)?;
        let (parent, leaf) = Self::opened_parent(host_path, expected)?;
        let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
        // SAFETY: parent and leaf are owned, valid handles.
        let result = unsafe { libc::unlinkat(parent.as_raw_fd(), leaf.as_ptr(), flags) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(not(unix))]
    fn unlink_host(
        host_path: &Path,
        _expected: Option<&HostIdentity>,
        directory: bool,
    ) -> io::Result<()> {
        if directory {
            std::fs::remove_dir(host_path)
        } else {
            std::fs::remove_file(host_path)
        }
    }

    #[cfg(unix)]
    fn create_host_directory(host_path: &Path, expected: Option<&HostIdentity>) -> io::Result<()> {
        let expected = expected.ok_or_else(Self::stale_resolution)?;
        let (parent, leaf) = Self::opened_parent(host_path, expected)?;
        // SAFETY: parent and leaf are owned, valid handles.
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), leaf.as_ptr(), 0o777) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(not(unix))]
    fn create_host_directory(host_path: &Path, _expected: Option<&HostIdentity>) -> io::Result<()> {
        std::fs::create_dir(host_path)
    }

    #[cfg(unix)]
    fn rename_host(
        from: &Path,
        from_expected: Option<&HostIdentity>,
        to: &Path,
        to_expected: Option<&HostIdentity>,
    ) -> io::Result<()> {
        let from_expected = from_expected.ok_or_else(Self::stale_resolution)?;
        let to_expected = to_expected.ok_or_else(Self::stale_resolution)?;
        let (from_parent, from_leaf) = Self::opened_parent(from, from_expected)?;
        let (to_parent, to_leaf) = Self::opened_parent(to, to_expected)?;
        // SAFETY: both parent and leaf pairs are owned, valid handles.
        let result = unsafe {
            libc::renameat(
                from_parent.as_raw_fd(),
                from_leaf.as_ptr(),
                to_parent.as_raw_fd(),
                to_leaf.as_ptr(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(not(unix))]
    fn rename_host(
        from: &Path,
        _from_expected: Option<&HostIdentity>,
        to: &Path,
        _to_expected: Option<&HostIdentity>,
    ) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    #[cfg(unix)]
    fn create_host_symlink(
        target: &str,
        link: &Path,
        expected: Option<&HostIdentity>,
    ) -> io::Result<()> {
        let expected = expected.ok_or_else(Self::stale_resolution)?;
        let (parent, leaf) = Self::opened_parent(link, expected)?;
        let target = CString::new(target.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "symlink target contains a NUL byte",
            )
        })?;
        // SAFETY: target, parent, and leaf are owned, valid handles.
        let result = unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), leaf.as_ptr()) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn set_host_permissions(
        host_path: &Path,
        mode: u32,
        expected: Option<&HostIdentity>,
    ) -> io::Result<()> {
        let expected = expected.ok_or_else(Self::stale_resolution)?;
        let (expected_device, expected_inode) = match expected {
            HostIdentity::Present { device, inode, .. } => (*device, *inode),
            HostIdentity::Missing { .. } | HostIdentity::Unavailable { .. } => {
                return Err(Self::stale_resolution());
            }
        };
        let (parent, leaf) = Self::opened_parent(host_path, expected)?;
        #[cfg(target_os = "linux")]
        {
            // `O_PATH` opens the leaf with no access check, and `/proc/self/fd` then names that exact
            // descriptor for `chmod`, so a leaf swapped for a symlink cannot redirect the change.
            let open_flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_PATH;
            // SAFETY: parent and leaf are owned, valid handles. The returned descriptor is checked.
            let descriptor =
                unsafe { libc::openat(parent.as_raw_fd(), leaf.as_ptr(), open_flags, 0) };
            if descriptor < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: openat returned this owned descriptor and File closes it once.
            let file = unsafe { File::from_raw_fd(descriptor) };
            let metadata = file.metadata()?;
            if metadata.dev() != expected_device || metadata.ino() != expected_inode {
                return Err(Self::stale_resolution());
            }
            let descriptor_path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
                .expect("descriptor path has no NUL byte");
            // SAFETY: the proc path names the exact open descriptor whose identity was verified.
            let result = unsafe { libc::chmod(descriptor_path.as_ptr(), mode as libc::mode_t) };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        #[cfg(target_os = "macos")]
        {
            // macOS has no permission-free `O_PATH`: `O_EVTONLY` still needs read authorization and
            // fails `EACCES` on a mode-0 file the process owns. So verify the leaf identity with
            // `fstatat` and change it with `fchmodat`, both under the parent fd `opened_parent`
            // pinned by (device, inode), and both `AT_SYMLINK_NOFOLLOW` so a leaf swapped for a
            // symlink is not followed.
            let mut leaf_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: parent and leaf are owned, valid handles; leaf_stat is written before it is read.
            let statted = unsafe {
                libc::fstatat(
                    parent.as_raw_fd(),
                    leaf.as_ptr(),
                    leaf_stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if statted < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fstatat returned 0, so leaf_stat is initialized.
            let leaf_stat = unsafe { leaf_stat.assume_init() };
            if leaf_stat.st_dev as u64 != expected_device || leaf_stat.st_ino != expected_inode {
                return Err(Self::stale_resolution());
            }
            // SAFETY: parent and leaf are owned, valid handles.
            let result = unsafe {
                libc::fchmodat(
                    parent.as_raw_fd(),
                    leaf.as_ptr(),
                    mode as libc::mode_t,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    fn set_host_permissions(
        _host_path: &Path,
        _mode: u32,
        _expected: Option<&HostIdentity>,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "descriptor-bound host chmod requires Linux or macOS",
        ))
    }

    #[cfg(target_arch = "wasm32")]
    async fn open_host(
        &self,
        proc: &mut Process,
        spelled: &str,
        host_path: &std::path::Path,
        flags: &OpenFlags,
        _expected: Option<&HostIdentity>,
    ) -> io::Result<Fd> {
        if flags.read && !flags.write {
            use std::io::Read;
            let mut file = std::fs::File::open(host_path)?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;
            let (tx, rx) = crate::os::pipe(data.len().max(64));
            let _ = tx.send(bytes::Bytes::from(data)).await;
            drop(tx);
            proc.alloc_fd(FdKind::ChannelReader {
                rx,
                buf: Vec::new(),
            })
        } else if flags.write {
            let (tx, rx) = crate::os::pipe(HOST_WRITER_DEPTH);
            let writer = tx.downgrade();
            let fd = proc.alloc_fd(FdKind::ChannelWriter {
                tx,
                limit: Some(WriteLimit::new(0, 0)),
            })?;
            let path = host_path.to_path_buf();
            let append = flags.append;
            let drain = tokio::task::spawn_local(async move {
                let mut rx = rx;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .append(append)
                    .truncate(!append)
                    .open(&path)?;
                while let Some(chunk) = rx.recv().await {
                    file.write_all(&chunk)?;
                }
                Ok(())
            });
            self.track_write(spelled, writer, drain);
            Ok(fd)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid open flags",
            ))
        }
    }
}

/// The effect implementations. Each performs one effect on an already-resolved
/// path. Admission happened above the trait, in `Mediated`; nothing here decides.
impl VfsKernel {
    fn new_process(&self) -> Process {
        let cwd = PathBuf::from("/home/lash");
        let mut env = HashMap::new();
        env.insert("HOME".into(), "/home/lash".into());
        env.insert("PWD".into(), "/home/lash".into());
        env.insert("PATH".into(), "/usr/bin:/bin".into());
        env.insert("USER".into(), "lash".into());
        Process::new(cwd, env)
    }

    async fn open_effect(
        &self,
        proc: &mut Process,
        path: &str,
        flags: OpenFlags,
        expected: Option<&HostIdentity>,
    ) -> io::Result<Fd> {
        let abs = Self::abs(proc, path);

        // Check for host-backed path (bind_direct passthrough)
        {
            let vfs = self.vfs.lock().await;
            if let Some((host_path, ro, _)) = Self::resolve_host(&vfs, &abs) {
                drop(vfs);
                if ro && (flags.write || flags.create || flags.truncate) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "read-only bind mount",
                    ));
                }
                return self
                    .open_host(proc, &abs, &host_path, &flags, expected)
                    .await;
            }
        }

        let mut vfs = self.vfs.lock().await;

        let ino = if flags.create {
            match vfs.resolve(&abs, true) {
                Ok(ino) => {
                    // File exists — check write permission on the file for truncate
                    if (flags.write || flags.truncate)
                        && !vfs.check_permission(ino, LASH_UID, LASH_GID, 2)
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "permission denied",
                        ));
                    }
                    if flags.truncate && matches!(vfs.get(ino)?.data, InodeData::File(_)) {
                        vfs.write_file(ino, Vec::new())?;
                    }
                    ino
                }
                Err(_) => {
                    // Create new file — need write permission on parent directory
                    Self::check_parent_write(&vfs, &abs)?;
                    vfs.create_file(&abs, 0o644, LASH_UID, LASH_GID)?
                }
            }
        } else {
            let ino = vfs.resolve(&abs, true)?;
            if flags.write && !vfs.check_permission(ino, LASH_UID, LASH_GID, 2) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "permission denied",
                ));
            }
            ino
        };

        // For device nodes, return special readers/writers
        let inode = vfs.get(ino)?;
        match &inode.data {
            InodeData::CharDevice(1, 3) => {
                // /dev/null
                drop(vfs);
                return make_dev_null_fd(proc, &flags);
            }
            InodeData::CharDevice(1, 5) => {
                // /dev/zero
                drop(vfs);
                return make_dev_zero_fd(proc, &flags);
            }
            InodeData::CharDevice(1, 8) | InodeData::CharDevice(1, 9) => {
                // /dev/random, /dev/urandom
                drop(vfs);
                return make_dev_urandom_fd(proc, &flags);
            }
            _ => {}
        }

        // For regular files, create a channel-based fd backed by the file data
        let data = match &inode.data {
            InodeData::File(d) => d.clone(),
            InodeData::Dir(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "is a directory",
                ));
            }
            _ => Vec::new(),
        };

        drop(vfs);

        if flags.read && !flags.write {
            let (tx, rx) = crate::os::pipe(data.len().max(64));
            let _ = tx.send(bytes::Bytes::from(data)).await;
            drop(tx);
            proc.alloc_fd(FdKind::ChannelReader {
                rx,
                buf: Vec::new(),
            })
        } else if flags.read && flags.write {
            // Read-write (<>): provide existing data as a reader.
            // The channel model doesn't support true read-write on one fd,
            // so we give a reader seeded with the current contents.
            let (tx, rx) = crate::os::pipe(data.len().max(64));
            let _ = tx.send(bytes::Bytes::from(data)).await;
            drop(tx);
            proc.alloc_fd(FdKind::ChannelReader {
                rx,
                buf: Vec::new(),
            })
        } else if flags.write {
            // For writes, we use a channel that collects data and flushes to VFS
            let vfs_ref = self.vfs.clone();
            let max_file_size = self.vfs.lock().await.max_file_size;
            let held = if flags.append { data.len() } else { 0 };
            let limit = WriteLimit::new(max_file_size, held);
            // A file already at the cap cannot grow, so the append is refused at open.
            if max_file_size > 0 && held >= max_file_size {
                return Err(limit.exceeded());
            }
            let (tx, rx) = crate::os::pipe(8192);
            let writer = tx.downgrade();
            let fd = proc.alloc_fd(FdKind::ChannelWriter {
                tx,
                limit: Some(limit.clone()),
            })?;
            let append = flags.append;
            // Spawn a task to collect writes and flush to VFS
            let drain = tokio::task::spawn_local(async move {
                let mut rx = rx;
                let mut buf = if append {
                    let v = vfs_ref.lock().await;
                    v.read_file(ino).unwrap_or(&[]).to_vec()
                } else {
                    Vec::new()
                };
                while let Some(chunk) = rx.recv().await {
                    buf.extend_from_slice(&chunk);
                }
                let mut v = vfs_ref.lock().await;
                v.write_file(ino, buf)
            });
            self.track_write(&abs, writer, drain);
            Ok(fd)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid open flags",
            ))
        }
    }

    async fn list_dir_effect(&self, proc: &Process, path: &str) -> io::Result<Vec<DirEntry>> {
        let abs = Self::abs(proc, path);
        let vfs = self.vfs.lock().await;

        if let Some((host_path, _ro, _)) = Self::resolve_host(&vfs, &abs) {
            drop(vfs);
            let mut entries = Vec::new();
            for entry in std::fs::read_dir(&host_path)? {
                let entry = entry?;
                let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
                entries.push(DirEntry {
                    name: entry.file_name().to_string_lossy().into_owned(),
                    is_dir,
                });
            }
            return Ok(entries);
        }

        let ino = vfs.resolve(&abs, true)?;
        let entries = vfs.read_dir(ino)?;
        Ok(entries
            .into_iter()
            .map(|(name, child_ino)| {
                let is_dir = vfs
                    .get(child_ino)
                    .map(|i| matches!(i.data, InodeData::Dir(_)))
                    .unwrap_or(false);
                DirEntry { name, is_dir }
            })
            .collect())
    }

    async fn change_dir_effect(&self, proc: &mut Process, path: &str) -> io::Result<()> {
        let abs = Self::abs(proc, path);
        let vfs = self.vfs.lock().await;

        if let Some((host_path, _ro, _)) = Self::resolve_host(&vfs, &abs) {
            drop(vfs);
            let meta = std::fs::metadata(&host_path)?;
            if !meta.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "Not a directory",
                ));
            }
            proc.cwd = PathBuf::from(&abs);
            return Ok(());
        }

        let ino = vfs.resolve(&abs, true)?;
        let inode = vfs.get(ino)?;
        if !matches!(inode.data, InodeData::Dir(_)) {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "Not a directory",
            ));
        }
        proc.cwd = PathBuf::from(&abs);
        Ok(())
    }

    async fn stat_effect(&self, proc: &Process, path: &str) -> FileStat {
        let abs = Self::abs(proc, path);
        let vfs = self.vfs.lock().await;

        if let Some((host_path, _ro, _)) = Self::resolve_host(&vfs, &abs) {
            drop(vfs);
            #[cfg(not(target_arch = "wasm32"))]
            return host_stat(&host_path).await;
            #[cfg(target_arch = "wasm32")]
            return host_stat_sync(&host_path);
        }

        match vfs.resolve(&abs, true) {
            Ok(ino) => vfs.inode_to_filestat(ino),
            Err(_) => FileStat::default(),
        }
    }

    async fn lstat_effect(&self, proc: &Process, path: &str) -> FileStat {
        let abs = Self::abs(proc, path);
        let vfs = self.vfs.lock().await;

        if let Some((host_path, _ro, _)) = Self::resolve_host(&vfs, &abs) {
            drop(vfs);
            #[cfg(not(target_arch = "wasm32"))]
            return host_stat(&host_path).await;
            #[cfg(target_arch = "wasm32")]
            return host_stat_sync(&host_path);
        }

        match vfs.resolve(&abs, false) {
            Ok(ino) => vfs.inode_to_filestat(ino),
            Err(_) => FileStat::default(),
        }
    }

    async fn access_effect(&self, proc: &Process, path: &str, mode: i32) -> bool {
        let abs = Self::abs(proc, path);
        let vfs = self.vfs.lock().await;

        if let Some((host_path, ro, _)) = Self::resolve_host(&vfs, &abs) {
            drop(vfs);
            if mode == 0 {
                return std::fs::metadata(&host_path).is_ok();
            }
            if ro && mode & ACCESS_W != 0 {
                return false;
            }
            let meta = match std::fs::metadata(&host_path) {
                Ok(m) => m,
                Err(_) => return false,
            };
            if mode & ACCESS_W != 0 && meta.permissions().readonly() {
                return false;
            }
            return true;
        }
        {
            let ino = match vfs.resolve(&abs, true) {
                Ok(i) => i,
                Err(_) => return false,
            };
            if mode == 0 {
                return true;
            }
            let want =
                ((mode & ACCESS_R) >> 2) << 2 | ((mode & ACCESS_W) >> 1) << 1 | (mode & ACCESS_X);
            vfs.check_permission(ino, LASH_UID, LASH_GID, want as u32)
        }
    }

    async fn canonicalize_effect(&self, proc: &Process, path: &str) -> io::Result<PathBuf> {
        let abs = Self::abs(proc, path);
        let vfs = self.vfs.lock().await;
        // Resolve to verify the path exists and follow symlinks
        let _ = vfs.resolve(&abs, true)?;
        Ok(PathBuf::from(vfs.canonicalize_path(&abs)?))
    }

    async fn is_executable_effect(&self, proc: &Process, path: &str) -> bool {
        let abs = Self::abs(proc, path);
        let vfs = self.vfs.lock().await;

        if let Some((_host_path, _ro, _)) = Self::resolve_host(&vfs, &abs) {
            drop(vfs);
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if let Ok(m) = std::fs::metadata(&_host_path) {
                    return m.is_file() && m.mode() & 0o111 != 0;
                }
            }
            return false;
        }

        match vfs.resolve(&abs, true) {
            Ok(ino) => {
                let inode = match vfs.get(ino) {
                    Ok(i) => i,
                    Err(_) => return false,
                };
                matches!(inode.data, InodeData::File(_)) && inode.mode & 0o111 != 0
            }
            Err(_) => false,
        }
    }

    async fn glob_effect(&self, proc: &Process, pattern: &str) -> Vec<String> {
        let abs_pattern = Self::abs(proc, pattern);
        let vfs = self.vfs.lock().await;
        let mut results = Vec::new();
        glob_vfs(&vfs, &abs_pattern, &mut results);
        // Convert back to relative if pattern was relative
        if !pattern.starts_with('/') {
            let cwd = format!("{}/", proc.cwd.display());
            results = results
                .into_iter()
                .map(|p| p.strip_prefix(&cwd).unwrap_or(&p).to_string())
                .collect();
        }
        results.sort();
        results
    }

    fn isatty(&self, _fd: i32) -> bool {
        false
    }

    async fn remove_file_effect(
        &self,
        proc: &Process,
        path: &str,
        expected: Option<&HostIdentity>,
    ) -> io::Result<()> {
        let abs = Self::abs(proc, path);
        let vfs = self.vfs.lock().await;
        if Self::is_bind_point(&vfs, &abs) {
            return Err(Self::bind_point_busy());
        }
        if let Some((host_path, ro, _)) = Self::resolve_host_for(&vfs, &abs, Follow::No) {
            drop(vfs);
            if ro {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "read-only bind mount",
                ));
            }
            return Self::unlink_host(&host_path, expected, false);
        }
        Self::check_parent_write(&vfs, &abs)?;
        drop(vfs);
        self.vfs.lock().await.unlink(&abs)
    }

    async fn remove_dir_effect(
        &self,
        proc: &Process,
        path: &str,
        expected: Option<&HostIdentity>,
    ) -> io::Result<()> {
        let abs = Self::abs(proc, path);
        let vfs = self.vfs.lock().await;
        if let Some((host_path, ro, _)) = Self::resolve_host(&vfs, &abs) {
            drop(vfs);
            if ro {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "read-only bind mount",
                ));
            }
            return Self::unlink_host(&host_path, expected, true);
        }
        Self::check_parent_write(&vfs, &abs)?;
        drop(vfs);
        self.vfs.lock().await.rmdir(&abs)
    }

    async fn create_dir_effect(
        &self,
        proc: &Process,
        path: &str,
        expected: Option<&HostIdentity>,
    ) -> io::Result<()> {
        let abs = Self::abs(proc, path);
        let vfs = self.vfs.lock().await;
        if let Some((host_path, ro, _)) = Self::resolve_host_for(&vfs, &abs, Follow::No) {
            drop(vfs);
            if ro {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "read-only bind mount",
                ));
            }
            return Self::create_host_directory(&host_path, expected);
        }
        Self::check_parent_write(&vfs, &abs)?;
        drop(vfs);
        self.vfs
            .lock()
            .await
            .mkdir(&abs, 0o755, LASH_UID, LASH_GID)?;
        Ok(())
    }

    async fn rename_effect(
        &self,
        proc: &Process,
        from: &str,
        from_expected: Option<&HostIdentity>,
        to: &str,
        to_expected: Option<&HostIdentity>,
    ) -> io::Result<()> {
        let abs_from = Self::abs(proc, from);
        let abs_to = Self::abs(proc, to);
        let vfs = self.vfs.lock().await;
        let host_from = Self::resolve_host(&vfs, &abs_from);
        let host_to = Self::resolve_host_for(&vfs, &abs_to, Follow::No);
        if let Some((host_path, _, _)) = &host_to {
            match host_path.symlink_metadata() {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "cannot rename onto a host symlink",
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        if host_from.is_none() && host_to.is_none() {
            Self::check_parent_write(&vfs, &abs_from)?;
            Self::check_parent_write(&vfs, &abs_to)?;
        }
        drop(vfs);
        match (host_from, host_to) {
            (Some((_, true, _)), _) | (_, Some((_, true, _))) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read-only bind mount",
            )),
            (Some((hf, _, _)), Some((ht, _, _))) => {
                Self::rename_host(&hf, from_expected, &ht, to_expected)
            }
            (None, None) => self.vfs.lock().await.rename(&abs_from, &abs_to),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot rename between host and virtual filesystem",
            )),
        }
    }

    /// Refuse a host symlink whose target is absolute or escapes the bind mount.
    #[cfg(unix)]
    fn verify_symlink_target(
        target: &str,
        host_link: &std::path::Path,
        canon_base: &std::path::Path,
    ) -> io::Result<()> {
        let escaped = || {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "symlink target escapes the bind mount",
            )
        };
        if target.starts_with('/') {
            return Err(escaped());
        }
        let link_dir = host_link.parent().unwrap_or(canon_base);
        let mut resolved = link_dir.canonicalize().map_err(|_| escaped())?;
        if !resolved.starts_with(canon_base) {
            return Err(escaped());
        }
        let mut exists = true;
        for component in std::path::Path::new(target).components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    resolved.pop();
                    if !resolved.starts_with(canon_base) {
                        return Err(escaped());
                    }
                    exists = match std::fs::symlink_metadata(&resolved) {
                        Ok(_) => true,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                        Err(_) => return Err(escaped()),
                    };
                }
                std::path::Component::Normal(name) => {
                    resolved.push(name);
                    if exists {
                        match std::fs::symlink_metadata(&resolved) {
                            Ok(metadata) if metadata.file_type().is_symlink() => {
                                resolved = resolved.canonicalize().map_err(|_| escaped())?;
                            }
                            Ok(_) => {}
                            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                                exists = false;
                            }
                            Err(_) => return Err(escaped()),
                        }
                    }
                    if !resolved.starts_with(canon_base) {
                        return Err(escaped());
                    }
                }
                _ => return Err(escaped()),
            }
        }
        Ok(())
    }

    async fn symlink_effect(
        &self,
        proc: &Process,
        target: &str,
        link: &str,
        expected: Option<&HostIdentity>,
    ) -> io::Result<()> {
        let abs_link = Self::abs(proc, link);
        let mut vfs = self.vfs.lock().await;
        if Self::is_bind_point(&vfs, &abs_link) {
            return Err(Self::bind_point_busy());
        }
        if let Some((host_link, ro, canon_base)) =
            Self::resolve_host_for(&vfs, &abs_link, Follow::No)
        {
            drop(vfs);
            if ro {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "read-only bind mount",
                ));
            }
            #[cfg(unix)]
            {
                Self::verify_symlink_target(target, &host_link, &canon_base)?;
                return Self::create_host_symlink(target, &host_link, expected);
            }
            #[cfg(not(unix))]
            {
                let _ = (&target, &host_link, &canon_base);
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "host-backed symlink requires a unix target",
                ));
            }
        }
        // One lock across the permission check and the create, as the original did, so a
        // concurrent task cannot change the parent's permissions between them.
        Self::check_parent_write(&vfs, &abs_link)?;
        vfs.symlink(&abs_link, target, LASH_UID, LASH_GID)?;
        Ok(())
    }

    async fn read_link_effect(&self, proc: &Process, path: &str) -> io::Result<String> {
        let abs = Self::abs(proc, path);
        let vfs = self.vfs.lock().await;
        // `readlink` reads the link itself, so resolve the parent to its host directory and
        // read the leaf there — resolving the full path would follow the final link and return
        // its target instead.
        let (parent, leaf) = match abs.rfind('/') {
            Some(0) => ("/".to_string(), &abs[1..]),
            Some(i) => (abs[..i].to_string(), &abs[i + 1..]),
            None => (String::new(), abs.as_str()),
        };
        if !leaf.is_empty()
            && let Some((host_parent, _ro, _)) = Self::resolve_host(&vfs, &parent)
        {
            drop(vfs);
            let target = std::fs::read_link(host_parent.join(leaf))?;
            return Ok(target.to_string_lossy().into_owned());
        }
        let ino = vfs.resolve(&abs, false)?;
        match &vfs.get(ino)?.data {
            InodeData::Symlink(target) => Ok(target.clone()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a symbolic link",
            )),
        }
    }

    async fn set_permissions_effect(
        &self,
        proc: &Process,
        path: &str,
        mode: u32,
        expected: Option<&HostIdentity>,
    ) -> io::Result<()> {
        let abs = Self::abs(proc, path);
        let mut vfs = self.vfs.lock().await;
        if let Some((host_path, ro, _)) = Self::resolve_host(&vfs, &abs) {
            drop(vfs);
            if ro {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "read-only bind mount",
                ));
            }
            // The Shell runs outside the OS cage on inodes a writable bind shares with the
            // operator's real filesystem, so setuid/setgid/sticky here would land an authority
            // bit on the real disk honoured by a process outside the box. `write` cannot set one;
            // `chmod` can, so refuse it here rather than silently strip.
            if mode & 0o7000 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "setuid/setgid/sticky bits are not permitted in this box",
                ));
            }
            #[cfg(unix)]
            {
                return Self::set_host_permissions(&host_path, mode & 0o777, expected);
            }
            #[cfg(not(unix))]
            {
                let _ = &host_path;
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "host-backed chmod requires a unix target",
                ));
            }
        }
        let ino = vfs.resolve(&abs, true)?;
        let inode = vfs.get_mut(ino)?;
        // Only the file owner can chmod
        if inode.uid != LASH_UID && LASH_UID != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "permission denied",
            ));
        }
        // Preserve the file type bits, replace permission bits
        inode.mode = (inode.mode & 0o170000) | (mode & 0o7777);
        Ok(())
    }

    fn now(&self) -> std::time::SystemTime {
        std::time::SystemTime::now()
    }

    /// The two controls every outbound URL passes, in order.
    ///
    /// Neither is authorization. `network_enabled` is the embedder's blanket
    /// off-switch, and [`check_url_safe`] is the SSRF floor — a deny-only guard
    /// against reaching IMDS, link-local, loopback, and RFC1918 addresses. Both
    /// hold unconditionally; neither can grant. The authorization decision for a
    /// request belongs to the egress boundary the workload is confined to.
    fn check_url_effect(&self, url: &str) -> io::Result<()> {
        if !self.network_enabled {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "network access disabled",
            ));
        }
        check_url_safe(url)
    }

    async fn http_request_effect(&self, req: HttpRequest) -> io::Result<HttpResponse> {
        // The floor runs before any transport, direct or supplied, so a routed
        // request cannot reach an address a direct one could not.
        self.check_url_effect(&req.url)?;

        #[cfg(not(target_arch = "wasm32"))]
        {
            // 1. Build reqwest client. `req.insecure` (a `curl -k`) is honored ONLY on the
            // direct-dial path below — never on the proxy path, where it would let the
            // caller turn off the gateway-CA pin from inside the Shell.
            let client_builder =
                reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
            let client_builder = match &self.egress_proxy {
                // Route through the governed boundary and trust its intercept CA. DNS
                // is the proxy's job on the CONNECT path, so `SafeResolver` does not
                // apply here — the proxy enforces its own destination floor, and the
                // kernel already ran `check_url_effect` above.
                Some(proxy) => client_builder
                    .proxy(
                        reqwest::Proxy::all(&proxy.target)
                            .map_err(|e| io::Error::other(e.to_string()))?,
                    )
                    // Trust ONLY the gateway's intercept CA — drop the built-in WebPKI
                    // roots. The gateway forges every leaf from that one CA, so nothing
                    // else should validate: a real public-CA certificate reaching this
                    // client (a proxy misconfig, a future direct-dial bug) must fail
                    // rather than be accepted. This mirrors the workload, whose
                    // `SSL_CERT_FILE` is the gateway CA alone, not an addition to the
                    // system store.
                    //
                    // `req.insecure` is deliberately NOT applied here: the gateway-CA pin
                    // must not be defeatable from inside the Shell. A `curl -k` cannot
                    // disable validation on the client→gateway leg; the gateway's forged
                    // leaf is always valid against its own CA, and whether the *upstream*
                    // leg tolerates a bad cert is the gateway's decision, not the client's.
                    .tls_built_in_root_certs(false)
                    .add_root_certificate(
                        reqwest::Certificate::from_pem(&proxy.ca_pem)
                            .map_err(|e| io::Error::other(e.to_string()))?,
                    ),
                // No proxy: dial the origin directly, guarding DNS with the SSRF-aware
                // resolver so a name cannot resolve onto a floored address. Only here does
                // `req.insecure` (a `curl -k`) relax certificate validation.
                None => client_builder
                    .danger_accept_invalid_certs(req.insecure)
                    .dns_resolver(std::sync::Arc::new(SafeResolver)),
            };
            let client = client_builder
                .build()
                .map_err(|e| io::Error::other(e.to_string()))?;

            // 2. Build the request
            let method: reqwest::Method = req.method.parse().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("bad HTTP method: {}", req.method),
                )
            })?;
            let mut http_req = client.request(method, &req.url);

            // 3. Set headers
            for (name, value) in &req.headers {
                http_req = http_req.header(name.as_str(), value.as_str());
            }

            // 4. Set body
            if let Some(body) = req.body {
                http_req = http_req.body(body);
            }

            // 5. Send
            let mut resp = http_req
                .send()
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))?;

            // **A refusal the proxy originated is a refusal, not a response.** Checked before the
            // response is built, so no command can render it and no caller can read the marker: the
            // body carries the reason the gateway recorded, and `PermissionDenied` is the kind every
            // command already maps to a non-zero exit.
            if let Some(proxy) = &self.egress_proxy
                && let Some(marker) = &proxy.refusal_header
                && resp.headers().contains_key(marker.as_str())
            {
                let reason = resp.text().await.unwrap_or_default();
                let reason = reason.trim();
                let reason = if reason.is_empty() {
                    "the egress gateway refused this request".to_string()
                } else {
                    reason.lines().next().unwrap_or(reason).to_string()
                };
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, reason));
            }

            // 6. Build response
            let status = resp.status().as_u16();
            let version = match resp.version() {
                reqwest::Version::HTTP_11 => "1.1",
                reqwest::Version::HTTP_2 => "2",
                _ => "1.0",
            }
            .to_string();
            let reason = resp.status().canonical_reason().unwrap_or("").to_string();
            let headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let body = if req.max_response > 0 {
                let mut buf = Vec::new();
                while let Some(chunk) = resp
                    .chunk()
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?
                {
                    if buf.len() + chunk.len() > req.max_response {
                        return Err(io::Error::other("response body too large"));
                    }
                    buf.extend_from_slice(&chunk);
                }
                buf
            } else {
                resp.bytes()
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?
                    .to_vec()
            };

            Ok(HttpResponse {
                status,
                headers,
                body,
                version,
                reason,
            })
        }

        #[cfg(target_arch = "wasm32")]
        {
            use wasi::http::outgoing_handler;
            use wasi::http::types::{
                Fields, IncomingBody, Method, OutgoingBody, OutgoingRequest, Scheme,
            };

            // 1. Parse URL
            let parsed = url::Url::parse(&req.url)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

            // 2. Build method
            let method = match req.method.to_uppercase().as_str() {
                "GET" => Method::Get,
                "POST" => Method::Post,
                "PUT" => Method::Put,
                "DELETE" => Method::Delete,
                "PATCH" => Method::Patch,
                "HEAD" => Method::Head,
                other => Method::Other(other.to_string()),
            };

            // 4. Build headers
            let fields = Fields::new();
            for (name, value) in &req.headers {
                let _ = fields.append(&name.to_lowercase(), &value.as_bytes().to_vec());
            }

            // 5. Build scheme, authority, path
            let scheme = if parsed.scheme() == "https" {
                Some(&Scheme::Https)
            } else {
                Some(&Scheme::Http)
            };
            let authority = parsed.host_str().map(|h| {
                if let Some(port) = parsed.port() {
                    format!("{h}:{port}")
                } else {
                    h.to_string()
                }
            });
            let path_and_query = if let Some(q) = parsed.query() {
                format!("{}?{}", parsed.path(), q)
            } else {
                parsed.path().to_string()
            };

            // 6. Create outgoing request
            let out_req = OutgoingRequest::new(fields);
            out_req
                .set_method(&method)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to set method"))?;
            out_req
                .set_scheme(scheme)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to set scheme"))?;
            out_req
                .set_authority(authority.as_deref())
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to set authority"))?;
            out_req
                .set_path_with_query(Some(&path_and_query))
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to set path"))?;

            // 7. Write body if present
            if let Some(body_bytes) = &req.body {
                let out_body = out_req.body().map_err(|_| {
                    io::Error::new(io::ErrorKind::Other, "failed to get outgoing body")
                })?;
                let stream = out_body.write().map_err(|_| {
                    io::Error::new(io::ErrorKind::Other, "failed to get write stream")
                })?;
                stream.blocking_write_and_flush(body_bytes).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("write body: {e:?}"))
                })?;
                drop(stream);
                OutgoingBody::finish(out_body, None)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to finish body"))?;
            } else {
                let out_body = out_req.body().map_err(|_| {
                    io::Error::new(io::ErrorKind::Other, "failed to get outgoing body")
                })?;
                OutgoingBody::finish(out_body, None)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to finish body"))?;
            }

            // 8. Send request
            let future_resp = outgoing_handler::handle(out_req, None).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("send request: {e:?}"))
            })?;

            // 9. Block until response is ready
            let incoming_resp = loop {
                if let Some(result) = future_resp.get() {
                    break result
                        .map_err(|_| io::Error::new(io::ErrorKind::Other, "response error"))?
                        .map_err(|e| {
                            io::Error::new(io::ErrorKind::Other, format!("HTTP error: {e:?}"))
                        })?;
                }
                // Yield to WASI event loop
                future_resp.subscribe().block();
            };

            // 10. Read response status and headers
            let status = incoming_resp.status();
            let resp_headers: Vec<(String, String)> = incoming_resp
                .headers()
                .entries()
                .into_iter()
                .map(|(k, v)| (k, String::from_utf8_lossy(&v).to_string()))
                .collect();

            // 11. Read response body
            let incoming_body = incoming_resp.consume().map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "failed to consume response body")
            })?;
            let body_stream = incoming_body
                .stream()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to get body stream"))?;
            let mut body = Vec::new();
            loop {
                match body_stream.read(65536) {
                    Ok(chunk) => {
                        if req.max_response > 0 && body.len() + chunk.len() > req.max_response {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                "response body too large",
                            ));
                        }
                        body.extend_from_slice(&chunk);
                    }
                    Err(wasi::io::streams::StreamError::Closed) => break,
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("read body: {e:?}"),
                        ));
                    }
                }
            }
            drop(body_stream);
            IncomingBody::finish(incoming_body);

            // 12. Map status to reason
            let reason = match status {
                200 => "OK",
                201 => "Created",
                204 => "No Content",
                301 => "Moved Permanently",
                302 => "Found",
                304 => "Not Modified",
                400 => "Bad Request",
                401 => "Unauthorized",
                403 => "Forbidden",
                404 => "Not Found",
                405 => "Method Not Allowed",
                409 => "Conflict",
                500 => "Internal Server Error",
                502 => "Bad Gateway",
                503 => "Service Unavailable",
                _ => "",
            }
            .to_string();

            Ok(HttpResponse {
                status,
                headers: resp_headers,
                body,
                version: "1.1".to_string(),
                reason,
            })
        }
    }
}

#[async_trait]
impl Kernel for VfsKernel {
    fn new_process(&self) -> Process {
        VfsKernel::new_process(self)
    }

    /// Applies the working directory, then resolves per `follow`.
    ///
    /// `Self::abs` normalizes the string only. `Self::resolved_target` additionally
    /// follows symlinks and handles a not-yet-existing leaf by canonicalizing its
    /// existing ancestors — which is what makes a create authorize under its real
    /// parent rather than under a symlink's name.
    async fn resolve(&self, proc: &Process, path: &str, follow: Follow) -> Resolved {
        let generation = self.resolution_generation.lock().await;
        let abs = Self::abs(proc, path);
        let resolved = match follow {
            Follow::Yes => self.resolved_target(&abs).await,
            // `Follow::No` exempts the *final* component only. Intermediate symlinks
            // are still traversed, exactly as `lstat` and `unlink` traverse them — so
            // the parent is resolved and the leaf re-appended verbatim. Leaving the
            // whole path unresolved would let `rm /alias/f` be judged on the alias
            // while unlinking `/vault/f`.
            Follow::No => match abs.rfind('/') {
                Some(0) | None => abs,
                Some(slash) => {
                    let (parent, leaf) = abs.split_at(slash);
                    let base = self.resolved_target(parent).await;
                    format!("{}{leaf}", base.trim_end_matches('/'))
                }
            },
        };
        let host_identity = {
            let vfs = self.vfs.lock().await;
            Self::host_identity(&vfs, &resolved, follow)
        };
        Resolved::new(resolved, follow, *generation, host_identity)
    }

    async fn settle_writes(&self) -> Vec<WriteFailure> {
        let mut failures = Vec::new();
        for write in self.closed_writes() {
            let outcome = match write.drain.await {
                Ok(outcome) => outcome,
                Err(_) => Err(io::Error::other("write task failed")),
            };
            if let Err(error) = outcome {
                failures.push(WriteFailure {
                    path: write.path,
                    error,
                });
            }
        }
        failures
    }

    fn isatty(&self, fd: i32) -> bool {
        VfsKernel::isatty(self, fd)
    }

    fn now(&self) -> std::time::SystemTime {
        VfsKernel::now(self)
    }

    async fn open(&self, proc: &mut Process, path: Resolved, flags: OpenFlags) -> io::Result<Fd> {
        debug_assert_eq!(
            path.follow(),
            Follow::Yes,
            "open acts on a symlink's target"
        );
        let mut generation = self.guard_resolution(&path).await?;
        let result = self
            .open_effect(proc, path.path(), flags, path.host_identity())
            .await;
        if result.is_ok() && flags.create {
            Self::changed_resolution(&mut generation);
        }
        result
    }

    async fn list_dir(&self, proc: &Process, path: Resolved) -> io::Result<Vec<DirEntry>> {
        debug_assert_eq!(path.follow(), Follow::Yes, "list_dir follows to its target");
        let _generation = self.guard_resolution(&path).await?;
        self.list_dir_effect(proc, path.path()).await
    }

    async fn change_dir(&self, proc: &mut Process, path: Resolved) -> io::Result<()> {
        debug_assert_eq!(
            path.follow(),
            Follow::Yes,
            "change_dir follows to its target"
        );
        let _generation = self.guard_resolution(&path).await?;
        self.change_dir_effect(proc, path.path()).await
    }

    async fn stat(&self, proc: &Process, path: Resolved) -> FileStat {
        debug_assert_eq!(path.follow(), Follow::Yes, "stat follows a final symlink");
        let Ok(_generation) = self.guard_resolution(&path).await else {
            return FileStat::default();
        };
        self.stat_effect(proc, path.path()).await
    }

    async fn lstat(&self, proc: &Process, path: Resolved) -> FileStat {
        debug_assert_eq!(path.follow(), Follow::No, "lstat acts on the link itself");
        let Ok(_generation) = self.guard_resolution(&path).await else {
            return FileStat::default();
        };
        self.lstat_effect(proc, path.path()).await
    }

    async fn access(&self, proc: &Process, path: Resolved, mode: i32) -> bool {
        debug_assert_eq!(path.follow(), Follow::Yes, "access follows to its target");
        let Ok(_generation) = self.guard_resolution(&path).await else {
            return false;
        };
        self.access_effect(proc, path.path(), mode).await
    }

    async fn canonicalize(&self, proc: &Process, path: Resolved) -> io::Result<PathBuf> {
        debug_assert_eq!(path.follow(), Follow::Yes, "canonicalize resolves symlinks");
        let _generation = self.guard_resolution(&path).await?;
        self.canonicalize_effect(proc, path.path()).await
    }

    async fn is_executable(&self, proc: &Process, path: Resolved) -> bool {
        debug_assert_eq!(path.follow(), Follow::Yes, "exec follows to its target");
        let Ok(_generation) = self.guard_resolution(&path).await else {
            return false;
        };
        self.is_executable_effect(proc, path.path()).await
    }

    /// Takes a pattern, not a path: a glob has no single identity to resolve.
    ///
    /// [`crate::Mediated::glob`] admits the directory being enumerated and then each
    /// match individually, so the expansion is mediated without a token here.
    async fn glob(&self, proc: &Process, pattern: &str) -> Vec<String> {
        self.glob_effect(proc, pattern).await
    }

    async fn remove_file(&self, proc: &Process, path: Resolved) -> io::Result<()> {
        debug_assert_eq!(path.follow(), Follow::No, "unlink removes the name given");
        let mut generation = self.guard_resolution(&path).await?;
        let result = self
            .remove_file_effect(proc, path.path(), path.host_identity())
            .await;
        if result.is_ok() {
            Self::changed_resolution(&mut generation);
        }
        result
    }

    async fn remove_dir(&self, proc: &Process, path: Resolved) -> io::Result<()> {
        debug_assert_eq!(path.follow(), Follow::Yes, "rmdir follows to its target");
        let mut generation = self.guard_resolution(&path).await?;
        let result = self
            .remove_dir_effect(proc, path.path(), path.host_identity())
            .await;
        if result.is_ok() {
            Self::changed_resolution(&mut generation);
        }
        result
    }

    async fn create_dir(&self, proc: &Process, path: Resolved) -> io::Result<()> {
        debug_assert_eq!(
            path.follow(),
            Follow::No,
            "mkdir creates the final name itself"
        );
        let mut generation = self.guard_resolution(&path).await?;
        let result = self
            .create_dir_effect(proc, path.path(), path.host_identity())
            .await;
        if result.is_ok() {
            Self::changed_resolution(&mut generation);
        }
        result
    }

    async fn rename(&self, proc: &Process, from: Resolved, to: Resolved) -> io::Result<()> {
        debug_assert_eq!(from.follow(), Follow::No, "rename moves the link itself");
        debug_assert_eq!(
            to.follow(),
            Follow::No,
            "rename replaces the destination name"
        );
        let mut generation = self.resolution_generation.lock().await;
        if !self.resolution_is_current(&from, *generation).await
            || !self.resolution_is_current(&to, *generation).await
        {
            return Err(Self::stale_resolution());
        }
        let result = self
            .rename_effect(
                proc,
                from.path(),
                from.host_identity(),
                to.path(),
                to.host_identity(),
            )
            .await;
        if result.is_ok() {
            Self::changed_resolution(&mut generation);
        }
        result
    }

    async fn symlink(&self, proc: &Process, target: &str, link: Resolved) -> io::Result<()> {
        debug_assert_eq!(
            link.follow(),
            Follow::No,
            "the link is created, not followed"
        );
        let mut generation = self.guard_resolution(&link).await?;
        let result = self
            .symlink_effect(proc, target, link.path(), link.host_identity())
            .await;
        if result.is_ok() {
            Self::changed_resolution(&mut generation);
        }
        result
    }

    async fn read_link(&self, proc: &Process, path: Resolved) -> io::Result<String> {
        debug_assert_eq!(path.follow(), Follow::No, "read_link acts on the link");
        let _generation = self.guard_resolution(&path).await?;
        self.read_link_effect(proc, path.path()).await
    }

    async fn set_permissions(&self, proc: &Process, path: Resolved, mode: u32) -> io::Result<()> {
        debug_assert_eq!(path.follow(), Follow::Yes, "chmod follows to its target");
        let _generation = self.guard_resolution(&path).await?;
        self.set_permissions_effect(proc, path.path(), mode, path.host_identity())
            .await
    }

    /// The SSRF floor — a deny-only control, not an authorization decision.
    fn check_url(&self, url: &str) -> io::Result<()> {
        self.check_url_effect(url)
    }

    /// Dispatches through the floor and then the embedder's transport.
    ///
    /// Raises no admission: the Shell does not authorize egress. The transport's own
    /// boundary decides, with the request vocabulary that decision needs.
    async fn http_request(&self, req: HttpRequest) -> io::Result<HttpResponse> {
        self.http_request_effect(req).await
    }

    /// Forward the source to the installed interpreter hook, or refuse when none is set.
    ///
    /// Raises no admission of its own: the hook the box installs runs the script through
    /// its own policy-governed interpreter (Monty), which judges each effect there.
    async fn run_script(&self, source: String) -> io::Result<ScriptOutcome> {
        match &self.script_interpreter {
            Some(hook) => hook(source).await,
            None => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "script interpreter not available",
            )),
        }
    }

    /// Forward the binary to the installed host-spawner hook, or refuse when none is set.
    async fn spawn_host(
        &self,
        spawn: crate::os::HostSpawn,
    ) -> io::Result<crate::os::HostSpawnOutcome> {
        match &self.host_spawner {
            Some(hook) => hook(spawn).await,
            None => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "host-binary execution requires a contained spawner; none is installed",
            )),
        }
    }
}

// --- host stat helper ---

#[cfg(not(target_arch = "wasm32"))]
async fn host_stat(path: &std::path::Path) -> FileStat {
    let meta = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(_) => return FileStat::default(),
    };
    FileStat {
        exists: true,
        is_file: meta.is_file(),
        is_dir: meta.is_dir(),
        is_symlink: meta.is_symlink(),
        len: meta.len(),
        is_socket: false,
        is_fifo: false,
        is_block_device: false,
        is_char_device: false,
        mode: {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                meta.mode()
            }
            #[cfg(not(unix))]
            {
                if meta.is_dir() { 0o040755 } else { 0o100644 }
            }
        },
        dev: 0,
        ino: 0,
        modified: meta.modified().ok(),
    }
}

#[cfg(target_arch = "wasm32")]
fn host_stat_sync(path: &std::path::Path) -> FileStat {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return FileStat::default(),
    };
    FileStat {
        exists: true,
        is_file: meta.is_file(),
        is_dir: meta.is_dir(),
        is_symlink: meta.is_symlink(),
        len: meta.len(),
        is_socket: false,
        is_fifo: false,
        is_block_device: false,
        is_char_device: false,
        mode: if meta.is_dir() { 0o040755 } else { 0o100644 },
        dev: 0,
        ino: 0,
        modified: meta.modified().ok(),
    }
}

// --- device fd helpers ---

fn make_dev_null_fd(proc: &mut Process, flags: &OpenFlags) -> io::Result<Fd> {
    if flags.read {
        let (_tx, rx) = crate::os::pipe(1);
        // tx dropped immediately → reader gets EOF
        proc.alloc_fd(FdKind::ChannelReader {
            rx,
            buf: Vec::new(),
        })
    } else {
        let (tx, _rx) = crate::os::pipe(8192);
        // Spawn a drain task
        tokio::task::spawn_local(async move {
            let mut _rx = _rx;
            while _rx.recv().await.is_some() {}
        });
        proc.alloc_fd(FdKind::ChannelWriter { tx, limit: None })
    }
}

fn make_dev_zero_fd(proc: &mut Process, flags: &OpenFlags) -> io::Result<Fd> {
    if flags.write {
        return make_dev_null_fd(proc, flags);
    }
    // Infinite stream of zeros
    let (tx, rx) = crate::os::pipe(1);
    tokio::task::spawn_local(async move {
        let zeros = bytes::Bytes::from(vec![0u8; 4096]);
        while tx.send(zeros.clone()).await.is_ok() {}
    });
    proc.alloc_fd(FdKind::ChannelReader {
        rx,
        buf: Vec::new(),
    })
}

fn make_dev_urandom_fd(proc: &mut Process, flags: &OpenFlags) -> io::Result<Fd> {
    if flags.write {
        return make_dev_null_fd(proc, flags);
    }
    // Generate pseudo-random data
    let (tx, rx) = crate::os::pipe(1);
    #[cfg(not(target_arch = "wasm32"))]
    tokio::task::spawn_local(async move {
        use tokio::io::AsyncReadExt;
        if let Ok(mut f) = tokio::fs::File::open("/dev/urandom").await {
            let mut buf = vec![0u8; 4096];
            while let Ok(n) = f.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                if tx
                    .send(bytes::Bytes::copy_from_slice(&buf[..n]))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    });
    #[cfg(target_arch = "wasm32")]
    tokio::task::spawn_local(async move {
        // Simple PRNG fallback for WASM — produce pseudo-random bytes
        // using a basic xorshift seeded from the system time.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(42);
        let mut state = seed;
        let mut buf = vec![0u8; 4096];
        loop {
            for byte in buf.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            if tx.send(bytes::Bytes::copy_from_slice(&buf)).await.is_err() {
                break;
            }
        }
    });
    proc.alloc_fd(FdKind::ChannelReader {
        rx,
        buf: Vec::new(),
    })
}

// --- glob matching for VFS ---

fn glob_vfs(vfs: &Vfs, pattern: &str, results: &mut Vec<String>) {
    let parts: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    glob_recurse(vfs, vfs::Ino::from(1u64), "/", &parts, 0, results);
}

fn glob_recurse(
    vfs: &Vfs,
    dir_ino: vfs::Ino,
    dir_path: &str,
    parts: &[&str],
    idx: usize,
    results: &mut Vec<String>,
) {
    if idx >= parts.len() {
        results.push(dir_path.to_string());
        return;
    }
    let pat = parts[idx];
    let is_last = idx == parts.len() - 1;

    let entries = match vfs.read_dir(dir_ino) {
        Ok(e) => e,
        Err(_) => return,
    };

    for (name, child_ino) in &entries {
        if !glob_match_simple(pat, name) {
            continue;
        }
        let child_path = if dir_path == "/" {
            format!("/{name}")
        } else {
            format!("{dir_path}/{name}")
        };
        if is_last {
            results.push(child_path);
        } else {
            // Must be a directory to continue
            if let Ok(inode) = vfs.get(*child_ino)
                && matches!(inode.data, InodeData::Dir(_))
            {
                glob_recurse(vfs, *child_ino, &child_path, parts, idx + 1, results);
            }
        }
    }
}

/// Simple glob matching (supports * and ?).
fn glob_match_simple(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_chars(&p, &t)
}

fn glob_match_chars(p: &[char], t: &[char]) -> bool {
    match (p.first(), t.first()) {
        (None, None) => true,
        (Some('*'), _) => {
            glob_match_chars(&p[1..], t) || (!t.is_empty() && glob_match_chars(p, &t[1..]))
        }
        (Some('?'), Some(_)) => glob_match_chars(&p[1..], &t[1..]),
        (Some(a), Some(b)) if a == b => glob_match_chars(&p[1..], &t[1..]),
        _ => false,
    }
}

/// Check if an IP address is private/loopback/link-local/IMDS.
fn is_ip_blocked(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.octets()[..2] == [169, 254]
        }
        std::net::IpAddr::V6(v6) => {
            // Loopback (::1)
            if v6.is_loopback() {
                return true;
            }
            // Unspecified (::)
            if v6.is_unspecified() {
                return true;
            }
            // IPv4-mapped (::ffff:x.x.x.x) and IPv4-compatible (::x.x.x.x)
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_ip_blocked(std::net::IpAddr::V4(v4));
            }
            let segs = v6.segments();
            // IPv4-compatible addresses (deprecated but still routable)
            if segs[..6] == [0, 0, 0, 0, 0, 0] && (segs[6] != 0 || segs[7] > 1) {
                let o = v6.octets();
                let v4 = std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15]);
                return is_ip_blocked(std::net::IpAddr::V4(v4));
            }
            // ULA (fc00::/7)
            if segs[0] & 0xfe00 == 0xfc00 {
                return true;
            }
            // Link-local (fe80::/10)
            if segs[0] & 0xffc0 == 0xfe80 {
                return true;
            }
            // 6to4 (2002::/16) — check embedded IPv4
            if segs[0] == 0x2002 {
                let v4 = std::net::Ipv4Addr::new(
                    (segs[1] >> 8) as u8,
                    segs[1] as u8,
                    (segs[2] >> 8) as u8,
                    segs[2] as u8,
                );
                return is_ip_blocked(std::net::IpAddr::V4(v4));
            }
            // Teredo (2001:0000::/32) — check embedded IPv4 (bitwise NOT of last 32 bits)
            if segs[0] == 0x2001 && segs[1] == 0x0000 {
                let o = v6.octets();
                let v4 = std::net::Ipv4Addr::new(!o[12], !o[13], !o[14], !o[15]);
                return is_ip_blocked(std::net::IpAddr::V4(v4));
            }
            false
        }
    }
}

/// Check a URL for blocked schemes, hostnames, and IP literals.
/// Does NOT resolve DNS — use `SafeResolver` on the reqwest client for
/// connect-time DNS filtering.
pub fn check_url_safe(url: &str) -> io::Result<()> {
    // Scheme whitelist
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("access denied: unsupported scheme in {url}"),
        ));
    }
    // Match on the parsed `url::Host` rather than `host_str()` + string parse.
    // `host_str()` keeps IPv6 literals bracketed (`[::1]`), which made the
    // `parse::<IpAddr>()` below fail silently and skip `is_ip_blocked` entirely
    // — a full IPv6 SSRF bypass (incl. IMDS via `[::ffff:169.254.169.254]`).
    // The `Host` enum gives us a real `Ipv4Addr`/`Ipv6Addr` with no brackets.
    let parsed = url::Url::parse(url).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("access denied: cannot parse host from {url}"),
        )
    })?;
    match parsed.host() {
        Some(url::Host::Ipv4(v4)) => {
            if is_ip_blocked(std::net::IpAddr::V4(v4)) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("access denied: {v4}"),
                ));
            }
        }
        Some(url::Host::Ipv6(v6)) => {
            if is_ip_blocked(std::net::IpAddr::V6(v6)) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("access denied: {v6}"),
                ));
            }
        }
        Some(url::Host::Domain(d)) => {
            let normalized = d.trim_end_matches('.').to_ascii_lowercase();
            if normalized == "localhost" || normalized.ends_with(".localhost") {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("access denied: {d}"),
                ));
            }
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("access denied: cannot parse host from {url}"),
            ));
        }
    }
    Ok(())
}

/// A DNS resolver that filters out blocked IPs at resolution time,
/// eliminating TOCTOU between DNS check and connection.
#[cfg(not(target_arch = "wasm32"))]
pub struct SafeResolver;

#[cfg(not(target_arch = "wasm32"))]
impl reqwest::dns::Resolve for SafeResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let host = name.as_str();
            let host_port = format!("{host}:0");
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&host_port)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();
            let safe: Vec<std::net::SocketAddr> = addrs
                .into_iter()
                .filter(|a| !is_ip_blocked(a.ip()))
                .collect();
            if safe.is_empty() {
                return Err(format!("access denied: {host} resolves to blocked address").into());
            }
            Ok(Box::new(safe.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod url_safety_tests {
    use super::check_url_safe;

    // A1: IPv6 literals (incl. IPv4-mapped IMDS) must be blocked by
    // `check_url_safe` ITSELF — not merely by the SafeResolver/connection
    // backstop. Asserting on the function return value (rather than a curl exit
    // code) is what proves the fix: against the old `host_str()` code these all
    // returned Ok(()) because the bracketed literal failed to parse as an IP.
    #[test]
    fn check_url_safe_blocks_ipv6_literals() {
        for u in [
            "http://[::1]/",                    // loopback
            "http://[::ffff:169.254.169.254]/", // IPv4-mapped IMDS
            "http://[fe80::1]/",                // link-local
            "http://[fc00::1]/",                // ULA
            "http://[::]/",                     // unspecified
        ] {
            assert!(check_url_safe(u).is_err(), "{u} should be blocked");
        }
    }

    #[test]
    fn check_url_safe_blocks_ipv4_and_localhost() {
        for u in [
            "http://169.254.169.254/", // IMDS
            "http://127.0.0.1/",       // loopback
            "http://10.0.0.1/",        // private
            "http://localhost/",       // localhost domain
            "http://x.localhost/",     // .localhost subdomain
            "http://localhost./",      // trailing root dot (FQDN form)
            "http://x.localhost./",    // .localhost subdomain, trailing root dot
            "http://LOCALHOST/",       // uppercase
            "http://LocalHost./",      // mixed case, trailing root dot
            "ftp://example.com/",      // non-http scheme
        ] {
            assert!(check_url_safe(u).is_err(), "{u} should be blocked");
        }
    }

    // Userinfo must not disguise the real host. `http://public.example@IMDS/` is a
    // URL whose *apparent* host reads as public while its real host is the metadata
    // service; matching on `url::Host` rather than on the raw string is what makes
    // the floor see the real one.
    #[test]
    fn check_url_safe_blocks_a_host_disguised_by_userinfo() {
        for u in [
            "http://good.example.com@169.254.169.254/",
            "http://good.example.com:8080@169.254.169.254/",
            "http://user:pass@127.0.0.1/",
        ] {
            assert!(
                check_url_safe(u).is_err(),
                "{u} names a blocked real host and must be refused"
            );
        }
    }

    #[test]
    fn check_url_safe_allows_public_hosts() {
        for u in [
            "http://example.com/",
            "https://example.com/path",
            "http://[2606:4700:4700::1111]/", // public IPv6 (Cloudflare DNS)
        ] {
            assert!(check_url_safe(u).is_ok(), "{u} should be allowed");
        }
    }
}

#[cfg(all(test, unix))]
mod resolve_host_tests {
    use std::path::{Path, PathBuf};

    use super::VfsKernel;
    use crate::vfs::{InodeData, LASH_GID, LASH_UID, Vfs};

    struct Fixture {
        vfs: Vfs,
        workspace: PathBuf,
        canonical: PathBuf,
    }

    fn fixture(name: &str) -> Fixture {
        let base = std::env::temp_dir().join(format!("resolve-host-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let workspace = base.join("ws");
        let outside = base.join("outside");
        std::fs::create_dir_all(workspace.join("sub")).expect("workspace");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(workspace.join("real.txt"), "IN_MOUNT").expect("file");
        std::os::unix::fs::symlink(base.join("absent"), workspace.join("dangle")).expect("dangle");
        std::os::unix::fs::symlink(&outside, workspace.join("escape")).expect("escape");

        let mut vfs = Vfs::new();
        vfs.mkdir_p("/mnt/deep", 0o755, LASH_UID, LASH_GID)
            .expect("parent");
        let source = workspace.to_str().expect("UTF-8 workspace").to_string();
        vfs.mknod(
            "/mnt/deep/ws",
            InodeData::HostDir(source, false),
            0o100644,
            LASH_UID,
            LASH_GID,
        )
        .expect("bind");
        vfs.symlink("/alias", "/mnt/deep/ws", LASH_UID, LASH_GID)
            .expect("alias");
        vfs.symlink("/chain", "alias", LASH_UID, LASH_GID)
            .expect("chain");
        let canonical = std::fs::canonicalize(&workspace).expect("canonical workspace");
        Fixture {
            vfs,
            workspace,
            canonical,
        }
    }

    fn host(fixture: &Fixture, path: &str) -> Option<PathBuf> {
        VfsKernel::resolve_host(&fixture.vfs, path).map(|(host, _, _)| host)
    }

    fn under(root: &Path, tail: &str) -> Option<PathBuf> {
        Some(root.join(tail))
    }

    #[test]
    fn a_path_under_a_bind_maps_to_the_host_path_below_it() {
        let fixture = fixture("under");
        let (workspace, canonical) = (&fixture.workspace, &fixture.canonical);
        assert_eq!(host(&fixture, "/mnt/deep/ws"), Some(workspace.clone()));
        assert_eq!(
            host(&fixture, "/mnt/deep/ws/real.txt"),
            under(canonical, "real.txt")
        );
        assert_eq!(
            host(&fixture, "/mnt/deep/ws/a/b/c"),
            under(workspace, "a/b/c")
        );
        assert_eq!(
            host(&fixture, "/mnt/deep/ws/sub/../real.txt"),
            under(canonical, "real.txt")
        );
        assert_eq!(
            host(&fixture, "/mnt/deep/absent/../ws/real.txt"),
            under(canonical, "real.txt")
        );
    }

    #[test]
    fn a_bind_reached_through_a_symlink_is_the_ancestor() {
        let fixture = fixture("symlinked");
        let (workspace, canonical) = (&fixture.workspace, &fixture.canonical);
        assert_eq!(
            host(&fixture, "/alias/real.txt"),
            under(canonical, "real.txt")
        );
        assert_eq!(host(&fixture, "/alias/sub/x"), under(workspace, "sub/x"));
        assert_eq!(host(&fixture, "/chain/a/b"), under(workspace, "a/b"));
    }

    #[test]
    fn a_host_symlink_that_leaves_or_dangles_is_refused() {
        let fixture = fixture("refused");
        assert_eq!(host(&fixture, "/mnt/deep/ws/dangle"), None);
        assert_eq!(host(&fixture, "/mnt/deep/ws/escape"), None);
        assert_eq!(host(&fixture, "/mnt/deep/ws/escape/f"), None);
    }

    #[test]
    fn a_path_with_no_bind_ancestor_has_no_host_path() {
        let fixture = fixture("virtual");
        assert_eq!(host(&fixture, "/"), None);
        assert_eq!(host(&fixture, "/mnt/deep"), None);
        assert_eq!(host(&fixture, "/mnt/deep/x/y"), None);
        assert_eq!(host(&fixture, "/absent/ws/real.txt"), None);
    }
}
