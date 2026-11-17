//! The host folders the Shell serves, and the effects that act on the identity a path resolved to
//! (docs/design/decisions.md#a-resolved-token-binds-the-object-it-names).

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use strands_shell::os::{DirEntry, Fd, FdKind, FileStat, OpenFlags, Process};

use crate::kernel::Follow;

/// The channel depth of one host writer, in chunks.
const HOST_WRITER_DEPTH: usize = 16;

/// One host folder the Shell names at `visible`.
#[derive(Debug, Clone)]
pub(crate) struct Mount {
    visible: String,
    source: PathBuf,
}

/// Every host folder the Shell serves.
#[derive(Debug, Clone, Default)]
pub(crate) struct Mounts(Vec<Mount>);

/// The object a resolved host path named when it was resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum HostIdentity {
    Present {
        path: PathBuf,
        parent: PathBuf,
        root: PathBuf,
        device: u64,
        inode: u64,
        parent_device: u64,
        parent_inode: u64,
    },
    Missing {
        path: PathBuf,
        parent: PathBuf,
        root: PathBuf,
        parent_device: u64,
        parent_inode: u64,
    },
    Unavailable {
        path: PathBuf,
    },
}

/// The refusal for an object that is not the one admission judged.
pub(super) fn stale_resolution() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "filesystem identity changed during effect admission",
    )
}

/// The refusal for removing or replacing a mount point.
pub(super) fn mount_point_busy() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "bind mount point is busy")
}

impl Mounts {
    /// Serve each `(source, visible)` pair, in order.
    pub(crate) fn new(binds: &[(&str, &str)]) -> Self {
        Self(
            binds
                .iter()
                .map(|(source, visible)| Mount {
                    visible: strands_shell::vfs::normalize(visible),
                    source: PathBuf::from(source),
                })
                .collect(),
        )
    }

    /// Each `(source, visible)` pair this table serves.
    pub(crate) fn binds(&self) -> impl Iterator<Item = (&Path, &str)> {
        self.0
            .iter()
            .map(|mount| (mount.source.as_path(), mount.visible.as_str()))
    }

    /// Whether `abs` is itself a mount point.
    pub(super) fn is_mount_point(&self, abs: &str) -> bool {
        self.0.iter().any(|mount| mount.visible == abs)
    }

    /// Whether `abs` is at or below a mount point.
    pub(super) fn serves(&self, abs: &str) -> bool {
        self.below(abs).is_some()
    }

    /// The mount `abs` lies at or below, and the components below its mount point.
    fn below<'a>(&self, abs: &'a str) -> Option<(&Mount, Vec<&'a str>)> {
        self.0
            .iter()
            .filter_map(|mount| {
                let rest = if mount.visible == "/" {
                    Some(abs)
                } else if abs == mount.visible {
                    Some("")
                } else {
                    abs.strip_prefix(mount.visible.as_str())
                        .and_then(|rest| rest.strip_prefix('/'))
                };
                rest.map(|rest| (mount, rest))
            })
            .max_by_key(|(mount, _)| mount.visible.len())
            .map(|(mount, rest)| (mount, rest.split('/').filter(|c| !c.is_empty()).collect()))
    }

    /// The host path and canonical mount root `abs` names, with every symlink followed, or `None`
    /// when it names nothing this table serves.
    pub(super) fn resolve_host(&self, abs: &str) -> Option<(PathBuf, PathBuf)> {
        let (mount, rest) = self.below(abs)?;
        let base = std::fs::canonicalize(&mount.source).unwrap_or_else(|_| mount.source.clone());
        if rest.is_empty() {
            return Some((mount.source.clone(), base));
        }
        let mut host = mount.source.clone();
        host.extend(&rest);
        if let Ok(canonical) = std::fs::canonicalize(&host) {
            return canonical.starts_with(&base).then_some((canonical, base));
        }
        if host.symlink_metadata().is_ok() {
            return None;
        }
        if let Some(parent) = host.parent()
            && let Ok(canonical_parent) = std::fs::canonicalize(parent)
            && !canonical_parent.starts_with(&base)
        {
            return None;
        }
        Some((host, base))
    }

    /// [`Self::resolve_host`] per `follow`; a mount point always follows.
    pub(super) fn resolve_host_for(&self, abs: &str, follow: Follow) -> Option<(PathBuf, PathBuf)> {
        if follow == Follow::Yes || self.is_mount_point(abs) {
            return self.resolve_host(abs);
        }
        let (parent, leaf) = split_leaf(abs);
        if leaf.is_empty() {
            return self.resolve_host(abs);
        }
        let (host_parent, base) = self.resolve_host(parent)?;
        Some((host_parent.join(leaf), base))
    }

    /// The host path `abs` spells below its mount, with no host symlink followed.
    fn spelled_host(&self, abs: &str) -> Option<PathBuf> {
        let (mount, rest) = self.below(abs)?;
        let mut spelled =
            std::fs::canonicalize(&mount.source).unwrap_or_else(|_| mount.source.clone());
        spelled.extend(rest);
        Some(spelled)
    }

    /// The spelling of `abs` with each host symlink below its mount followed, per `follow`.
    ///
    /// `None` keeps the caller's spelling: a mount point, a missing parent, or an identity outside
    /// the mount.
    pub(super) fn canonical_spelling(&self, abs: &str, follow: Follow) -> Option<String> {
        if self.is_mount_point(abs) {
            return None;
        }
        let (mount, rest) = self.below(abs)?;
        let base = std::fs::canonicalize(&mount.source).ok()?;
        let (leaf, parent_rest) = rest.split_last()?;
        let mut host_parent = mount.source.clone();
        host_parent.extend(parent_rest);
        let mut canonical = std::fs::canonicalize(&host_parent).ok()?.join(leaf);
        if follow == Follow::Yes
            && let Ok(target) = std::fs::canonicalize(&canonical)
        {
            canonical = target;
        }
        let tail = canonical.strip_prefix(&base).ok()?.to_str()?;
        if tail.is_empty() {
            return Some(mount.visible.clone());
        }
        Some(format!("{}/{tail}", mount.visible.trim_end_matches('/')))
    }

    /// Pin the object `abs` names, per `follow`.
    pub(super) fn identity(&self, abs: &str, follow: Follow) -> Option<HostIdentity> {
        let (path, base) = self.resolve_host_for(abs, follow)?;
        let parent = path.parent()?.canonicalize().ok()?;
        let mount_point = self.is_mount_point(abs);
        if !mount_point
            && let Some(spelled) = self.spelled_host(abs)
            && path.file_name().map(|leaf| parent.join(leaf)) != Some(spelled)
        {
            return Some(HostIdentity::Unavailable { path });
        }
        let root = if parent.starts_with(&base) {
            base
        } else if mount_point {
            parent.clone()
        } else {
            return Some(HostIdentity::Unavailable { path });
        };
        pinned_identity(path, parent, root, follow)
    }
}

/// The parent of `abs` and its last component.
pub(super) fn split_leaf(abs: &str) -> (&str, &str) {
    match abs.rfind('/') {
        Some(0) => ("/", &abs[1..]),
        Some(index) => (&abs[..index], &abs[index + 1..]),
        None => ("", abs),
    }
}

fn c_name(name: &std::ffi::OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "host path contains a NUL byte"))
}

/// Pin `path` by the parent reached from `root` one component at a time, with no symlink followed.
fn pinned_identity(
    path: PathBuf,
    parent: PathBuf,
    root: PathBuf,
    follow: Follow,
) -> Option<HostIdentity> {
    let directory = open_beneath(&root, &parent).ok()?;
    let parent_metadata = directory.metadata().ok()?;
    let leaf = c_name(path.file_name()?).ok()?;
    let flags = if follow == Follow::Yes {
        0
    } else {
        libc::AT_SYMLINK_NOFOLLOW
    };
    let mut leaf_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: directory and leaf are owned, valid handles; leaf_stat is written before it is read.
    let statted = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            leaf_stat.as_mut_ptr(),
            flags,
        )
    };
    if statted == 0 {
        // SAFETY: fstatat returned 0, so leaf_stat is initialized.
        let leaf_stat = unsafe { leaf_stat.assume_init() };
        return Some(HostIdentity::Present {
            path,
            parent,
            root,
            #[allow(clippy::unnecessary_cast)]
            device: leaf_stat.st_dev as u64,
            #[allow(clippy::unnecessary_cast)]
            inode: leaf_stat.st_ino as u64,
            parent_device: parent_metadata.dev(),
            parent_inode: parent_metadata.ino(),
        });
    }
    if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
        return Some(HostIdentity::Missing {
            path,
            parent,
            root,
            parent_device: parent_metadata.dev(),
            parent_inode: parent_metadata.ino(),
        });
    }
    Some(HostIdentity::Unavailable { path })
}

/// Open `directory` from `root` one component at a time, refusing a symlink at every component.
fn open_beneath(root: &Path, directory: &Path) -> io::Result<File> {
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| stale_resolution())?;
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root)?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(stale_resolution());
        };
        let name = c_name(name)?;
        // SAFETY: current and name are owned, valid handles. The returned descriptor is checked.
        let descriptor = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned this owned descriptor and File closes it once.
        current = unsafe { File::from_raw_fd(descriptor) };
    }
    Ok(current)
}

/// The pinned parent of `host_path` and its leaf name, or the stale refusal.
fn opened_parent(host_path: &Path, expected: &HostIdentity) -> io::Result<(File, CString)> {
    let (identity_path, parent, root, parent_device, parent_inode) = match expected {
        HostIdentity::Present {
            path,
            parent,
            root,
            parent_device,
            parent_inode,
            ..
        }
        | HostIdentity::Missing {
            path,
            parent,
            root,
            parent_device,
            parent_inode,
        } => (path, parent, root, *parent_device, *parent_inode),
        HostIdentity::Unavailable { .. } => return Err(stale_resolution()),
    };
    if identity_path != host_path {
        return Err(stale_resolution());
    }
    let directory = open_beneath(root, parent)?;
    let metadata = directory.metadata()?;
    if metadata.dev() != parent_device || metadata.ino() != parent_inode {
        return Err(stale_resolution());
    }
    let leaf = c_name(host_path.file_name().ok_or_else(stale_resolution)?)?;
    Ok((directory, leaf))
}

fn last_result(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Open the pinned file.
fn open_file(
    host_path: &Path,
    flags: &OpenFlags,
    expected: Option<&HostIdentity>,
) -> io::Result<File> {
    let expected = expected.ok_or_else(stale_resolution)?;
    let (parent, leaf) = opened_parent(host_path, expected)?;
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
        HostIdentity::Unavailable { .. } => return Err(stale_resolution()),
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
            return Err(stale_resolution());
        }
    }
    if flags.truncate {
        file.set_len(0)?;
    }
    Ok(file)
}

/// Open the pinned file as a descriptor of `proc`.
///
/// A write reaches the host before the writer's `write` returns, so a command's status follows
/// its bytes.
pub(super) async fn open(
    proc: &mut Process,
    host_path: &Path,
    flags: &OpenFlags,
    expected: Option<&HostIdentity>,
) -> io::Result<Fd> {
    let mut file = open_file(host_path, flags, expected)?;
    if flags.read && !flags.write {
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        let (tx, rx) = strands_shell::os::pipe(data.len().max(64));
        let _ = tx.send(bytes::Bytes::from(data)).await;
        drop(tx);
        return proc.alloc_fd(FdKind::ChannelReader {
            rx,
            buf: Vec::new(),
        });
    }
    if !flags.write {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid open flags",
        ));
    }
    if flags.append {
        file.seek(SeekFrom::End(0))?;
    }
    let (tx, rx) = strands_shell::os::pipe(HOST_WRITER_DEPTH);
    let failed = Arc::new(AtomicBool::new(false));
    let fd = proc.alloc_fd(FdKind::ChannelWriter {
        tx,
        error_flag: Some(Arc::clone(&failed)),
    })?;
    tokio::task::spawn_local(drain(rx, file, flags.append, failed));
    Ok(fd)
}

/// Write each chunk to `file` as it arrives, before the writer sees it accepted.
async fn drain(
    mut rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    mut file: File,
    append: bool,
    failed: Arc<AtomicBool>,
) {
    let mut written = 0_u64;
    while let Some(chunk) = rx.recv().await {
        if file.write_all(&chunk).is_err() {
            failed.store(true, Ordering::Relaxed);
            return;
        }
        written += chunk.len() as u64;
    }
    if !append && file.set_len(written).is_err() {
        failed.store(true, Ordering::Relaxed);
    }
}

/// List a host directory.
pub(super) fn list_dir(host_path: &Path) -> io::Result<Vec<DirEntry>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(host_path)? {
        let entry = entry?;
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        entries.push(DirEntry {
            name: entry.file_name().to_string_lossy().into_owned(),
            is_dir,
        });
    }
    Ok(entries)
}

/// The metadata of a host path, per `follow`.
pub(super) fn stat(path: &Path, follow: Follow) -> FileStat {
    let metadata = match follow {
        Follow::Yes => std::fs::metadata(path),
        Follow::No => std::fs::symlink_metadata(path),
    };
    let Ok(meta) = metadata else {
        return FileStat::default();
    };
    FileStat {
        exists: true,
        is_file: meta.is_file(),
        is_dir: meta.is_dir(),
        is_symlink: meta.is_symlink(),
        len: meta.len(),
        mode: meta.mode(),
        modified: meta.modified().ok(),
        ..FileStat::default()
    }
}

/// Whether a host path exists, or allows `mode`.
pub(super) fn access(host_path: &Path, mode: i32) -> bool {
    let Ok(meta) = std::fs::metadata(host_path) else {
        return false;
    };
    !(mode & strands_shell::os::ACCESS_W != 0 && meta.permissions().readonly())
}

/// Whether a host path is a regular file with an execute bit.
pub(super) fn is_executable(host_path: &Path) -> bool {
    std::fs::metadata(host_path).is_ok_and(|meta| meta.is_file() && meta.mode() & 0o111 != 0)
}

/// Remove the pinned name, as a directory when `directory`.
pub(super) fn unlink(
    host_path: &Path,
    expected: Option<&HostIdentity>,
    directory: bool,
) -> io::Result<()> {
    let expected = expected.ok_or_else(stale_resolution)?;
    let (parent, leaf) = opened_parent(host_path, expected)?;
    let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: parent and leaf are owned, valid handles.
    last_result(unsafe { libc::unlinkat(parent.as_raw_fd(), leaf.as_ptr(), flags) })
}

/// Create a directory at the pinned name.
pub(super) fn create_directory(
    host_path: &Path,
    expected: Option<&HostIdentity>,
) -> io::Result<()> {
    let expected = expected.ok_or_else(stale_resolution)?;
    let (parent, leaf) = opened_parent(host_path, expected)?;
    // SAFETY: parent and leaf are owned, valid handles.
    last_result(unsafe { libc::mkdirat(parent.as_raw_fd(), leaf.as_ptr(), 0o777) })
}

/// Rename one pinned name onto another.
pub(super) fn rename(
    from: &Path,
    from_expected: Option<&HostIdentity>,
    to: &Path,
    to_expected: Option<&HostIdentity>,
) -> io::Result<()> {
    let from_expected = from_expected.ok_or_else(stale_resolution)?;
    let to_expected = to_expected.ok_or_else(stale_resolution)?;
    let (from_parent, from_leaf) = opened_parent(from, from_expected)?;
    let (to_parent, to_leaf) = opened_parent(to, to_expected)?;
    // SAFETY: both parent and leaf pairs are owned, valid handles.
    last_result(unsafe {
        libc::renameat(
            from_parent.as_raw_fd(),
            from_leaf.as_ptr(),
            to_parent.as_raw_fd(),
            to_leaf.as_ptr(),
        )
    })
}

/// Refuse a symlink target that is absolute or that leaves the mount.
pub(super) fn verify_symlink_target(target: &str, host_link: &Path, base: &Path) -> io::Result<()> {
    let escaped = || {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "symlink target escapes the bind mount",
        )
    };
    if target.starts_with('/') {
        return Err(escaped());
    }
    let link_dir = host_link.parent().unwrap_or(base);
    let mut resolved = link_dir.canonicalize().map_err(|_| escaped())?;
    if !resolved.starts_with(base) {
        return Err(escaped());
    }
    let mut exists = true;
    for component in Path::new(target).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
                if !resolved.starts_with(base) {
                    return Err(escaped());
                }
                exists = match std::fs::symlink_metadata(&resolved) {
                    Ok(_) => true,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                    Err(_) => return Err(escaped()),
                };
            }
            Component::Normal(name) => {
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
                if !resolved.starts_with(base) {
                    return Err(escaped());
                }
            }
            _ => return Err(escaped()),
        }
    }
    Ok(())
}

/// Create a symlink holding `target` at the pinned name.
pub(super) fn symlink(
    target: &str,
    link: &Path,
    expected: Option<&HostIdentity>,
) -> io::Result<()> {
    let expected = expected.ok_or_else(stale_resolution)?;
    let (parent, leaf) = opened_parent(link, expected)?;
    let target = CString::new(target.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "symlink target contains a NUL byte",
        )
    })?;
    // SAFETY: target, parent, and leaf are owned, valid handles.
    last_result(unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), leaf.as_ptr()) })
}

/// Replace the permission bits of the pinned object.
pub(super) fn set_permissions(
    host_path: &Path,
    mode: u32,
    expected: Option<&HostIdentity>,
) -> io::Result<()> {
    let expected = expected.ok_or_else(stale_resolution)?;
    let (expected_device, expected_inode) = match expected {
        HostIdentity::Present { device, inode, .. } => (*device, *inode),
        HostIdentity::Missing { .. } | HostIdentity::Unavailable { .. } => {
            return Err(stale_resolution());
        }
    };
    let (parent, leaf) = opened_parent(host_path, expected)?;
    #[cfg(target_os = "linux")]
    {
        let open_flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_PATH;
        // SAFETY: parent and leaf are owned, valid handles. The returned descriptor is checked.
        let descriptor = unsafe { libc::openat(parent.as_raw_fd(), leaf.as_ptr(), open_flags, 0) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned this owned descriptor and File closes it once.
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata()?;
        if metadata.dev() != expected_device || metadata.ino() != expected_inode {
            return Err(stale_resolution());
        }
        let descriptor_path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .expect("a descriptor path has no NUL byte");
        // SAFETY: the proc path names the exact open descriptor whose identity was verified.
        last_result(unsafe { libc::chmod(descriptor_path.as_ptr(), mode as libc::mode_t) })
    }
    #[cfg(not(target_os = "linux"))]
    {
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
        #[allow(clippy::unnecessary_cast)]
        if leaf_stat.st_dev as u64 != expected_device || leaf_stat.st_ino as u64 != expected_inode {
            return Err(stale_resolution());
        }
        // SAFETY: parent and leaf are owned, valid handles.
        last_result(unsafe {
            libc::fchmodat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                mode as libc::mode_t,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _base: tempfile::TempDir,
        workspace: PathBuf,
        canonical: PathBuf,
        mounts: Mounts,
    }

    fn fixture() -> Fixture {
        let base = tempfile::tempdir().expect("a base directory");
        let workspace = base.path().join("ws");
        let outside = base.path().join("outside");
        std::fs::create_dir_all(workspace.join("sub")).expect("workspace");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(workspace.join("real.txt"), "IN_MOUNT").expect("file");
        std::os::unix::fs::symlink(base.path().join("absent"), workspace.join("dangle"))
            .expect("dangle");
        std::os::unix::fs::symlink(&outside, workspace.join("escape")).expect("escape");
        let source = workspace.to_str().expect("UTF-8").to_string();
        let mounts = Mounts::new(&[(&source, "/mnt/deep/ws")]);
        let canonical = std::fs::canonicalize(&workspace).expect("canonical");
        Fixture {
            _base: base,
            workspace,
            canonical,
            mounts,
        }
    }

    fn host(fixture: &Fixture, path: &str) -> Option<PathBuf> {
        fixture.mounts.resolve_host(path).map(|(host, _)| host)
    }

    #[test]
    fn a_path_under_a_mount_maps_to_the_host_path_below_it() {
        let fixture = fixture();
        assert_eq!(
            host(&fixture, "/mnt/deep/ws"),
            Some(fixture.workspace.clone())
        );
        assert_eq!(
            host(&fixture, "/mnt/deep/ws/real.txt"),
            Some(fixture.canonical.join("real.txt"))
        );
        assert_eq!(
            host(&fixture, "/mnt/deep/ws/a/b/c"),
            Some(fixture.workspace.join("a/b/c"))
        );
    }

    #[test]
    fn a_pin_whose_host_identity_is_not_the_spelling_is_unavailable() {
        let fixture = fixture();
        std::fs::write(fixture.workspace.join("sub/f"), "IN_SUB").expect("file");
        std::os::unix::fs::symlink("sub", fixture.workspace.join("hop")).expect("hop");
        let identity = |path| fixture.mounts.identity(path, Follow::Yes);
        assert!(matches!(
            identity("/mnt/deep/ws/sub/f"),
            Some(HostIdentity::Present { .. })
        ));
        assert!(matches!(
            identity("/mnt/deep/ws/sub/new"),
            Some(HostIdentity::Missing { .. })
        ));
        assert!(matches!(
            identity("/mnt/deep/ws/hop/f"),
            Some(HostIdentity::Unavailable { .. })
        ));
        assert!(matches!(
            identity("/mnt/deep/ws/hop/new"),
            Some(HostIdentity::Unavailable { .. })
        ));
    }

    #[test]
    fn a_symlinked_ancestor_is_neither_pinned_nor_opened() {
        let fixture = fixture();
        let outside = fixture.canonical.parent().expect("base").join("outside");
        std::fs::create_dir_all(outside.join("b")).expect("outside dir");
        std::fs::write(outside.join("b/f"), "OUTSIDE").expect("outside file");
        std::os::unix::fs::symlink(&outside, fixture.workspace.join("a")).expect("ancestor link");
        let root = fixture.canonical.clone();
        let parent = root.join("a/b");

        let pinned = pinned_identity(parent.join("f"), parent.clone(), root.clone(), Follow::Yes);
        assert_eq!(pinned, None);

        let target = std::fs::metadata(outside.join("b")).expect("outside metadata");
        let forged = HostIdentity::Missing {
            path: parent.join("g"),
            parent: parent.clone(),
            root,
            parent_device: target.dev(),
            parent_inode: target.ino(),
        };
        assert!(opened_parent(&parent.join("g"), &forged).is_err());
        assert!(!outside.join("b/g").exists());
    }

    #[test]
    fn a_spelling_under_a_mount_is_translated_to_its_host_identity() {
        let fixture = fixture();
        std::os::unix::fs::symlink("sub", fixture.workspace.join("hop")).expect("hop");
        std::os::unix::fs::symlink("real.txt", fixture.workspace.join("flink")).expect("flink");
        let spelling = |path, follow| fixture.mounts.canonical_spelling(path, follow);
        assert_eq!(
            spelling("/mnt/deep/ws/hop/new", Follow::Yes).as_deref(),
            Some("/mnt/deep/ws/sub/new")
        );
        assert_eq!(
            spelling("/mnt/deep/ws/flink", Follow::Yes).as_deref(),
            Some("/mnt/deep/ws/real.txt")
        );
        assert_eq!(
            spelling("/mnt/deep/ws/flink", Follow::No).as_deref(),
            Some("/mnt/deep/ws/flink")
        );
        assert_eq!(spelling("/mnt/deep/ws/escape/x", Follow::Yes), None);
        assert_eq!(spelling("/mnt/deep/ws", Follow::Yes), None);
    }

    #[test]
    fn a_host_symlink_that_leaves_or_dangles_is_refused() {
        let fixture = fixture();
        assert_eq!(host(&fixture, "/mnt/deep/ws/dangle"), None);
        assert_eq!(host(&fixture, "/mnt/deep/ws/escape"), None);
        assert_eq!(host(&fixture, "/mnt/deep/ws/escape/f"), None);
    }

    #[test]
    fn a_path_with_no_mount_ancestor_has_no_host_path() {
        let fixture = fixture();
        assert_eq!(host(&fixture, "/"), None);
        assert_eq!(host(&fixture, "/mnt/deep"), None);
        assert_eq!(host(&fixture, "/mnt/deep/x/y"), None);
        assert_eq!(host(&fixture, "/mnt/deep/wsx/real.txt"), None);
    }
}
