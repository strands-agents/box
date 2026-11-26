//! Selected incoming mount connections retained while the ordinary view becomes private.

use super::*;
use std::fs::File;
use std::os::unix::fs::OpenOptionsExt;

pub(super) struct IncomingMount {
    target: PathBuf,
    source: File,
}

pub(super) fn require_compatible_entries(
    paths: &[PathBuf],
    entries: &[MountEntry],
) -> Result<(), ContainmentError> {
    for (index, path) in paths.iter().enumerate() {
        if !path.is_absolute()
            || path == Path::new("/")
            || path.components().any(|part| {
                !matches!(
                    part,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
            || paths[..index]
                .iter()
                .any(|other| path.starts_with(other) || other.starts_with(path))
        {
            return Err(refusal(format!(
                "invalid or overlapping incoming mount path '{}'",
                path.display()
            )));
        }
        let canonical = std::fs::canonicalize(path).map_err(|error| {
            refusal(format!(
                "resolving incoming mount '{}': {error}",
                path.display()
            ))
        })?;
        if canonical != *path || !path.is_dir() {
            return Err(refusal(format!(
                "incoming mount '{}' must name an existing canonical directory",
                path.display()
            )));
        }
        let covered = entries.iter().any(|entry| {
            entry.kind == MountKind::Bind
                && entry.origin == MountOrigin::Grant
                && entry.writable
                && entry.executable
                && path.starts_with(&entry.target)
                && entry.source.as_ref() == Some(&entry.target)
        });
        if !covered
            || entries.iter().any(|entry| {
                (entry.target.starts_with(path) || path.starts_with(&entry.target))
                    && matches!(
                        entry.origin,
                        MountOrigin::Refusal
                            | MountOrigin::Protection { .. }
                            | MountOrigin::TreeProtection { .. }
                    )
            })
        {
            return Err(refusal(format!(
                "incoming mount '{}' needs an unrestricted writable and executable directory grant",
                path.display()
            )));
        }
    }
    Ok(())
}

pub(super) fn capture(
    paths: &[PathBuf],
    identities: &BTreeMap<PathBuf, ObjectIdentity>,
) -> Result<Vec<IncomingMount>, ContainmentError> {
    paths
        .iter()
        .map(|path| {
            let source = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
                .map_err(|error| failure("opening", path, error))?;
            let identity = identities.get(path).ok_or_else(|| {
                refusal(format!(
                    "incoming mount '{}' has no prepared identity",
                    path.display()
                ))
            })?;
            require_grant_identity(&targets::descriptor_path(&source), *identity)?;
            require_connection(&source, false, path)?;
            mount_subtree(&source, path)?;
            Ok(IncomingMount {
                target: path.clone(),
                source,
            })
        })
        .collect()
}

pub(super) fn install(
    view: &MountView,
    root: &Path,
    incoming: Vec<IncomingMount>,
) -> Result<(), ContainmentError> {
    for connection in incoming {
        let entry = MountEntry {
            source: Some(connection.target.clone()),
            target: connection.target.clone(),
            kind: MountKind::Bind,
            writable: true,
            executable: true,
            origin: MountOrigin::Grant,
        };
        let target = targets::MountTarget::prepare_bind(view, &entry, root, true)?;
        let previous = targets::mount_ids()?;
        require_current_source(&connection)?;
        let before = mount_subtree(&connection.source, &connection.target)?;
        #[cfg(test)]
        test_barrier(SetupStage::BeforeBind);
        mount_syscall(
            Some(&targets::descriptor_path(&connection.source)),
            &target.path(),
            None,
            libc::MS_BIND | libc::MS_REC,
            None,
        )
        .map_err(|error| failure("attaching", &connection.target, error))?;
        #[cfg(test)]
        test_barrier(SetupStage::AfterBind);
        // A handle pinned before an overmount still names the covered directory. Refuse a
        // changed source, including the pin-to-bind interval, instead of exposing a stale view.
        require_current_source(&connection)?;
        let spelling = root.join(connection.target.strip_prefix("/").unwrap());
        let mounted = target.require_new_mount(&spelling, &previous)?;
        let after = mount_subtree(&connection.source, &connection.target)?;
        let copied = mount_subtree(&mounted, &spelling)?;
        // Recursive binding silently omits unbindable children. Check both source snapshots
        // against the copy, including stacked mounts at the same path. A child can become
        // unbindable for the bind syscall and become bindable again before the postcheck.
        for (point, count) in before.iter().chain(&after) {
            if copied.get(point).copied().unwrap_or(0) < *count {
                return Err(refusal(format!(
                    "incoming mount '{}' did not preserve child mount '{}'; retry startup against a stable bindable source",
                    connection.target.display(),
                    connection.target.join(point).display()
                )));
            }
        }
        mount_syscall(
            None,
            &targets::descriptor_path(&mounted),
            None,
            libc::MS_SLAVE | libc::MS_REC,
            None,
        )
        .map_err(|error| failure("making one-way", &connection.target, error))?;
        let (writable, executable) = restrict_existing(&mounted, true, true)?;
        require_mount_flags(&mounted, writable, executable, false)?;
        require_connection(&mounted, true, &spelling)?;
        target.require_same_mount(&spelling, &previous, &mounted)?;
    }
    Ok(())
}

pub(super) fn restrict_existing(
    mounted: &File,
    writable: bool,
    executable: bool,
) -> Result<(bool, bool), ContainmentError> {
    let mut status = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the descriptor is owned and status is writable storage for the result.
    if unsafe { libc::fstatvfs(mounted.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(refusal(format!(
            "reading incoming source permissions: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fstatvfs initialized the structure on success.
    let flags = unsafe { status.assume_init() }.f_flag;
    let attributes = libc::mount_attr {
        attr_set: libc::MOUNT_ATTR_NOSUID
            | libc::MOUNT_ATTR_NODEV
            | if writable { 0 } else { libc::MOUNT_ATTR_RDONLY }
            | if executable {
                0
            } else {
                libc::MOUNT_ATTR_NOEXEC
            },
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: the owned mount is changed recursively using the Linux ABI structure.
    if unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            mounted.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_RECURSIVE,
            &attributes,
            std::mem::size_of_val(&attributes),
        )
    } != 0
    {
        return Err(refusal(format!(
            "preserving incoming source permissions: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok((
        writable && flags & libc::ST_RDONLY == 0,
        executable && flags & libc::ST_NOEXEC == 0,
    ))
}

fn mount_id(file: &File) -> Result<u64, ContainmentError> {
    mountinfo::mount_id(file)
        .map_err(|error| refusal(format!("reading incoming mount identity: {error}")))
}

fn require_current_source(connection: &IncomingMount) -> Result<(), ContainmentError> {
    let current = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&connection.target)
        .map_err(|error| failure("rechecking", &connection.target, error))?;
    let pinned = connection
        .source
        .metadata()
        .map_err(|error| failure("checking pinned source for", &connection.target, error))?;
    require_grant_identity(
        &targets::descriptor_path(&current),
        ObjectIdentity::from_metadata(&pinned),
    )?;
    if mount_id(&current)? != mount_id(&connection.source)? {
        return Err(refusal(format!(
            "incoming mount '{}' changed during setup; retry startup against the current source",
            connection.target.display()
        )));
    }
    require_connection(&current, true, &connection.target)
}

fn require_connection(file: &File, receiver: bool, exact: &Path) -> Result<(), ContainmentError> {
    let id = mount_id(file)?;
    let table = mountinfo::read()
        .map_err(|error| refusal(format!("reading incoming mount connections: {error}")))?;
    let mounts =
        mountinfo::parse(&table).ok_or_else(|| refusal("malformed incoming mount table".into()))?;
    let mount = mounts
        .iter()
        .find(|mount| mount.identity == id)
        .ok_or_else(|| refusal("incoming mount is absent from the mount table".into()))?;
    if mount.point != exact {
        return Err(refusal(format!(
            "incoming mount '{}' must be the currently reachable dedicated mount point; a directory beneath a connected ancestor is not sufficient",
            exact.display()
        )));
    }
    let shared = mount.propagation.shared.is_some();
    let slave = mount.propagation.master.is_some();
    if (!shared && !slave) || (receiver && (!slave || shared)) {
        return Err(refusal("incoming mount has no connected one-way upstream; the publisher must provide a shared mount".into()));
    }
    Ok(())
}

// Inspect mount ancestry rather than all paths with the same prefix: an older covered
// mount or an ordinary bind in the new view must not stand in for the selected source.
fn mount_subtree(root: &File, path: &Path) -> Result<BTreeMap<PathBuf, usize>, ContainmentError> {
    let root_id = mount_id(root)?;
    let table = mountinfo::read()
        .map_err(|error| refusal(format!("reading incoming child mounts: {error}")))?;
    let mut rows = BTreeMap::new();
    let mut children: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let mounts = mountinfo::parse(&table)
        .ok_or_else(|| refusal("malformed incoming child mount table".into()))?;
    for mount in mounts {
        let id = mount.identity;
        let parent = mount.parent;
        rows.insert(id, (mount.point, mount.propagation.unbindable));
        if parent != id {
            children.entry(parent).or_default().push(id);
        }
    }
    let mut points = BTreeMap::new();
    let mut pending = vec![root_id];
    while let Some(id) = pending.pop() {
        let (point, unbindable) = rows
            .get(&id)
            .ok_or_else(|| refusal("incoming child mount disappeared during setup".into()))?;
        let relative = point.strip_prefix(path).map_err(|_| {
            refusal(format!(
                "incoming child mount '{}' moved outside '{}' during setup",
                point.display(),
                path.display()
            ))
        })?;
        if *unbindable {
            return Err(refusal(format!(
                "incoming mount '{}' contains unbindable child mount '{}'; recursive binding cannot preserve it",
                path.display(),
                point.display()
            )));
        }
        *points.entry(relative.to_path_buf()).or_default() += 1;
        if let Some(descendants) = children.remove(&id) {
            pending.extend(descendants);
        }
    }
    Ok(points)
}

pub(super) fn verify_final(paths: &[PathBuf]) -> Result<(), ContainmentError> {
    if paths.is_empty() {
        return Ok(());
    }
    for path in paths {
        let source = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| failure("checking final", path, error))?;
        require_connection(&source, true, path)?;
    }
    let table = mountinfo::read()
        .map_err(|error| refusal(format!("checking final incoming mount isolation: {error}")))?;
    let mounts =
        mountinfo::parse(&table).ok_or_else(|| refusal("malformed final mount table".into()))?;
    for mount in mounts {
        let point = mount.point;
        let shared = mount.propagation.shared.is_some();
        let receiving = mount.propagation.master.is_some();
        if shared || (receiving && !paths.iter().any(|path| point.starts_with(path))) {
            return Err(refusal(format!(
                "final mount '{}' has propagation outside the selected one-way subtrees",
                point.display()
            )));
        }
    }
    Ok(())
}

fn failure(action: &str, path: &Path, error: std::io::Error) -> ContainmentError {
    refusal(format!(
        "{action} incoming mount '{}': {error}",
        path.display()
    ))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum SetupStage {
    AfterCapture,
    BeforeBind,
    AfterBind,
    BeforePivot,
}

#[cfg(test)]
thread_local! {
    static SETUP_BARRIER: RefCell<Option<(SetupStage, std::os::unix::net::UnixStream)>> = const { RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn test_barrier(stage: SetupStage) {
    use std::io::{Read, Write};
    SETUP_ACTION.with_borrow_mut(|action| {
        if let Some(action) = action {
            action(stage);
        }
    });
    SETUP_BARRIER.with_borrow_mut(|barrier| {
        if barrier
            .as_ref()
            .is_some_and(|(expected, _)| *expected == stage)
        {
            let (_, mut stream) = barrier.take().unwrap();
            stream.write_all(b"b").unwrap();
            stream.read_exact(&mut [0]).unwrap();
        }
    });
}

#[cfg(test)]
thread_local! {
    static AFTER_PIVOT_ACTION: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn after_pivot() {
    if let Some(action) = AFTER_PIVOT_ACTION.with_borrow_mut(Option::take) {
        action();
    }
}

#[cfg(test)]
type SetupAction = Box<dyn FnMut(SetupStage)>;

#[cfg(test)]
thread_local! {
    static SETUP_ACTION: RefCell<Option<SetupAction>> = const { RefCell::new(None) };
}
