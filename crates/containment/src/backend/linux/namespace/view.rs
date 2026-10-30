//! Lowering filesystem grants onto a constructed mount view.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::config::ContainmentConfig;
use crate::error::ContainmentError;
use crate::model::{ObjectIdentity, ObjectPin, Operation, Scope};

use super::MECHANISM;
use crate::backend::dependencies::{MissingReads, folded, require_not_refused, workload_writable};

mod targets;

/// What provides an entry's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MountKind {
    /// A bind of an existing host file or directory.
    Bind,
    /// A fresh filesystem instance, with no host contents.
    Fresh {
        /// The filesystem type to mount, e.g. `tmpfs` or `proc`.
        fstype: &'static str,
    },
    /// A fresh empty regular file, with no host contents.
    EmptyFile,
}

/// Why an entry is in the view. Carried so a reader of a planned view can tell a
/// grant-derived mount from one the launcher adds on every run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MountOrigin {
    /// Derived directly from a filesystem grant.
    Grant,
    /// The ELF interpreter of an executable grant.
    Interpreter,
    /// A shared library an executable grant needs.
    Library,
    /// A pathname Unix socket the workload may connect to — a broker route.
    Socket,
    /// Part of the launcher's fixed scaffold: the root, `/proc`, `/tmp`, `/dev`.
    Scaffold,
    /// A path the caller refused, overmounted empty and read-only so a grant above it stops here.
    Refusal,
    /// An exact write-protected object, with the identity the caller opened.
    Protection { device: u64, inode: u64 },
}

/// One planned mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountEntry {
    /// The host path providing the bytes. Unused for [`MountKind::Fresh`].
    pub(crate) source: Option<PathBuf>,
    /// The path inside the view.
    pub(crate) target: PathBuf,
    pub(crate) kind: MountKind,
    /// Whether the workload may write through this mount.
    pub(crate) writable: bool,
    /// Whether the workload may execute, or map as code, a file reached through this mount.
    pub(crate) executable: bool,
    pub(crate) origin: MountOrigin,
}

/// An ordered, verified plan for the workload's filesystem.
#[derive(Debug)]
pub(crate) struct MountView {
    entries: Vec<MountEntry>,
    protected_parents: BTreeSet<PathBuf>,
    grant_identities: BTreeMap<PathBuf, ObjectIdentity>,
    grant_pins: Vec<ObjectPin>,
    dependency_sources: RefCell<BTreeMap<PathBuf, Rc<std::fs::File>>>,
}

impl MountView {
    /// Plan the view from a request, without touching any namespace.
    pub(crate) fn plan(config: &ContainmentConfig) -> Result<Self, ContainmentError> {
        let mut grant_identities = BTreeMap::new();
        for granted in config.authorizations() {
            if let Some(identity) = granted.identity
                && let Some(previous) = grant_identities.insert(granted.resolved.clone(), identity)
                && previous != identity
            {
                return Err(refusal(format!(
                    "filesystem grants name different objects at '{}'",
                    granted.resolved.display()
                )));
            }
        }
        let mut entries = vec![MountEntry {
            source: None,
            target: PathBuf::from("/"),
            kind: MountKind::Fresh { fstype: "tmpfs" },
            // The root itself is writable while the launcher builds it, and is remounted read-only
            // before `pivot_root`.
            writable: true,
            executable: false,
            origin: MountOrigin::Scaffold,
        }];

        // A fresh `/proc` is what makes the PID namespace visible as isolation rather than merely
        // present: without it the workload reads the host's procfs and sees every process on the
        // machine.
        entries.push(MountEntry {
            source: None,
            target: PathBuf::from("/proc"),
            kind: MountKind::Fresh { fstype: "proc" },
            // Keep process inspection available, but do not allow `/proc/*/mem` to write through
            // the executable-memory syscall restrictions.
            writable: false,
            executable: false,
            origin: MountOrigin::Scaffold,
        });

        // A private `/tmp`, because a workload that cannot write anywhere fails in
        // ways that read as bugs, and because the host's `/tmp` is shared state.
        entries.push(MountEntry {
            source: None,
            target: PathBuf::from("/tmp"),
            kind: MountKind::Fresh { fstype: "tmpfs" },
            writable: true,
            executable: false,
            origin: MountOrigin::Scaffold,
        });

        // The four character devices a normal runtime expects.
        for device in DEVICE_NODES {
            entries.push(MountEntry {
                source: Some(PathBuf::from(device)),
                target: PathBuf::from(device),
                kind: MountKind::Bind,
                // `/dev/null` is written by almost everything; the write lands in
                // the kernel's sink, not in a file the workload can read back.
                writable: true,
                executable: false,
                origin: MountOrigin::Scaffold,
            });
        }

        // `dedup` tracks targets already planned, so two grants naming the same path — or two
        // executables sharing libc — plan one mount.
        let mut dedup: BTreeSet<PathBuf> = entries.iter().map(|e| e.target.clone()).collect();

        let scaffold = entries.len();
        let mut exec_files: Vec<PathBuf> = Vec::new();
        for granted in config.authorizations() {
            let resolved = granted.resolved.clone();

            // Defence in depth at this backend's last safe point: the vocabulary already
            // reconciled the authored scope with the filesystem.
            if granted.scope == Scope::File && resolved.is_dir() {
                return Err(refusal(format!(
                    "grant for '{}' is at file scope but the path is a directory; \
                     binding the directory would authorize every file in it",
                    resolved.display()
                )));
            }

            // **`List` has no lowering in a mount view.** A bind of the tree exposes every file's
            // bytes, and an empty filesystem exposes no entry, so neither is enumeration without
            // content. Refused by name rather than widened to a read.
            if granted.operation == Operation::List {
                return Err(ContainmentError::UnsupportedCapability {
                    capability: format!(
                        "list grant on '{}': a bind mount cannot enumerate a tree without exposing \
                         its files' bytes, so this backend has no lowering for List; grant Read at \
                         Root scope, or each directory at Dir scope",
                        resolved.display()
                    ),
                    backend: MECHANISM.to_string(),
                });
            }

            // A pathname socket grant needs the socket *file* present, or `connect(2)` fails with
            // `ENOENT` before any authorization is consulted. Brought in writable.
            if granted.operation == Operation::Connect {
                for target in granted.reachable_paths() {
                    if dedup.insert(target.clone()) {
                        entries.push(MountEntry {
                            source: Some(resolved.clone()),
                            target,
                            kind: MountKind::Bind,
                            writable: true,
                            executable: false,
                            origin: MountOrigin::Socket,
                        });
                    }
                }
                continue;
            }

            // **`Metadata` at `Root` scope is left OUT of the view, and that is deliberate.** A
            // mount cannot carry metadata without read: a read-only bind of the subtree would let
            // the workload read every byte of a tree the grant says it may only stat, which is a
            // fail-open. Absent from the view is fail-closed — the path does not resolve at all.
            if granted.operation == Operation::Metadata && granted.scope == Scope::Root {
                continue;
            }

            // **`Dir` scope is a FRESH empty filesystem, never a bind of the real path.** The
            // requirement is that the workload can `chdir` here and read nothing. On macOS the same
            // cell renders the real directory's entry names, which is the divergence the decision
            // record states.
            // `Metadata` at `Dir` scope lands here too: an empty filesystem is stricter than the
            // entry's own metadata, so it holds the requirement rather than widening it.
            if granted.scope == Scope::Dir {
                for target in granted.reachable_paths() {
                    // An authorized descendant supplies the contents beneath this directory.
                    let has_granted_descendant =
                        config.authorizations().into_iter().any(|candidate| {
                            candidate
                                .reachable_paths()
                                .iter()
                                .any(|path| path != &target && path.starts_with(&target))
                        });
                    if has_granted_descendant {
                        continue;
                    }
                    if dedup.insert(target.clone()) {
                        entries.push(MountEntry {
                            source: None,
                            target,
                            kind: MountKind::Fresh { fstype: "tmpfs" },
                            // Read-only, so the workload cannot populate the directory it is
                            // standing in.
                            writable: false,
                            executable: false,
                            origin: MountOrigin::Grant,
                        });
                    }
                }
                continue;
            }

            let writable = granted.operation == Operation::Write;
            // A read root on a loader directory is exec-capable, because the loader maps code from
            // it and a mount cannot separate `mmap(PROT_EXEC)` from `execve`.
            let executable = granted.operation == Operation::Exec
                || config.broad_exec()
                    && matches!(granted.operation, Operation::Read | Operation::Write)
                    && (resolved.is_file() || resolved.is_dir())
                || granted.operation == Operation::Read
                    && granted.scope == Scope::Root
                    && is_loader_directory(&resolved);

            // A grant is bound under BOTH its spellings, to the same source. A path granted read
            // and write arrives as two grants, so the second ORs the first entry's flags.
            for target in granted.reachable_paths() {
                if dedup.insert(target.clone()) {
                    entries.push(MountEntry {
                        source: Some(resolved.clone()),
                        target,
                        kind: MountKind::Bind,
                        writable,
                        executable,
                        origin: MountOrigin::Grant,
                    });
                } else if let Some(existing) = entries.iter_mut().find(|e| e.target == target) {
                    existing.writable |= writable;
                    existing.executable |= executable;
                }
            }

            // Only an exec grant on one file pulls in dependencies: a tree names no one image to
            // read them from, so a program under it brings its own through a grant of their own.
            if granted.operation == Operation::Exec && granted.scope == Scope::File {
                exec_files.push(resolved);
            }
        }

        // **The loader closure of each exec file, beneath the trees already planned.** A dependency
        // inside an exec-capable tree bind is reached through that bind, so it is not bound twice.
        let covering: Vec<PathBuf> = entries
            .iter()
            .filter(|entry| {
                entry.kind == MountKind::Bind
                    && entry.executable
                    && !entry.writable
                    && entry.origin == MountOrigin::Grant
                    && entry.source.as_deref().is_some_and(Path::is_dir)
            })
            .map(|entry| entry.target.clone())
            .collect();
        let mut dependency_sources = BTreeMap::new();
        let mut missing = MissingReads::default();
        for executable in exec_files {
            for dependency in collect_elf_dependencies(&executable, config, &mut missing)? {
                if covering
                    .iter()
                    .any(|tree| dependency.path.starts_with(tree))
                {
                    continue;
                }
                if dedup.insert(dependency.path.clone()) {
                    dependency_sources.insert(dependency.path.clone(), dependency.file);
                    entries.push(MountEntry {
                        source: Some(dependency.resolved),
                        target: dependency.path,
                        kind: MountKind::Bind,
                        // Never writable: read-plus-execute is the safe pairing precisely
                        // because the bytes cannot change under the grant.
                        writable: false,
                        executable: true,
                        origin: dependency.origin,
                    });
                }
            }
        }

        missing.require_complete(MECHANISM)?;

        // **A grant inside another grant's tree is established after it, whatever order the two
        // were stated in.** A nested bind sits on top of the tree that encloses it, and its own
        // flags decide what the workload finds there: a bind that is not an exec grant is no-exec,
        // so an exec file inside a read tree must be the upper mount, and a write root inside an
        // exec tree must be the upper mount to stay writable. Stable, so grants at one depth keep
        // the order they were stated in.
        entries[scaffold..].sort_by_key(|entry| entry.target.components().count());

        // **The pair the floor warns about lowers as stated, on this backend too.** A bind inside a
        // stated exec tree is executable, and an exec grant inside a stated write grant is
        // writable, so a build writes its output and runs it here as it does on macOS. Every other
        // bind stays no-exec or read-only.
        let write_roots = config.grants_in(Operation::Write, Scope::Root);
        let write_files = config.grants_in(Operation::Write, Scope::File);
        let exec_roots = config.grants_in(Operation::Exec, Scope::Root);
        for entry in entries
            .iter_mut()
            .filter(|entry| entry.kind == MountKind::Bind && entry.origin == MountOrigin::Grant)
        {
            let Some(source) = entry.source.as_deref() else {
                continue;
            };
            if entry.executable
                && (write_roots
                    .iter()
                    .any(|writable| source.starts_with(&writable.resolved))
                    || write_files
                        .iter()
                        .any(|writable| writable.resolved == source))
            {
                entry.writable = true;
            }
            if exec_roots
                .iter()
                .any(|tree| source.starts_with(&tree.resolved))
            {
                entry.executable = true;
            }
        }

        let mut protections = Vec::new();
        let mut protected_parents = BTreeSet::new();
        for protected in config.write_protections() {
            let mut targets = BTreeSet::from([protected.path().to_path_buf()]);
            for entry in &entries {
                if !entry.writable || entry.kind != MountKind::Bind {
                    continue;
                }
                let Some(source) = &entry.source else {
                    continue;
                };
                let Ok(relative) = protected.path().strip_prefix(source) else {
                    continue;
                };
                let target = entry.target.join(relative);
                for parent in target.ancestors().skip(1).take_while(|parent| {
                    *parent != entry.target && parent.starts_with(&entry.target)
                }) {
                    protected_parents.insert(parent.to_path_buf());
                }
                targets.insert(target);
            }
            for target in targets {
                protections.push(MountEntry {
                    source: Some(protected.path().to_path_buf()),
                    target,
                    kind: MountKind::Bind,
                    writable: false,
                    executable: false,
                    origin: MountOrigin::Protection {
                        device: protected.device(),
                        inode: protected.inode(),
                    },
                });
            }
        }
        entries.extend(protections);

        // **Every refusal, planned last, so it overmounts the grant that bound its parent.**
        // A fresh read-only tmpfs is how this backend already spells "present, empty, and
        // unwritable", so a refused tree needs no new mechanism here: the workload finds an empty
        // directory where the refused tree is, and the bytes are not in the view at all. That is
        // strictly stronger than a rule, and it is why the Linux half needs no path matching. A
        // refused file that exists is overmounted with an empty read-only file on the same terms.
        //
        // It covers only the paths named before launch. A directory the workload creates afterwards
        // is not in any plan, which is why the box also refuses to adopt a project nested inside
        // another one. **A refused file that does not exist yet has no lowering**: an overmount
        // needs an existing target, and creating one through a writable bind would create it on
        // the host, so it is refused by name rather than planned.
        for refused in config.refusals() {
            // A refusal under a refused tree is already honoured by that tree's empty filesystem,
            // and a mountpoint cannot be created inside one.
            let covered = config.refusals().iter().any(|tree| {
                tree.scope == Scope::Root
                    && tree.resolved != refused.resolved
                    && refused.resolved.starts_with(&tree.resolved)
            });
            if covered {
                continue;
            }
            let present = std::fs::metadata(&refused.resolved).ok();
            let kind = if present.as_ref().is_some_and(std::fs::Metadata::is_file) {
                MountKind::EmptyFile
            } else if refused.scope == Scope::File {
                return Err(ContainmentError::UnsupportedCapability {
                    capability: format!(
                        "file refusal on '{}': the path does not exist yet, and an overmount needs \
                         an existing target, so this backend has no lowering for a refusal of a \
                         future file; refuse its directory at Root scope instead",
                        refused.original.display()
                    ),
                    backend: MECHANISM.to_string(),
                });
            } else {
                MountKind::Fresh { fstype: "tmpfs" }
            };
            for target in refused.reachable_paths() {
                let entry = MountEntry {
                    source: None,
                    target: target.clone(),
                    kind,
                    writable: false,
                    executable: false,
                    origin: MountOrigin::Refusal,
                };
                if dedup.insert(target.clone()) {
                    entries.push(entry);
                } else if let Some(index) = entries.iter().position(|entry| entry.target == target)
                {
                    // **Removed and re-appended, never mutated in place.** A refusal outranks
                    // whatever named this path first, and order is the mechanism here: an entry left
                    // at its original index is established BEFORE any deeper grant, which would then
                    // re-establish the real bytes underneath the refused tree.
                    entries.remove(index);
                    entries.push(entry);
                }
            }
        }

        // A fresh grant hides every descendant. Extra denial or protection mountpoints would
        // reveal names beneath a metadata-only grant; the empty filesystem already denies access.
        let empty_roots: Vec<_> = entries
            .iter()
            .filter(|entry| {
                entry.origin == MountOrigin::Grant
                    && entry.kind == MountKind::Fresh { fstype: "tmpfs" }
                    && !entry.writable
            })
            .map(|entry| entry.target.clone())
            .collect();
        entries.retain(|entry| {
            !matches!(
                entry.origin,
                MountOrigin::Refusal | MountOrigin::Protection { .. }
            ) || !empty_roots
                .iter()
                .any(|root| entry.target != *root && entry.target.starts_with(root))
        });
        protected_parents.retain(|parent| {
            !empty_roots.iter().any(|root| parent.starts_with(root))
                && !entries.iter().any(|entry| {
                    entry.origin == MountOrigin::Refusal && parent.starts_with(&entry.target)
                })
        });

        Ok(Self {
            entries,
            protected_parents,
            grant_identities,
            grant_pins: config
                .authorizations()
                .iter()
                .filter_map(|grant| grant.pin.clone())
                .collect(),
            dependency_sources: RefCell::new(dependency_sources),
        })
    }

    /// The planned mounts, in the order they must be established.
    #[cfg(test)]
    pub(crate) fn entries(&self) -> &[MountEntry] {
        &self.entries
    }

    /// Execute the plan and `pivot_root` into it.
    pub(crate) fn materialize(&self) -> Result<(), ContainmentError> {
        // Detach this namespace's propagation from the host's before mounting anything.
        mount_syscall(
            None,
            Path::new("/"),
            None,
            libc::MS_REC | libc::MS_PRIVATE,
            None,
        )
        .map_err(|e| refusal(format!("making the mount tree private: {e}")))?;

        // A FIXED path under the host's world-writable `/tmp`, created with `create_dir_all`, was a
        // symlink-following TOCTOU: `create_dir_all` follows symlinks, so a pre-placed link
        // redirected where the entire view was assembled and `apply` still returned `Ok`
        // (measured).
        let unique = format!("{STAGING_ROOT}.{}", unique_suffix()?);
        let root_owned = PathBuf::from(&unique);
        let root = root_owned.as_path();
        std::fs::create_dir(root).map_err(|e| {
            refusal(format!(
                "creating the staging root '{unique}': {e}; refusing rather than \
                 following an existing entry at that path"
            ))
        })?;

        for entry in &self.entries {
            self.establish(entry, root)?;
        }
        self.protect_parents(root)?;

        // The pivot's temporary old-root mountpoint has to exist *before* the root is sealed read-
        // only.
        let old_root = root.join(OLD_ROOT_NAME);
        std::fs::create_dir_all(&old_root)
            .map_err(|e| refusal(format!("creating the pivot target: {e}")))?;

        // Remount the root read-only now that every bind is in place.
        mount_syscall(
            None,
            root,
            None,
            libc::MS_REMOUNT
                | libc::MS_BIND
                | libc::MS_RDONLY
                | libc::MS_NOSUID
                | libc::MS_NODEV
                | libc::MS_NOEXEC,
            None,
        )
        .map_err(|e| refusal(format!("remounting the view root read-only: {e}")))?;

        self.pivot_into(root)?;
        for pin in &self.grant_pins {
            pin.release()?;
        }
        self.dependency_sources.borrow_mut().clear();
        Ok(())
    }

    /// Pin each protected parent before the root becomes read-only.
    fn protect_parents(&self, root: &Path) -> Result<(), ContainmentError> {
        for parent in &self.protected_parents {
            let target = root.join(parent.strip_prefix("/").unwrap_or(parent));
            let metadata = std::fs::symlink_metadata(&target).map_err(|error| {
                refusal(format!(
                    "inspecting protected parent '{}': {error}",
                    target.display()
                ))
            })?;
            if !metadata.is_dir() {
                return Err(refusal(format!(
                    "protected parent '{}' is not a directory",
                    target.display()
                )));
            }
            mount_syscall(
                Some(&target),
                &target,
                None,
                libc::MS_BIND | libc::MS_REC,
                None,
            )
            .map_err(|error| {
                refusal(format!(
                    "binding protected parent '{}': {error}",
                    target.display()
                ))
            })?;
        }

        Ok(())
    }

    /// Establish one planned mount beneath `root`.
    fn establish(&self, entry: &MountEntry, root: &Path) -> Result<(), ContainmentError> {
        // The root entry is the staging tmpfs itself, mounted at `root` rather
        // than inside it.
        let target = if entry.target == Path::new("/") {
            root.to_path_buf()
        } else {
            // `target` is absolute, so `join` would discard `root`.
            if entry
                .target
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            {
                return Err(refusal(format!(
                    "planned mount target '{}' contains a '..' component; refusing \
                     rather than resolving a path that could climb out of the view",
                    entry.target.display()
                )));
            }
            root.join(entry.target.strip_prefix("/").unwrap_or(&entry.target))
        };

        match entry.kind {
            MountKind::Fresh { fstype } => {
                let pinned = targets::MountTarget::prepare(self, entry, root, true)?;
                let previous = targets::mount_ids()?;
                #[cfg(test)]
                if entry.origin == MountOrigin::Refusal {
                    targets::after_open();
                }
                // `nosuid` and `nodev` on every fresh filesystem: a setuid bit or a device node the
                // workload created would be authority the plan never granted.
                let mut fresh_flags = if fstype == "proc" {
                    libc::MS_NOSUID | libc::MS_NODEV
                } else {
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC
                };
                // **`writable` was ignored here until 2026-08-19, and every fresh mount was
                // writable.** That was harmless while the only fresh mounts were `/proc`, `/tmp`,
                // and the root while the launcher builds it.
                if !entry.writable {
                    fresh_flags |= libc::MS_RDONLY;
                }
                mount_syscall(
                    Some(Path::new(fstype)),
                    &pinned.path(),
                    Some(fstype),
                    fresh_flags,
                    None,
                )
                .map_err(|e| {
                    refusal(format!(
                        "mounting a fresh {fstype} at '{}': {e}",
                        target.display()
                    ))
                })?;
                #[cfg(test)]
                if entry.origin == MountOrigin::Refusal {
                    targets::after_mount();
                }
                pinned.require_new_mount(&target, &previous)?;
            }
            MountKind::EmptyFile => {
                let source = root.join(EMPTY_FILE_NAME);
                if !source.exists() {
                    std::fs::OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .open(&source)
                        .map_err(|e| {
                            refusal(format!(
                                "creating the empty file '{}' a refusal binds: {e}",
                                source.display()
                            ))
                        })?;
                }
                let pinned = targets::MountTarget::prepare(self, entry, root, false)?;
                let previous = targets::mount_ids()?;
                #[cfg(test)]
                targets::after_open();
                mount_syscall(Some(&source), &pinned.path(), None, libc::MS_BIND, None).map_err(
                    |e| {
                        refusal(format!(
                            "binding the empty file over '{}': {e}",
                            target.display()
                        ))
                    },
                )?;
                #[cfg(test)]
                targets::after_mount();
                let mounted = pinned.require_new_mount(&target, &previous)?;
                remount_protected(&targets::descriptor_path(&mounted))?;
            }
            MountKind::Bind => {
                let source = entry.source.as_deref().ok_or_else(|| {
                    refusal(format!(
                        "planned bind for '{}' has no source; a bind with nothing \
                         to bind would silently create an empty mountpoint",
                        entry.target.display()
                    ))
                })?;
                let expected = if matches!(entry.origin, MountOrigin::Grant | MountOrigin::Socket) {
                    Some(*self.grant_identities.get(source).ok_or_else(|| {
                        refusal(format!("missing grant identity for '{}'", source.display()))
                    })?)
                } else {
                    None
                };
                let pinned = expected
                    .map(|identity| pin_grant_source(source, identity))
                    .transpose()?;
                let pinned_path = pinned
                    .as_ref()
                    .map(|file| PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())));
                let dependency_sources = self.dependency_sources.borrow();
                let pinned_source = dependency_sources
                    .get(&entry.target)
                    .map(|admitted| pin_admitted_source(admitted, source))
                    .transpose()?;
                let source = pinned_source
                    .as_ref()
                    .map_or(source, |(_, path)| path.as_path());
                let mount_source = pinned_path.as_deref().unwrap_or(source);

                // The mountpoint must match the source's kind: a file binds onto a
                // file, a directory onto a directory.
                if matches!(entry.origin, MountOrigin::Protection { .. }) {
                    let metadata = std::fs::symlink_metadata(&target).map_err(|e| {
                        refusal(format!(
                            "opening write-protected mountpoint '{}': {e}",
                            target.display()
                        ))
                    })?;
                    if !metadata.is_file() {
                        return Err(refusal(format!(
                            "write-protected mountpoint '{}' is not a regular file",
                            target.display()
                        )));
                    }
                    Ok(())
                } else if mount_source.is_dir() {
                    std::fs::create_dir_all(&target)
                } else {
                    // An existing file is already its own mountpoint. A symbolic link an enclosing
                    // bind brought in is left to that bind: its resolved spelling carries its own bind.
                    match std::fs::symlink_metadata(&target) {
                        Ok(metadata) if metadata.is_file() => Ok(()),
                        Ok(metadata)
                            if metadata.is_symlink() && self.enclosed_by_a_bind(&entry.target) =>
                        {
                            return Ok(());
                        }
                        Ok(_) => Err(std::io::Error::other(format!(
                            "'{}' is not a regular file",
                            entry.target.display()
                        ))),
                        Err(_) if self.enclosed_by_a_bind(&entry.target) => {
                            Err(std::io::Error::other(format!(
                                "'{}' is absent from the tree bound over it, and a mountpoint \
                                 created there would be created on the host",
                                entry.target.display()
                            )))
                        }
                        Err(_) => target
                            .parent()
                            .map_or(Ok(()), std::fs::create_dir_all)
                            .and_then(|()| {
                                std::fs::OpenOptions::new()
                                    .create_new(true)
                                    .write(true)
                                    .open(&target)
                                    .map(|_| ())
                            }),
                    }
                }
                .map_err(|e| {
                    refusal(format!(
                        "creating the mountpoint '{}': {e}",
                        target.display()
                    ))
                })?;

                mount_syscall(
                    Some(mount_source),
                    &target,
                    None,
                    libc::MS_BIND | libc::MS_REC,
                    None,
                )
                .map_err(|e| {
                    refusal(format!(
                        "binding '{}' to '{}': {e}",
                        source.display(),
                        target.display()
                    ))
                })?;

                if let Some(identity) = expected {
                    require_grant_identity(&target, identity)?;
                }
                if let MountOrigin::Protection { device, inode } = entry.origin {
                    require_mounted_identity(&target, device, inode)?;
                    remount_protected(&target)?;
                    return Ok(());
                }

                // Read-only and no-exec are a *second* operation. The bind above is `MS_REC`, so a
                // granted directory containing a submount brings that submount in too.
                match (entry.writable, entry.executable) {
                    // An exec grant, its loader, or a library: read-only, and runnable.
                    (false, true) => remount_read_only(&target)?,
                    // Every other read-only bind: a read grant confers no exec.
                    (false, false) => remount_read_only_noexec(&target)?,
                    // The pair the floor warns about, lowered as stated.
                    (true, true) => remount_writable_executable(&target)?,
                    (true, false) => {
                        // W^X: a writable bind is the one surface whose bytes the workload chooses,
                        // so it must not also be executable.
                        let is_device = std::fs::metadata(mount_source)
                            .map(|meta| {
                                let kind = meta.file_type();
                                std::os::unix::fs::FileTypeExt::is_char_device(&kind)
                                    || std::os::unix::fs::FileTypeExt::is_block_device(&kind)
                            })
                            .unwrap_or(false);
                        if is_device {
                            remount_writable_device_noexec(&target)?;
                        } else {
                            remount_writable_noexec(&target)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Whether a planned bind of a host tree encloses this view path.
    fn enclosed_by_a_bind(&self, target: &Path) -> bool {
        self.entries.iter().any(|entry| {
            entry.kind == MountKind::Bind
                && entry.target != target
                && target.starts_with(&entry.target)
        })
    }

    /// `pivot_root` into the assembled view and detach the old root.
    fn pivot_into(&self, root: &Path) -> Result<(), ContainmentError> {
        // `materialize` created this before sealing the root read-only.
        let old_root = root.join(OLD_ROOT_NAME);

        let root_c = path_to_c(root)?;
        let old_c = path_to_c(&old_root)?;

        // SAFETY: both pointers are NUL-terminated strings that outlive the call.
        let pivoted =
            unsafe { libc::syscall(libc::SYS_pivot_root, root_c.as_ptr(), old_c.as_ptr()) };
        if pivoted != 0 {
            return Err(refusal(format!(
                "pivot_root into the view: {}",
                std::io::Error::last_os_error()
            )));
        }

        std::env::set_current_dir("/")
            .map_err(|e| refusal(format!("entering the pivoted root: {e}")))?;

        let old = Path::new("/").join(OLD_ROOT_NAME);
        let old_c = path_to_c(&old)?;
        // `MNT_DETACH` because the old root's subtree is still busy: a lazy unmount releases it as
        // references drop.
        if unsafe { libc::umount2(old_c.as_ptr(), libc::MNT_DETACH) } != 0 {
            return Err(refusal(format!(
                "detaching the old root: {}",
                std::io::Error::last_os_error()
            )));
        }
        // The mountpoint itself stays, and that is deliberate rather than overlooked.
        let leftover = std::fs::read_dir(&old)
            .map_err(|e| refusal(format!("inspecting the detached old root: {e}")))?
            .count();
        if leftover != 0 {
            return Err(refusal(format!(
                "the detached old root still has {leftover} entries, so the host \
                 filesystem is still reachable inside the view"
            )));
        }

        Ok(())
    }
}

fn pin_grant_source(
    source: &Path,
    expected: ObjectIdentity,
) -> Result<std::fs::File, ContainmentError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(source)
        .map_err(|error| {
            refusal(format!(
                "opening grant source '{}': {error}",
                source.display()
            ))
        })?;
    let metadata = file.metadata().map_err(|error| {
        refusal(format!(
            "inspecting grant source '{}': {error}",
            source.display()
        ))
    })?;
    if ObjectIdentity::from_metadata(&metadata) != expected {
        return Err(refusal(format!(
            "mounted grant identity changed before binding '{}'",
            source.display()
        )));
    }
    Ok(file)
}

fn require_grant_identity(target: &Path, expected: ObjectIdentity) -> Result<(), ContainmentError> {
    let metadata = std::fs::metadata(target).map_err(|error| {
        refusal(format!(
            "inspecting mounted grant '{}': {error}",
            target.display()
        ))
    })?;
    if ObjectIdentity::from_metadata(&metadata) != expected {
        return Err(refusal(format!(
            "mounted grant identity changed at '{}'",
            target.display()
        )));
    }
    Ok(())
}

/// Remount `target` read-only, and every submount beneath it.
fn remount_read_only(target: &Path) -> Result<(), ContainmentError> {
    const FLAGS: libc::c_ulong =
        libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV;
    remount_recursive(target, FLAGS, "read-only")
}

/// Remount `target` read-only and no-exec, and every submount beneath it.
fn remount_read_only_noexec(target: &Path) -> Result<(), ContainmentError> {
    const FLAGS: libc::c_ulong = libc::MS_REMOUNT
        | libc::MS_BIND
        | libc::MS_RDONLY
        | libc::MS_NOEXEC
        | libc::MS_NOSUID
        | libc::MS_NODEV;
    remount_recursive(target, FLAGS, "read-only no-exec")
}

/// Remount `target` writable and runnable, and every submount beneath it.
fn remount_writable_executable(target: &Path) -> Result<(), ContainmentError> {
    const FLAGS: libc::c_ulong =
        libc::MS_REMOUNT | libc::MS_BIND | libc::MS_NOSUID | libc::MS_NODEV;
    remount_recursive(target, FLAGS, "writable and executable")
}

fn remount_protected(target: &Path) -> Result<(), ContainmentError> {
    const FLAGS: libc::c_ulong = libc::MS_REMOUNT
        | libc::MS_BIND
        | libc::MS_RDONLY
        | libc::MS_NOEXEC
        | libc::MS_NOSUID
        | libc::MS_NODEV;
    remount_recursive(target, FLAGS, "protected")
}

fn require_mounted_identity(
    target: &Path,
    device: u64,
    inode: u64,
) -> Result<(), ContainmentError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::metadata(target).map_err(|error| {
        refusal(format!(
            "inspecting mounted write protection '{}': {error}",
            target.display()
        ))
    })?;
    if metadata.dev() != device || metadata.ino() != inode || metadata.nlink() != 1 {
        return Err(refusal(format!(
            "mounted write protection has a different identity: {}",
            target.display()
        )));
    }
    Ok(())
}

/// Remount a writable *device-node* bind no-exec, keeping the device usable.
fn remount_writable_device_noexec(target: &Path) -> Result<(), ContainmentError> {
    const FLAGS: libc::c_ulong =
        libc::MS_REMOUNT | libc::MS_BIND | libc::MS_NOEXEC | libc::MS_NOSUID;
    remount_recursive(target, FLAGS, "no-exec (device)")
}

/// Remount `target` no-exec, and every submount beneath it, still writable.
fn remount_writable_noexec(target: &Path) -> Result<(), ContainmentError> {
    const FLAGS: libc::c_ulong =
        libc::MS_REMOUNT | libc::MS_BIND | libc::MS_NOEXEC | libc::MS_NOSUID | libc::MS_NODEV;
    remount_recursive(target, FLAGS, "no-exec")
}

/// Remount `target` and every submount beneath it with `flags`.
fn remount_recursive(
    target: &Path,
    flags: libc::c_ulong,
    what: &str,
) -> Result<(), ContainmentError> {
    // The target itself always gets remounted: it was just bound, so it is a mount
    // point by construction whether or not the table has caught up.
    let mut points = vec![target.to_path_buf()];

    // `/proc/self/mounts` is the view's own table here -- the mount namespace is already unshared,
    // so this cannot see host-only mounts.
    let table = std::fs::read_to_string("/proc/self/mounts").map_err(|source| {
        refusal(format!(
            "reading the mount table to remount '{}' {what} recursively: {source}; \
             refusing rather than leave a submount wider than its grant",
            target.display()
        ))
    })?;

    for line in table.lines() {
        // Field 2 is the mount point, with octal escapes for space/tab/newline.
        let Some(raw) = line.split_whitespace().nth(1) else {
            continue;
        };
        let point = PathBuf::from(unescape_mount_field(raw));
        if point != target && point.starts_with(target) {
            points.push(point);
        }
    }

    points.sort_by_key(|path| std::cmp::Reverse(path.components().count()));

    for point in points {
        let outcome = mount_syscall(None, &point, None, flags, None);
        // A *shadowed* submount cannot be remounted, and refusing on it would refuse a composition
        // that is already safe.
        if let Err(error) = outcome {
            let shadowed = error.raw_os_error() == Some(libc::EINVAL)
                && shadowing_mount(&point, target)?.is_some();
            if !shadowed {
                return Err(refusal(format!(
                    "remounting '{}' {what}: {error}",
                    point.display()
                )));
            }
        }
    }

    Ok(())
}

/// The mount that covers `point`, if one shadows it inside `target`.
fn shadowing_mount(point: &Path, target: &Path) -> Result<Option<PathBuf>, ContainmentError> {
    let table = std::fs::read_to_string("/proc/self/mounts").map_err(|source| {
        refusal(format!(
            "re-reading the mount table to classify '{}': {source}",
            point.display()
        ))
    })?;

    let mut seen_point = false;
    for line in table.lines() {
        let Some(raw) = line.split_whitespace().nth(1) else {
            continue;
        };
        let candidate = PathBuf::from(unescape_mount_field(raw));
        if candidate == point {
            seen_point = true;
            continue;
        }
        // Only a mount established after `point` can shadow it, and it must sit at a strict
        // ancestor of `point` within the grant being remounted.
        if seen_point
            && point.starts_with(&candidate)
            && candidate != point
            && candidate.starts_with(target)
        {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

/// Undo the octal escapes `/proc/self/mounts` uses for space, tab, newline, and backslash.
fn unescape_mount_field(field: &str) -> String {
    let chars: Vec<char> = field.chars().collect();
    let mut out = String::with_capacity(field.len());
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '\\' && index + 3 < chars.len() {
            let digits = &chars[index + 1..index + 4];
            if digits.iter().all(|digit| ('0'..='7').contains(digit)) {
                let value = digits.iter().fold(0u32, |acc, digit| {
                    acc * 8 + (u32::from(*digit) - u32::from('0'))
                });
                if let Some(decoded) = char::from_u32(value) {
                    out.push(decoded);
                    index += 4;
                    continue;
                }
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

/// A suffix no other process can predict, for the staging directory's name.
fn unique_suffix() -> Result<String, ContainmentError> {
    let mut bytes = [0u8; 8];
    std::io::Read::read_exact(
        &mut std::fs::File::open("/dev/urandom").map_err(|source| {
            refusal(format!(
                "opening /dev/urandom to name the staging root: {source}"
            ))
        })?,
        &mut bytes,
    )
    .map_err(|source| refusal(format!("reading /dev/urandom: {source}")))?;

    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Prefix for the directory the view is assembled in, before the pivot.
const STAGING_ROOT: &str = "/tmp/.strands-box-view";

/// The pivot's temporary old-root mountpoint.
const OLD_ROOT_NAME: &str = ".old-root";

/// The empty file every refused file is a bind of, in the view's own root.
const EMPTY_FILE_NAME: &str = ".strands-box-empty";

/// `mount(2)`, with `Option`s for the arguments the kernel accepts as NULL.
fn mount_syscall(
    source: Option<&Path>,
    target: &Path,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<(), std::io::Error> {
    let source_c = source.map(path_to_cstring).transpose()?;
    let target_c = path_to_cstring(target)?;
    let fstype_c = fstype
        .map(std::ffi::CString::new)
        .transpose()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "fstype has a NUL"))?;
    let data_c = data
        .map(std::ffi::CString::new)
        .transpose()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "data has a NUL"))?;

    let pointer_or_null = |value: &Option<std::ffi::CString>| {
        value
            .as_ref()
            .map_or(std::ptr::null(), |owned| owned.as_ptr())
    };

    // SAFETY: every pointer is either NULL or a NUL-terminated string owned by a
    // local that outlives the call.
    let result = unsafe {
        libc::mount(
            pointer_or_null(&source_c),
            target_c.as_ptr(),
            pointer_or_null(&fstype_c),
            flags,
            pointer_or_null(&data_c).cast(),
        )
    };

    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// A path as a C string, refusing an embedded NUL rather than truncating.
fn path_to_cstring(path: &Path) -> Result<std::ffi::CString, std::io::Error> {
    use std::os::unix::ffi::OsStrExt as _;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains a NUL"))
}

/// A path as a C string, as this module's own refusal.
fn path_to_c(path: &Path) -> Result<std::ffi::CString, ContainmentError> {
    path_to_cstring(path).map_err(|e| refusal(format!("'{}': {e}", path.display())))
}

/// The character devices every planned view contains.
const DEVICE_NODES: &[&str] = &["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"];

/// One resolved dependency of an executable.
struct Dependency {
    path: PathBuf,
    resolved: PathBuf,
    file: Rc<std::fs::File>,
    origin: MountOrigin,
}

/// What one ELF image asks the loader for.
#[derive(Default)]
struct ImageNeeds {
    interpreter: Option<PathBuf>,
    needed: Vec<String>,
    runpath: Option<Vec<String>>,
    rpath: Vec<String>,
}

/// An image's search directories and its shared RPATH ancestry.
struct LibrarySearch {
    directories: Vec<PathBuf>,
    parent: Option<std::rc::Rc<LibrarySearch>>,
}

/// A ceiling on the images one closure walks.
const MAXIMUM_IMAGES: usize = 512;

/// Retain a mount source that matches the admitted dependency's identity.
fn pin_admitted_source(
    admitted: &std::fs::File,
    source: &Path,
) -> Result<(std::fs::File, PathBuf), ContainmentError> {
    use std::os::unix::fs::MetadataExt as _;

    let file = open_dependency(source)?;
    let expected = admitted
        .metadata()
        .map_err(|error| refusal(format!("reading admitted dependency identity: {error}")))?;
    let actual = file
        .metadata()
        .map_err(|error| refusal(format!("reading dependency mount identity: {error}")))?;
    if actual.dev() != expected.dev() || actual.ino() != expected.ino() {
        return Err(refusal(format!(
            "dependency '{}' changed after admission",
            source.display()
        )));
    }
    let path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    Ok((file, path))
}

/// Open a canonical dependency without following replacement links.
fn open_dependency(path: &Path) -> Result<std::fs::File, ContainmentError> {
    use std::os::fd::FromRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let open = || -> std::io::Result<std::fs::File> {
        let expected = std::fs::metadata(path)?;
        if !expected.is_file() {
            return Err(std::io::Error::other("dependency is not a regular file"));
        }
        let mut parent = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open("/")?;
        let mut components = path.components().peekable();
        if components.next() != Some(std::path::Component::RootDir) {
            return Err(std::io::Error::other("dependency path is not absolute"));
        }
        while let Some(component) = components.next() {
            let std::path::Component::Normal(name) = component else {
                return Err(std::io::Error::other("dependency path is not canonical"));
            };
            let name = path_to_cstring(Path::new(name))?;
            let flags = libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | if components.peek().is_some() {
                    libc::O_PATH | libc::O_DIRECTORY
                } else {
                    libc::O_RDONLY | libc::O_NONBLOCK
                };
            // SAFETY: parent is open, and name is a live NUL-terminated component.
            let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: openat returned a new descriptor owned by this file.
            parent = unsafe { std::fs::File::from_raw_fd(fd) };
        }
        let actual = parent.metadata()?;
        if !actual.is_file() || actual.dev() != expected.dev() || actual.ino() != expected.ino() {
            return Err(std::io::Error::other(
                "dependency identity changed before opening",
            ));
        }
        Ok(parent)
    };
    open().map_err(|error| {
        refusal(format!(
            "dependency '{}' cannot be granted: {error}",
            path.display()
        ))
    })
}

/// The ELF interpreter and every shared library `executable` loads, through each library's own
/// needs, resolved as the loader resolves them with no environment and no cache.
#[cfg(test)]
fn elf_dependencies(
    executable: &Path,
    config: &ContainmentConfig,
) -> Result<Vec<Dependency>, ContainmentError> {
    let mut missing = MissingReads::default();
    let dependencies = collect_elf_dependencies(executable, config, &mut missing)?;
    missing.require_complete(MECHANISM)?;
    Ok(dependencies)
}

fn collect_elf_dependencies(
    executable: &Path,
    config: &ContainmentConfig,
    missing: &mut MissingReads,
) -> Result<Vec<Dependency>, ContainmentError> {
    let mut dependencies: Vec<Dependency> = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut walked = BTreeSet::new();
    let restricted = workload_writable(config, executable, MECHANISM)?;
    let resolved = executable.canonicalize().map_err(|error| {
        refusal(format!(
            "dependency '{}' cannot be granted: {error}",
            executable.display()
        ))
    })?;
    let file = Rc::new(open_dependency(&resolved)?);
    let mut pending =
        std::collections::VecDeque::from([(executable.to_path_buf(), file, None, restricted)]);
    while let Some((image, file, inherited_rpath, restricted)) = pending.pop_front() {
        if !walked.insert((image.clone(), restricted)) {
            continue;
        }
        if dependencies.len() > MAXIMUM_IMAGES {
            return Err(refusal(format!(
                "'{}' loads more than {MAXIMUM_IMAGES} images; refusing rather than walking on",
                executable.display()
            )));
        }
        let needs = image_needs_from_file(
            &mut file
                .try_clone()
                .map_err(|error| refusal(format!("cloning dependency handle: {error}")))?,
        )?;
        let rpath = if needs.runpath.is_none() && !needs.rpath.is_empty() {
            Some(std::rc::Rc::new(LibrarySearch {
                directories: search_directories(&image, &needs.rpath),
                parent: inherited_rpath,
            }))
        } else {
            inherited_rpath
        };
        let search = if let Some(paths) = &needs.runpath {
            Some(std::rc::Rc::new(LibrarySearch {
                directories: search_directories(&image, paths),
                parent: None,
            }))
        } else {
            rpath.clone()
        };
        if let Some(interpreter) = needs.interpreter
            && let Some((resolved, file, _)) =
                require_loadable(&image, &interpreter, config, restricted, missing)?
            && seen.insert(interpreter.clone())
        {
            dependencies.push(Dependency {
                path: interpreter,
                resolved,
                file,
                origin: MountOrigin::Interpreter,
            });
        }
        for name in &needs.needed {
            let Some(found) = resolve_needed(name, search.as_deref()) else {
                return Err(refusal(format!(
                    "'{}' needs the shared library '{}', which is not in its DT_RUNPATH, its \
                     DT_RPATH, or any standard system library directory; the view would be \
                     missing it and exec would fail with ENOENT",
                    image.display(),
                    name
                )));
            };
            let Some((identity, file, next_restricted)) =
                require_loadable(&image, &found, config, restricted, missing)?
            else {
                continue;
            };
            pending.push_back((
                identity.clone(),
                file.clone(),
                rpath.clone(),
                next_restricted,
            ));
            if seen.insert(identity.clone()) {
                dependencies.push(Dependency {
                    path: found,
                    resolved: identity,
                    file,
                    origin: MountOrigin::Library,
                });
            }
        }
    }
    Ok(dependencies)
}

/// Check a dependency against the floors and the originating image's filesystem grants.
fn require_loadable(
    image: &Path,
    library: &Path,
    config: &ContainmentConfig,
    restricted: bool,
    missing: &mut MissingReads,
) -> Result<Option<(PathBuf, Rc<std::fs::File>, bool)>, ContainmentError> {
    let restricted = restricted || workload_writable(config, library, MECHANISM)?;
    let granted =
        crate::model::PathGrant::new(library, Operation::Read, Scope::File).map_err(|error| {
            refusal(format!(
                "'{}' needs '{}', which cannot be granted: {error}",
                image.display(),
                library.display()
            ))
        })?;
    crate::floors::require_bounded_grant(&granted, config.operator_home(), false).map_err(
        |error| {
            refusal(format!(
                "'{}' needs '{}', which the floor refuses: {error}",
                image.display(),
                library.display()
            ))
        },
    )?;
    require_not_refused(config, &granted, MECHANISM)?;
    if restricted
        && !inside_loader_directory(&granted.resolved)
        && !stated_grant_reaches(config, &granted.resolved)
    {
        missing.add(&granted.resolved, image);
        return Ok(None);
    }
    let file = Rc::new(open_dependency(&granted.resolved)?);
    Ok(Some((granted.resolved, file, restricted)))
}

fn inside_loader_directory(identity: &Path) -> bool {
    LIBRARY_DIRECTORIES
        .iter()
        .any(|directory| identity.starts_with(directory))
}

fn stated_grant_reaches(config: &ContainmentConfig, identity: &Path) -> bool {
    config.authorizations().iter().any(|grant| {
        matches!(
            grant.operation,
            Operation::Read | Operation::Write | Operation::Exec
        ) && match grant.scope {
            Scope::Root => identity.starts_with(&grant.resolved),
            Scope::File => identity == grant.resolved,
            Scope::Dir => false,
        }
    })
}

/// Search directories with `$ORIGIN` expanded against the image that owns the entry.
fn search_directories(image: &Path, paths: &[String]) -> Vec<PathBuf> {
    let origin = image.parent().unwrap_or(Path::new("/"));
    paths
        .iter()
        .filter_map(|entry| {
            let directory = entry
                .replace("${ORIGIN}", &origin.to_string_lossy())
                .replace("$ORIGIN", &origin.to_string_lossy());
            // `$LIB` and `$PLATFORM` depend on the host's ABI spelling, which this walk does not model.
            (!directory.contains('$') && !directory.is_empty()).then(|| PathBuf::from(directory))
        })
        .collect()
}

/// Resolve a dependency through its applicable search directories, then the system directories.
fn resolve_needed(name: &str, search: Option<&LibrarySearch>) -> Option<PathBuf> {
    if name.contains('/') {
        let spelled = PathBuf::from(name);
        return spelled.is_file().then_some(spelled);
    }
    std::iter::successors(search, |entry| entry.parent.as_deref())
        .flat_map(|entry| entry.directories.iter().map(PathBuf::as_path))
        .chain(LIBRARY_DIRECTORIES.iter().map(Path::new))
        .map(|directory| folded(&directory.join(name)))
        .find(|candidate| candidate.is_file())
}

/// Whether `resolved` is one of the directories the loader maps code from.
fn is_loader_directory(resolved: &Path) -> bool {
    LIBRARY_DIRECTORIES.iter().any(|directory| {
        Path::new(directory)
            .canonicalize()
            .is_ok_and(|identity| identity == resolved)
    })
}

/// Read what one ELF image asks for: its interpreter, its `DT_NEEDED` names, and its search list.
#[cfg(test)]
fn image_needs(executable: &Path) -> Result<ImageNeeds, ContainmentError> {
    let mut file = std::fs::File::open(executable).map_err(|source| {
        refusal(format!(
            "opening '{}' to resolve its dynamic dependencies: {source}",
            executable.display()
        ))
    })?;
    image_needs_from_file(&mut file)
}

fn image_needs_from_file(file: &mut std::fs::File) -> Result<ImageNeeds, ContainmentError> {
    use std::io::{Read as _, Seek as _};

    /// A 64-bit ELF header, and the fixed part of one program header.
    const ELF_HEADER_BYTES: usize = 64;
    const PROGRAM_HEADER_BYTES: usize = 56;
    /// A ceiling on the two variable-length reads.
    const MAXIMUM_SEGMENT_BYTES: usize = 4 * 1024 * 1024;

    /// Read exactly `length` bytes at `offset`, refusing an implausible length.
    fn read_at(
        file: &mut std::fs::File,
        offset: u64,
        length: usize,
        what: &str,
    ) -> Result<Vec<u8>, ContainmentError> {
        if length > MAXIMUM_SEGMENT_BYTES {
            return Err(refusal(format!(
                "{what} claims {length} bytes, above the {MAXIMUM_SEGMENT_BYTES}-byte \
                 ceiling; refusing rather than allocating it"
            )));
        }
        file.seek(std::io::SeekFrom::Start(offset))
            .map_err(|source| refusal(format!("seeking to {what}: {source}")))?;
        let mut bytes = vec![0u8; length];
        file.read_exact(&mut bytes)
            .map_err(|source| refusal(format!("reading {what}: {source}")))?;
        Ok(bytes)
    }

    /// Read up to `length` bytes at `offset`, returning however many exist.
    fn read_at_most(file: &mut std::fs::File, offset: u64, length: usize) -> Vec<u8> {
        if length > MAXIMUM_SEGMENT_BYTES || file.seek(std::io::SeekFrom::Start(offset)).is_err() {
            return Vec::new();
        }
        let mut bytes = Vec::new();
        if file.take(length as u64).read_to_end(&mut bytes).is_err() {
            return Vec::new();
        }
        bytes
    }

    let mut needs = ImageNeeds::default();
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|error| refusal(format!("seeking dependency header: {error}")))?;

    // A file shorter than an ELF header is not an ELF; that is not an error.
    let mut header = [0u8; ELF_HEADER_BYTES];
    if file.read_exact(&mut header).is_err() {
        return Ok(needs);
    }
    // `\x7fELF`, 64-bit, little-endian. Anything else is refused by returning
    // nothing rather than misparsed — this backend targets 64-bit LE architectures.
    if &header[..4] != b"\x7fELF" || header[4] != 2 || header[5] != 1 {
        return Ok(needs);
    }

    let program_headers = u64::from_le_bytes(
        header[32..40]
            .try_into()
            .map_err(|_| refusal("malformed e_phoff".to_string()))?,
    );
    let program_header_size = usize::from(u16::from_le_bytes(
        header[54..56]
            .try_into()
            .map_err(|_| refusal("malformed e_phentsize".to_string()))?,
    ));
    let program_header_count = usize::from(u16::from_le_bytes(
        header[56..58]
            .try_into()
            .map_err(|_| refusal("malformed e_phnum".to_string()))?,
    ));
    if program_header_size < PROGRAM_HEADER_BYTES {
        return Ok(needs);
    }

    let Some(table_bytes) = program_header_size.checked_mul(program_header_count) else {
        return Ok(needs);
    };
    // A malformed table offset or length plans NOTHING rather than erroring.
    let Ok(table) = read_at(file, program_headers, table_bytes, "the program headers") else {
        return Ok(needs);
    };

    // Walk the table once, collecting what the two segments of interest need.
    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;
    const PT_INTERP: u32 = 3;

    let mut interpreter_segment = None;
    let mut dynamic_segment = None;
    let mut loads = Vec::new();

    for index in 0..program_header_count {
        let start = index * program_header_size;
        let Some(entry) = table.get(start..start + PROGRAM_HEADER_BYTES) else {
            break;
        };
        let field = |range: std::ops::Range<usize>| -> u64 {
            u64::from_le_bytes(entry[range].try_into().unwrap_or_default())
        };
        let kind = u32::from_le_bytes(entry[0..4].try_into().unwrap_or_default());
        let offset = field(8..16);
        let virtual_address = field(16..24);
        let size = field(32..40);

        match kind {
            PT_INTERP => interpreter_segment = Some((offset, size)),
            PT_DYNAMIC => dynamic_segment = Some((offset, size)),
            PT_LOAD => loads.push((offset, virtual_address, size)),
            _ => {}
        }
    }

    if let Some((offset, size)) = interpreter_segment {
        let length = usize::try_from(size).unwrap_or(0);
        let segment = read_at(file, offset, length, "the ELF interpreter path").unwrap_or_default();
        if let Some(text) = segment.split(|byte| *byte == 0).next()
            && let Ok(path) = String::from_utf8(text.to_vec())
            && !path.is_empty()
        {
            needs.interpreter = Some(PathBuf::from(path));
        }
    }

    let Some((offset, size)) = dynamic_segment else {
        // Statically linked: no dynamic table, so nothing further to resolve.
        return Ok(needs);
    };
    let length = usize::try_from(size).unwrap_or(0);
    let Ok(dynamic) = read_at(file, offset, length, "the ELF dynamic segment") else {
        return Ok(needs);
    };

    const DT_NULL: u64 = 0;
    const DT_NEEDED: u64 = 1;
    const DT_STRTAB: u64 = 5;
    const DT_RPATH: u64 = 15;
    const DT_RUNPATH: u64 = 29;

    // Two passes over the table: `DT_STRTAB` may appear after the `DT_NEEDED` entries.
    let mut string_table_address = None;
    let mut needed_offsets = Vec::new();
    let mut runpath_offsets = Vec::new();
    let mut rpath_offsets = Vec::new();
    for entry in dynamic.as_chunks::<16>().0 {
        let tag = u64::from_le_bytes(entry[0..8].try_into().unwrap_or_default());
        let value = u64::from_le_bytes(entry[8..16].try_into().unwrap_or_default());
        match tag {
            DT_NULL => break,
            DT_NEEDED => needed_offsets.push(value),
            DT_STRTAB => string_table_address = Some(value),
            DT_RUNPATH => runpath_offsets.push(value),
            DT_RPATH => rpath_offsets.push(value),
            _ => {}
        }
    }

    if needed_offsets.is_empty() {
        return Ok(needs);
    }
    let Some(address) = string_table_address else {
        return Ok(needs);
    };

    // `DT_STRTAB` is a virtual address; translate it through the `PT_LOAD` segment
    // whose virtual range contains it.
    let Some(string_table_offset) = loads.iter().find_map(|(offset, virtual_address, size)| {
        (address >= *virtual_address && address < virtual_address.checked_add(*size)?)
            .then(|| (address - virtual_address).checked_add(*offset))
            .flatten()
    }) else {
        return Ok(needs);
    };

    // One bounded read covers every name: they are contiguous in the string table,
    // and the largest offset plus a name's maximum length bounds it.
    let furthest = needed_offsets
        .iter()
        .chain(&runpath_offsets)
        .chain(&rpath_offsets)
        .copied()
        .max()
        .unwrap_or(0);
    let span = usize::try_from(furthest).unwrap_or(0).saturating_add(4096);
    // A short read is expected here rather than exceptional: the span is an upper bound (largest
    // offset plus a name's maximum length), so it routinely runs past the end of the file.
    let strings = read_at_most(file, string_table_offset, span);
    if strings.is_empty() {
        return Ok(needs);
    }
    let string_at = |name_offset: u64| -> Option<String> {
        let start = usize::try_from(name_offset).unwrap_or(usize::MAX);
        let text = strings.get(start..)?.split(|byte| *byte == 0).next()?;
        let name = String::from_utf8(text.to_vec()).ok()?;
        (!name.is_empty()).then_some(name)
    };

    needs.needed = needed_offsets.into_iter().filter_map(string_at).collect();
    let paths_at = |offsets: Vec<u64>| -> Vec<String> {
        offsets
            .into_iter()
            .filter_map(string_at)
            .flat_map(|list| list.split(':').map(str::to_owned).collect::<Vec<String>>())
            .collect()
    };
    if !runpath_offsets.is_empty() {
        needs.runpath = Some(paths_at(runpath_offsets));
    }
    needs.rpath = paths_at(rpath_offsets);

    Ok(needs)
}

/// Where a `DT_NEEDED` name is looked up. Fixed, per-architecture, and never from the environment.
#[cfg(target_arch = "aarch64")]
const LIBRARY_DIRECTORIES: &[&str] = &[
    "/lib64",
    "/usr/lib64",
    "/lib/aarch64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/lib",
    "/usr/lib",
];

#[cfg(target_arch = "x86_64")]
const LIBRARY_DIRECTORIES: &[&str] = &[
    "/lib64",
    "/usr/lib64",
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib",
    "/usr/lib",
];

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const LIBRARY_DIRECTORIES: &[&str] = &["/lib64", "/usr/lib64", "/lib", "/usr/lib"];

/// A refusal to plan a view, carrying this backend's mechanism name.
fn refusal(reason: String) -> ContainmentError {
    ContainmentError::ApplyFailed {
        backend: MECHANISM.to_string(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    mod loader_admission;
    mod refusal;
    use super::*;

    /// **The escapes the kernel actually emits decode, and nothing else is touched.**
    /// `/proc/self/mounts` escapes exactly four characters, all below 128.
    #[test]
    fn the_kernel_octal_escapes_decode() {
        assert_eq!(unescape_mount_field(r"/mnt/two\040words"), "/mnt/two words");
        assert_eq!(unescape_mount_field(r"/mnt/a\011tab"), "/mnt/a\ttab");
        assert_eq!(unescape_mount_field(r"/mnt/a\012line"), "/mnt/a\nline");
        assert_eq!(unescape_mount_field(r"/mnt/a\134slash"), r"/mnt/a\slash");
        assert_eq!(unescape_mount_field("/mnt/plain"), "/mnt/plain");
    }

    /// **A non-ASCII path survives byte-for-byte, and this function had no test at all before.**
    /// The old implementation walked bytes and finished with `push(byte as char)`, a Latin-1
    /// widening: `café` came back as `cafÃ©`.
    #[test]
    fn a_non_ascii_path_is_not_mangled_and_still_prefixes_its_target() {
        for path in [
            "/mnt/café",
            "/mnt/日本語/src",
            "/mnt/emoji-🚀",
            "/mnt/naïve/two\u{a0}nbsp",
        ] {
            assert_eq!(
                unescape_mount_field(path),
                path,
                "a path with no escape in it must come back unchanged"
            );
        }

        // The shape `remount_recursive` relies on: an escaped space beside a non-ASCII component.
        let target = "/mnt/café";
        let point = unescape_mount_field(r"/mnt/café/two\040words");
        assert_eq!(point, "/mnt/café/two words");
        assert!(
            point.starts_with(target),
            "the decoded point must still prefix its target, or the remount silently skips it: \
             {point:?} vs {target:?}"
        );
    }

    fn planned(config: &ContainmentConfig) -> Vec<MountEntry> {
        MountView::plan(config)
            .expect("plan must succeed")
            .entries()
            .to_vec()
    }

    #[test]
    fn broad_exec_keeps_scaffolds_refusals_and_protected_files_non_executable() {
        let root = tempfile::tempdir().expect("fixture");
        let work = root.path().join("work");
        let denied = work.join("denied");
        let protected = work.join("protected");
        let readable = root.path().join("helper");
        let metadata = root.path().join("metadata");
        let writable_file = root.path().join("output");
        std::fs::create_dir_all(&denied).expect("denied subtree");
        std::fs::create_dir(&metadata).expect("metadata directory");
        for path in [&protected, &readable, &writable_file] {
            std::fs::write(path, "fixture").expect("fixture file");
        }
        let opened = std::fs::File::open(&protected).expect("protected identity");
        let config = ContainmentConfig::new()
            .allow(&work, Operation::Read, Scope::Root)
            .unwrap()
            .allow(&work, Operation::Write, Scope::Root)
            .unwrap()
            .allow(&readable, Operation::Read, Scope::File)
            .unwrap()
            .allow(&metadata, Operation::Metadata, Scope::Dir)
            .unwrap()
            .allow(&writable_file, Operation::Read, Scope::File)
            .unwrap()
            .allow(&writable_file, Operation::Write, Scope::File)
            .unwrap()
            .allow("/dev/null", Operation::Write, Scope::File)
            .unwrap()
            .refuse(&denied, Scope::Root)
            .unwrap()
            .protect_write(&protected, &opened)
            .unwrap();
        let agent = planned(&config);
        assert!(agent.iter().all(|entry| !entry.executable));
        let leaf = planned(&config.allow_broad_exec());
        for entry in &leaf {
            let expected =
                entry.target == work || entry.target == readable || entry.target == writable_file;
            assert_eq!(entry.executable, expected, "{entry:?}");
            if entry.target == work || entry.target == writable_file {
                assert!(entry.writable);
            }
            if entry.target == readable {
                assert!(!entry.writable);
            }
        }
        assert!(
            leaf.iter()
                .any(|entry| entry.origin == MountOrigin::Refusal)
        );
        assert!(
            leaf.iter()
                .any(|entry| matches!(entry.origin, MountOrigin::Protection { .. }))
        );
    }

    /// Every path a planned view leaves `execve`-able, as `(origin, target)`.
    ///
    /// The `executable` flag is what `establish` acts on: a bind without it is mounted no-exec, so
    /// a host file carrying `+x` behind one cannot run.
    fn executable_set(entries: &[MountEntry]) -> Vec<(MountOrigin, PathBuf)> {
        let mut set: Vec<(MountOrigin, PathBuf)> = entries
            .iter()
            .filter(|entry| entry.kind == MountKind::Bind && entry.executable)
            .map(|entry| (entry.origin, entry.target.clone()))
            .collect();
        // By path only: `MountOrigin` needs no `Ord` just to make a test deterministic, and
        // deriving one on it would add an ordering the domain does not have.
        set.sort_by(|left, right| left.1.cmp(&right.1));
        set
    }

    /// **The view leaves exactly these paths `execve`-able, and no others.** A closed-world census,
    /// the Linux counterpart of `profile_conformance.rs::the_rendered_profile_grants_exactly_these_
    /// operations_and_no_others`.
    #[test]
    fn the_view_leaves_exactly_the_intended_paths_executable() {
        // `/bin/sh` and `/bin/cat`: two real dynamically linked binaries, so the census sees an
        // interpreter and libraries rather than a synthetic fixture.
        let config = ContainmentConfig::new()
            .allow("/bin/sh", Operation::Exec, Scope::File)
            .expect("execute grant")
            .allow("/bin/cat", Operation::Exec, Scope::File)
            .expect("second execute grant");

        let entries = planned(&config);
        let executable = executable_set(&entries);

        // Every member must come from one of exactly three origins. A fourth origin appearing
        // here is the finding: a scaffold mount, a socket, or a data grant became runnable.
        let unexpected: Vec<_> = executable
            .iter()
            .filter(|(origin, _)| {
                !matches!(
                    origin,
                    MountOrigin::Grant | MountOrigin::Interpreter | MountOrigin::Library
                )
            })
            .collect();
        assert!(
            unexpected.is_empty(),
            "only an exec grant, its ELF interpreter, and its libraries may be executable in \
             the view; these came from another origin: {unexpected:?}"
        );

        // Every *grant*-origin member must be a path the caller actually named for execute.
        let granted_for_execute: Vec<PathBuf> = config
            .grants_in(Operation::Exec, Scope::File)
            .into_iter()
            .flat_map(|granted| granted.reachable_paths())
            .collect();
        for (origin, target) in &executable {
            if *origin == MountOrigin::Grant {
                assert!(
                    granted_for_execute.contains(target),
                    "'{}' is executable in the view but was not granted execute; a read \
                     grant on a host file carrying +x must not confer exec",
                    target.display()
                );
            }
        }

        // And the closed-world half: nothing writable is executable, which is W^X route 1
        // stated as a property of the plan rather than of a kernel probe.
        for entry in &entries {
            if entry.writable {
                assert!(
                    !executable.iter().any(|(_, target)| target == &entry.target),
                    "'{}' is writable and executable at once, which is the write-then-execute \
                     union W^X exists to refuse",
                    entry.target.display()
                );
            }
        }

        // The census itself: an exec grant contributes its own spellings, and the only other
        // members are the interpreter and libraries those binaries need.
        let grant_members = executable
            .iter()
            .filter(|(origin, _)| *origin == MountOrigin::Grant)
            .count();
        assert_eq!(
            grant_members,
            granted_for_execute.len(),
            "each execute grant must contribute exactly its own bound spellings; got \
             {grant_members} for {} granted paths. Full set: {executable:#?}",
            granted_for_execute.len()
        );
        assert!(
            executable
                .iter()
                .any(|(origin, _)| *origin == MountOrigin::Interpreter),
            "a dynamically linked grant must bring its loader, and the loader is executable — \
             recorded deliberately, because it is the one general-purpose exec engine in the \
             view. Full set: {executable:#?}"
        );
    }

    /// A read-only directory grant may enclose an exec literal's own file bind.
    #[test]
    fn a_read_only_directory_grant_may_enclose_an_exec_literals_file_bind() {
        // Runs in a forked child, and that is required rather than tidy: `unshare(CLONE_NEWUSER)`
        // returns `EINVAL` in a multi-threaded process, and the test harness is multi-threaded.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork: {}", std::io::Error::last_os_error());
        if child == 0 {
            let code = i32::from(!shadowed_submount_case_holds());
            // SAFETY: skip every destructor; this child shares the parent's heap.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: reaping the child forked above.
        let waited = unsafe { libc::waitpid(child, &raw mut status, 0) };
        assert_eq!(
            waited,
            child,
            "waitpid: {}",
            std::io::Error::last_os_error()
        );
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "the shadowed-submount case failed in the child (status {status}); a read-only \
             directory grant enclosing an exec literal's file bind must apply, and the \
             shadowed path must be read-only afterwards"
        );
    }

    /// The body of the test above, run inside a forked child's own mount namespace.
    fn shadowed_submount_case_holds() -> bool {
        // SAFETY: single-threaded in this fresh child, which is what `CLONE_NEWUSER` requires.
        if unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWUSER) } != 0 {
            eprintln!(
                "unshare(CLONE_NEWNS|CLONE_NEWUSER): {}",
                std::io::Error::last_os_error()
            );
            return false;
        }
        // Make the propagation private, or these binds escape to the host.
        if mount_syscall(
            None,
            Path::new("/"),
            None,
            libc::MS_REC | libc::MS_PRIVATE,
            None,
        )
        .is_err()
        {
            eprintln!("could not make / private in the new namespace");
            return false;
        }

        let source = tempfile::tempdir().expect("source tree");
        let bin = source.path().join("bin");
        std::fs::create_dir_all(&bin).expect("source bin");
        std::fs::write(bin.join("prog"), b"host").expect("source program");

        let view = tempfile::tempdir().expect("view tree");
        let view_tree = view.path().join("tree");
        std::fs::create_dir_all(view_tree.join("bin")).expect("view bin");
        std::fs::write(view_tree.join("bin/prog"), b"view").expect("view program");

        // Order matters, and it is the order this backend uses: the exec literal is bound as
        // a file first, then the read grant's directory goes over it.
        mount_syscall(
            Some(&bin.join("prog")),
            &view_tree.join("bin/prog"),
            None,
            libc::MS_BIND,
            None,
        )
        .expect("bind the exec literal as a file");
        mount_syscall(Some(source.path()), &view_tree, None, libc::MS_BIND, None)
            .expect("bind the read grant's directory over it");

        // The whole point: this must succeed rather than refuse on the shadowed submount.
        if let Err(error) = remount_read_only(&view_tree) {
            eprintln!("remount_read_only refused: {error}");
            return false;
        }

        // And the reason skipping is sound: the covering mount made that path read-only.
        if std::fs::OpenOptions::new()
            .write(true)
            .open(view_tree.join("bin/prog"))
            .is_ok()
        {
            eprintln!("the shadowed path is WRITABLE under a read-only grant");
            return false;
        }
        true
    }

    fn entry_for<'a>(entries: &'a [MountEntry], target: &Path) -> &'a MountEntry {
        entries
            .iter()
            .find(|entry| entry.target == target)
            .unwrap_or_else(|| panic!("no planned entry for {}", target.display()))
    }

    /// A read grant is present and not writable. If this ever plans a writable
    /// bind, a `Read` grant would silently authorize modification.
    #[test]
    fn a_read_grant_plans_a_read_only_bind() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = ContainmentConfig::new()
            .allow(directory.path(), Operation::Read, Scope::Root)
            .expect("read grant");

        let entries = planned(&config);
        let entry = entry_for(&entries, directory.path());

        assert!(
            !entry.writable,
            "a Read grant must not plan a writable bind"
        );
        assert!(
            !entry.executable,
            "a Read grant confers no exec: its bind is mounted no-exec"
        );
        assert_eq!(entry.kind, MountKind::Bind);
        assert_eq!(entry.origin, MountOrigin::Grant);
    }

    /// **An exec tree plans one read-only, executable bind**, and a read tree beside it does not.
    #[test]
    fn an_exec_tree_plans_an_executable_read_only_bind_and_a_read_tree_a_no_exec_one() {
        let directory = tempfile::tempdir().expect("tempdir");
        let tools = directory.path().join("tools");
        let data = directory.path().join("data");
        std::fs::create_dir(&tools).expect("an exec tree");
        std::fs::create_dir(&data).expect("a read tree");
        let config = ContainmentConfig::new()
            .allow(&tools, Operation::Exec, Scope::Root)
            .expect("exec at root scope")
            .allow(&data, Operation::Read, Scope::Root)
            .expect("read at root scope");

        let entries = planned(&config);
        let tree = entry_for(&entries, &tools);
        assert_eq!(tree.kind, MountKind::Bind);
        assert!(tree.executable, "every program under an exec tree runs");
        assert!(!tree.writable, "an exec tree is read-only");
        assert_eq!(tree.origin, MountOrigin::Grant);
        assert!(
            !entry_for(&entries, &data).executable,
            "a read tree beside it confers no exec"
        );
        assert!(
            !entries.iter().any(|entry| matches!(
                entry.origin,
                MountOrigin::Interpreter | MountOrigin::Library
            )),
            "a tree names no one image, so no dependency is planned for it"
        );
    }

    /// **A grant nested inside another is planned after the tree that encloses it, whatever order
    /// the two were stated in**, so the nested bind is the upper mount and its flags hold at runtime.
    #[test]
    fn a_nested_grant_is_planned_after_the_tree_that_encloses_it_whatever_the_grant_order() {
        let directory = tempfile::tempdir().expect("tempdir");
        let tree = directory.path().join("tools");
        let corner = tree.join("cache");
        std::fs::create_dir_all(&corner).expect("an exec tree with a writable corner");
        let program = corner.join("built");
        std::fs::write(&program, "built").expect("a program inside the corner");
        // Deepest first, so a planner that kept grant order would establish the tree last and
        // shadow the two below it.
        let config = ContainmentConfig::new()
            .allow(&program, Operation::Read, Scope::File)
            .expect("a read file, deepest")
            .allow(&corner, Operation::Write, Scope::Root)
            .expect("a write root inside the tree")
            .allow(&tree, Operation::Exec, Scope::Root)
            .expect("the exec tree, stated last");

        let entries = planned(&config);
        let at = |path: &std::path::Path| {
            entries
                .iter()
                .position(|entry| entry.target == path)
                .unwrap_or_else(|| panic!("{} is planned", path.display()))
        };
        assert!(
            at(&tree) < at(&corner) && at(&corner) < at(&program),
            "each nested bind must be established after the tree that encloses it: {entries:#?}"
        );
        let corner_entry = entry_for(&entries, &corner);
        assert!(
            corner_entry.writable && corner_entry.executable,
            "the write root inside the exec tree is the upper mount, writable and runnable"
        );
        assert!(
            entry_for(&entries, &program).executable,
            "a read file inside the exec tree is runnable"
        );
    }

    /// **A write root inside a read root plans the outer bind read-only and no-exec, and the inner
    /// bind writable after it.**
    #[test]
    fn a_write_root_inside_a_read_root_plans_the_writable_bind_on_top() {
        let directory = tempfile::tempdir().expect("tempdir");
        let project = directory.path().join("project");
        let output = project.join("build");
        std::fs::create_dir_all(&output).expect("a read tree with a writable corner");
        let config = ContainmentConfig::new()
            .allow(&project, Operation::Read, Scope::Root)
            .expect("the read root")
            .allow(&output, Operation::Write, Scope::Root)
            .expect("a write root inside the read root");

        let entries = planned(&config);
        let at = |path: &Path| {
            entries
                .iter()
                .position(|entry| entry.target == path)
                .unwrap_or_else(|| panic!("{} is planned", path.display()))
        };
        assert!(
            at(&project) < at(&output),
            "the writable bind must be established after the read root, or the read root \
             shadows it: {entries:#?}"
        );

        let outer = entry_for(&entries, &project);
        assert!(
            !outer.writable && !outer.executable,
            "the read root stays read-only and no-exec"
        );
        assert!(
            entry_for(&entries, &output).writable,
            "the inner root is writable"
        );
    }

    /// **An exec file inside a read tree is planned after the tree**, so its executable bind sits
    /// on top of the no-exec one that encloses it, whatever order the grants arrived in.
    #[test]
    fn an_exec_file_inside_a_read_tree_is_planned_after_the_tree() {
        let directory = tempfile::tempdir().expect("tempdir");
        let tree = directory.path().join("runtime");
        std::fs::create_dir_all(tree.join("bin")).expect("a read tree");
        let program = tree.join("bin/prog");
        std::fs::write(&program, "not a program").expect("a file inside it");
        let config = ContainmentConfig::new()
            .allow(&program, Operation::Exec, Scope::File)
            .expect("the exec grant, stated first")
            .allow(&tree, Operation::Read, Scope::Root)
            .expect("the read tree, stated second");

        let entries = planned(&config);
        let tree_at = entries
            .iter()
            .position(|entry| entry.target == tree)
            .expect("the tree is planned");
        let program_at = entries
            .iter()
            .position(|entry| entry.target == program)
            .expect("the program is planned");
        assert!(
            program_at > tree_at,
            "the executable bind must be established after the no-exec tree, or the tree shadows it"
        );
        assert!(entries[program_at].executable && !entries[program_at].writable);
        assert!(!entries[tree_at].executable);
    }

    /// **An exec grant inside a write root plans a writable, executable island**, which is the pair
    /// the floor warns about lowered as stated; and a write root inside an exec tree runs.
    #[test]
    fn the_warned_write_plus_exec_pair_plans_a_writable_executable_bind() {
        let directory = tempfile::tempdir().expect("tempdir");
        let project = directory.path().join("project");
        let output = project.join("target");
        std::fs::create_dir_all(&output).expect("build output inside the project");
        let program = output.join("built");
        std::fs::write(&program, "built").expect("a program the workload builds");
        let tools = directory.path().join("tools");
        let cache = tools.join("cache");
        std::fs::create_dir_all(&cache).expect("an exec tree with a writable corner");

        let config = ContainmentConfig::new()
            .allow(&project, Operation::Write, Scope::Root)
            .expect("the write root")
            .allow(&output, Operation::Exec, Scope::Root)
            .expect("an exec tree inside it")
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an exec literal inside it")
            .allow(&tools, Operation::Exec, Scope::Root)
            .expect("an exec tree")
            .allow(&cache, Operation::Write, Scope::Root)
            .expect("a write root inside it");

        let entries = planned(&config);
        for (label, path) in [
            ("the exec tree inside the write root", &output),
            ("the exec literal inside the write root", &program),
            ("the write root inside the exec tree", &cache),
        ] {
            let entry = entry_for(&entries, path);
            assert!(
                entry.writable && entry.executable,
                "{label} is the warned pair, lowered as writable and executable: {entry:?}"
            );
        }
        assert!(
            entry_for(&entries, &project).writable && !entry_for(&entries, &project).executable,
            "the write root itself stays no-exec outside its exec tree"
        );
        assert!(
            entry_for(&entries, &tools).executable && !entry_for(&entries, &tools).writable,
            "the exec tree itself stays read-only outside its write root"
        );
    }

    /// **`List` is refused by name**, because a bind exposes bytes and an empty filesystem exposes
    /// no entry, so neither is enumeration without content.
    #[test]
    fn a_list_grant_is_refused_by_name() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = ContainmentConfig::new()
            .allow(directory.path(), Operation::List, Scope::Root)
            .expect("the vocabulary accepts the cell");

        let error = MountView::plan(&config).expect_err("List has no lowering here");
        assert!(
            matches!(error, ContainmentError::UnsupportedCapability { .. }),
            "got {error:?}"
        );
        let text = error.to_string();
        assert!(
            text.contains("list grant") && text.contains("no lowering"),
            "the refusal names the cell and the reason: {text}"
        );
    }

    /// **A refused file that exists plans an empty-file overmount after the grant that binds it**,
    /// so the workload finds an empty, unwritable file where the refused one is.
    #[test]
    fn a_refused_file_that_exists_plans_an_empty_file_overmount_after_its_grant() {
        let directory = tempfile::tempdir().expect("tempdir");
        let tree = directory.path().join("project");
        std::fs::create_dir(&tree).expect("a project");
        let secret = tree.join(".env");
        std::fs::write(&secret, "TOKEN=1").expect("a file to refuse");
        let config = ContainmentConfig::new()
            .allow(&tree, Operation::Read, Scope::Root)
            .expect("the tree")
            .refuse(&secret, Scope::File)
            .expect("one file refused inside it");

        let entries = planned(&config);
        let resolved = secret.canonicalize().expect("canonical");
        let refusal_at = entries
            .iter()
            .position(|entry| entry.target == resolved)
            .expect("the refusal is planned");
        let tree_at = entries
            .iter()
            .position(|entry| entry.target == tree.canonicalize().expect("canonical"))
            .expect("the tree is planned");
        let entry = &entries[refusal_at];
        assert_eq!(entry.kind, MountKind::EmptyFile);
        assert_eq!(entry.origin, MountOrigin::Refusal);
        assert!(!entry.writable && !entry.executable);
        assert!(entry.source.is_none(), "no host bytes reach a refused file");
        assert!(
            refusal_at > tree_at,
            "the overmount must be established after the bind that exposes the file"
        );
        // The same lowering for a file refused as a tree of one.
        let as_tree = ContainmentConfig::new()
            .allow(&tree, Operation::Read, Scope::Root)
            .expect("the tree")
            .refuse(&secret, Scope::Root)
            .expect("the file refused at root scope");
        assert_eq!(
            entry_for(&planned(&as_tree), &resolved).kind,
            MountKind::EmptyFile,
            "a refused path that is a file overmounts as a file whatever the scope says"
        );
    }

    /// **A refusal under a refused tree plans nothing of its own**: the tree's empty filesystem
    /// already holds it, and a mountpoint cannot be created inside one.
    #[test]
    fn a_refusal_under_a_refused_tree_plans_nothing_of_its_own() {
        let directory = tempfile::tempdir().expect("tempdir");
        let tree = directory.path().join("hidden");
        std::fs::create_dir(&tree).expect("a tree to refuse");
        let file = tree.join("settings.json");
        std::fs::write(&file, "{}").expect("a file inside it");
        let nested = tree.join("deeper");
        std::fs::create_dir(&nested).expect("a tree inside it");
        let config = ContainmentConfig::new()
            .allow(directory.path(), Operation::Read, Scope::Root)
            .expect("the enclosing grant")
            .refuse(&tree, Scope::Root)
            .expect("the tree")
            .refuse(&file, Scope::File)
            .expect("a file under it")
            .refuse(&nested, Scope::Root)
            .expect("a tree under it");

        let entries = planned(&config);
        let resolved = tree.canonicalize().expect("canonical");
        assert_eq!(entry_for(&entries, &resolved).origin, MountOrigin::Refusal);
        for covered in [&file, &nested] {
            let covered = covered.canonicalize().expect("canonical");
            assert!(
                !entries.iter().any(|entry| entry.target == covered),
                "{} is under the refused tree, so its own mount would land inside a read-only \
                 filesystem: {entries:#?}",
                covered.display()
            );
        }
    }

    /// **A refused file that does not exist yet is refused by name**: an overmount needs an
    /// existing target, and creating one through a writable bind would create it on the host.
    #[test]
    fn a_refused_file_that_does_not_exist_is_refused_by_name() {
        let directory = tempfile::tempdir().expect("tempdir");
        let future = directory.path().join("not-yet-written.env");
        let config = ContainmentConfig::new()
            .allow(directory.path(), Operation::Write, Scope::Root)
            .expect("a write root")
            .refuse(&future, Scope::File)
            .expect("the vocabulary accepts a future file");

        let error = MountView::plan(&config).expect_err("a future file has no overmount target");
        assert!(
            matches!(error, ContainmentError::UnsupportedCapability { .. }),
            "got {error:?}"
        );
        let text = error.to_string();
        assert!(
            text.contains("file refusal") && text.contains("does not exist yet"),
            "the refusal names the cell and the reason: {text}"
        );
        // The control: the same future path refused as a tree still plans, as it always has.
        let as_tree = ContainmentConfig::new()
            .allow(directory.path(), Operation::Write, Scope::Root)
            .expect("a write root")
            .refuse(&future, Scope::Root)
            .expect("a future tree");
        MountView::plan(&as_tree).expect("a future tree plans a fresh filesystem");
    }

    /// A directory-scope grant plans a **fresh, read-only** filesystem, not a bind.
    #[test]
    fn a_directory_scope_grant_plans_a_fresh_read_only_filesystem() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = ContainmentConfig::new()
            .allow(directory.path(), Operation::Read, Scope::Dir)
            .expect("directory-scope grant");

        let entries = planned(&config);
        let entry = entry_for(&entries, directory.path());

        assert_eq!(
            entry.kind,
            MountKind::Fresh { fstype: "tmpfs" },
            "a Dir-scope grant must plan an empty filesystem, never a bind of the host directory"
        );
        assert!(
            !entry.writable,
            "a Dir-scope grant must not plan a writable mount"
        );
        assert_eq!(
            entry.source, None,
            "a fresh filesystem has no host source to copy contents from"
        );
        assert_eq!(entry.origin, MountOrigin::Grant);
    }

    /// A metadata-only ancestor must not hide an explicitly granted descendant.
    #[test]
    fn an_explicit_descendant_replaces_its_metadata_only_ancestor() {
        let ancestor = tempfile::tempdir().expect("ancestor");
        let descendant = ancestor.path().join("box");
        std::fs::create_dir(&descendant).expect("descendant");
        let config = ContainmentConfig::new()
            .allow(ancestor.path(), Operation::Metadata, Scope::Dir)
            .expect("metadata ancestor")
            .allow(&descendant, Operation::Read, Scope::Root)
            .expect("explicit descendant");

        let entries = planned(&config);
        assert!(
            entries.iter().all(|entry| {
                entry.target != ancestor.path() || entry.origin != MountOrigin::Grant
            }),
            "a fresh ancestor mount would hide the explicit descendant"
        );
        let entry = entry_for(&entries, &descendant);
        assert_eq!(entry.kind, MountKind::Bind);
        assert_eq!(entry.source.as_deref(), Some(descendant.as_path()));
        assert!(!entry.writable);
    }

    /// A refusal leaves its metadata-only ancestor empty and read-only.
    #[test]
    fn a_refusal_keeps_its_metadata_only_ancestor_read_only() {
        let ancestor = tempfile::tempdir().expect("ancestor");
        let refused = ancestor.path().join("box/private");
        std::fs::create_dir_all(&refused).expect("the refused tree");
        let config = ContainmentConfig::new()
            .allow(ancestor.path(), Operation::Metadata, Scope::Dir)
            .expect("metadata ancestor")
            .refuse(&refused, Scope::Root)
            .expect("the refusal");

        let entries = planned(&config);
        let parent = entry_for(&entries, ancestor.path());
        assert_eq!(parent.origin, MountOrigin::Grant);
        assert_eq!(parent.kind, MountKind::Fresh { fstype: "tmpfs" });
        assert!(!parent.writable);
        assert!(
            entries.iter().all(|entry| {
                entry.target == ancestor.path() || !entry.target.starts_with(ancestor.path())
            }),
            "a descendant mountpoint would expose names below the metadata grant: {entries:?}"
        );
    }

    /// A read-write grant is writable — the box's home depends on this.
    #[test]
    fn a_read_write_grant_plans_a_writable_bind() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = ContainmentConfig::new()
            .allow(directory.path(), Operation::Read, Scope::Root)
            .expect("read grant")
            .allow(directory.path(), Operation::Write, Scope::Root)
            .expect("write grant");

        let entries = planned(&config);
        assert!(entry_for(&entries, directory.path()).writable);
    }

    #[test]
    fn a_write_protection_overlays_its_writable_ancestor() {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical root");
        let authority = root.join("authority");
        std::fs::write(&authority, "authority").expect("authority fixture");
        let opened = std::fs::File::open(&authority).expect("open authority");
        let identity = opened.metadata().expect("opened metadata");
        let config = ContainmentConfig::new()
            .allow(&root, Operation::Write, Scope::Root)
            .expect("write root")
            .protect_write(&authority, &opened)
            .expect("write protection");

        let entries = planned(&config);
        let writable_index = entries
            .iter()
            .position(|entry| entry.target == root && entry.writable)
            .expect("writable ancestor");
        let protected_index = entries
            .iter()
            .position(|entry| {
                entry.target == authority
                    && matches!(
                        entry.origin,
                        MountOrigin::Protection { device, inode }
                            if device == identity.dev() && inode == identity.ino()
                    )
            })
            .expect("exact protection");

        assert!(
            protected_index > writable_index,
            "the exact read-only bind must overlay the writable ancestor"
        );
        assert!(!entries[protected_index].writable);
        assert_eq!(
            entries[protected_index].source.as_deref(),
            Some(authority.as_path())
        );
    }

    #[test]
    fn duplicate_socket_grants_plan_one_writable_non_executable_socket() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("broker.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let config = ContainmentConfig::new()
            .allow(&path, Operation::Connect, Scope::File)
            .unwrap()
            .allow(&path, Operation::Connect, Scope::File)
            .unwrap();
        let entries = planned(&config);
        let sockets: Vec<_> = entries
            .iter()
            .filter(|entry| entry.origin == MountOrigin::Socket)
            .collect();
        assert_eq!(sockets.len(), 1);
        assert_eq!(
            *sockets[0],
            MountEntry {
                source: Some(path.canonicalize().unwrap()),
                target: path.canonicalize().unwrap(),
                kind: MountKind::Bind,
                writable: true,
                executable: false,
                origin: MountOrigin::Socket,
            }
        );
    }

    #[test]
    fn duplicate_directory_grants_plan_one_empty_read_only_filesystem() {
        let directory = tempfile::tempdir().unwrap();
        let config = ContainmentConfig::new()
            .allow(directory.path(), Operation::Read, Scope::Dir)
            .unwrap()
            .allow(directory.path(), Operation::Metadata, Scope::Dir)
            .unwrap();
        let entries = planned(&config);
        let grants: Vec<_> = entries
            .iter()
            .filter(|entry| entry.origin == MountOrigin::Grant)
            .collect();
        assert_eq!(grants.len(), 1);
        assert_eq!(
            *grants[0],
            MountEntry {
                source: None,
                target: directory.path().canonicalize().unwrap(),
                kind: MountKind::Fresh { fstype: "tmpfs" },
                writable: false,
                executable: false,
                origin: MountOrigin::Grant,
            }
        );
    }

    #[test]
    fn metadata_subtrees_remain_omitted_from_the_linux_view() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("private"), b"content").unwrap();
        let config = ContainmentConfig::new()
            .allow(directory.path(), Operation::Metadata, Scope::Root)
            .unwrap();
        let entries = planned(&config);
        assert!(!entries.iter().any(|entry| entry.target == directory.path()));
        assert!(
            !entries
                .iter()
                .any(|entry| entry.source.as_deref() == Some(directory.path()))
        );
    }

    #[test]
    fn protected_file_mounts_refuse_writes_and_parent_replacement() {
        super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            let parent = root.join("nested");
            std::fs::create_dir(&parent).unwrap();
            let protected = parent.join("authority");
            std::fs::write(&protected, b"unchanged").unwrap();
            let opened = std::fs::File::open(&protected).unwrap();
            let config = ContainmentConfig::new()
                .allow(&root, Operation::Write, Scope::Root)
                .unwrap()
                .protect_write(&protected, &opened)
                .unwrap();
            let mut view = MountView::plan(&config).unwrap();
            view.entries.retain(|entry| {
                entry.origin != MountOrigin::Scaffold || entry.target == Path::new("/")
            });
            assert!(view.protected_parents.contains(&parent));
            view.materialize().unwrap();
            assert!(std::fs::write(&protected, b"changed").is_err());
            assert_eq!(std::fs::read(&protected).unwrap(), b"unchanged");
            assert!(std::fs::rename(&parent, root.join("moved")).is_err());
            std::fs::write(parent.join("ordinary"), b"allowed").unwrap();
            assert_eq!(std::fs::read(parent.join("ordinary")).unwrap(), b"allowed");
        });
    }

    fn planned_parent_fixture() -> (tempfile::TempDir, tempfile::TempDir, MountView, PathBuf) {
        let source = tempfile::tempdir().unwrap();
        let parent = source.path().join("nested");
        std::fs::create_dir(&parent).unwrap();
        let protected = parent.join("authority");
        std::fs::write(&protected, b"protected").unwrap();
        let opened = std::fs::File::open(&protected).unwrap();
        let config = ContainmentConfig::new()
            .allow(source.path(), Operation::Write, Scope::Root)
            .unwrap()
            .protect_write(&protected, &opened)
            .unwrap();
        let view = MountView::plan(&config).unwrap();
        assert!(view.protected_parents.contains(&parent));
        let staging = tempfile::tempdir().unwrap();
        let target = staging.path().join(parent.strip_prefix("/").unwrap());
        (source, staging, view, target)
    }

    #[test]
    fn a_missing_or_replaced_protected_parent_refuses_the_view() {
        let (_source, staging, view, target) = planned_parent_fixture();
        let error = view.protect_parents(staging.path()).unwrap_err();
        assert!(
            error.to_string().contains("inspecting protected parent"),
            "{error}"
        );
        std::fs::create_dir_all(&target).unwrap();
        std::fs::rename(&target, target.with_extension("before")).unwrap();
        std::fs::write(&target, b"replacement").unwrap();
        let error = view.protect_parents(staging.path()).unwrap_err();
        assert!(error.to_string().contains("is not a directory"), "{error}");
        assert_eq!(std::fs::read(&target).unwrap(), b"replacement");
    }

    #[test]
    fn a_failed_protected_parent_bind_refuses_the_view() {
        super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
            let (_source, staging, view, target) = planned_parent_fixture();
            std::fs::create_dir_all(&target).unwrap();
            view.protect_parents(staging.path()).unwrap();
            super::super::failure_tests::refuse_syscall(libc::SYS_mount, None);
            let error = view.protect_parents(staging.path()).unwrap_err();
            assert!(
                error.to_string().contains("binding protected parent"),
                "{error}"
            );
            assert!(target.is_dir());
        });
    }

    #[test]
    fn an_empty_directory_mount_is_read_only() {
        super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            std::fs::write(root.join("hidden"), b"host bytes").unwrap();
            let config = ContainmentConfig::new()
                .allow(&root, Operation::Read, Scope::Dir)
                .unwrap();
            let mut view = MountView::plan(&config).unwrap();
            view.entries.retain(|entry| {
                entry.origin != MountOrigin::Scaffold || entry.target == Path::new("/")
            });
            view.materialize().unwrap();
            assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
            assert!(std::fs::write(root.join("new"), b"refused").is_err());
        });
    }

    #[test]
    fn a_refused_file_outside_a_tree_bind_is_empty_and_read_only() {
        super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("private");
            std::fs::write(&path, b"host bytes").unwrap();
            let config = ContainmentConfig::new().refuse(&path, Scope::File).unwrap();
            let mut view = MountView::plan(&config).unwrap();
            view.entries.retain(|entry| {
                entry.origin != MountOrigin::Scaffold || entry.target == Path::new("/")
            });
            view.materialize().unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"");
            assert!(std::fs::write(&path, b"refused").is_err());
        });
    }

    /// The grant's own resolved path is the path inside the view, so one policy
    /// file names the same thing on both platforms.
    #[test]
    fn a_grant_is_planned_at_its_own_resolved_path() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = ContainmentConfig::new()
            .allow(directory.path(), Operation::Read, Scope::Root)
            .expect("read grant");

        let entries = planned(&config);
        let entry = entry_for(&entries, directory.path());
        assert_eq!(
            entry.source.as_deref(),
            Some(entry.target.as_path()),
            "source and target must agree, or policy would name a path the \
             workload does not see"
        );
    }

    /// A refusal is planned after every grant, and an override is re-appended rather than left at
    /// the index the grant gave it.
    #[test]
    fn a_refusal_is_planned_last_and_shadows_the_grant_that_bound_its_parent() {
        let project = tempfile::tempdir().expect("tempdir");
        let refused = project.path().join("inner");
        std::fs::create_dir(&refused).expect("inner directory");

        // The inner grant is stated first, so an override left at that index is established
        // before the enclosing grant re-exposes the real bytes underneath it.
        let config = ContainmentConfig::new()
            .allow(&refused, Operation::Read, Scope::Root)
            .expect("inner grant")
            .allow(project.path(), Operation::Write, Scope::Root)
            .expect("enclosing grant")
            .refuse(&refused, Scope::Root)
            .expect("refusal");

        let entries = planned(&config);
        let resolved = refused.canonicalize().expect("canonical inner");

        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.target == resolved)
                .count(),
            1,
            "the refusal must replace the grant's entry rather than sit beside it"
        );

        let entry = entry_for(&entries, &resolved);
        assert_eq!(entry.origin, MountOrigin::Refusal);
        assert_eq!(entry.kind, MountKind::Fresh { fstype: "tmpfs" });
        assert!(!entry.writable, "a refused tree must not be writable");
        assert!(
            entry.source.is_none(),
            "a refusal brings no host bytes into the view"
        );

        let last_grant = entries
            .iter()
            .rposition(|entry| entry.origin != MountOrigin::Refusal)
            .expect("the scaffold alone plans several");
        let refusal_at = entries
            .iter()
            .position(|entry| entry.target == resolved)
            .expect("planned above");
        assert!(
            refusal_at > last_grant,
            "every refusal must be established after every grant, or a deeper grant \
             re-establishes the bytes under the refused tree"
        );
    }

    #[test]
    fn a_refusal_replaces_parent_protection_below_its_mountpoint() {
        let root = tempfile::tempdir().expect("workspace");
        let refused = root.path().join("authority");
        let nested = refused.join("nested");
        std::fs::create_dir_all(&nested).expect("authority directories");
        let source = nested.join("policy.dw");
        std::fs::write(&source, "authority").expect("authority file");
        let opened = std::fs::File::open(&source).expect("opened authority");
        let config = ContainmentConfig::new()
            .allow(root.path(), Operation::Write, Scope::Root)
            .expect("write root")
            .protect_write(&source, &opened)
            .expect("loaded authority")
            .refuse(&refused, Scope::Root)
            .expect("directory refusal");

        let view = MountView::plan(&config).expect("mount plan");
        let refused = refused.canonicalize().expect("refused identity");
        assert!(
            view.protected_parents
                .iter()
                .all(|parent| !parent.starts_with(&refused)),
            "the refusal hides its descendants, so later parent binds cannot reach them"
        );
        assert!(view.entries.iter().any(|entry| {
            entry.target == refused && entry.origin == MountOrigin::Refusal && !entry.writable
        }));
    }

    /// Every view has a root, a fresh `/proc`, a private `/tmp`, and the four device nodes — and
    /// the root comes first, since nothing can be bound into a filesystem that does not exist yet.
    #[test]
    fn the_scaffold_is_always_planned_and_the_root_is_first() {
        let config = ContainmentConfig::new();
        let entries = planned(&config);

        assert_eq!(entries[0].target, Path::new("/"));
        assert_eq!(entries[0].kind, MountKind::Fresh { fstype: "tmpfs" });
        assert_eq!(
            entry_for(&entries, Path::new("/proc")).kind,
            MountKind::Fresh { fstype: "proc" },
            "a fresh /proc is what makes the PID namespace visible as isolation"
        );
        assert_eq!(
            entry_for(&entries, Path::new("/tmp")).kind,
            MountKind::Fresh { fstype: "tmpfs" }
        );
        for device in DEVICE_NODES {
            let entry = entry_for(&entries, Path::new(device));
            assert_eq!(entry.kind, MountKind::Bind);
            assert_eq!(entry.origin, MountOrigin::Scaffold);
        }
    }

    /// No grant means no host path at all beyond the scaffold. This is the
    /// property that makes an ungranted path `ENOENT` rather than readable.
    #[test]
    fn a_view_with_no_grants_contains_no_host_paths_beyond_the_scaffold() {
        let entries = planned(&ContainmentConfig::new());

        assert!(
            entries
                .iter()
                .all(|entry| entry.origin == MountOrigin::Scaffold),
            "an empty request must plan only the scaffold; anything else is a \
             host path the caller never asked for"
        );
    }

    /// An execute grant on a real dynamically linked binary plans its interpreter
    /// and its libraries, and does *not* plan the directory holding them.
    #[test]
    fn an_execute_grant_plans_its_interpreter_and_libraries_but_not_their_directory() {
        // `/bin/sh` is dynamically linked on every supported host, so this needs
        // no fixture and exercises the real parser against a real image.
        let config = ContainmentConfig::new()
            .allow("/bin/sh", Operation::Exec, Scope::File)
            .expect("execute grant");

        let entries = planned(&config);

        let interpreter = entries
            .iter()
            .find(|entry| entry.origin == MountOrigin::Interpreter)
            .expect("a dynamically linked binary must plan its ELF interpreter");
        assert!(
            !interpreter.writable,
            "the loader must be read-only: read-plus-execute is safe only because \
             the bytes cannot change under the grant"
        );

        let libraries: Vec<_> = entries
            .iter()
            .filter(|entry| entry.origin == MountOrigin::Library)
            .collect();
        assert!(
            !libraries.is_empty(),
            "/bin/sh links at least libc, so DT_NEEDED must resolve something"
        );
        assert!(
            libraries.iter().all(|entry| !entry.writable),
            "a library must never be writable"
        );

        // The whole point of resolving DT_NEEDED: no library *directory* is bound.
        for directory in LIBRARY_DIRECTORIES {
            assert!(
                !entries
                    .iter()
                    .any(|entry| entry.target == Path::new(directory)),
                "binding '{directory}' would authorize every library on the host, \
                 which is exactly what resolving DT_NEEDED exists to avoid"
            );
        }
    }

    /// A submount under a read-only grant is read-only too.
    #[test]
    fn a_submount_under_a_read_only_grant_is_also_read_only() {
        if !crate::backend::linux::namespace::probe::user_namespace_is_permitted() {
            println!("skipping: this host forbids user namespaces");
            return;
        }

        // SAFETY: the child enters new namespaces and exits; it never returns into
        // test-harness code.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");

        if child == 0 {
            // Read ids before the unshare: after it, `getuid()` is the overflow uid.
            // SAFETY: reading this process's own ids.
            let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
            // SAFETY: irreversible for this child only.
            if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
                // SAFETY: terminating the child.
                unsafe { libc::_exit(40) };
            }
            let _ = std::fs::write("/proc/self/setgroups", "deny");
            let _ = std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"));
            let _ = std::fs::write("/proc/self/gid_map", format!("0 {gid} 1"));

            let outcome = (|| -> Result<u8, ContainmentError> {
                // Detach propagation so nothing here reaches the host.
                mount_syscall(
                    None,
                    Path::new("/"),
                    None,
                    libc::MS_REC | libc::MS_PRIVATE,
                    None,
                )
                .map_err(|e| refusal(format!("rprivate: {e}")))?;

                // A directory with a real submount inside it.
                let base = Path::new("/tmp/strands-submount-test");
                let _ = std::fs::remove_dir_all(base);
                std::fs::create_dir_all(base.join("sub"))
                    .map_err(|e| refusal(format!("mkdir: {e}")))?;
                mount_syscall(
                    Some(Path::new("tmpfs")),
                    &base.join("sub"),
                    Some("tmpfs"),
                    0,
                    None,
                )
                .map_err(|e| refusal(format!("submount: {e}")))?;
                std::fs::write(base.join("sub").join("inner.txt"), b"inner")
                    .map_err(|e| refusal(format!("write inner: {e}")))?;

                // Bind it recursively, then remount read-only the way `establish` does.
                let target = Path::new("/tmp/strands-submount-view");
                std::fs::create_dir_all(target).map_err(|e| refusal(format!("mkdir view: {e}")))?;
                mount_syscall(Some(base), target, None, libc::MS_BIND | libc::MS_REC, None)
                    .map_err(|e| refusal(format!("bind: {e}")))?;
                remount_read_only(target)?;

                // The bind itself must be read-only, and so must the submount.
                let top_writable = std::fs::write(target.join("top_probe"), b"x").is_ok();
                let submount_writable =
                    std::fs::write(target.join("sub").join("probe"), b"x").is_ok();

                Ok(match (top_writable, submount_writable) {
                    (false, false) => 0,
                    (true, _) => 41,
                    (_, true) => 42,
                })
            })()
            .unwrap_or(43);

            // SAFETY: terminating the child with the verdict.
            unsafe { libc::_exit(i32::from(outcome)) };
        }

        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "the child must exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "read-only did not cover the whole tree (40=no namespace, \
             41=the bind itself was writable, \
             42=THE SUBMOUNT WAS WRITABLE under a read-only grant, \
             43=a mount step errored)"
        );
    }

    /// A grant through a symlink is reachable under BOTH names.
    #[test]
    fn a_grant_through_a_symlink_is_reachable_under_both_names() {
        let directory = tempfile::tempdir().expect("tempdir");
        let real = directory.path().join("real.txt");
        std::fs::write(&real, b"contents").expect("write target");
        let link = directory.path().join("alias.txt");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let config = ContainmentConfig::new()
            .allow(&link, Operation::Read, Scope::File)
            .expect("grant through the symlink");

        let entries = planned(&config);
        let canonical = real.canonicalize().expect("canonical target");

        let resolved_entry = entry_for(&entries, &canonical);
        assert_eq!(
            resolved_entry.source.as_deref(),
            Some(canonical.as_path()),
            "the resolved identity must be bound: it is what policy names"
        );

        let alias_entry = entry_for(&entries, &link);
        assert_eq!(
            alias_entry.source.as_deref(),
            Some(canonical.as_path()),
            "the caller's spelling must reach the SAME object, not a second one"
        );
    }

    /// Two grants for one path plan one mount whose access is their union, so
    /// mount order cannot decide whether the path is writable.
    #[test]
    fn two_grants_for_one_path_plan_one_mount_with_the_union_of_their_access() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = ContainmentConfig::new()
            .allow(directory.path(), Operation::Read, Scope::Root)
            .expect("read grant")
            .allow(directory.path(), Operation::Write, Scope::Root)
            .expect("write grant");

        let entries = planned(&config);
        let matching: Vec<_> = entries
            .iter()
            .filter(|entry| entry.target == directory.path())
            .collect();

        assert_eq!(
            matching.len(),
            1,
            "a duplicate bind would stack mounts and let the last one decide access"
        );
        assert!(
            matching[0].writable,
            "the union of a read root and a write root is writable"
        );
    }

    /// Two executables sharing libc plan one bind for it.
    #[test]
    fn a_library_shared_by_two_executables_is_planned_once() {
        let config = ContainmentConfig::new()
            .allow("/bin/sh", Operation::Exec, Scope::File)
            .expect("sh grant")
            .allow("/bin/cat", Operation::Exec, Scope::File)
            .expect("cat grant");

        let entries = planned(&config);
        let mut targets: Vec<_> = entries.iter().map(|entry| entry.target.clone()).collect();
        let before = targets.len();
        targets.sort();
        targets.dedup();

        assert_eq!(
            before,
            targets.len(),
            "the planned view must contain no duplicate targets"
        );
    }

    /// A static binary plans no interpreter and no libraries, rather than failing.
    #[test]
    fn a_non_elf_executable_plans_no_dependencies() {
        let directory = tempfile::tempdir().expect("tempdir");
        let script = directory.path().join("script.sh");
        std::fs::write(&script, b"#!/bin/sh\necho hi\n").expect("write script");

        let dependencies = elf_dependencies(&script, &ContainmentConfig::new())
            .expect("a script must plan cleanly");
        assert!(
            dependencies.is_empty(),
            "a script has no ELF interpreter or DT_NEEDED table"
        );
    }

    /// A truncated or hostile file must not panic the planner.
    #[test]
    fn a_malformed_elf_plans_no_dependencies_rather_than_panicking() {
        let directory = tempfile::tempdir().expect("tempdir");

        for (name, bytes) in [
            ("truncated.elf", b"\x7fELF\x02\x01".to_vec()),
            ("claims_huge_phoff.elf", {
                let mut bytes = vec![0u8; 64];
                bytes[..4].copy_from_slice(b"\x7fELF");
                bytes[4] = 2;
                bytes[5] = 1;
                // e_phoff far past the end of the file.
                bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
                bytes[54..56].copy_from_slice(&64u16.to_le_bytes());
                bytes[56..58].copy_from_slice(&16u16.to_le_bytes());
                bytes
            }),
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, &bytes).expect("write fixture");
            let dependencies = elf_dependencies(&path, &ContainmentConfig::new())
                .unwrap_or_else(|error| panic!("{name} errored: {error}"));
            assert!(dependencies.is_empty(), "{name} must plan nothing");
        }
    }

    /// A file grant whose path is a directory is refused, not widened. The check
    /// exists because binding the directory would authorize every file in it.
    #[test]
    fn a_file_grant_whose_path_became_a_directory_is_refused() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("target");
        std::fs::write(&path, b"file for now").expect("write file");

        let config = ContainmentConfig::new()
            .allow(&path, Operation::Read, Scope::File)
            .expect("file grant");

        // Swap the file for a directory after the grant was authorized — the shape live
        // revalidation exists to catch, checked here at plan time too so a widening cannot reach
        // the kernel.
        std::fs::remove_file(&path).expect("remove file");
        std::fs::create_dir(&path).expect("create directory");

        let error = MountView::plan(&config).expect_err("a widened file grant must be refused");
        assert!(
            matches!(error, ContainmentError::ApplyFailed { .. }),
            "got {error:?}"
        );
    }

    /// Run `case` in a forked child; the child's exit status is the verdict.
    fn forked(case: impl FnOnce() -> bool) -> bool {
        // SAFETY: the child unshares, mounts, and `_exit`s; it never returns to the harness.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork: {}", std::io::Error::last_os_error());
        if child == 0 {
            let code = i32::from(!case());
            // SAFETY: skip every destructor; this child shares the parent's heap.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: reaping the child forked above.
        let waited = unsafe { libc::waitpid(child, &raw mut status, 0) };
        assert_eq!(waited, child, "waitpid");
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }

    /// Enter a private user and mount namespace, or report why the host refuses one.
    fn enter_private_namespace() -> bool {
        // SAFETY: reading this process's own identity before the unshare.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        // SAFETY: single-threaded in this fresh child, which is what `CLONE_NEWUSER` requires.
        if unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWUSER) } != 0 {
            eprintln!("unshare: {}", std::io::Error::last_os_error());
            return false;
        }
        for (path, value) in [
            ("/proc/self/setgroups", "deny".to_string()),
            ("/proc/self/uid_map", format!("0 {uid} 1")),
            ("/proc/self/gid_map", format!("0 {gid} 1")),
        ] {
            if let Err(error) = std::fs::write(path, &value) {
                eprintln!("writing {path}: {error}");
                return false;
            }
        }
        mount_syscall(
            None,
            Path::new("/"),
            None,
            libc::MS_REC | libc::MS_PRIVATE,
            None,
        )
        .is_ok()
    }

    /// Establish every planned entry but `/proc` under `root`.
    fn establish_every_entry(view: &MountView, root: &Path) -> bool {
        for entry in view.entries() {
            if entry.target == Path::new("/proc") {
                continue;
            }
            if let Err(error) = view.establish(entry, root) {
                eprintln!("establish {}: {error}", entry.target.display());
                return false;
            }
        }
        true
    }

    /// A workspace with `out/built-hello` copied from `/bin/true`, or a link to such a copy.
    fn workspace_with_program(directory: &Path, linked: bool) -> (PathBuf, PathBuf) {
        let workspace = directory.join("workspace");
        let out = workspace.join("out");
        std::fs::create_dir_all(&out).expect("out");
        let program = out.join("built-hello");
        if linked {
            let real = out.join("hello-v2");
            std::fs::copy("/bin/true", &real).expect("program");
            std::os::unix::fs::symlink(&real, &program).expect("symlink");
        } else {
            std::fs::copy("/bin/true", &program).expect("program");
        }
        (workspace, program)
    }

    /// **A program under a tree its own `read` list grants establishes**: the file an earlier bind
    /// brought in is its own mountpoint.
    #[test]
    fn an_exec_file_under_a_read_root_establishes() {
        if !crate::backend::linux::namespace::probe::user_namespace_is_permitted() {
            println!("skipping: this host forbids user namespaces");
            return;
        }
        assert!(forked(|| {
            if !enter_private_namespace() {
                return false;
            }
            let directory = tempfile::tempdir().expect("tempdir");
            let (workspace, program) = workspace_with_program(directory.path(), false);
            let config = ContainmentConfig::new()
                .allow(&workspace, Operation::Read, Scope::Root)
                .expect("read root")
                .allow(&program, Operation::Exec, Scope::File)
                .expect("exec file");
            let view = MountView::plan(&config).expect("plan");
            let root = directory.path().join("view-root");
            std::fs::create_dir(&root).expect("view root");
            establish_every_entry(&view, &root)
        }));
    }

    /// **A program reached through a symbolic link inside the granted tree establishes**: the link
    /// is left to the enclosing bind and its resolved spelling carries its own.
    #[test]
    fn a_symlinked_exec_file_under_a_read_root_establishes() {
        if !crate::backend::linux::namespace::probe::user_namespace_is_permitted() {
            println!("skipping: this host forbids user namespaces");
            return;
        }
        assert!(forked(|| {
            if !enter_private_namespace() {
                return false;
            }
            let directory = tempfile::tempdir().expect("tempdir");
            let (workspace, link) = workspace_with_program(directory.path(), true);
            let config = ContainmentConfig::new()
                .allow(&workspace, Operation::Read, Scope::Root)
                .expect("read root")
                .allow(&link, Operation::Exec, Scope::File)
                .expect("exec file");
            let view = MountView::plan(&config).expect("plan");
            let root = directory.path().join("view-root");
            std::fs::create_dir(&root).expect("view root");
            establish_every_entry(&view, &root)
        }));
    }

    /// **An absent mountpoint inside a writable bind is refused, never created on the host.**
    #[test]
    fn an_absent_mountpoint_is_not_created_on_the_host() {
        if !crate::backend::linux::namespace::probe::user_namespace_is_permitted() {
            println!("skipping: this host forbids user namespaces");
            return;
        }
        let directory = tempfile::tempdir().expect("tempdir");
        let (workspace, program) = workspace_with_program(directory.path(), false);
        let config = ContainmentConfig::new()
            .allow(&workspace, Operation::Write, Scope::Root)
            .expect("write root")
            .allow(&program, Operation::Exec, Scope::File)
            .expect("exec file");
        let root = directory.path().join("view-root");
        std::fs::create_dir(&root).expect("view root");
        let (program_in_child, root_in_child) = (program.clone(), root.clone());
        let refused = forked(move || {
            if !enter_private_namespace() {
                return false;
            }
            let view = MountView::plan(&config).expect("plan");
            std::fs::remove_file(&program_in_child).expect("the program goes missing");
            !establish_every_entry(&view, &root_in_child)
        });
        assert!(
            refused,
            "the namespace was entered and the absent mountpoint inside a bind was refused"
        );
        assert!(
            !program.exists(),
            "view assembly must not create the mountpoint on the host at {}",
            program.display()
        );
    }

    /// **A symbolic link at a mountpoint no bind encloses is refused**: only a link an enclosing
    /// bind brought in is left to that bind.
    #[test]
    fn a_symlink_at_a_mountpoint_outside_any_bind_is_refused() {
        if !crate::backend::linux::namespace::probe::user_namespace_is_permitted() {
            println!("skipping: this host forbids user namespaces");
            return;
        }
        assert!(forked(|| {
            if !enter_private_namespace() {
                return false;
            }
            let directory = tempfile::tempdir().expect("tempdir");
            let program = directory.path().join("program");
            std::fs::copy("/bin/true", &program).expect("program");
            let config = ContainmentConfig::new()
                .allow(&program, Operation::Exec, Scope::File)
                .expect("exec file");
            let view = MountView::plan(&config).expect("plan");
            let root = directory.path().join("view-root");
            let stale = root.join(program.strip_prefix("/").expect("absolute"));
            std::fs::create_dir_all(stale.parent().expect("parent")).expect("parent");
            std::os::unix::fs::symlink("/bin/true", &stale)
                .expect("a stale link at the mountpoint");
            let entry = view
                .entries()
                .iter()
                .find(|entry| entry.target == program)
                .expect("the program's entry");
            match view.establish(entry, &root) {
                Err(error) => error.to_string().contains("is not a regular file"),
                Ok(()) => {
                    eprintln!("a link at the mountpoint was accepted");
                    false
                }
            }
        }));
    }

    /// A minimal 64-bit little-endian ELF image carrying the entries the planner reads. It is not
    /// runnable; the parser reads the headers and two segments.
    fn synthetic_elf(interpreter: Option<&str>, needed: &[&str], runpath: Option<&str>) -> Vec<u8> {
        synthetic_elf_paths(interpreter, needed, runpath, None)
    }

    fn synthetic_elf_paths(
        interpreter: Option<&str>,
        needed: &[&str],
        runpath: Option<&str>,
        rpath: Option<&str>,
    ) -> Vec<u8> {
        let mut strtab: Vec<u8> = vec![0];
        let mut needed_offsets = Vec::new();
        for name in needed {
            needed_offsets.push(strtab.len() as u64);
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
        }
        let runpath_offset = runpath.map(|list| {
            let offset = strtab.len() as u64;
            strtab.extend_from_slice(list.as_bytes());
            strtab.push(0);
            offset
        });
        let rpath_offset = rpath.map(|list| {
            let offset = strtab.len() as u64;
            strtab.extend_from_slice(list.as_bytes());
            strtab.push(0);
            offset
        });
        let interp: Vec<u8> = interpreter
            .map(|path| {
                let mut bytes = path.as_bytes().to_vec();
                bytes.push(0);
                bytes
            })
            .unwrap_or_default();
        let phnum: u16 = 2 + u16::from(interpreter.is_some());
        let interp_offset = 64 + 56 * usize::from(phnum);
        let strtab_offset = interp_offset + interp.len();
        let dynamic_offset = strtab_offset + strtab.len();
        let mut dynamic: Vec<u8> = Vec::new();
        let mut entry = |tag: u64, value: u64| {
            dynamic.extend_from_slice(&tag.to_le_bytes());
            dynamic.extend_from_slice(&value.to_le_bytes());
        };
        for offset in &needed_offsets {
            entry(1, *offset);
        }
        if let Some(offset) = runpath_offset {
            entry(29, offset);
        }
        if let Some(offset) = rpath_offset {
            entry(15, offset);
        }
        entry(5, strtab_offset as u64);
        entry(0, 0);
        let total = dynamic_offset + dynamic.len();

        let mut image = Vec::with_capacity(total);
        image.extend_from_slice(b"\x7fELF\x02\x01\x01\x00");
        image.extend_from_slice(&[0u8; 8]);
        image.extend_from_slice(&3u16.to_le_bytes());
        image.extend_from_slice(&0xB7u16.to_le_bytes());
        image.extend_from_slice(&1u32.to_le_bytes());
        image.extend_from_slice(&0u64.to_le_bytes());
        image.extend_from_slice(&64u64.to_le_bytes());
        image.extend_from_slice(&0u64.to_le_bytes());
        image.extend_from_slice(&0u32.to_le_bytes());
        image.extend_from_slice(&64u16.to_le_bytes());
        image.extend_from_slice(&56u16.to_le_bytes());
        image.extend_from_slice(&phnum.to_le_bytes());
        image.extend_from_slice(&64u16.to_le_bytes());
        image.extend_from_slice(&0u16.to_le_bytes());
        image.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(image.len(), 64);
        let mut program_header = |kind: u32, offset: usize, size: usize| {
            image.extend_from_slice(&kind.to_le_bytes());
            image.extend_from_slice(&5u32.to_le_bytes());
            for value in [offset, offset, offset, size, size, 1] {
                image.extend_from_slice(&(value as u64).to_le_bytes());
            }
        };
        if interpreter.is_some() {
            program_header(3, interp_offset, interp.len());
        }
        program_header(1, 0, total);
        program_header(2, dynamic_offset, dynamic.len());
        image.extend_from_slice(&interp);
        image.extend_from_slice(&strtab);
        image.extend_from_slice(&dynamic);
        image
    }

    /// One executable image at `root/relative`.
    fn planted_image(root: &Path, relative: &str, image: &[u8]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("the image directory");
        std::fs::write(&path, image).expect("the image");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("+x");
        path
    }

    #[test]
    fn unsupported_elf_headers_and_invalid_program_tables_plan_no_dependencies() {
        let base = synthetic_elf(None, &["libfixture.so"], None);
        let mut cases = Vec::new();
        for (label, offset, value) in [("magic", 0, 0), ("32-bit", 4, 1), ("big-endian", 5, 2)] {
            let mut image = base.clone();
            image[offset] = value;
            cases.push((label, image));
        }
        let mut short_entry = base.clone();
        short_entry[54..56].copy_from_slice(&55u16.to_le_bytes());
        cases.push(("short program entry", short_entry));
        let mut oversized_table = base.clone();
        oversized_table[54..56].copy_from_slice(&u16::MAX.to_le_bytes());
        oversized_table[56..58].copy_from_slice(&u16::MAX.to_le_bytes());
        cases.push(("oversized table", oversized_table));
        let mut bad_offset = base.clone();
        bad_offset[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        cases.push(("invalid table offset", bad_offset));
        cases.push(("truncated table", base[..70].to_vec()));
        let directory = tempfile::tempdir().unwrap();
        for (label, image) in cases {
            let path = planted_image(directory.path(), label, &image);
            let needs = image_needs(&path).unwrap();
            assert!(needs.interpreter.is_none(), "{label}");
            assert!(needs.needed.is_empty(), "{label}");
            assert!(needs.runpath.is_none(), "{label}");
            assert!(needs.rpath.is_empty(), "{label}");
        }
    }

    #[test]
    fn mount_arguments_with_nul_are_refused_before_the_syscall() {
        let invalid = Path::new("/tmp/before\0after");
        for (source, target, fstype, data) in [
            (Some(invalid), Path::new("/"), None, None),
            (None, invalid, None, None),
            (None, Path::new("/"), Some("tmpfs\0other"), None),
            (None, Path::new("/"), None, Some("mode=755\0other")),
        ] {
            assert_eq!(
                mount_syscall(source, target, fstype, 0, data)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
        assert!(path_to_c(invalid).unwrap_err().to_string().contains("NUL"));
    }

    #[test]
    fn unsafe_internal_mount_entries_are_refused_before_mounting() {
        let root = tempfile::tempdir().unwrap();
        let view = MountView {
            entries: Vec::new(),
            protected_parents: BTreeSet::new(),
            grant_identities: BTreeMap::new(),
            grant_pins: Vec::new(),
            dependency_sources: RefCell::new(BTreeMap::new()),
        };
        let mut entry = MountEntry {
            source: None,
            target: PathBuf::from("/entry"),
            kind: MountKind::Bind,
            writable: false,
            executable: false,
            origin: MountOrigin::Grant,
        };
        let error = view.establish(&entry, root.path()).unwrap_err();
        assert!(error.to_string().contains("has no source"));
        entry.target = PathBuf::from("/../escape");
        let error = view.establish(&entry, root.path()).unwrap_err();
        assert!(error.to_string().contains("contains a '..'"));
        assert!(!root.path().join("entry").exists());
    }

    #[test]
    fn a_protected_mountpoint_must_exist_as_a_regular_file() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::write(&source, b"protected").unwrap();
        let view = MountView {
            entries: Vec::new(),
            protected_parents: BTreeSet::new(),
            grant_identities: BTreeMap::new(),
            grant_pins: Vec::new(),
            dependency_sources: RefCell::new(BTreeMap::new()),
        };
        let entry = MountEntry {
            source: Some(source),
            target: PathBuf::from("/entry"),
            kind: MountKind::Bind,
            writable: false,
            executable: false,
            origin: MountOrigin::Protection {
                device: 0,
                inode: 0,
            },
        };
        let error = view.establish(&entry, root.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("opening write-protected mountpoint")
        );
        std::fs::create_dir(root.path().join("entry")).unwrap();
        let error = view.establish(&entry, root.path()).unwrap_err();
        assert!(error.to_string().contains("is not a regular file"));
    }

    #[test]
    fn a_refused_file_never_creates_a_mountpoint_through_a_host_bind() {
        let root = tempfile::tempdir().unwrap();
        let parent = MountEntry {
            source: Some(root.path().join("host")),
            target: PathBuf::from("/bound"),
            kind: MountKind::Bind,
            writable: false,
            executable: false,
            origin: MountOrigin::Grant,
        };
        let view = MountView {
            entries: vec![parent],
            protected_parents: BTreeSet::new(),
            grant_identities: BTreeMap::new(),
            grant_pins: Vec::new(),
            dependency_sources: RefCell::new(BTreeMap::new()),
        };
        let entry = MountEntry {
            source: None,
            target: PathBuf::from("/bound/refused"),
            kind: MountKind::EmptyFile,
            writable: false,
            executable: false,
            origin: MountOrigin::Refusal,
        };
        let error = view.establish(&entry, root.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("absent from the tree bound over it")
        );
        assert!(!root.path().join("bound/refused").exists());
        std::fs::create_dir_all(root.path().join("bound/refused")).unwrap();
        let error = view.establish(&entry, root.path()).unwrap_err();
        assert!(error.to_string().contains("is not a regular file"));
    }

    #[test]
    fn mounted_protection_checks_device_inode_and_link_count() {
        use std::os::unix::fs::MetadataExt as _;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("protected");
        assert!(
            require_mounted_identity(&path, 0, 0)
                .unwrap_err()
                .to_string()
                .contains("inspecting")
        );
        std::fs::write(&path, b"identity").unwrap();
        let metadata = path.metadata().unwrap();
        require_mounted_identity(&path, metadata.dev(), metadata.ino()).unwrap();
        for (device, inode) in [
            (metadata.dev() ^ 1, metadata.ino()),
            (metadata.dev(), metadata.ino() ^ 1),
        ] {
            assert!(require_mounted_identity(&path, device, inode).is_err());
        }
        std::fs::hard_link(&path, directory.path().join("alias")).unwrap();
        assert!(require_mounted_identity(&path, metadata.dev(), metadata.ino()).is_err());
    }

    #[test]
    fn a_grant_mount_that_does_not_install_the_checked_object_is_refused() {
        super::super::failure_tests::in_fresh_process(|| {
            use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            std::fs::write(&source, b"granted").unwrap();
            let identity = ObjectIdentity::from_metadata(&source.metadata().unwrap());
            let view = MountView {
                entries: Vec::new(),
                protected_parents: BTreeSet::new(),
                grant_identities: BTreeMap::from([(source.clone(), identity)]),
                grant_pins: Vec::new(),
                dependency_sources: RefCell::new(BTreeMap::new()),
            };
            let entry = MountEntry {
                source: Some(source),
                target: PathBuf::from("/entry"),
                kind: MountKind::Bind,
                writable: true,
                executable: false,
                origin: MountOrigin::Grant,
            };
            // Report mount success without installing the object, so establish must inspect it.
            let filter = SeccompFilter::new(
                BTreeMap::from([(libc::SYS_mount, Vec::new())]),
                SeccompAction::Allow,
                SeccompAction::Errno(0),
                std::env::consts::ARCH.try_into().unwrap(),
            )
            .unwrap();
            let program: BpfProgram = filter.try_into().unwrap();
            seccompiler::apply_filter(&program).unwrap();

            let error = view.establish(&entry, root.path()).unwrap_err();
            assert!(
                error.to_string().contains("mounted grant identity changed"),
                "{error}"
            );
            let target = root.path().join("entry");
            assert_ne!(
                ObjectIdentity::from_metadata(&target.metadata().unwrap()),
                identity
            );
            assert_eq!(std::fs::read(target).unwrap(), b"");
        });
    }

    #[test]
    fn an_opened_grant_source_keeps_its_object_after_path_replacement() {
        super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
            let directory = tempfile::tempdir().unwrap();
            for is_directory in [false, true] {
                let root = directory
                    .path()
                    .join(if is_directory { "directory" } else { "file" });
                std::fs::create_dir(&root).unwrap();
                let source = root.join("source");
                let target = root.join("target");
                let replacement = root.join("replacement");
                for path in [&source, &target, &replacement] {
                    if is_directory {
                        std::fs::create_dir(path).unwrap();
                        std::fs::write(path.join("value"), path.as_os_str().as_encoded_bytes())
                            .unwrap();
                    } else {
                        std::fs::write(path, path.as_os_str().as_encoded_bytes()).unwrap();
                    }
                }
                let identity = ObjectIdentity::from_metadata(&source.metadata().unwrap());
                let pinned = pin_grant_source(&source, identity).unwrap();
                std::fs::rename(&source, root.join("held")).unwrap();
                std::fs::rename(&replacement, &source).unwrap();
                assert_ne!(
                    ObjectIdentity::from_metadata(&source.metadata().unwrap()),
                    identity
                );
                let pinned_path = PathBuf::from(format!("/proc/self/fd/{}", pinned.as_raw_fd()));
                mount_syscall(
                    Some(&pinned_path),
                    &target,
                    None,
                    libc::MS_BIND | libc::MS_REC,
                    None,
                )
                .unwrap();
                require_grant_identity(&target, identity).unwrap();
                let value = if is_directory {
                    target.join("value")
                } else {
                    target.clone()
                };
                assert_eq!(
                    std::fs::read(value).unwrap(),
                    source.as_os_str().as_encoded_bytes()
                );
                let error = require_grant_identity(&source, identity).unwrap_err();
                assert!(
                    error.to_string().contains("mounted grant identity changed"),
                    "{error}"
                );
            }
        });
    }

    #[test]
    fn dependency_lookup_handles_explicit_paths_and_refuses_unmodeled_tokens() {
        let directory = tempfile::tempdir().unwrap();
        let library = directory.path().join("libfixture-coverage.so");
        std::fs::write(&library, b"library").unwrap();
        let image = directory.path().join("program");
        assert_eq!(
            resolve_needed(library.to_str().unwrap(), None),
            Some(library.clone())
        );
        assert!(resolve_needed("/absent/fixture.so", None).is_none());
        let search = LibrarySearch {
            directories: search_directories(
                &image,
                &["".into(), "$LIB".into(), "$PLATFORM".into()],
            ),
            parent: None,
        };
        assert!(search.directories.is_empty());
        assert!(resolve_needed("libfixture-coverage.so", Some(&search)).is_none());
        let search = LibrarySearch {
            directories: search_directories(&image, &["${ORIGIN}/missing/..".into()]),
            parent: None,
        };
        assert_eq!(
            resolve_needed("libfixture-coverage.so", Some(&search)),
            Some(library)
        );
        assert_eq!(folded(Path::new("./one/../two")), PathBuf::from("two"));
    }

    #[test]
    fn malformed_mount_escapes_remain_literal() {
        for spelling in [r"tail\", r"\12", r"\888", r"\08x"] {
            assert_eq!(unescape_mount_field(spelling), spelling);
        }
    }

    fn materialize_refuses(number: libc::c_long, argument: Option<(u8, u64)>, reason: &str) {
        use super::super::failure_tests::{in_fresh_process_with_user_namespace, refuse_syscall};
        in_fresh_process_with_user_namespace(true, || {
            // A root-only view tests the build sequence without requiring a fresh PID namespace.
            let mut view = MountView::plan(&ContainmentConfig::new()).unwrap();
            view.entries.retain(|entry| entry.target == Path::new("/"));
            refuse_syscall(number, argument);
            let error = view.materialize().unwrap_err();
            assert!(error.to_string().contains(reason), "{error}");
        });
    }

    #[test]
    fn failed_mount_propagation_change_refuses_the_view() {
        materialize_refuses(libc::SYS_mount, None, "making the mount tree private");
    }

    #[test]
    fn unavailable_random_device_refuses_the_staging_root() {
        materialize_refuses(libc::SYS_openat, None, "opening /dev/urandom");
    }

    #[test]
    fn unreadable_random_device_refuses_the_staging_root() {
        materialize_refuses(libc::SYS_read, None, "reading /dev/urandom");
    }

    #[test]
    fn failed_staging_directory_creation_refuses_the_view() {
        #[cfg(target_arch = "x86_64")]
        let call = libc::SYS_mkdir;
        #[cfg(not(target_arch = "x86_64"))]
        let call = libc::SYS_mkdirat;
        materialize_refuses(call, None, "creating the staging root");
    }

    #[test]
    fn failed_fresh_filesystem_mount_refuses_the_view() {
        materialize_refuses(
            libc::SYS_mount,
            Some((3, libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC)),
            "mounting a fresh tmpfs",
        );
    }

    #[test]
    fn failed_root_read_only_remount_refuses_the_view() {
        materialize_refuses(
            libc::SYS_mount,
            Some((
                3,
                libc::MS_REMOUNT
                    | libc::MS_BIND
                    | libc::MS_RDONLY
                    | libc::MS_NOSUID
                    | libc::MS_NODEV
                    | libc::MS_NOEXEC,
            )),
            "remounting the view root read-only",
        );
    }

    #[test]
    fn failed_root_pivot_refuses_the_view() {
        materialize_refuses(libc::SYS_pivot_root, None, "pivot_root into the view");
    }

    #[test]
    fn failed_directory_change_after_pivot_refuses_the_view() {
        materialize_refuses(libc::SYS_chdir, None, "entering the pivoted root");
    }

    #[test]
    fn failed_old_root_detachment_refuses_the_view() {
        materialize_refuses(libc::SYS_umount2, None, "detaching the old root");
    }

    #[test]
    fn an_unreadable_detached_root_refuses_the_view() {
        materialize_refuses(
            libc::SYS_openat,
            Some((
                2,
                (libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NONBLOCK) as u64,
            )),
            "inspecting the detached old root",
        );
    }

    #[test]
    fn a_nonempty_old_root_mountpoint_refuses_the_pivoted_view() {
        super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
            mount_syscall(
                None,
                Path::new("/"),
                None,
                libc::MS_REC | libc::MS_PRIVATE,
                None,
            )
            .unwrap();
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("root");
            std::fs::create_dir(&root).unwrap();
            mount_syscall(None, &root, Some("tmpfs"), 0, Some("mode=755")).unwrap();
            let old = root.join(OLD_ROOT_NAME);
            std::fs::create_dir(&old).unwrap();
            std::fs::write(old.join("unexpected"), b"marker").unwrap();
            let view = MountView {
                entries: Vec::new(),
                protected_parents: BTreeSet::new(),
                grant_identities: BTreeMap::new(),
                grant_pins: Vec::new(),
                dependency_sources: RefCell::new(BTreeMap::new()),
            };
            let error = view.pivot_into(&root).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("detached old root still has 1 entries"),
                "{error}"
            );
            assert_eq!(
                std::fs::read(Path::new("/").join(OLD_ROOT_NAME).join("unexpected")).unwrap(),
                b"marker"
            );
        });
    }

    #[test]
    fn unreadable_mount_tables_refuse_remounting_and_shadow_classification() {
        super::super::failure_tests::in_fresh_process(|| {
            super::super::failure_tests::refuse_syscall(libc::SYS_openat, None);
            let target = Path::new("/fixture");
            let error = remount_read_only(target).unwrap_err();
            assert!(
                error.to_string().contains("reading the mount table"),
                "{error}"
            );
            let error = shadowing_mount(&target.join("child"), target).unwrap_err();
            assert!(
                error.to_string().contains("re-reading the mount table"),
                "{error}"
            );
        });
    }

    #[test]
    fn an_unshadowed_remount_error_refuses_the_view() {
        super::super::failure_tests::in_fresh_process(|| {
            let directory = tempfile::tempdir().unwrap();
            super::super::failure_tests::refuse_syscall(libc::SYS_mount, None);
            let error = remount_read_only(directory.path()).unwrap_err();
            assert!(error.to_string().contains("remounting"), "{error}");
        });
    }

    fn establish_refuses(
        kind: MountKind,
        create_empty_source: bool,
        target: &str,
        denied_call: libc::c_long,
        reason: &str,
    ) {
        super::super::failure_tests::in_fresh_process(|| {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            std::fs::write(&source, b"source").unwrap();
            let grant_identities = BTreeMap::from([(
                source.clone(),
                ObjectIdentity::from_metadata(&source.metadata().unwrap()),
            )]);
            if create_empty_source {
                std::fs::write(root.path().join(EMPTY_FILE_NAME), b"").unwrap();
            }
            let entry = MountEntry {
                source: (kind == MountKind::Bind).then_some(source),
                target: target.into(),
                kind,
                writable: false,
                executable: false,
                origin: if kind == MountKind::EmptyFile {
                    MountOrigin::Refusal
                } else {
                    MountOrigin::Grant
                },
            };
            let view = MountView {
                entries: Vec::new(),
                protected_parents: BTreeSet::new(),
                grant_identities,
                grant_pins: Vec::new(),
                dependency_sources: RefCell::new(BTreeMap::new()),
            };
            let argument =
                (kind == MountKind::Bind && denied_call == libc::SYS_openat).then_some((
                    2,
                    (libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC) as u64,
                ));
            super::super::failure_tests::refuse_syscall(denied_call, argument);
            let error = view.establish(&entry, root.path()).unwrap_err();
            assert!(error.to_string().contains(reason), "{error}");
        });
    }

    #[test]
    fn failed_empty_refusal_source_creation_refuses_the_view() {
        establish_refuses(
            MountKind::EmptyFile,
            false,
            "/entry",
            libc::SYS_openat,
            "creating the empty file",
        );
    }

    #[test]
    fn failed_empty_refusal_target_opening_refuses_the_view() {
        establish_refuses(
            MountKind::EmptyFile,
            true,
            "/entry",
            libc::SYS_openat,
            "opening the staging root",
        );
    }

    #[test]
    fn failed_empty_refusal_parent_creation_refuses_the_view() {
        let call = libc::SYS_mkdirat;
        establish_refuses(
            MountKind::EmptyFile,
            true,
            "/parent/entry",
            call,
            "creating '",
        );
    }

    #[test]
    fn failed_empty_file_binding_refuses_the_view() {
        establish_refuses(
            MountKind::EmptyFile,
            true,
            "/entry",
            libc::SYS_mount,
            "binding the empty file",
        );
    }

    #[test]
    fn failed_source_binding_refuses_the_view() {
        establish_refuses(MountKind::Bind, false, "/entry", libc::SYS_mount, "binding");
    }

    #[test]
    fn failed_file_bind_mountpoint_creation_refuses_the_view() {
        establish_refuses(
            MountKind::Bind,
            false,
            "/entry",
            libc::SYS_openat,
            "creating the mountpoint",
        );
    }

    #[test]
    fn failed_fresh_mount_directory_creation_refuses_the_view() {
        let call = libc::SYS_mkdirat;
        establish_refuses(
            MountKind::Fresh { fstype: "tmpfs" },
            false,
            "/parent/entry",
            call,
            "creating",
        );
    }

    #[test]
    fn a_file_bind_cannot_replace_a_directory_mountpoint() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        std::fs::write(&source, b"source").unwrap();
        let grant_identities = BTreeMap::from([(
            source.clone(),
            ObjectIdentity::from_metadata(&source.metadata().unwrap()),
        )]);
        let target = root.path().join("entry");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("sentinel"), b"unchanged").unwrap();
        let entry = MountEntry {
            source: Some(source),
            target: "/entry".into(),
            kind: MountKind::Bind,
            writable: false,
            executable: false,
            origin: MountOrigin::Grant,
        };
        let view = MountView {
            entries: Vec::new(),
            protected_parents: BTreeSet::new(),
            grant_identities,
            grant_pins: Vec::new(),
            dependency_sources: RefCell::new(BTreeMap::new()),
        };
        let error = view.establish(&entry, root.path()).unwrap_err();
        assert!(
            error.to_string().contains("is not a regular file"),
            "{error}"
        );
        assert_eq!(
            std::fs::read(target.join("sentinel")).unwrap(),
            b"unchanged"
        );
    }

    #[test]
    fn unrelated_mounts_and_ancestors_outside_the_grant_do_not_count_as_shadowing() {
        super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
            let root = tempfile::tempdir().unwrap();
            let grant = root.path().join("grant");
            let point = grant.join("point");
            let sibling = root.path().join("sibling");
            std::fs::create_dir_all(&point).unwrap();
            std::fs::create_dir(&sibling).unwrap();
            let mount = |path: &Path| {
                mount_syscall(
                    Some(Path::new("tmpfs")),
                    path,
                    Some("tmpfs"),
                    libc::MS_NOSUID | libc::MS_NODEV,
                    None,
                )
                .unwrap()
            };
            mount(&point);
            mount(&sibling);
            assert!(shadowing_mount(&point, &grant).unwrap().is_none());
            mount(root.path());
            assert!(shadowing_mount(&point, &grant).unwrap().is_none());
        });
    }

    #[test]
    fn a_missing_executable_names_the_failed_dependency_lookup() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("absent");
        let error = image_needs(&missing)
            .err()
            .expect("missing image must fail");
        assert!(error.to_string().contains("opening"));
        assert!(error.to_string().contains("absent"));
    }

    #[test]
    fn malformed_interpreter_segments_do_not_create_an_interpreter_grant() {
        let base = synthetic_elf(Some("/ld-fixture"), &[], None);
        let mut cases = Vec::new();
        for (label, byte) in [("empty interpreter", 0), ("invalid UTF-8", 0xff)] {
            let mut image = base.clone();
            image[64 + 3 * 56] = byte;
            cases.push((label, image));
        }
        let mut oversized = base.clone();
        oversized[64 + 32..64 + 40].copy_from_slice(&(4_194_305u64).to_le_bytes());
        cases.push(("oversized interpreter", oversized));
        let mut absent = base.clone();
        absent[64 + 8..64 + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        cases.push(("absent interpreter", absent));
        let directory = tempfile::tempdir().unwrap();
        for (label, image) in cases {
            let path = planted_image(directory.path(), label, &image);
            assert!(image_needs(&path).unwrap().interpreter.is_none(), "{label}");
        }
    }

    #[test]
    fn absent_or_malformed_dynamic_metadata_plans_no_libraries() {
        let base = synthetic_elf(None, &["libfixture.so"], None);
        let dynamic = u64::from_le_bytes(base[128..136].try_into().unwrap()) as usize;
        let mut cases = Vec::new();
        let mut no_dynamic = base.clone();
        no_dynamic[120..124].copy_from_slice(&0u32.to_le_bytes());
        cases.push(("static image", no_dynamic));
        let mut oversized = base.clone();
        oversized[152..160].copy_from_slice(&4_194_305u64.to_le_bytes());
        cases.push(("oversized dynamic", oversized));
        let mut no_strings = base.clone();
        no_strings[dynamic + 16..dynamic + 24].copy_from_slice(&99u64.to_le_bytes());
        cases.push(("no string table", no_strings));
        let mut no_load = base.clone();
        no_load[64..68].copy_from_slice(&99u32.to_le_bytes());
        cases.push(("no load segment", no_load));
        let mut overflowing_range = base.clone();
        overflowing_range[80..88].copy_from_slice(&u64::MAX.to_le_bytes());
        overflowing_range[dynamic + 24..dynamic + 32].copy_from_slice(&u64::MAX.to_le_bytes());
        cases.push(("overflowing virtual range", overflowing_range));
        let mut oversized_strings = base.clone();
        oversized_strings[dynamic + 8..dynamic + 16].copy_from_slice(&4_194_305u64.to_le_bytes());
        cases.push(("oversized strings", oversized_strings));
        let mut absent_strings = base.clone();
        absent_strings[72..80].copy_from_slice(&1_000_000u64.to_le_bytes());
        cases.push(("strings past EOF", absent_strings));
        let mut empty_name = base.clone();
        empty_name[177] = 0;
        cases.push(("empty library name", empty_name));
        let mut invalid_name = base.clone();
        invalid_name[177] = 0xff;
        cases.push(("invalid library name", invalid_name));
        let directory = tempfile::tempdir().unwrap();
        for (label, image) in cases {
            let path = planted_image(directory.path(), label, &image);
            assert!(image_needs(&path).unwrap().needed.is_empty(), "{label}");
        }
    }

    #[test]
    fn an_overflowing_string_table_file_offset_does_not_panic() {
        let mut image = synthetic_elf(None, &["libfixture.so"], None);
        image[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
        let directory = tempfile::tempdir().unwrap();
        let path = planted_image(directory.path(), "overflowing-offset", &image);
        assert!(image_needs(&path).unwrap().needed.is_empty());
    }

    #[test]
    fn legacy_rpath_is_used_when_runpath_is_absent() {
        let mut image = synthetic_elf(None, &["libfixture.so"], Some("/one:/two"));
        let dynamic = u64::from_le_bytes(image[128..136].try_into().unwrap()) as usize;
        image[dynamic + 16..dynamic + 24].copy_from_slice(&15u64.to_le_bytes());
        let directory = tempfile::tempdir().unwrap();
        let path = planted_image(directory.path(), "legacy-rpath", &image);
        let needs = image_needs(&path).unwrap();
        assert_eq!(needs.needed, ["libfixture.so"]);
        assert!(needs.runpath.is_none());
        assert_eq!(needs.rpath, ["/one", "/two"]);
    }

    #[test]
    fn dependency_cycles_and_repeated_interpreters_terminate_without_duplicate_images() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let interpreter = planted_image(root, "loader", b"loader");
        let interpreter = interpreter.to_str().unwrap();
        let first = planted_image(
            root,
            "first.so",
            &synthetic_elf(
                Some(interpreter),
                &["second.so", "second.so"],
                Some("$ORIGIN"),
            ),
        );
        let second = planted_image(
            root,
            "second.so",
            &synthetic_elf(Some(interpreter), &["first.so"], Some("$ORIGIN")),
        );
        let dependencies = elf_dependencies(&first, &ContainmentConfig::new()).unwrap();
        assert_eq!(dependencies.len(), 3);
        assert_eq!(
            dependencies
                .iter()
                .filter(|entry| entry.origin == MountOrigin::Interpreter)
                .count(),
            1
        );
        assert_eq!(
            dependencies
                .iter()
                .filter(|entry| entry.path == first)
                .count(),
            1
        );
        assert_eq!(
            dependencies
                .iter()
                .filter(|entry| entry.path == second)
                .count(),
            1
        );
    }

    #[test]
    fn dependency_walk_refuses_more_than_its_image_limit() {
        let directory = tempfile::tempdir().unwrap();
        for index in 0..=MAXIMUM_IMAGES + 2 {
            let next = format!("image-{}.so", index + 1);
            let needed = if index == MAXIMUM_IMAGES + 2 {
                Vec::new()
            } else {
                vec![next.as_str()]
            };
            planted_image(
                directory.path(),
                &format!("image-{index}.so"),
                &synthetic_elf(None, &needed, Some("$ORIGIN")),
            );
        }
        let error = elf_dependencies(
            &directory.path().join("image-0.so"),
            &ContainmentConfig::new(),
        )
        .err()
        .expect("dependency limit must refuse the walk");
        assert!(
            error.to_string().contains("loads more than 512 images"),
            "{error}"
        );
    }

    #[test]
    fn an_unseekable_string_table_offset_plans_no_libraries() {
        let mut image = synthetic_elf(None, &["fixture.so"], None);
        image.extend_from_slice(b"\0fixture.so\0");
        // The table address is 176. This translation fits u64 but cannot be a file offset.
        image[72..80].copy_from_slice(&(u64::MAX - 176).to_le_bytes());
        let directory = tempfile::tempdir().unwrap();
        let path = planted_image(directory.path(), "unseekable", &image);
        assert!(image_needs(&path).unwrap().needed.is_empty());
    }

    #[test]
    fn an_unreadable_string_table_plans_no_libraries() {
        super::super::failure_tests::in_fresh_process(|| {
            let directory = tempfile::tempdir().unwrap();
            let mut image = synthetic_elf(None, &["fixture.so"], None);
            image.resize(2048, 0);
            let path = planted_image(directory.path(), "unreadable-strings", &image);
            assert_eq!(image_needs(&path).unwrap().needed, ["fixture.so"]);
            // A later read fails after the string reader has collected a valid dependency name.
            super::super::failure_tests::refuse_syscall(libc::SYS_read, Some((2, 256)));
            assert!(image_needs(&path).unwrap().needed.is_empty());
        });
    }

    #[test]
    fn a_library_with_unverifiable_path_identity_refuses_dependency_planning() {
        super::super::failure_tests::in_fresh_process(|| {
            let directory = tempfile::tempdir().unwrap();
            let program = planted_image(
                directory.path(),
                "program",
                &synthetic_elf(None, &["fixture.so"], Some("$ORIGIN")),
            );
            planted_image(directory.path(), "fixture.so", b"library");
            assert_eq!(
                elf_dependencies(&program, &ContainmentConfig::new())
                    .unwrap()
                    .len(),
                1
            );
            #[cfg(target_arch = "x86_64")]
            let call = libc::SYS_readlink;
            #[cfg(not(target_arch = "x86_64"))]
            let call = libc::SYS_readlinkat;
            super::super::failure_tests::refuse_syscall(call, None);
            let error = elf_dependencies(&program, &ContainmentConfig::new())
                .err()
                .expect("an unverifiable library must be refused");
            assert!(error.to_string().contains("cannot be granted"), "{error}");
        });
    }

    #[test]
    fn string_tables_outside_load_segment_ranges_plan_no_libraries() {
        let directory = tempfile::tempdir().unwrap();
        for (virtual_address, size) in [(1024u64, 4096u64), (0, 1)] {
            let mut image = synthetic_elf(None, &["fixture.so"], None);
            image[80..88].copy_from_slice(&virtual_address.to_le_bytes());
            image[96..104].copy_from_slice(&size.to_le_bytes());
            let path = planted_image(directory.path(), "outside-load", &image);
            assert!(image_needs(&path).unwrap().needed.is_empty());
        }
    }

    /// **An exec file brings the libraries its `DT_RUNPATH` names, and theirs in turn**, each as
    /// a read-only executable file bind.
    #[test]
    fn an_exec_file_pulls_its_runpath_libraries_transitively() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical");
        let app = planted_image(
            &root,
            "bin/app",
            &synthetic_elf(None, &["libapp.so"], Some("$ORIGIN/../lib")),
        );
        let libapp = planted_image(
            &root,
            "lib/libapp.so",
            &synthetic_elf(None, &["libinner.so"], Some("${ORIGIN}")),
        );
        let libinner = planted_image(&root, "lib/libinner.so", &synthetic_elf(None, &[], None));
        let config = ContainmentConfig::new()
            .allow(&app, Operation::Exec, Scope::File)
            .expect("execute grant");

        let entries = planned(&config);

        for library in [&libapp, &libinner] {
            let entry = entries
                .iter()
                .find(|entry| entry.target == *library)
                .unwrap_or_else(|| panic!("{} must be planned: {entries:#?}", library.display()));
            assert_eq!(entry.origin, MountOrigin::Library);
            assert!(entry.executable && !entry.writable, "{entry:?}");
        }
        assert!(
            !entries.iter().any(|entry| entry.target == root.join("lib")),
            "the library directory itself is not bound: {entries:#?}"
        );
    }

    #[cfg(target_env = "gnu")]
    #[test]
    fn an_executable_runpath_does_not_shadow_a_system_librarys_child() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical");
        let app = planted_image(
            &root,
            "app",
            &synthetic_elf(None, &["libm.so.6"], Some("$ORIGIN/private")),
        );
        let shadow = planted_image(&root, "private/libc.so.6", &synthetic_elf(None, &[], None));
        let system_libc = resolve_needed("libc.so.6", None).expect("the GNU runtime supplies libc");
        let entries = planned(
            &ContainmentConfig::new()
                .allow(&app, Operation::Exec, Scope::File)
                .expect("execute grant"),
        );

        assert!(
            entries.iter().any(|entry| entry.target == system_libc),
            "libm must use the system libc"
        );
        assert!(
            !entries.iter().any(|entry| entry.target == shadow),
            "the executable's RUNPATH must not expose an indirect dependency"
        );
    }

    #[cfg(target_env = "gnu")]
    #[test]
    fn library_search_inheritance_matches_the_native_loader() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical");
        std::fs::create_dir(root.join("deps")).expect("library directory");
        for (name, source) in [
            ("leaf.c", "int box_leaf(void) { return 42; }\n"),
            (
                "mid.c",
                "extern int box_leaf(void); int box_mid(void) { return box_leaf(); }\n",
            ),
            (
                "app.c",
                "extern int box_mid(void); int main(void) { return box_mid() == 42 ? 0 : 1; }\n",
            ),
        ] {
            std::fs::write(root.join(name), source).expect("fixture source");
        }
        let compile = |arguments: &[&str]| {
            let output = std::process::Command::new("cc")
                .current_dir(&root)
                .args(arguments)
                .output()
                .expect("the C compiler used to build Box");
            assert!(
                output.status.success(),
                "fixture compilation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        compile(&[
            "-shared",
            "-fPIC",
            "leaf.c",
            "-o",
            "deps/libbox_search_leaf.so",
        ]);
        compile(&[
            "-shared",
            "-fPIC",
            "mid.c",
            "-Ldeps",
            "-lbox_search_leaf",
            "-o",
            "deps/libbox_search_mid.so",
        ]);
        for (name, tag, should_start) in [
            ("app-rpath", "--disable-new-dtags", true),
            ("app-runpath", "--enable-new-dtags", false),
        ] {
            compile(&[
                "app.c",
                "-Ldeps",
                "-lbox_search_mid",
                "-Wl,-rpath-link,deps",
                &format!("-Wl,{tag}"),
                "-Wl,-rpath,$ORIGIN/deps",
                "-o",
                name,
            ]);
            let app = root.join(name);
            let native = std::process::Command::new(&app)
                .env_remove("LD_LIBRARY_PATH")
                .env_remove("LD_PRELOAD")
                .env_remove("LD_AUDIT")
                .output()
                .expect("run the trusted fixture");
            assert_eq!(
                native.status.success(),
                should_start,
                "{name}: {}",
                String::from_utf8_lossy(&native.stderr)
            );
            let config = ContainmentConfig::new()
                .allow(&app, Operation::Exec, Scope::File)
                .expect("execute grant");
            let plan = MountView::plan(&config);
            assert_eq!(
                plan.is_ok(),
                should_start,
                "the mount plan must agree with the native loader for {name}: {plan:?}"
            );
            if !should_start {
                assert!(
                    String::from_utf8_lossy(&native.stderr).contains("libbox_search_leaf.so"),
                    "the native failure must name the indirect dependency"
                );
                assert!(
                    plan.unwrap_err()
                        .to_string()
                        .contains("libbox_search_leaf.so"),
                    "the planner must refuse the same missing dependency"
                );
            }
        }
    }

    #[cfg(target_env = "gnu")]
    #[test]
    fn an_exec_file_pulls_system_libraries_transitively() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical");
        let app = planted_image(&root, "app", &synthetic_elf(None, &["libm.so.6"], None));
        let libm = resolve_needed("libm.so.6", None).expect("the GNU runtime supplies libm");
        let needs = image_needs(&libm).expect("read libm's dependencies");
        assert!(
            needs.needed.iter().any(|name| name == "libc.so.6"),
            "the system library must require libc for this regression"
        );
        let libc = resolve_needed("libc.so.6", None).expect("libm's libc dependency exists");
        let config = ContainmentConfig::new()
            .allow(&app, Operation::Exec, Scope::File)
            .expect("execute grant");

        let entries = planned(&config);

        for library in [&libm, &libc] {
            let entry = entries
                .iter()
                .find(|entry| entry.target == *library)
                .unwrap_or_else(|| panic!("{} must be planned", library.display()));
            assert_eq!(entry.origin, MountOrigin::Library);
            assert!(entry.executable && !entry.writable, "{entry:?}");
        }
        assert!(
            !entries.iter().any(|entry| {
                entry.kind == MountKind::Bind
                    && entry.source.as_deref().is_some_and(Path::is_dir)
                    && LIBRARY_DIRECTORIES
                        .iter()
                        .any(|directory| entry.target == Path::new(directory))
            }),
            "dependency discovery must not grant whole library directories"
        );
    }

    /// **A read root on a loader directory is bound executable and read-only**, and a read root
    /// anywhere else stays no-exec.
    #[test]
    fn a_read_root_on_a_loader_directory_is_bound_executable_and_read_only() {
        let loader = LIBRARY_DIRECTORIES
            .iter()
            .map(Path::new)
            .find(|directory| directory.is_dir())
            .expect("a loader directory on this host");
        let directory = tempfile::tempdir().expect("tempdir");
        let other = directory.path().canonicalize().expect("canonical");
        let config = ContainmentConfig::new()
            .allow("/bin/sh", Operation::Exec, Scope::File)
            .expect("execute grant")
            .allow(loader, Operation::Read, Scope::Root)
            .expect("loader read root")
            .allow(&other, Operation::Read, Scope::Root)
            .expect("other read root");

        let entries = planned(&config);

        let bound = entries
            .iter()
            .find(|entry| entry.target == loader)
            .expect("the loader directory is bound under its own spelling");
        assert!(bound.executable && !bound.writable, "{bound:?}");
        assert_eq!(bound.origin, MountOrigin::Grant);
        let plain = entries
            .iter()
            .find(|entry| entry.target == other)
            .expect("the other read root is bound");
        assert!(!plain.executable && !plain.writable, "{plain:?}");
    }

    /// **A dependency a loader directory already covers is not planned twice.**
    #[test]
    fn a_dependency_a_loader_directory_covers_is_not_planned_twice() {
        let libc_directory = LIBRARY_DIRECTORIES
            .iter()
            .map(Path::new)
            .find(|directory| directory.join("libc.so.6").is_file())
            .expect("libc in a loader directory");
        let resolved = libc_directory.canonicalize().expect("canonical");
        let config = ContainmentConfig::new()
            .allow("/bin/sh", Operation::Exec, Scope::File)
            .expect("execute grant")
            .allow(libc_directory, Operation::Read, Scope::Root)
            .expect("loader read root");

        let entries = planned(&config);

        let leaked: Vec<&MountEntry> = entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.origin,
                    MountOrigin::Library | MountOrigin::Interpreter
                ) && (entry.target.starts_with(libc_directory)
                    || entry.target.starts_with(&resolved))
            })
            .collect();
        assert!(
            leaked.is_empty(),
            "a file beneath the bound loader directory is reached through it: {leaked:#?}"
        );
    }

    #[test]
    fn an_executable_rpath_keeps_its_origin_in_indirect_dependencies() {
        let directory = tempfile::tempdir().expect("tempdir");
        let home = directory.path().canonicalize().expect("canonical");
        let app = planted_image(
            &home,
            "bin/app",
            &synthetic_elf_paths(None, &["libmid.so"], None, Some("$ORIGIN/../lib/nested")),
        );
        planted_image(
            &home,
            "lib/nested/libmid.so",
            &synthetic_elf(None, &["libleaf.so"], None),
        );
        let leaf = planted_image(
            &home,
            "lib/nested/libleaf.so",
            &synthetic_elf(None, &[], None),
        );
        let config = ContainmentConfig::new()
            .allow(&app, Operation::Exec, Scope::File)
            .expect("execute grant")
            .anchored_at(&home);

        let entries = planned(&config);
        assert!(entries.iter().any(|entry| entry.target == leaf));
    }

    #[test]
    fn an_empty_runpath_suppresses_local_and_inherited_rpath() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical");
        let app = planted_image(
            &root,
            "app",
            &synthetic_elf_paths(None, &["libmid.so"], None, Some("$ORIGIN/lib")),
        );
        planted_image(
            &root,
            "lib/libmid.so",
            &synthetic_elf_paths(None, &["libbox_leaf.so"], Some(""), Some("$ORIGIN")),
        );
        planted_image(&root, "lib/libbox_leaf.so", &synthetic_elf(None, &[], None));
        let config = ContainmentConfig::new()
            .allow(&app, Operation::Exec, Scope::File)
            .expect("execute grant");

        let error = MountView::plan(&config).expect_err("RUNPATH suppresses every RPATH here");
        assert!(error.to_string().contains("libbox_leaf.so"), "{error}");
    }

    #[test]
    fn an_ancestor_rpath_survives_a_descendants_runpath() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical");
        let app = planted_image(
            &root,
            "app",
            &synthetic_elf_paths(None, &["libmid.so"], None, Some("$ORIGIN/parent")),
        );
        planted_image(
            &root,
            "parent/libmid.so",
            &synthetic_elf(None, &["libleaf.so"], Some("$ORIGIN/../child")),
        );
        planted_image(
            &root,
            "child/libleaf.so",
            &synthetic_elf(None, &["libdeep.so"], None),
        );
        let deep = planted_image(&root, "parent/libdeep.so", &synthetic_elf(None, &[], None));
        let config = ContainmentConfig::new()
            .allow(&app, Operation::Exec, Scope::File)
            .expect("execute grant");

        let entries = planned(&config);
        assert!(entries.iter().any(|entry| entry.target == deep));
    }

    #[test]
    fn the_first_loader_supplies_a_shared_librarys_inherited_rpath() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical");
        let shared = planted_image(
            &root,
            "shared.so",
            &synthetic_elf(None, &["libchoice.so"], None),
        );
        let first = planted_image(
            &root,
            "first.so",
            &synthetic_elf_paths(
                None,
                &[shared.to_str().unwrap()],
                None,
                Some("$ORIGIN/first"),
            ),
        );
        let second = planted_image(
            &root,
            "second.so",
            &synthetic_elf_paths(
                None,
                &[shared.to_str().unwrap()],
                None,
                Some("$ORIGIN/second"),
            ),
        );
        let expected = planted_image(&root, "first/libchoice.so", &synthetic_elf(None, &[], None));
        let unused = planted_image(
            &root,
            "second/libchoice.so",
            &synthetic_elf(None, &[], None),
        );
        let app = planted_image(
            &root,
            "app",
            &synthetic_elf(
                None,
                &[first.to_str().unwrap(), second.to_str().unwrap()],
                None,
            ),
        );
        let config = ContainmentConfig::new()
            .allow(&app, Operation::Exec, Scope::File)
            .expect("execute grant");

        let entries = planned(&config);
        assert!(entries.iter().any(|entry| entry.target == expected));
        assert!(!entries.iter().any(|entry| entry.target == unused));
    }

    /// **An interpreter the floor refuses is refused by name**, because the workload authors the
    /// program header that names it.
    #[test]
    fn an_interpreter_inside_a_credential_store_is_refused_by_name() {
        let directory = tempfile::tempdir().expect("tempdir");
        let home = directory.path().canonicalize().expect("canonical");
        let loader = planted_image(&home, ".aws/ld.so", &synthetic_elf(None, &[], None));
        let app = planted_image(
            &home,
            "bin/app",
            &synthetic_elf(Some(&loader.to_string_lossy()), &[], None),
        );
        let config = ContainmentConfig::new()
            .allow(&app, Operation::Exec, Scope::File)
            .expect("execute grant")
            .anchored_at(&home);

        let error =
            MountView::plan(&config).expect_err("a credential store is never an interpreter");

        let text = error.to_string();
        assert!(
            text.contains("floor refuses") && text.contains("ld.so"),
            "the refusal names the interpreter and the floor: {text}"
        );
    }

    /// **A needed library no search directory holds is refused by name**, so the closure refuses
    /// the plan rather than leaving the view short of an image `exec` needs.
    #[test]
    fn a_needed_library_no_search_directory_holds_is_refused_by_name() {
        let directory = tempfile::tempdir().expect("tempdir");
        let home = directory.path().canonicalize().expect("canonical");
        let app = planted_image(
            &home,
            "bin/app",
            &synthetic_elf(None, &["libnowhere.so.999"], None),
        );
        let config = ContainmentConfig::new()
            .allow(&app, Operation::Exec, Scope::File)
            .expect("execute grant")
            .anchored_at(&home);

        let error = MountView::plan(&config).expect_err("an unresolved need refuses the plan");

        let text = error.to_string();
        assert!(
            text.contains("libnowhere.so.999") && text.contains("needs the shared library"),
            "the refusal names the library it cannot find: {text}"
        );
    }

    /// **A library the floor refuses is refused by name**, so a rewritten binary cannot reach a
    /// credential store through its `DT_RUNPATH`.
    #[test]
    fn a_runpath_library_inside_a_credential_store_is_refused_by_name() {
        let directory = tempfile::tempdir().expect("tempdir");
        let home = directory.path().canonicalize().expect("canonical");
        planted_image(&home, ".aws/libapp.so", &synthetic_elf(None, &[], None));
        let app = planted_image(
            &home,
            "bin/app",
            &synthetic_elf(None, &["libapp.so"], Some("$ORIGIN/../.aws")),
        );
        let config = ContainmentConfig::new()
            .allow(&app, Operation::Exec, Scope::File)
            .expect("execute grant")
            .anchored_at(&home);

        let error = MountView::plan(&config).expect_err("a credential store is never a library");

        let text = error.to_string();
        assert!(
            text.contains("floor refuses") && text.contains("libapp.so"),
            "the refusal names the library and the floor: {text}"
        );
    }
}
