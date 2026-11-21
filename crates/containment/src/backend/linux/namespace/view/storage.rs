//! Private construction of storage subtrees from the ordinary mount plan.

use super::*;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

impl MountView {
    /// Attach a sealed empty file to the logical target FD, including an existing symlink.
    pub(super) fn establish_pending_file(
        &self,
        entry: &MountEntry,
        root: &Path,
    ) -> Result<(), ContainmentError> {
        let target = targets::MountTarget::prepare_logical_file(self, entry, root)?;
        let empty_path = root.join(EMPTY_FILE_NAME);
        if !empty_path.exists() {
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&empty_path)
                .map_err(|error| {
                    refusal(format!("creating private pending-mask source: {error}"))
                })?;
        }
        // Keep the source on its own private bind before cloning, matching the verified file-mount
        // operation. This changes only the launcher's scratch mount table, not the backing file.
        mount_syscall(Some(&empty_path), &empty_path, None, libc::MS_BIND, None)
            .map_err(|error| refusal(format!("binding private pending-mask source: {error}")))?;
        let empty = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&empty_path)
            .map_err(|error| refusal(format!("opening private pending-mask source: {error}")))?;
        let metadata = empty
            .metadata()
            .map_err(|error| refusal(format!("inspecting pending-mask source: {error}")))?;
        if !metadata.is_file() || metadata.len() != 0 {
            return Err(refusal(
                "pending-mask source is not an empty regular file".into(),
            ));
        }
        let prepared = protected_file_clone(&empty, false, false)?;
        attach_file_to_logical_target(
            &prepared,
            &target,
            &root.join(entry.target.strip_prefix("/").unwrap_or(&entry.target)),
        )
    }

    /// Make file aliases inside a selected projection independent of canonical paths outside it.
    /// The source is opened only in the completed protected view. Adding restrictions to its clone
    /// preserves the provider flags and the alias entry's own read/write/execute policy.
    fn materialize_projected_file_aliases(
        &self,
        root: &Path,
        selected: &[PathBuf],
    ) -> Result<(), ContainmentError> {
        let selected = selected
            .iter()
            .map(|path| view_spelling(path, &host_usr_links()))
            .collect::<Vec<_>>();
        for entry in &self.entries {
            let Some(canonical) = entry.source.as_ref() else {
                continue;
            };
            if entry.kind != MountKind::Bind
                || entry.origin != MountOrigin::Grant
                || *canonical == entry.target
                || !selected.iter().any(|path| entry.target.starts_with(path))
            {
                continue;
            }
            let source =
                targets::open_protected_object(root, &view_spelling(canonical, &host_usr_links()))?;
            if !source
                .metadata()
                .map_err(|error| refusal(format!("inspecting protected alias source: {error}")))?
                .is_file()
            {
                continue;
            }
            let target = targets::MountTarget::prepare_logical_file(self, entry, root)?;
            if !target.metadata()?.is_symlink() {
                continue;
            }
            let prepared = protected_file_clone(&source, entry.writable, entry.executable)?;
            attach_file_to_logical_target(
                &prepared,
                &target,
                &root.join(entry.target.strip_prefix("/").unwrap_or(&entry.target)),
            )?;
        }
        Ok(())
    }

    /// Construct the configured view privately and retain one protected directory subtree.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn stage_subtree(&self, selected_root: &Path) -> Result<OwnedFd, ContainmentError> {
        let mut projections = self.stage_projections(&[selected_root.to_path_buf()])?;
        let projection = std::fs::File::from(projections.remove(0));
        if !projection
            .metadata()
            .map_err(|error| refusal(format!("inspecting protected storage subtree: {error}")))?
            .is_dir()
        {
            return Err(refusal(
                "the selected storage subtree is not a directory".into(),
            ));
        }
        Ok(projection.into())
    }

    /// Build one protected view and retain independent file or directory projections from it.
    pub(crate) fn stage_projections(
        &self,
        selected_targets: &[PathBuf],
    ) -> Result<Vec<OwnedFd>, ContainmentError> {
        if selected_targets.is_empty() {
            return Err(refusal(
                "a protected generation has no publication targets".into(),
            ));
        }
        for (index, target) in selected_targets.iter().enumerate() {
            if !target.is_absolute()
                || target == Path::new("/")
                || target.components().any(|component| {
                    !matches!(
                        component,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )
                })
            {
                return Err(refusal(
                    "a publication target must be an absolute non-root path without dot components"
                        .into(),
                ));
            }
            if selected_targets[..index]
                .iter()
                .any(|previous| target.starts_with(previous) || previous.starts_with(target))
            {
                return Err(refusal("publication targets overlap or repeat".into()));
            }
        }
        let root = PathBuf::from(format!("{STAGING_ROOT}.storage.{}", unique_suffix()?));
        std::fs::create_dir(&root)
            .map_err(|error| refusal(format!("creating storage staging root: {error}")))?;
        let staging = StagingRoot(root);
        std::fs::set_permissions(&staging.0, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| refusal(format!("protecting storage staging root: {error}")))?;
        self.mount_locations.borrow_mut().clear();
        for entry in &self.entries {
            if entry.origin == MountOrigin::Scaffold && entry.target != Path::new("/") {
                continue;
            }
            self.establish_with_source_restrictions(entry, &staging.0, true)?;
            if entry.origin == MountOrigin::Grant
                && entry.kind == MountKind::Bind
                && entry.writable
                && self.protect_parents(&staging.0, &entry.target)?
            {
                self.establish_with_source_restrictions(entry, &staging.0, true)?;
            }
        }
        for (name, target) in &self.root_links {
            std::os::unix::fs::symlink(target, staging.0.join(name))
                .map_err(|error| refusal(format!("creating storage view root link: {error}")))?;
        }
        self.materialize_projected_file_aliases(&staging.0, selected_targets)?;
        mount_syscall(
            None,
            &staging.0,
            None,
            libc::MS_REMOUNT
                | libc::MS_BIND
                | libc::MS_RDONLY
                | libc::MS_NOSUID
                | libc::MS_NODEV
                | libc::MS_NOEXEC,
            None,
        )
        .map_err(|error| refusal(format!("sealing storage staging root: {error}")))?;
        let mut projections = Vec::with_capacity(selected_targets.len());
        for target in selected_targets {
            let selected = staging.0.join(
                view_spelling(target, &host_usr_links())
                    .strip_prefix("/")
                    .map_err(|_| {
                        refusal("publication target has no absolute view spelling".into())
                    })?,
            );
            let source = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&selected)
                .map_err(|error| {
                    refusal(format!(
                        "opening protected publication target '{}': {error}",
                        target.display()
                    ))
                })?;
            if source
                .metadata()
                .map_err(|error| {
                    refusal(format!("inspecting protected publication target: {error}"))
                })?
                .file_type()
                .is_symlink()
            {
                return Err(refusal(
                    "a protected projection must name a mounted object, not a symlink".into(),
                ));
            }
            projections.push(super::super::storage::clone_private_tree(&source.into())?);
        }
        Ok(projections)
    }
}

fn protected_file_clone(
    source: &std::fs::File,
    writable: bool,
    executable: bool,
) -> Result<std::fs::File, ContainmentError> {
    let source = source
        .try_clone()
        .map_err(|error| refusal(format!("retaining protected file source: {error}")))?;
    let prepared = std::fs::File::from(super::super::storage::clone_private_tree(&source.into())?);
    restrict_mount_tree(&prepared, writable, executable, false)?;
    require_mount_flags_with_source_restrictions(&prepared, writable, executable, false, true)?;
    Ok(prepared)
}

fn attach_file_to_logical_target(
    prepared: &std::fs::File,
    target: &targets::MountTarget,
    spelling: &Path,
) -> Result<(), ContainmentError> {
    let previous = targets::mount_ids()?;
    #[cfg(test)]
    targets::after_open();
    // SAFETY: both descriptors pin exact objects. T_EMPTY_PATH does not follow a symlink target.
    if unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            prepared.as_raw_fd(),
            c"".as_ptr(),
            target.descriptor().as_raw_fd(),
            c"".as_ptr(),
            libc::MOVE_MOUNT_F_EMPTY_PATH | libc::MOVE_MOUNT_T_EMPTY_PATH,
        )
    } != 0
    {
        return Err(refusal(format!(
            "attaching a protected file to its logical target: {}",
            std::io::Error::last_os_error()
        )));
    }
    #[cfg(test)]
    targets::after_mount();
    let mounted = target.require_new_mount(spelling, &previous)?;
    let expected = ObjectIdentity::from_metadata(
        &prepared
            .metadata()
            .map_err(|error| refusal(format!("inspecting attached file source: {error}")))?,
    );
    require_grant_identity(&targets::descriptor_path(&mounted), expected)?;
    Ok(())
}

struct StagingRoot(PathBuf);

impl Drop for StagingRoot {
    fn drop(&mut self) {
        if let Ok(path) = path_to_c(&self.0) {
            // SAFETY: this is the private scratch mount owned by this guard.
            unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) };
        }
        let _ = std::fs::remove_dir(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Operation, Scope};
    use std::os::fd::AsRawFd;

    fn tmpfs(path: &Path) {
        mount_syscall(
            Some(Path::new("tmpfs")),
            path,
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV,
            Some("mode=0755,size=4m"),
        )
        .unwrap();
    }

    fn attach(tree: &OwnedFd, destination: &Path) {
        let destination = path_to_c(destination).unwrap();
        // SAFETY: the detached tree and empty target belong to this isolated test namespace.
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_move_mount,
                    tree.as_raw_fd(),
                    c"".as_ptr(),
                    libc::AT_FDCWD,
                    destination.as_ptr(),
                    libc::MOVE_MOUNT_F_EMPTY_PATH,
                )
            },
            0,
            "attach protected tree: {}",
            std::io::Error::last_os_error()
        );
    }

    fn pin(path: &Path) -> std::fs::File {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(path)
            .unwrap()
    }

    fn executable_errno(path: &Path) -> i32 {
        let path = path_to_c(path).unwrap();
        let arguments = [path.as_ptr(), std::ptr::null()];
        let environment = [std::ptr::null()];
        // SAFETY: the fixture contains invalid image bytes and cannot replace the test process.
        assert_eq!(
            unsafe { libc::execve(path.as_ptr(), arguments.as_ptr(), environment.as_ptr()) },
            -1
        );
        std::io::Error::last_os_error().raw_os_error().unwrap()
    }

    #[test]
    fn staging_preserves_stronger_source_flags_and_recursive_child_restrictions() {
        super::super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
            tmpfs(Path::new("/mnt"));
            let root = Path::new("/mnt/storage");
            let target = Path::new("/mnt/published");
            std::fs::create_dir(root).unwrap();
            std::fs::create_dir(target).unwrap();
            tmpfs(root);
            let child = root.join("child");
            std::fs::create_dir(&child).unwrap();
            tmpfs(&child);
            for directory in [root, child.as_path()] {
                std::fs::write(directory.join("program"), b"not an executable image").unwrap();
                std::fs::set_permissions(
                    directory.join("program"),
                    std::fs::Permissions::from_mode(0o755),
                )
                .unwrap();
                assert_eq!(executable_errno(&directory.join("program")), libc::ENOEXEC);
            }
            let config = ContainmentConfig::new()
                .allow(root, Operation::Read, Scope::Root)
                .unwrap()
                .allow(root, Operation::Write, Scope::Root)
                .unwrap()
                .allow(root, Operation::Exec, Scope::Root)
                .unwrap();
            restrict_mount_tree(&pin(&child), false, false, false).unwrap();
            let plan = MountView::plan(&config).unwrap();
            let staged = plan.stage_subtree(root).unwrap();
            attach(&staged, target);
            std::fs::write(target.join("permitted"), b"writable root").unwrap();
            assert_eq!(executable_errno(&target.join("program")), libc::ENOEXEC);
            assert_eq!(
                std::fs::read(target.join("child/program")).unwrap(),
                b"not an executable image"
            );
            assert!(std::fs::write(target.join("child/forbidden"), b"x").is_err());
            assert_eq!(
                executable_errno(&target.join("child/program")),
                libc::EACCES
            );
            restrict_mount_tree(&pin(root), false, false, false).unwrap();
            let stronger_target = Path::new("/mnt/stronger");
            std::fs::create_dir(stronger_target).unwrap();
            let stronger = MountView::plan(&config)
                .unwrap()
                .stage_subtree(root)
                .unwrap();
            attach(&stronger, stronger_target);
            assert!(std::fs::write(stronger_target.join("forbidden"), b"x").is_err());
            assert_eq!(
                executable_errno(&stronger_target.join("program")),
                libc::EACCES
            );
            assert_eq!(
                std::fs::read(stronger_target.join("program")).unwrap(),
                b"not an executable image"
            );
        });
    }

    #[test]
    fn staging_keeps_file_only_grant_ancestors_read_only() {
        super::super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
            tmpfs(Path::new("/mnt"));
            let root = Path::new("/mnt/storage");
            let target = Path::new("/mnt/published");
            std::fs::create_dir(root).unwrap();
            std::fs::create_dir(target).unwrap();
            std::fs::write(root.join("allowed"), b"allowed bytes").unwrap();
            std::fs::write(root.join("secret"), b"secret bytes").unwrap();
            let config = ContainmentConfig::new()
                .allow(root.join("allowed"), Operation::Read, Scope::File)
                .unwrap();
            let tree = MountView::plan(&config)
                .unwrap()
                .stage_subtree(root)
                .unwrap();
            attach(&tree, target);
            assert_eq!(
                std::fs::read(target.join("allowed")).unwrap(),
                b"allowed bytes"
            );
            assert!(std::fs::read(target.join("secret")).is_err());
            assert!(std::fs::write(target.join("new"), b"x").is_err());
        });
    }

    #[test]
    fn staging_applies_nested_denials_and_write_protection_under_a_writable_grant() {
        super::super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
            tmpfs(Path::new("/mnt"));
            let root = Path::new("/mnt/storage");
            let target = Path::new("/mnt/published");
            std::fs::create_dir(root).unwrap();
            std::fs::create_dir(target).unwrap();
            for name in ["protected", "hidden"] {
                std::fs::create_dir(root.join(name)).unwrap();
                std::fs::write(root.join(name).join("value"), name.as_bytes()).unwrap();
            }
            std::fs::write(root.join("denied-file"), b"denied bytes").unwrap();
            let config = ContainmentConfig::new()
                .allow(root, Operation::Read, Scope::Root)
                .unwrap()
                .allow(root, Operation::Write, Scope::Root)
                .unwrap()
                .protect_write_tree(root.join("protected"))
                .unwrap()
                .refuse(root.join("hidden"), Scope::Root)
                .unwrap()
                .refuse(root.join("denied-file"), Scope::File)
                .unwrap();
            let tree = MountView::plan(&config)
                .unwrap()
                .stage_subtree(root)
                .unwrap();
            attach(&tree, target);
            std::fs::write(target.join("allowed"), b"allowed").unwrap();
            assert_eq!(
                std::fs::read(target.join("protected/value")).unwrap(),
                b"protected"
            );
            assert!(std::fs::write(target.join("protected/value"), b"changed").is_err());
            assert!(std::fs::write(target.join("protected/new"), b"new").is_err());
            assert!(std::fs::read(target.join("hidden/value")).is_err());
            assert!(
                std::fs::read(target.join("denied-file"))
                    .unwrap_or_default()
                    .is_empty()
            );
            assert!(std::fs::write(target.join("hidden/new"), b"new").is_err());
            assert!(std::fs::write(target.join("denied-file"), b"new").is_err());
            assert_eq!(std::fs::read(root.join("hidden/value")).unwrap(), b"hidden");
            assert_eq!(
                std::fs::read(root.join("denied-file")).unwrap(),
                b"denied bytes"
            );
        });
    }

    #[test]
    fn staging_preserves_an_explicit_child_grant_beneath_a_restricted_source_parent() {
        super::super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
            tmpfs(Path::new("/mnt"));
            let root = Path::new("/mnt/storage");
            let target = Path::new("/mnt/published");
            std::fs::create_dir(root).unwrap();
            std::fs::create_dir(target).unwrap();
            tmpfs(root);
            let child = root.join("child");
            std::fs::create_dir(&child).unwrap();
            tmpfs(&child);
            std::fs::write(child.join("program"), b"not an executable image").unwrap();
            std::fs::set_permissions(
                child.join("program"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            mount_syscall(
                None,
                root,
                None,
                libc::MS_REMOUNT
                    | libc::MS_BIND
                    | libc::MS_RDONLY
                    | libc::MS_NOEXEC
                    | libc::MS_NOSUID
                    | libc::MS_NODEV,
                None,
            )
            .unwrap();
            std::fs::write(child.join("source-control"), b"writable child").unwrap();
            assert_eq!(executable_errno(&child.join("program")), libc::ENOEXEC);
            let config = ContainmentConfig::new()
                .allow(root, Operation::Read, Scope::Root)
                .unwrap()
                .allow(&child, Operation::Write, Scope::Root)
                .unwrap()
                .allow(&child, Operation::Exec, Scope::Root)
                .unwrap();
            let tree = MountView::plan(&config)
                .unwrap()
                .stage_subtree(root)
                .unwrap();
            attach(&tree, target);
            assert!(std::fs::write(target.join("forbidden"), b"x").is_err());
            std::fs::write(target.join("child/permitted"), b"writable child").unwrap();
            assert_eq!(
                executable_errno(&target.join("child/program")),
                libc::ENOEXEC
            );
            assert_eq!(
                std::fs::read(child.join("permitted")).unwrap(),
                b"writable child"
            );
        });
    }

    #[test]
    fn staging_extracts_directory_and_authored_file_alias_from_one_protected_view() {
        super::super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
            tmpfs(Path::new("/mnt"));
            let root = Path::new("/mnt/storage");
            let alias = Path::new("/mnt/alias");
            let directory_target = Path::new("/mnt/published");
            let file_target = Path::new("/mnt/published-file");
            std::fs::create_dir(root).unwrap();
            std::fs::create_dir(directory_target).unwrap();
            std::fs::write(file_target, b"placeholder").unwrap();
            std::fs::write(root.join("allowed"), b"allowed bytes").unwrap();
            std::fs::write(root.join("secret"), b"secret bytes").unwrap();
            std::os::unix::fs::symlink(root.join("allowed"), alias).unwrap();
            let config = ContainmentConfig::new()
                .allow(root, Operation::Read, Scope::Root)
                .unwrap()
                .allow(alias, Operation::Read, Scope::File)
                .unwrap()
                .refuse(root.join("secret"), Scope::File)
                .unwrap();
            let projections = MountView::plan(&config)
                .unwrap()
                .stage_projections(&[root.to_path_buf(), alias.to_path_buf()])
                .unwrap();
            assert_eq!(projections.len(), 2);
            attach(&projections[0], directory_target);
            attach(&projections[1], file_target);
            assert_eq!(
                std::fs::read(directory_target.join("allowed")).unwrap(),
                b"allowed bytes"
            );
            assert!(
                std::fs::read(directory_target.join("secret"))
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(std::fs::read(file_target).unwrap(), b"allowed bytes");
            assert!(std::fs::write(file_target, b"changed").is_err());
            assert!(std::fs::write(directory_target.join("new"), b"changed").is_err());
            assert_eq!(std::fs::read(root.join("secret")).unwrap(), b"secret bytes");
            assert_eq!(std::fs::read_link(alias).unwrap(), root.join("allowed"));
        });
    }

    #[test]
    fn pending_logical_masks_hide_nonempty_underlay_and_do_not_follow_a_dangling_alias() {
        super::super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
            tmpfs(Path::new("/mnt"));
            let parent = Path::new("/mnt/parent");
            let root = parent.join("storage");
            let alias = Path::new("/mnt/alias");
            let target = Path::new("/mnt/published");
            let file_target = Path::new("/mnt/published-file");
            std::fs::create_dir(parent).unwrap();
            std::fs::create_dir(&root).unwrap();
            std::fs::create_dir(target).unwrap();
            std::fs::write(file_target, b"placeholder").unwrap();
            std::fs::write(root.join("underlay"), b"must remain hidden").unwrap();
            std::fs::write(parent.join("sibling"), b"still available").unwrap();
            let absent = root.join("not-present");
            std::os::unix::fs::symlink(&absent, alias).unwrap();
            let config = ContainmentConfig::new()
                .allow(parent, Operation::Read, Scope::Root)
                .unwrap();
            let view = MountView::plan(&config)
                .unwrap()
                .with_pending_masks(&[
                    (root.clone(), Scope::Root),
                    (alias.to_path_buf(), Scope::File),
                ])
                .unwrap();
            let projections = view
                .stage_projections(&[parent.to_path_buf(), alias.to_path_buf()])
                .unwrap();
            attach(&projections[0], target);
            attach(&projections[1], file_target);
            assert!(std::fs::read(target.join("storage/underlay")).is_err());
            assert!(
                std::fs::read_dir(target.join("storage"))
                    .unwrap()
                    .next()
                    .is_none()
            );
            assert_eq!(
                std::fs::read(target.join("sibling")).unwrap(),
                b"still available"
            );
            assert!(std::fs::read(file_target).unwrap().is_empty());
            assert!(std::fs::write(file_target, b"changed").is_err());
            assert_eq!(
                std::fs::read(root.join("underlay")).unwrap(),
                b"must remain hidden"
            );
            assert_eq!(std::fs::read_link(alias).unwrap(), absent);
            assert!(!absent.exists());
        });
    }

    #[test]
    fn ordinary_view_preserves_read_file_alias_inside_an_ancestor_directory_grant() {
        super::super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
            tmpfs(Path::new("/mnt"));
            let parent = Path::new("/mnt/parent");
            let root = Path::new("/mnt/storage");
            let alias = parent.join("alias");
            std::fs::create_dir(parent).unwrap();
            std::fs::create_dir(root).unwrap();
            std::fs::write(root.join("value"), b"source bytes").unwrap();
            std::fs::write(parent.join("sibling"), b"sibling bytes").unwrap();
            std::os::unix::fs::symlink(root.join("value"), &alias).unwrap();
            let config = ContainmentConfig::new()
                .allow(parent, Operation::Read, Scope::Root)
                .unwrap()
                .allow(&alias, Operation::Read, Scope::File)
                .unwrap();
            // The ordinary view mounts proc only after the real launcher creates its PID
            // namespace. Calling materialize directly here would test an unsupported setup.
            // SAFETY: this isolated fixture owns the child, which exits after containment.
            let child = unsafe { libc::fork() };
            assert!(child >= 0);
            if child == 0 {
                use crate::backend::ContainmentBackend as _;
                super::super::super::NamespaceBackend::with_probe_result(true)
                    .apply(&config, None, None, None, None)
                    .unwrap();
                assert_eq!(unsafe { libc::getpid() }, 2);
                assert_eq!(std::fs::read(&alias).unwrap(), b"source bytes");
                assert_eq!(
                    std::fs::read(parent.join("sibling")).unwrap(),
                    b"sibling bytes"
                );
                assert!(std::fs::write(&alias, b"changed").is_err());
                // SAFETY: the contained workload must not return into the test harness.
                unsafe { libc::_exit(0) };
            }
            let mut status = 0;
            // SAFETY: this fixture waits for its own launcher child exactly once.
            assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
            assert!(libc::WIFEXITED(status), "launcher status {status}");
            assert_eq!(libc::WEXITSTATUS(status), 0, "launcher status {status}");
            assert_eq!(std::fs::read_link(&alias).unwrap(), root.join("value"));
            assert_eq!(std::fs::read(root.join("value")).unwrap(), b"source bytes");
            assert_eq!(
                std::fs::read(parent.join("sibling")).unwrap(),
                b"sibling bytes"
            );
        });
    }

    #[test]
    fn pending_alias_inside_ancestor_bind_masks_existing_and_dangling_links_without_host_changes() {
        for present in [true, false] {
            super::super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
                tmpfs(Path::new("/mnt"));
                let parent = Path::new("/mnt/parent");
                let root = Path::new("/mnt/storage");
                let alias = parent.join("alias");
                let published = Path::new("/mnt/published");
                std::fs::create_dir(parent).unwrap();
                std::fs::create_dir(root).unwrap();
                std::fs::create_dir(published).unwrap();
                if present {
                    std::fs::write(root.join("value"), b"source bytes").unwrap();
                }
                std::fs::write(parent.join("sibling"), b"sibling bytes").unwrap();
                std::os::unix::fs::symlink(root.join("value"), &alias).unwrap();
                let config = ContainmentConfig::new()
                    .allow(parent, Operation::Read, Scope::Root)
                    .unwrap();
                let view = MountView::plan(&config)
                    .unwrap()
                    .with_pending_masks(&[
                        (root.to_path_buf(), Scope::Root),
                        (alias.clone(), Scope::File),
                    ])
                    .unwrap();
                let projections = view.stage_projections(&[parent.to_path_buf()]).unwrap();
                attach(&projections[0], published);
                assert!(
                    std::fs::symlink_metadata(published.join("alias"))
                        .unwrap()
                        .is_file()
                );
                assert!(std::fs::read(published.join("alias")).unwrap().is_empty());
                assert!(std::fs::write(published.join("alias"), b"changed").is_err());
                assert_eq!(
                    std::fs::read(published.join("sibling")).unwrap(),
                    b"sibling bytes"
                );
                assert_eq!(std::fs::read_link(&alias).unwrap(), root.join("value"));
                if present {
                    assert_eq!(std::fs::read(&alias).unwrap(), b"source bytes");
                } else {
                    assert!(!root.join("value").exists());
                }
                assert_eq!(
                    std::fs::read(parent.join("sibling")).unwrap(),
                    b"sibling bytes"
                );
            });
        }
    }

    #[test]
    fn completed_alias_within_directory_projection_keeps_own_read_only_policy() {
        super::super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
            tmpfs(Path::new("/mnt"));
            let parent = Path::new("/mnt/parent");
            let root = Path::new("/mnt/storage");
            let alias = parent.join("alias");
            let value = root.join("value");
            let published_parent = Path::new("/mnt/published-parent");
            let published_root = Path::new("/mnt/published-storage");
            for path in [parent, root, published_parent, published_root] {
                std::fs::create_dir(path).unwrap();
            }
            std::fs::write(&value, b"source bytes").unwrap();
            std::fs::set_permissions(&value, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::write(parent.join("sibling"), b"sibling bytes").unwrap();
            std::os::unix::fs::symlink(&value, &alias).unwrap();
            let config = ContainmentConfig::new()
                .allow(parent, Operation::Read, Scope::Root)
                .unwrap()
                .allow(root, Operation::Read, Scope::Root)
                .unwrap()
                .allow(&alias, Operation::Read, Scope::File)
                .unwrap()
                .allow(&value, Operation::Write, Scope::File)
                .unwrap();
            let projections = MountView::plan(&config)
                .unwrap()
                .stage_projections(&[parent.to_path_buf(), root.to_path_buf()])
                .unwrap();
            attach(&projections[0], published_parent);
            attach(&projections[1], published_root);
            assert!(
                std::fs::symlink_metadata(published_parent.join("alias"))
                    .unwrap()
                    .is_file()
            );
            assert_eq!(
                std::fs::read(published_parent.join("alias")).unwrap(),
                b"source bytes"
            );
            std::fs::write(published_root.join("value"), b"canonical write").unwrap();
            assert_eq!(
                std::fs::read(published_parent.join("alias")).unwrap(),
                b"canonical write"
            );
            assert!(std::fs::write(published_parent.join("alias"), b"alias write").is_err());
            assert_eq!(
                executable_errno(&published_parent.join("alias")),
                libc::EACCES
            );
            assert_eq!(std::fs::read_link(&alias).unwrap(), value);
            assert_eq!(
                std::fs::read(parent.join("sibling")).unwrap(),
                b"sibling bytes"
            );
        });
    }

    #[test]
    fn completed_file_alias_projection_uses_protected_canonical_bytes_after_denial() {
        super::super::super::failure_tests::in_fresh_process_with_user_namespace(true, || {
            tmpfs(Path::new("/mnt"));
            let parent = Path::new("/mnt/parent");
            let root = Path::new("/mnt/storage");
            let alias = parent.join("alias");
            let value = root.join("value");
            let published = Path::new("/mnt/published-file");
            std::fs::create_dir(parent).unwrap();
            std::fs::create_dir(root).unwrap();
            std::fs::write(&value, b"ambient bytes must not leak").unwrap();
            std::fs::write(published, b"placeholder").unwrap();
            std::os::unix::fs::symlink(&value, &alias).unwrap();
            let config = ContainmentConfig::new()
                .allow(parent, Operation::Read, Scope::Root)
                .unwrap()
                .allow(&alias, Operation::Read, Scope::File)
                .unwrap()
                .refuse(&value, Scope::File)
                .unwrap();
            let projections = MountView::plan(&config)
                .unwrap()
                .stage_projections(std::slice::from_ref(&alias))
                .unwrap();
            attach(&projections[0], published);
            assert!(std::fs::read(published).unwrap().is_empty());
            assert!(std::fs::write(published, b"changed").is_err());
            assert_eq!(
                std::fs::read(&value).unwrap(),
                b"ambient bytes must not leak"
            );
            assert_eq!(std::fs::read_link(&alias).unwrap(), value);
        });
    }
}
