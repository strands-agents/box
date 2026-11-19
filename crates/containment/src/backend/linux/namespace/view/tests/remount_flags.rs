use super::*;
use std::cell::Cell;
use std::os::unix::fs::OpenOptionsExt;

fn value_path(path: &Path, directory: bool) -> PathBuf {
    if directory {
        path.join("value")
    } else {
        path.to_path_buf()
    }
}

fn require_access(path: &Path, writable: bool, executable: bool) {
    let write = std::fs::OpenOptions::new().write(true).open(path);
    if writable {
        write.unwrap();
    } else {
        assert_eq!(write.unwrap_err().raw_os_error(), Some(libc::EROFS));
    }
    let file = std::fs::File::open(path).unwrap();
    // SAFETY: map one page of the open fixture without executing its contents.
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    if executable {
        assert_ne!(
            mapping,
            libc::MAP_FAILED,
            "{}",
            std::io::Error::last_os_error()
        );
        // SAFETY: release only the successful mapping above.
        assert_eq!(unsafe { libc::munmap(mapping, 4096) }, 0);
    } else {
        let error = std::io::Error::last_os_error();
        if mapping != libc::MAP_FAILED {
            // SAFETY: release the unexpected successful mapping before failing.
            assert_eq!(unsafe { libc::munmap(mapping, 4096) }, 0);
        }
        assert_eq!(
            mapping,
            libc::MAP_FAILED,
            "an ungranted executable mapping succeeded"
        );
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    }
}

fn retained_permissions(directory: bool, writable: bool, executable: bool) {
    if !super::super::super::failure_tests::namespace_test_is_permitted() {
        return;
    }
    for replace in [false, true] {
        let fixture = tempfile::tempdir().unwrap();
        let tree = fixture.path().join("tree");
        let middle = tree.join("middle");
        let source = middle.join("leaf");
        let held = tree.join("held");
        let outside = fixture.path().join("outside");
        let outside_target = outside.join("leaf");
        let root = fixture.path().join("view");
        std::fs::create_dir_all(&middle).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::create_dir(&root).unwrap();
        if directory {
            std::fs::create_dir(&source).unwrap();
            std::fs::create_dir(&outside_target).unwrap();
        }
        // An executable file grant needs an actual image during dependency planning.
        std::fs::copy("/bin/true", value_path(&source, directory)).unwrap();
        std::fs::write(value_path(&outside_target, directory), b"outside").unwrap();
        let scope = if directory { Scope::Root } else { Scope::File };
        let mut config = ContainmentConfig::new()
            .allow(&tree, Operation::Read, Scope::Root)
            .unwrap()
            .allow(&source, Operation::Read, scope)
            .unwrap();
        if writable {
            config = config.allow(&source, Operation::Write, scope).unwrap();
        }
        if executable {
            config = config.allow(&source, Operation::Exec, scope).unwrap();
        }
        let view = MountView::plan(&config).unwrap();
        nested_grants::with_private_namespace(|| {
            // Keep an independent fixture mount as the unchanged permission control.
            mount_syscall(
                Some(&outside_target),
                &outside_target,
                None,
                libc::MS_BIND,
                None,
            )
            .unwrap();
            remount_writable_executable(&outside_target, &outside_target).unwrap();
            let outside_value = value_path(&outside_target, directory);
            require_access(&outside_value, true, true);
            let retained = Rc::new(RefCell::new(None::<std::fs::File>));
            let fired = Rc::new(Cell::new(false));
            for entry in view
                .entries()
                .iter()
                .filter(|entry| entry.target != Path::new("/proc"))
            {
                if entry.target == source {
                    let retained = retained.clone();
                    let fired = fired.clone();
                    let staged = root.join(source.strip_prefix("/").unwrap());
                    let middle = middle.clone();
                    let held = held.clone();
                    let outside = outside.clone();
                    targets::AFTER_BIND_VERIFICATION.with(|hook| {
                        *hook.borrow_mut() = Some(Box::new(move || {
                            *retained.borrow_mut() = Some(
                                std::fs::OpenOptions::new()
                                    .read(true)
                                    .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                                    .open(staged)
                                    .unwrap(),
                            );
                            if replace {
                                std::fs::rename(&middle, &held).unwrap();
                                std::os::unix::fs::symlink(&outside, &middle).unwrap();
                            }
                            fired.set(true);
                        }));
                    });
                }
                let outcome = view.establish(entry, &root);
                if entry.target == source {
                    assert!(fired.get(), "the post-verification interval did not run");
                    assert_eq!(outcome.is_ok(), !replace, "{outcome:?}");
                    let borrowed = retained.borrow();
                    let target = targets::descriptor_path(borrowed.as_ref().unwrap());
                    require_access(&value_path(&target, directory), writable, executable);
                    require_access(&outside_value, true, true);
                    break;
                }
                outcome.unwrap();
            }
            assert!(fired.get());
        });
        assert_eq!(
            std::fs::read(value_path(&outside_target, directory)).unwrap(),
            b"outside"
        );
    }
}

#[test]
fn verified_file_remount_retains_read_only_noexec_permissions() {
    retained_permissions(false, false, false);
}

#[test]
fn verified_directory_remount_retains_read_only_noexec_permissions() {
    retained_permissions(true, false, false);
}

#[test]
fn verified_file_remount_retains_writable_noexec_permissions() {
    retained_permissions(false, true, false);
}

#[test]
fn verified_directory_remount_retains_writable_noexec_permissions() {
    retained_permissions(true, true, false);
}

#[test]
fn verified_file_remount_retains_read_only_executable_permissions() {
    retained_permissions(false, false, true);
}

#[test]
fn verified_directory_remount_retains_read_only_executable_permissions() {
    retained_permissions(true, false, true);
}

#[test]
fn verified_file_remount_retains_explicit_writable_executable_permissions() {
    retained_permissions(false, true, true);
}

#[test]
fn verified_directory_remount_retains_explicit_writable_executable_permissions() {
    retained_permissions(true, true, true);
}
