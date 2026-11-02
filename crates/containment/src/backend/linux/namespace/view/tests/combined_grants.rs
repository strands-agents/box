use super::*;

fn with_loader_directory(body: impl FnOnce(&Path, &Path, &Path)) {
    super::super::super::failure_tests::in_fresh_process(|| {
        if !super::forked(enter_private_namespace) {
            eprintln!("skipping: combined-grant fixture requires private user/mount namespaces");
            return;
        }
        assert!(super::forked(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert!(enter_private_namespace());
                mount_syscall(
                    Some(Path::new("tmpfs")),
                    Path::new("/usr/lib"),
                    Some("tmpfs"),
                    libc::MS_NOSUID | libc::MS_NODEV,
                    None,
                )
                .unwrap();
                let temporary = tempfile::tempdir().unwrap();
                let root = temporary.path().canonicalize().unwrap();
                let library = root.join("libraries");
                std::fs::create_dir(&library).unwrap();
                let spelling = LIBRARY_DIRECTORIES
                    .iter()
                    .map(Path::new)
                    .find(|path| path.starts_with("/usr/lib/") && path != &Path::new("/usr/lib/"))
                    .expect("an architecture-specific library directory");
                std::os::unix::fs::symlink(&library, spelling).unwrap();
                assert!(is_loader_directory(&library));
                body(&root, &library, spelling);
            }))
            .is_ok()
        }));
    });
}

fn read_write(read: &Path, write: &Path, write_first: bool) -> ContainmentConfig {
    let grants = if write_first {
        [(write, Operation::Write), (read, Operation::Read)]
    } else {
        [(read, Operation::Read), (write, Operation::Write)]
    };
    grants
        .into_iter()
        .fold(ContainmentConfig::new(), |config, (path, operation)| {
            config.allow(path, operation, Scope::Root).unwrap()
        })
}

fn refuses_implicit_execution(config: &ContainmentConfig, library: &Path) {
    crate::floors::require_all(config).unwrap();
    assert!(config.warnings().is_empty());
    match MountView::plan(config) {
        Err(error) => {
            let text = error.to_string();
            assert!(text.contains("writable executable mount"), "{text}");
            assert!(text.contains("no explicit execution grant"), "{text}");
            assert!(text.contains(library.to_str().unwrap()), "{text}");
        }
        Ok(view) => panic!("implicit execution was admitted: {:#?}", view.entries()),
    }
}

#[test]
fn combined_loader_grants_require_execution_in_either_order_and_spelling() {
    with_loader_directory(|root, library, spelling| {
        let alias = root.join("library-alias");
        std::os::unix::fs::symlink(library, &alias).unwrap();
        for read in [library, spelling, alias.as_path()] {
            for write in [library, spelling, alias.as_path()] {
                for write_first in [false, true] {
                    refuses_implicit_execution(&read_write(read, write, write_first), library);
                }
            }
        }
    });
}

#[test]
fn a_writable_ancestor_cannot_make_a_loader_directory_executable() {
    with_loader_directory(|root, library, spelling| {
        for read in [library, spelling] {
            for write_first in [false, true] {
                let config = read_write(read, root, write_first)
                    .allow(root, Operation::Read, Scope::Root)
                    .unwrap();
                refuses_implicit_execution(&config, library);
            }
        }
    });
}

#[test]
fn execution_of_one_library_file_does_not_authorize_its_writable_directory() {
    with_loader_directory(|_, library, spelling| {
        let program = planted_image(library, "program", &synthetic_elf(None, &[], None));
        let config = read_write(library, spelling, false)
            .allow(&program, Operation::Exec, Scope::File)
            .unwrap();
        crate::floors::require_all(&config).unwrap();
        assert_eq!(config.warnings().len(), 1);
        let error = MountView::plan(&config).unwrap_err().to_string();
        assert!(error.contains("writable executable mount"), "{error}");
        assert!(error.contains(library.to_str().unwrap()), "{error}");
    });
}

#[test]
fn explicit_tree_execution_and_broad_execution_preserve_combined_loader_grants() {
    with_loader_directory(|_, library, spelling| {
        for write_first in [false, true] {
            let config = read_write(library, spelling, write_first);
            for explicit in [library, spelling] {
                let allowed = config
                    .clone()
                    .allow(explicit, Operation::Exec, Scope::Root)
                    .unwrap();
                crate::floors::require_all(&allowed).unwrap();
                assert_eq!(allowed.warnings().len(), 1);
                let view = MountView::plan(&allowed).unwrap();
                assert!(view.entries().iter().any(|entry| {
                    entry.source.as_deref() == Some(library) && entry.writable && entry.executable
                }));
            }
            let view = MountView::plan(&config.allow_broad_exec()).unwrap();
            assert!(view.entries().iter().any(|entry| {
                entry.source.as_deref() == Some(library) && entry.writable && entry.executable
            }));
        }
    });
}

#[test]
fn read_only_loader_access_and_unrelated_data_writes_keep_their_modes() {
    with_loader_directory(|root, library, spelling| {
        let data = root.join("data");
        std::fs::create_dir(&data).unwrap();
        let config = read_write(&data, &data, false)
            .allow(spelling, Operation::Read, Scope::Root)
            .unwrap();
        crate::floors::require_all(&config).unwrap();
        let view = MountView::plan(&config).unwrap();
        assert!(view.entries().iter().any(|entry| {
            entry.source.as_deref() == Some(library) && !entry.writable && entry.executable
        }));
        assert!(view.entries().iter().any(|entry| {
            entry.source.as_deref() == Some(data.as_path()) && entry.writable && !entry.executable
        }));
        assert!(!view.entries().iter().any(|entry| {
            matches!(
                entry.origin,
                MountOrigin::Library | MountOrigin::Interpreter
            )
        }));
    });
}
