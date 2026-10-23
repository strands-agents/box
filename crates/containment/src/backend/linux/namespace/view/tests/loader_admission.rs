use super::*;

fn forked(case: impl FnOnce() -> bool) -> bool {
    super::forked(|| std::panic::catch_unwind(std::panic::AssertUnwindSafe(case)).unwrap_or(false))
}

fn mount_namespace_is_available() -> bool {
    let available = forked(enter_private_namespace);
    if !available {
        println!("skipping: this host refuses a private user/mount namespace with UID/GID mappings");
    }
    available
}

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, ContainmentConfig) {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let program = planted_image(&home, "project/bin/tool", &synthetic_elf(None, &[], None));
    let note = planted_image(&home, "notes/operator.txt", b"synthetic operator bytes\n");
    let config = ContainmentConfig::new()
        .allow(home.join("project"), Operation::Write, Scope::Root)
        .unwrap()
        .allow(&program, Operation::Exec, Scope::File)
        .unwrap()
        .anchored_at(&home);
    (directory, program, note, config)
}

fn refuses_ungranted(config: &ContainmentConfig, note: &Path) {
    crate::floors::require_all(config).unwrap();
    match MountView::plan(config) {
        Err(error) => {
            eprintln!("loader refusal: {error}");
            assert!(
                error.to_string().contains("no filesystem grant reaches"),
                "{error}"
            );
        }
        Ok(view) => {
            assert!(crate::backend::linux::namespace::probe::user_namespace_is_permitted());
            let expected = std::fs::read(note).unwrap();
            assert!(forked(|| {
                assert!(enter_private_namespace());
                let directory = tempfile::tempdir().unwrap();
                assert!(establish_every_entry(&view, directory.path()));
                let root = path_to_c(directory.path()).unwrap();
                // SAFETY: this child owns its namespace and enters the completed fixture view.
                unsafe {
                    assert_eq!(libc::chroot(root.as_ptr()), 0);
                    assert_eq!(libc::chdir(c"/".as_ptr()), 0);
                }
                match std::fs::read(note) {
                    Ok(observed) => {
                        eprintln!("UNGRANTED BYTES: {}: {:?}", note.display(), observed);
                        assert_eq!(observed, expected);
                    }
                    Err(error) => {
                        eprintln!("admitted dependency is unreadable in the view: {error}")
                    }
                }
                true
            }));
            panic!("dependency planning accepted an ungranted dependency");
        }
    }
}

#[test]
fn writable_image_cannot_name_an_ungranted_direct_dependency() {
    let (_directory, program, note, config) = fixture();
    assert_eq!(config.warnings().len(), 1);
    std::fs::write(
        &program,
        synthetic_elf(None, &[note.to_str().unwrap()], None),
    )
    .unwrap();
    refuses_ungranted(&config, &note);
}

#[test]
fn writable_image_cannot_search_an_ungranted_directory() {
    let (_directory, program, note, config) = fixture();
    std::fs::write(
        &program,
        synthetic_elf(None, &["operator.txt"], Some("$ORIGIN/../../notes")),
    )
    .unwrap();
    refuses_ungranted(&config, &note);
}

#[test]
fn writable_image_cannot_name_an_ungranted_interpreter() {
    let (_directory, program, note, config) = fixture();
    std::fs::write(
        &program,
        synthetic_elf(Some(note.to_str().unwrap()), &[], None),
    )
    .unwrap();
    refuses_ungranted(&config, &note);
}

#[test]
fn writable_dependency_cannot_extend_a_read_only_programs_reach() {
    let (_directory, program, note, config) = fixture();
    let library = planted_image(
        program.parent().unwrap(),
        "libbuilt.so",
        &synthetic_elf(None, &[note.to_str().unwrap()], None),
    );
    let launcher = planted_image(
        note.parent().unwrap(),
        "launcher",
        &synthetic_elf(None, &[library.to_str().unwrap()], None),
    );
    let config = config
        .allow(launcher, Operation::Exec, Scope::File)
        .unwrap();
    refuses_ungranted(&config, &note);
}

#[test]
fn a_read_only_program_cannot_import_a_writable_dependency_links_target() {
    let (_directory, program, note, config) = fixture();
    let library = program.parent().unwrap().join("libbuilt.so");
    std::os::unix::fs::symlink(&note, &library).unwrap();
    let launcher = planted_image(
        note.parent().unwrap(),
        "launcher",
        &synthetic_elf(None, &[library.to_str().unwrap()], None),
    );
    let config = config
        .allow(launcher, Operation::Exec, Scope::File)
        .unwrap();
    refuses_ungranted(&config, &note);
}

#[test]
fn a_writable_parent_in_a_dependency_link_chain_cannot_import_operator_bytes() {
    let (_directory, program, note, config) = fixture();
    let hop = program.parent().unwrap().join("hop");
    std::os::unix::fs::symlink(note.parent().unwrap(), &hop).unwrap();
    let outer = note.parent().unwrap().join("outer.so");
    std::os::unix::fs::symlink(hop.join("operator.txt"), &outer).unwrap();
    let launcher = planted_image(
        note.parent().unwrap(),
        "launcher",
        &synthetic_elf(None, &[outer.to_str().unwrap()], None),
    );
    let config = config
        .allow(launcher, Operation::Exec, Scope::File)
        .unwrap();
    refuses_ungranted(&config, &outer);
}

#[test]
fn writable_rpath_cannot_extend_a_read_only_dependency() {
    let (_directory, program, note, config) = fixture();
    let library = planted_image(
        note.parent().unwrap(),
        "libmiddle.so",
        &synthetic_elf(None, &["operator.txt"], None),
    );
    let config = config
        .allow(&library, Operation::Read, Scope::File)
        .unwrap();
    std::fs::write(
        &program,
        synthetic_elf_paths(
            None,
            &[library.to_str().unwrap()],
            None,
            Some(note.parent().unwrap().to_str().unwrap()),
        ),
    )
    .unwrap();
    refuses_ungranted(&config, &note);
}

#[test]
fn a_dependency_symlink_inside_a_write_grant_does_not_authorize_its_target() {
    let (_directory, program, note, config) = fixture();
    let link = program.parent().unwrap().join("libnote.so");
    std::os::unix::fs::symlink(&note, &link).unwrap();
    std::fs::write(
        &program,
        synthetic_elf(None, &[link.to_str().unwrap()], None),
    )
    .unwrap();
    refuses_ungranted(&config, &link);
}

#[test]
fn a_replaceable_image_parent_cannot_supply_ungranted_dependencies() {
    let (_directory, program, note, config) = fixture();
    let parent = program.parent().unwrap();
    let old = parent.with_extension("old");
    std::fs::rename(parent, &old).unwrap();
    std::fs::create_dir(parent).unwrap();
    std::fs::write(
        &program,
        synthetic_elf(None, &[note.to_str().unwrap()], None),
    )
    .unwrap();
    refuses_ungranted(&config, &note);
}

#[test]
fn metadata_and_directory_entries_do_not_authorize_dependency_bytes() {
    for (operation, scope) in [
        (Operation::Metadata, Scope::Root),
        (Operation::Read, Scope::Dir),
    ] {
        let (_directory, program, note, config) = fixture();
        let path = if scope == Scope::File {
            note.as_path()
        } else {
            note.parent().unwrap()
        };
        let config = config.allow(path, operation, scope).unwrap();
        std::fs::write(
            &program,
            synthetic_elf(None, &[note.to_str().unwrap()], None),
        )
        .unwrap();
        refuses_ungranted(&config, &note);
    }
}

#[test]
fn a_loader_directory_symlink_does_not_authorize_operator_bytes() {
    if !mount_namespace_is_available() {
        return;
    }
    assert!(forked(|| {
        assert!(enter_private_namespace());
        mount_syscall(
            Some(Path::new("tmpfs")),
            Path::new("/usr/lib"),
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV,
            None,
        )
        .unwrap();
        let (_directory, program, note, config) = fixture();
        let link = Path::new("/usr/lib/libbox_operator.so");
        std::os::unix::fs::symlink(&note, link).unwrap();
        std::fs::write(
            &program,
            synthetic_elf(None, &[link.to_str().unwrap()], None),
        )
        .unwrap();
        refuses_ungranted(&config, link);
        true
    }));
}

#[test]
fn stated_byte_grants_admit_dependency_bytes() {
    if !mount_namespace_is_available() {
        return;
    }
    for operation in [Operation::Read, Operation::Write, Operation::Exec] {
        for scope in [Scope::File, Scope::Root] {
            let (_directory, program, note, config) = fixture();
            let grant = if scope == Scope::Root {
                note.parent().unwrap()
            } else {
                &note
            };
            let config = config.allow(grant, operation, scope).unwrap();
            std::fs::write(
                &program,
                synthetic_elf(None, &[note.to_str().unwrap()], None),
            )
            .unwrap();
            let view = MountView::plan(&config).unwrap();
            assert!(forked(|| {
                assert!(enter_private_namespace());
                let root = tempfile::tempdir().unwrap();
                assert!(establish_every_entry(&view, root.path()));
                let inside = root.path().join(note.strip_prefix("/").unwrap());
                assert_eq!(
                    std::fs::read(inside).unwrap(),
                    std::fs::read(&note).unwrap()
                );
                true
            }));
        }
    }
}

#[test]
fn dependency_mounts_refuse_leaf_or_parent_replacement() {
    if !mount_namespace_is_available() {
        return;
    }
    for interpreter in [false, true] {
        for parent in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let home = directory.path().canonicalize().unwrap();
            let library = planted_image(&home, "deps/library", b"admitted dependency bytes");
            let note = planted_image(&home, "outside/library", b"ungranted operator bytes");
            let image = if interpreter {
                synthetic_elf(Some(library.to_str().unwrap()), &[], None)
            } else {
                synthetic_elf(None, &[library.to_str().unwrap()], None)
            };
            let program = planted_image(&home, "bin/program", &image);
            let config = ContainmentConfig::new()
                .allow(program, Operation::Exec, Scope::File)
                .unwrap();
            let view = MountView::plan(&config).unwrap();
            let (replaced, destination) = if parent {
                (library.parent().unwrap(), note.parent().unwrap())
            } else {
                (library.as_path(), note.as_path())
            };
            std::fs::rename(replaced, replaced.with_extension("saved")).unwrap();
            std::os::unix::fs::symlink(destination, replaced).unwrap();
            assert_eq!(
                std::fs::read(&library).unwrap(),
                b"ungranted operator bytes"
            );
            assert!(forked(|| {
                assert!(enter_private_namespace());
                let root = tempfile::tempdir().unwrap();
                let established = establish_every_entry(&view, root.path());
                let inside = root.path().join(library.strip_prefix("/").unwrap());
                !established && std::fs::read(inside).is_err()
            }));
            eprintln!(
                "pinned dependency: interpreter={interpreter}, parent={parent}, refused=1, leaked=0"
            );
        }
    }
}

#[test]
fn concurrent_dependency_replacement_never_changes_the_mounted_bytes() {
    if !mount_namespace_is_available() {
        return;
    }
    race_dependency_replacement(false);
    race_dependency_replacement(true);
}

fn race_dependency_replacement(parent: bool) {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixStream;

    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().canonicalize().unwrap();
    let library = planted_image(&home, "deps/library", b"admitted dependency bytes");
    let note = planted_image(&home, "outside/library", b"ungranted operator bytes");
    let program = planted_image(
        &home,
        "bin/program",
        &synthetic_elf(None, &[library.to_str().unwrap()], None),
    );
    let config = ContainmentConfig::new()
        .allow(program, Operation::Exec, Scope::File)
        .unwrap();
    let view = MountView::plan(&config).unwrap();
    let replacement = home.join("replacement");
    let (replaced, destination) = if parent {
        (library.parent().unwrap(), note.parent().unwrap())
    } else {
        (library.as_path(), note.as_path())
    };
    std::os::unix::fs::symlink(destination, &replacement).unwrap();
    // The replacement runs in a separate process so forked mount probes stay single-threaded.
    let (mut control, mut worker) = UnixStream::pair().unwrap();
    worker.set_nonblocking(true).unwrap();
    assert!(forked(|| {
        assert!(enter_private_namespace());
        let left = path_to_c(replaced).unwrap();
        let right = path_to_c(&replacement).unwrap();
        // SAFETY: the child only exchanges two fixture paths until the parent terminates it.
        let racer = unsafe { libc::fork() };
        assert!(racer >= 0);
        if racer == 0 {
            let mut swaps = 0u64;
            worker.write_all(b"R").unwrap();
            loop {
                let mut stop = [0];
                if worker.read(&mut stop).is_ok_and(|count| count == 1) {
                    worker.write_all(&swaps.to_le_bytes()).unwrap();
                    // SAFETY: the race child terminates without running the test harness.
                    unsafe { libc::_exit(0) };
                }
                // SAFETY: both names are live C strings and both paths belong to this fixture.
                let result = unsafe {
                    libc::syscall(
                        libc::SYS_renameat2,
                        libc::AT_FDCWD,
                        left.as_ptr(),
                        libc::AT_FDCWD,
                        right.as_ptr(),
                        libc::RENAME_EXCHANGE,
                    )
                };
                if result != 0 {
                    // SAFETY: the race child reports a fixture failure and terminates.
                    unsafe { libc::_exit(1) };
                }
                swaps += 1;
            }
        }
        let mut ready = [0];
        control.read_exact(&mut ready).unwrap();
        let mut admitted = 0;
        let mut refused = 0;
        let mut leaked = 0;
        for _ in 0..64 {
            let root = tempfile::tempdir().unwrap();
            let established = establish_every_entry(&view, root.path());
            let inside = root.path().join(library.strip_prefix("/").unwrap());
            match std::fs::read(inside) {
                Ok(bytes) if bytes == b"admitted dependency bytes" && established => admitted += 1,
                Err(_) if !established => refused += 1,
                _ => leaked += 1,
            }
        }
        control.write_all(b"S").unwrap();
        let mut swaps = [0; 8];
        control.read_exact(&mut swaps).unwrap();
        let swaps = u64::from_le_bytes(swaps);
        // SAFETY: racer is this process's child.
        unsafe {
            let mut status = 0;
            assert_eq!(libc::waitpid(racer, &mut status, 0), racer);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
        assert!(swaps > 0);
        eprintln!(
            "concurrent dependency replacement: parent={parent} swaps={swaps} attempts=64 admitted={admitted} refused={refused} leaked={leaked}"
        );
        assert_eq!(admitted + refused, 64);
        assert_eq!(leaked, 0);
        true
    }));
}
