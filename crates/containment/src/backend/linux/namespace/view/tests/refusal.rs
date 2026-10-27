use super::*;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

const AUTHORITY: &str = "original authority\n";
const PLANTED: &str = "replacement authority\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Replacement {
    None,
    Ancestor,
    AncestorExisting,
    AncestorDirectory,
    Leaf,
    LeafDirectory,
    Missing,
    MissingAtPlan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Timing {
    BeforeAssembly,
    AfterOpen,
    Racing(u32),
}

fn refusal_case(replacement: Replacement) {
    let _ = run_case(replacement, Timing::BeforeAssembly, false);
}

fn run_case(replacement: Replacement, timing: Timing, file: bool) -> Option<bool> {
    if !super::super::super::failure_tests::namespace_test_is_permitted() {
        return None;
    }
    let host = tempfile::tempdir().unwrap();
    let work = host.path().join("work");
    let project = work.join("project");
    let refused = project.join("box-authority");
    let stash = host.path().join("stash");
    let root = host.path().join("view");
    let report_path = host.path().join("report");
    std::fs::create_dir_all(&project).unwrap();
    if !file {
        std::fs::create_dir(&refused).unwrap();
    }
    std::fs::create_dir(&stash).unwrap();
    std::fs::create_dir(&root).unwrap();
    let authority = if file {
        refused.clone()
    } else {
        refused.join("box.toml")
    };
    std::fs::write(&authority, AUTHORITY).unwrap();
    let mut original = std::fs::File::open(&authority).unwrap();
    std::fs::write(stash.join("outside-sentinel"), "unchanged").unwrap();
    if replacement == Replacement::AncestorExisting {
        std::fs::create_dir(stash.join("box-authority")).unwrap();
        std::fs::write(stash.join("box-authority/outside-sentinel"), "unchanged").unwrap();
    }
    let outside_before = outside_contents(&stash);
    if replacement == Replacement::MissingAtPlan {
        std::fs::rename(&refused, project.join("authority.hidden")).unwrap();
    }
    let config = ContainmentConfig::new()
        .allow(&work, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&work, Operation::Write, Scope::Root)
        .unwrap()
        .refuse(&refused, if file { Scope::File } else { Scope::Root })
        .unwrap();
    crate::floors::require_all(&config).unwrap();
    crate::backend::ContainmentBackend::validate_config(
        &crate::backend::linux::namespace::NamespaceBackend::with_probe_result(true),
        &config,
    )
    .unwrap();
    config.require_live_path_identities().unwrap();
    let view = MountView::plan(&config).unwrap();
    let in_view = root.join(refused.strip_prefix("/").unwrap());
    let (mut parent, mut child) = UnixStream::pair().unwrap();
    parent
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    child
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    // SAFETY: the child confines mounts to a private namespace and exits without unwinding.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        exit_child(|| {
            if !enter_private_namespace() {
                return Err("private namespace unavailable".into());
            }
            child.read_exact(&mut [0u8])?;
            if timing != Timing::BeforeAssembly {
                let mut ready = child.try_clone()?;
                targets::AFTER_OPEN.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        ready.write_all(&[1]).unwrap();
                        if timing == Timing::AfterOpen {
                            ready.read_exact(&mut [0u8]).unwrap();
                        }
                    }));
                });
                if matches!(timing, Timing::Racing(_)) {
                    let mut done = child.try_clone()?;
                    targets::AFTER_MOUNT.with(|hook| {
                        *hook.borrow_mut() = Some(Box::new(move || {
                            done.read_exact(&mut [0u8]).unwrap();
                        }));
                    });
                }
            }
            let mut report = String::new();
            let result = view
                .entries()
                .iter()
                .filter(|entry| entry.target != Path::new("/proc"))
                .try_for_each(|entry| view.establish(entry, &root));
            match result {
                Err(error) => report.push_str(&format!("REFUSED={error}\n")),
                Ok(()) => {
                    report.push_str("ESTABLISHED\n");
                    let contents = if file {
                        in_view.clone()
                    } else {
                        in_view.join("box.toml")
                    };
                    report.push_str(&format!("READ={:?}\n", std::fs::read_to_string(&contents)));
                    report.push_str(&format!(
                        "DIRECT_WRITE={:?}\n",
                        std::fs::write(&contents, PLANTED)
                    ));
                    report.push_str(&format!(
                        "REPLACE={:?}\n",
                        std::fs::remove_file(&in_view)
                            .and_then(|()| std::fs::create_dir(&in_view))
                            .and_then(|()| std::fs::write(in_view.join("box.toml"), PLANTED))
                    ));
                    report.push_str(&format!(
                        "EMPTY={}\n",
                        if file {
                            std::fs::read(&in_view)?.is_empty()
                        } else {
                            std::fs::read_dir(&in_view)?.next().is_none()
                        }
                    ));
                    let sibling = root.join(work.strip_prefix("/").unwrap()).join("sibling");
                    report.push_str(&format!("SIBLING={:?}\n", std::fs::write(sibling, "ok")));
                    let nested = root
                        .join(project.strip_prefix("/").unwrap())
                        .join("sibling");
                    report.push_str(&format!(
                        "NESTED_SIBLING={:?}\n",
                        std::fs::write(nested, "ok")
                    ));
                    let outside = root
                        .join(stash.strip_prefix("/").unwrap())
                        .join("outside-sentinel");
                    report.push_str(&format!("OUTSIDE_READ={:?}\n", std::fs::read(outside)));
                }
            }
            let mounts = std::fs::read_to_string("/proc/self/mounts")?;
            let outside_mounts = mounts
                .lines()
                .filter(|line| {
                    line.split_whitespace().nth(1).is_some_and(|raw| {
                        Path::new(&unescape_mount_field(raw)).starts_with(&stash)
                    })
                })
                .count();
            report.push_str(&format!("OUTSIDE_MOUNTS={outside_mounts}\n"));
            for line in mounts.lines().filter(|line| line.contains("box-authority")) {
                report.push_str(line);
                report.push('\n');
            }
            std::fs::write(&report_path, report)?;
            Ok(())
        });
    }
    drop(child);
    if timing != Timing::BeforeAssembly {
        parent.write_all(&[1]).unwrap();
        parent.read_exact(&mut [0u8]).unwrap();
    }
    if let Timing::Racing(exchanges) = timing {
        let attacked = if replacement == Replacement::Ancestor {
            &project
        } else {
            &refused
        };
        let alternate = work.join("alternate");
        std::os::unix::fs::symlink(&stash, &alternate).unwrap();
        let attacked_c = path_to_c(attacked).unwrap();
        let alternate_c = path_to_c(&alternate).unwrap();
        for _ in 0..exchanges {
            // SAFETY: both C strings remain live, and both paths name synthetic fixtures.
            assert_eq!(
                unsafe {
                    libc::syscall(
                        libc::SYS_renameat2,
                        libc::AT_FDCWD,
                        attacked_c.as_ptr(),
                        libc::AT_FDCWD,
                        alternate_c.as_ptr(),
                        libc::RENAME_EXCHANGE,
                    )
                },
                0
            );
        }
    } else {
        match replacement {
            Replacement::None | Replacement::MissingAtPlan => {}
            Replacement::Ancestor | Replacement::AncestorExisting => {
                std::fs::rename(&project, work.join("project.hidden")).unwrap();
                std::os::unix::fs::symlink(&stash, &project).unwrap();
            }
            Replacement::Leaf => {
                std::fs::rename(&refused, project.join("authority.hidden")).unwrap();
                std::os::unix::fs::symlink(&stash, &refused).unwrap();
            }
            Replacement::Missing => {
                std::fs::rename(&refused, project.join("authority.hidden")).unwrap();
            }
            Replacement::AncestorDirectory => {
                std::fs::rename(&project, work.join("project.hidden")).unwrap();
                std::fs::create_dir_all(&refused).unwrap();
            }
            Replacement::LeafDirectory => {
                std::fs::rename(&refused, project.join("authority.hidden")).unwrap();
                std::fs::create_dir(&refused).unwrap();
            }
        }
    }
    parent.write_all(&[1]).unwrap();
    let mut status = 0;
    // SAFETY: pid is the child created above.
    assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    let report = std::fs::read_to_string(report_path).unwrap();
    println!("{replacement:?} {timing:?} file={file}:\n{report}");
    let established = report.contains("ESTABLISHED");
    assert!(report.contains("OUTSIDE_MOUNTS=0"), "{report}");
    if replacement == Replacement::None || (matches!(timing, Timing::Racing(_)) && established) {
        assert!(report.contains("ESTABLISHED"), "{report}");
        assert!(report.contains("DIRECT_WRITE=Err"), "{report}");
        assert!(report.contains("REPLACE=Err"), "{report}");
        assert!(report.contains("EMPTY=true"), "{report}");
        assert!(report.contains("SIBLING=Ok"), "{report}");
        assert!(report.contains("NESTED_SIBLING=Ok"), "{report}");
        assert!(report.contains("OUTSIDE_READ=Err"), "{report}");
        assert!(
            report.contains(if file { "READ=Ok(\"\")" } else { "READ=Err" }),
            "{report}"
        );
    } else {
        assert!(report.contains("REFUSED="), "{report}");
        if matches!(
            replacement,
            Replacement::Missing | Replacement::MissingAtPlan
        ) {
            assert!(
                !refused.exists(),
                "created a mountpoint through a writable bind"
            );
        }
    }
    assert_eq!(
        outside_contents(&stash),
        outside_before,
        "outside host writes"
    );
    let mut original_bytes = String::new();
    original.read_to_string(&mut original_bytes).unwrap();
    assert_eq!(original_bytes, AUTHORITY, "original authority changed");
    Some(established)
}

fn exit_child(action: impl FnOnce() -> Result<(), Box<dyn std::error::Error>>) -> ! {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));
    if let Ok(Err(error)) = &result {
        eprintln!("{error}");
    }
    // SAFETY: the forked child must not return to the test harness or run parent destructors.
    unsafe { libc::_exit(i32::from(!matches!(result, Ok(Ok(()))))) }
}

#[test]
fn a_panicking_refusal_child_cannot_report_success() {
    // SAFETY: the child exits through exit_child without returning to the test harness.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        exit_child(|| panic!("intentional refusal-test child panic"));
    }
    let mut status = 0;
    // SAFETY: pid identifies the child created above.
    assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 1);
}

fn outside_contents(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            entries.push((path.clone(), Vec::new()));
            entries.extend(outside_contents(&path));
        } else {
            entries.push((path.clone(), std::fs::read(&path).unwrap()));
        }
    }
    entries.sort();
    entries
}

#[test]
fn a_refusal_nobody_touches_lands_empty_and_read_only_in_the_view() {
    refusal_case(Replacement::None);
}

#[test]
fn a_refusal_whose_path_was_re_pointed_creates_no_mountpoint_on_the_host() {
    refusal_case(Replacement::Ancestor);
}

#[test]
fn a_refusal_whose_mountpoint_was_re_pointed_still_lands_on_the_refused_tree() {
    refusal_case(Replacement::Leaf);
}

#[test]
fn a_refusal_missing_beneath_a_writable_bind_creates_nothing() {
    refusal_case(Replacement::Missing);
}

#[test]
fn a_refusal_absent_during_planning_creates_nothing_under_a_writable_bind() {
    refusal_case(Replacement::MissingAtPlan);
}

#[test]
fn an_existing_outside_directory_cannot_receive_a_redirected_refusal() {
    refusal_case(Replacement::AncestorExisting);
}

#[test]
fn replacing_an_ancestor_after_the_target_opens_refuses_startup() {
    let _ = run_case(Replacement::Ancestor, Timing::AfterOpen, false);
}

#[test]
fn replacing_a_leaf_after_the_target_opens_refuses_startup() {
    let _ = run_case(Replacement::Leaf, Timing::AfterOpen, false);
}

#[test]
fn replacing_opened_targets_with_real_directories_cannot_fool_mount_verification() {
    let _ = run_case(Replacement::AncestorDirectory, Timing::AfterOpen, false);
    let _ = run_case(Replacement::LeafDirectory, Timing::AfterOpen, false);
}

#[test]
fn file_refusals_reject_ancestor_and_leaf_replacement_before_and_after_open() {
    let _ = run_case(Replacement::None, Timing::BeforeAssembly, true);
    for replacement in [Replacement::Ancestor, Replacement::Leaf] {
        for timing in [Timing::BeforeAssembly, Timing::AfterOpen] {
            let _ = run_case(replacement, timing, true);
        }
    }
}

#[test]
fn concurrent_replacements_cannot_redirect_directory_or_file_refusals() {
    for file in [false, true] {
        for replacement in [Replacement::Ancestor, Replacement::Leaf] {
            let mut established = 0;
            let attempts = 32;
            for attempt in 0..attempts {
                let Some(denied) = run_case(replacement, Timing::Racing(32 + attempt % 2), file)
                else {
                    return;
                };
                established += u32::from(denied);
            }
            println!(
                "RACE_COUNTS file={file} replacement={replacement:?} attempts={attempts} denied_after_establish={established} startup_refused={} outside_writes=0 authority_changes=0",
                attempts - established
            );
        }
    }
}
