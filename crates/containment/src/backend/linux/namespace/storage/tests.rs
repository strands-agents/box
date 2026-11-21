//! Actual namespace launcher controls; these are not a standalone mount-tree simulation.
use super::super::{NamespaceBackend, failure_tests};
use super::*;
use crate::{Operation, Scope};
use std::os::unix::fs::PermissionsExt as _;
use std::time::Instant;

fn mount_tmpfs(path: &Path) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: this fixture runs inside an outer private mount namespace.
    assert_eq!(
        unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                path.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV,
                c"mode=0755,size=4m".as_ptr().cast(),
            )
        },
        0,
        "mount tmpfs: {}",
        std::io::Error::last_os_error()
    );
}

fn publish_marker(path: &Path, contents: impl AsRef<[u8]>) {
    // Each marker has one writer. Rename exposes its complete payload atomically to the reader.
    let pending = path.with_extension("pending");
    std::fs::write(&pending, contents).unwrap();
    std::fs::rename(pending, path).unwrap();
}

fn storage_helper_pidfd(launcher: libc::pid_t) -> OwnedFd {
    let children =
        std::fs::read_to_string(format!("/proc/{launcher}/task/{launcher}/children")).unwrap();
    let helpers = children
        .split_whitespace()
        .map(|pid| pid.parse::<libc::pid_t>().unwrap())
        .filter(|pid| {
            let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
            let effective = status
                .lines()
                .find(|line| line.starts_with("CapEff:"))
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            u64::from_str_radix(effective, 16).unwrap() == ((1 << 18) | (1 << 21))
        })
        .collect::<Vec<_>>();
    assert_eq!(helpers.len(), 1, "expected one initialized storage helper");
    // SAFETY: this initialized child is blocked on our private controller socket and unreaped.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, helpers[0], 0) };
    assert!(
        descriptor >= 0,
        "pidfd_open: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: pidfd_open returned a new descriptor owned by this fixture.
    unsafe { OwnedFd::from_raw_fd(descriptor as i32) }
}

fn wait_helper_exit(helper: &OwnedFd) {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut event = libc::pollfd {
        fd: helper.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "storage helper did not exit after controller EOF"
        );
        // SAFETY: event describes our live pidfd and remains valid throughout poll.
        let result = unsafe { libc::poll(&mut event, 1, remaining.as_millis() as i32) };
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        assert!(result > 0, "waiting for storage helper exit: {result}");
        assert_ne!(
            event.revents & libc::POLLIN,
            0,
            "helper pidfd events {}",
            event.revents
        );
        break;
    }
}

fn wait_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while !path.exists() {
        assert!(Instant::now() < deadline, "waiting for {}", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_child(child: libc::pid_t) {
    let mut status = 0;
    // SAFETY: this fixture owns the launcher child and waits for it exactly once.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status), "launcher status {status}");
    assert_eq!(libc::WEXITSTATUS(status), 0, "launcher status {status}");
}

fn exec_errno(path: &Path) -> i32 {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let argv = [path.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null()];
    // SAFETY: the fixture is deliberately not an executable image, so exec cannot replace us.
    unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn populate(root: &Path, public: &str) {
    std::fs::write(root.join("public"), public).unwrap();
    std::fs::write(root.join("secret"), "must remain hidden").unwrap();
    std::fs::set_permissions(root.join("public"), std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn assert_capability_zero(status: &str) {
    for field in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        let value = status
            .lines()
            .find(|line| line.starts_with(field))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        assert_eq!(u64::from_str_radix(value, 16).unwrap(), 0, "{field}");
    }
    assert!(
        status
            .lines()
            .any(|line| line.starts_with("NoNewPrivs:") && line.ends_with('1'))
    );
}

fn fixture(admit: bool, stale_plan: bool, ancestor_grant: bool) {
    // /mnt itself is a temporary filesystem only in this isolated process's namespace.
    mount_tmpfs(Path::new("/mnt"));
    assert_eq!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/mnt".as_ptr(),
                std::ptr::null(),
                libc::MS_SHARED,
                std::ptr::null(),
            )
        },
        0
    );
    let root = PathBuf::from("/mnt/storage");
    let output = PathBuf::from("/mnt/output");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&output).unwrap();
    populate(&root, "UNDERLAY-MUST-NOT-BE-READABLE");
    std::fs::write(root.join("underlay-marker"), "private initialization bytes").unwrap();
    let initial_read_root = if ancestor_grant {
        Path::new("/mnt")
    } else {
        root.as_path()
    };
    let initial = ContainmentConfig::new()
        .allow(initial_read_root, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&output, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&output, Operation::Write, Scope::Root)
        .unwrap();
    let (controller, helper) = UnixStream::pair().unwrap();
    controller
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    // SAFETY: the child enters the actual namespace backend and exits instead of returning to tests.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        drop(controller);
        let result = (|| {
            NamespaceBackend::with_probe_result(true).apply_with_storage(
                &initial,
                None,
                None,
                None,
                Some(Request {
                    root: root.clone(),
                    control: helper,
                    capture: CaptureMode::Manual,
                }),
                None,
            )?;
            assert_eq!(unsafe { libc::getpid() }, 2);
            let inherited = std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .map(|entry| {
                    entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .parse::<i32>()
                        .unwrap()
                })
                .filter(|fd| *fd > 2)
                .collect::<Vec<_>>();
            for fd in inherited {
                // The enumeration descriptor is closed after collection; no private handoff remains.
                assert_eq!(
                    unsafe { libc::fcntl(fd, libc::F_GETFD) },
                    -1,
                    "unexpected inherited fd {fd}"
                );
            }
            assert_capability_zero(&std::fs::read_to_string("/proc/self/status").unwrap());
            assert_capability_zero(&std::fs::read_to_string("/proc/1/status").unwrap());
            assert!(
                std::fs::read(root.join("public")).is_err(),
                "pending root exposed underlay bytes before startup completed"
            );
            assert!(
                std::fs::read_dir(&root).unwrap().next().is_none(),
                "pending root exposed underlay names"
            );
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut checks = 0;
            loop {
                assert!(Instant::now() < deadline, "workload waiting for admission");
                assert!(
                    std::fs::read(root.join("underlay-marker")).is_err(),
                    "initial underlay marker became visible"
                );
                let secret = std::fs::read(root.join("secret")).unwrap_or_default();
                assert!(
                    secret.is_empty(),
                    "unprotected denied bytes reached the workload"
                );
                let public = std::fs::read(root.join("public"));
                checks += 1;
                if checks == 1 {
                    publish_marker(&output.join("started"), b"contained");
                }
                if admit
                    && !stale_plan
                    && let Ok(ref bytes) = public
                {
                    assert_eq!(
                        bytes, b"captured source",
                        "source was reopened after approval"
                    );
                    assert!(
                        std::fs::OpenOptions::new()
                            .write(true)
                            .open(root.join("public"))
                            .is_err()
                    );
                    assert!(
                        std::fs::OpenOptions::new()
                            .create_new(true)
                            .write(true)
                            .open(root.join("new-file"))
                            .is_err()
                    );
                    assert_eq!(exec_errno(&root.join("public")), libc::EACCES);
                    assert_capability_zero(&std::fs::read_to_string("/proc/self/status").unwrap());
                    publish_marker(&output.join("passed"), checks.to_string());
                    wait_file(&output.join("controller-finished"));
                    break;
                } else if (!admit || stale_plan)
                    && checks > 1
                    && output.join("controller-finished").exists()
                {
                    assert!(
                        public.is_err(),
                        "raw source reached the workload without admission"
                    );
                    publish_marker(&output.join("passed"), checks.to_string());
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Ok::<_, ContainmentError>(())
        })();
        if let Err(ref error) = result {
            eprintln!("storage launcher fixture failed: {error}");
        }
        // SAFETY: the workload never returns to the test harness after containment.
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 20 }) };
    }
    drop(helper);
    wait_file(&output.join("started"));
    let query_status = std::fs::read_to_string(format!("/proc/{child}/status")).unwrap();
    for field in ["CapEff:", "CapPrm:"] {
        let value = query_status
            .lines()
            .find(|line| line.starts_with(field))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        assert_eq!(
            u64::from_str_radix(value, 16).unwrap(),
            1 << 19,
            "query supervisor {field}"
        );
    }
    mount_tmpfs(&root);
    populate(&root, "captured source");
    if admit {
        (&controller).write_all(b"C").unwrap();
        let observed = transport::receive_fd(&controller).unwrap();
        let observed_path = PathBuf::from(format!("/proc/self/fd/{}", observed.as_raw_fd()));
        assert_eq!(
            std::fs::read(observed_path.join("public")).unwrap(),
            b"captured source"
        );
        let approved = ContainmentConfig::new()
            .allow(&root, Operation::Read, Scope::Root)
            .unwrap()
            .refuse(root.join("secret"), Scope::File)
            .unwrap();
        let approved_json = approved.to_json().unwrap();
        // Deliberately replace the outer pathname after approval. The helper must use its retained
        // disconnected source, and the workload must never see this replacement's bytes.
        mount_tmpfs(&root);
        populate(&root, "WRONG-REPLACEMENT");
        let approved_json = if stale_plan {
            ContainmentConfig::new()
                .allow(&root, Operation::Read, Scope::Root)
                .unwrap()
                .refuse(root.join("secret"), Scope::File)
                .unwrap()
                .to_json()
                .unwrap()
        } else {
            approved_json
        };
        transport::send_text(&controller, &approved_json).unwrap();
        let receipt: serde_json::Value =
            serde_json::from_str(&transport::receive_text(&controller, CONTROL_LIMIT).unwrap())
                .unwrap();
        if stale_plan {
            assert_eq!(receipt["status"], "failed", "{receipt}");
            publish_marker(&output.join("controller-finished"), b"rejected");
            wait_file(&output.join("passed"));
            wait_child(child);
            assert_eq!(
                unsafe { libc::umount2(c"/mnt".as_ptr(), libc::MNT_DETACH) },
                0
            );
            return;
        }
        assert_eq!(receipt["status"], "published", "{receipt}");
        let helper_status = receipt["helper_status"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        for field in ["CapEff:", "CapPrm:"] {
            let value = helper_status
                .lines()
                .find(|line| line.starts_with(field))
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            assert_eq!(
                u64::from_str_radix(value, 16).unwrap(),
                (1 << 18) | (1 << 21)
            );
        }
        for field in ["CapInh:", "CapBnd:", "CapAmb:"] {
            let value = helper_status
                .lines()
                .find(|line| line.starts_with(field))
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            assert_eq!(u64::from_str_radix(value, 16).unwrap(), 0);
        }
        assert!(
            helper_status
                .lines()
                .any(|line| line.starts_with("NoNewPrivs:") && line.ends_with('1'))
        );
        eprintln!("storage admission receipt: {receipt}");
        publish_marker(&output.join("controller-finished"), b"received");
    } else {
        let helper = storage_helper_pidfd(child);
        drop(controller);
        // Confirm actual helper exit after EOF before checking the workload's retained mask.
        wait_helper_exit(&helper);
        publish_marker(&output.join("controller-finished"), b"closed");
    }
    wait_file(&output.join("passed"));
    assert!(
        std::fs::read_to_string(output.join("passed"))
            .unwrap()
            .parse::<usize>()
            .unwrap()
            > 1
    );
    wait_child(child);
    // SAFETY: detach only the private tmpfs this fixture mounted. No host mount is modified.
    assert_eq!(
        unsafe { libc::umount2(c"/mnt".as_ptr(), libc::MNT_DETACH) },
        0
    );
}

#[test]
fn real_launcher_admits_only_the_protected_retained_tree_after_startup() {
    failure_tests::in_fresh_process_with_user_namespace(true, || fixture(true, false, false));
}

#[test]
fn real_launcher_keeps_raw_storage_hidden_when_controller_disappears() {
    failure_tests::in_fresh_process_with_user_namespace(true, || fixture(false, false, false));
}

#[test]
fn real_launcher_rejects_a_plan_for_a_different_source_identity() {
    failure_tests::in_fresh_process_with_user_namespace(true, || fixture(true, true, false));
}

#[test]
fn real_launcher_masks_pending_underlay_reached_by_an_ancestor_grant() {
    failure_tests::in_fresh_process_with_user_namespace(true, || fixture(true, false, true));
}
