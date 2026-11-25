use super::*;
use crate::backend::linux::namespace::{authority, syscall};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

fn user_namespace() {
    // SAFETY: these syscalls run only in the isolated test child.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    assert_eq!(
        unsafe { libc::unshare(libc::CLONE_NEWUSER) },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
    std::fs::write("/proc/self/setgroups", "deny").unwrap();
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).unwrap();
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).unwrap();
}

fn isolated(action: impl FnOnce()) {
    // SAFETY: the child changes namespaces and exits without returning to the test harness.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        // SAFETY: bound this child's lifetime, including its namespace children.
        unsafe { libc::alarm(45) };
        let passed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            user_namespace();
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
            mount_syscall(
                None,
                Path::new("/"),
                None,
                libc::MS_REC | libc::MS_PRIVATE,
                None,
            )
            .unwrap();
            action();
        }))
        .is_ok();
        // SAFETY: the isolated child must not reenter the parent test harness.
        unsafe { libc::_exit(i32::from(!passed)) };
    }
    let mut status = 0;
    // SAFETY: child is the process created above.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "isolated test status {status}"
    );
}

struct Fixture {
    directory: tempfile::TempDir,
    selected: PathBuf,
    second: PathBuf,
    sibling: PathBuf,
    payload: PathBuf,
    nested: PathBuf,
    ordinary: PathBuf,
    grant_parent: bool,
    preexisting_nested: bool,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir_in("/var/tmp").unwrap();
        let root = directory.path();
        let selected = root.join("source/selected");
        let second = root.join("source/second");
        let sibling = root.join("source/sibling");
        let payload = root.join("payload");
        let nested = root.join("nested");
        let ordinary = root.join("ordinary");
        for path in [&selected, &second, &sibling, &payload, &nested, &ordinary] {
            std::fs::create_dir_all(path.join("nested")).unwrap();
            std::fs::create_dir(path.join("reverse")).unwrap();
        }
        std::fs::write(payload.join("value"), b"arrived").unwrap();
        std::fs::copy("/bin/true", payload.join("program")).unwrap();
        std::fs::write(nested.join("value"), b"nested").unwrap();
        std::fs::write(ordinary.join("value"), b"ordinary").unwrap();
        let source = root.join("source");
        mount_syscall(
            Some(&source),
            &source,
            None,
            libc::MS_BIND | libc::MS_REC,
            None,
        )
        .unwrap();
        mount_syscall(None, &source, None, libc::MS_SHARED, None).unwrap();
        for path in [&selected, &second] {
            mount_syscall(Some(path), path, None, libc::MS_BIND, None).unwrap();
            mount_syscall(None, path, None, libc::MS_PRIVATE, None).unwrap();
            mount_syscall(None, path, None, libc::MS_SHARED, None).unwrap();
        }
        Self {
            directory,
            selected,
            second,
            sibling,
            payload,
            nested,
            ordinary,
            grant_parent: false,
            preexisting_nested: false,
        }
    }

    fn config(&self) -> ContainmentConfig {
        let mut config = ContainmentConfig::new();
        let parent = self.directory.path().join("source");
        let roots = if self.grant_parent {
            vec![&parent]
        } else {
            vec![&self.selected, &self.second]
        };
        for path in roots {
            for operation in [Operation::Read, Operation::Write, Operation::Exec] {
                config = config.allow(path, operation, Scope::Root).unwrap();
            }
        }
        config
            .allow(&self.ordinary, Operation::Read, Scope::Root)
            .unwrap()
    }
}

struct Receiver {
    supervisor: libc::pid_t,
    workload: libc::pid_t,
}

impl Receiver {
    fn start(fixture: &Fixture, separate_user: bool, connected: bool, restricted: bool) -> Self {
        let (mut parent, mut child) = UnixStream::pair().unwrap();
        // SAFETY: the child creates its own namespaces and never returns to the harness.
        let supervisor = unsafe { libc::fork() };
        assert!(supervisor >= 0);
        if supervisor == 0 {
            // SAFETY: terminate the owned receiver when its isolated test parent exits.
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) },
                0
            );
            drop(parent);
            if separate_user {
                user_namespace();
            }
            assert_eq!(
                unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWPID) },
                0
            );
            // The host's /tmp may be full; this mount exists only in the test receiver.
            mount_syscall(
                Some(Path::new("tmpfs")),
                Path::new("/tmp"),
                Some("tmpfs"),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                Some("size=8m"),
            )
            .unwrap();
            let mut config = fixture.config();
            if connected {
                for path in [&fixture.selected, &fixture.second] {
                    let directory = File::open(path).unwrap();
                    config = config.receive_mounts_from(path, &directory).unwrap();
                }
            }
            let loaded = ContainmentConfig::from_json(&config.to_json().unwrap()).unwrap();
            // Loading has replaced every source pin with an identity-checked local handle,
            // as in the trampoline. Only the loaded configuration reaches the mount planner.
            drop(config);
            let view = MountView::plan(&loaded).unwrap();
            let (mut ready_parent, mut ready_child) = UnixStream::pair().unwrap();
            // SAFETY: entering the fresh PID namespace requires this child fork.
            let workload = unsafe { libc::fork() };
            assert!(workload >= 0);
            if workload == 0 {
                // SAFETY: terminate this namespace when its test supervisor exits.
                assert_eq!(
                    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) },
                    0
                );
                drop(ready_parent);
                let source_descriptors: Vec<i32> = std::fs::read_dir("/proc/self/fd")
                    .unwrap()
                    .filter_map(|entry| {
                        let entry = entry.unwrap();
                        let target = std::fs::read_link(entry.path()).ok()?;
                        (target == fixture.selected || target == fixture.second)
                            .then(|| entry.file_name().to_str().unwrap().parse().unwrap())
                    })
                    .collect();
                if connected {
                    assert!(
                        !source_descriptors.is_empty(),
                        "the connected plan holds source pins"
                    );
                }
                view.materialize().unwrap();
                for descriptor in source_descriptors {
                    // SAFETY: F_GETFD only inspects this descriptor number.
                    assert_eq!(
                        unsafe { libc::fcntl(descriptor, libc::F_GETFD) },
                        -1,
                        "source descriptor {descriptor} survived completed setup"
                    );
                    assert_eq!(
                        std::io::Error::last_os_error().raw_os_error(),
                        Some(libc::EBADF)
                    );
                }
                let reverse = fixture.selected.join("reverse");
                mount_syscall(
                    Some(Path::new("tmpfs")),
                    &reverse,
                    Some("tmpfs"),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    None,
                )
                .unwrap();
                std::fs::write(reverse.join("value"), b"receiver only").unwrap();
                authority::drop_all_capabilities().unwrap();
                authority::set_no_new_privileges().unwrap();
                let filters = syscall::SyscallPolicy::for_config(&crate::Network::Blocked)
                    .compile()
                    .unwrap();
                crate::backend::linux::namespace::install_syscall_filters(&filters).unwrap();
                let error =
                    mount_syscall(Some(Path::new("tmpfs")), &reverse, Some("tmpfs"), 0, None)
                        .unwrap_err();
                assert_eq!(error.raw_os_error(), Some(libc::EPERM));
                let status = std::fs::read_to_string("/proc/self/status").unwrap();
                for name in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
                    assert!(
                        status.lines().any(
                            |line| line.starts_with(name) && line.ends_with("0000000000000000")
                        ),
                        "{status}"
                    );
                }
                ready_child.write_all(b"r").unwrap();
                let mut resumed = [0];
                ready_child.read_exact(&mut resumed).unwrap();
                if connected {
                    assert_eq!(
                        std::fs::read(fixture.selected.join("value")).unwrap(),
                        b"arrived"
                    );
                    assert_eq!(
                        std::fs::read(fixture.selected.join("nested/value")).unwrap(),
                        b"nested"
                    );
                    assert_eq!(
                        std::fs::read(fixture.second.join("value")).unwrap(),
                        b"arrived"
                    );
                    if fixture.preexisting_nested {
                        assert_eq!(
                            std::fs::read(fixture.selected.join("nested/nested/value")).unwrap(),
                            b"grandchild"
                        );
                    }
                    let write = std::fs::OpenOptions::new()
                        .write(true)
                        .open(fixture.selected.join("value"));
                    if restricted {
                        assert_eq!(write.unwrap_err().raw_os_error(), Some(libc::EROFS));
                    } else {
                        write.unwrap();
                    }
                    let program = File::open(fixture.selected.join("program")).unwrap();
                    // SAFETY: map only this open fixture file, without executing its contents.
                    let mapped = unsafe {
                        libc::mmap(
                            std::ptr::null_mut(),
                            4096,
                            libc::PROT_READ | libc::PROT_EXEC,
                            libc::MAP_PRIVATE,
                            program.as_raw_fd(),
                            0,
                        )
                    };
                    if restricted {
                        assert_eq!(mapped, libc::MAP_FAILED);
                        assert_eq!(
                            std::io::Error::last_os_error().raw_os_error(),
                            Some(libc::EPERM)
                        );
                    } else {
                        assert_ne!(mapped, libc::MAP_FAILED);
                        assert_eq!(unsafe { libc::munmap(mapped, 4096) }, 0);
                    }
                } else {
                    assert!(!fixture.selected.join("value").exists());
                }
                assert!(!fixture.sibling.join("value").exists());
                if !fixture.grant_parent {
                    assert!(!fixture.sibling.exists());
                }
                assert_eq!(
                    std::fs::read(fixture.ordinary.join("value")).unwrap(),
                    b"ordinary"
                );
                assert_eq!(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(fixture.ordinary.join("value"))
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::EROFS)
                );
                unsafe { libc::_exit(0) };
            }
            drop(ready_child);
            let mut ready = [0];
            ready_parent.read_exact(&mut ready).unwrap();
            // SAFETY: the parent namespace may stop its owned namespace-init process.
            assert_eq!(unsafe { libc::kill(workload, libc::SIGSTOP) }, 0);
            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(workload, &mut status, libc::WUNTRACED) },
                workload
            );
            assert!(
                libc::WIFSTOPPED(status),
                "receiver failed before ready: {status}"
            );
            child.write_all(&workload.to_ne_bytes()).unwrap();
            assert_eq!(
                unsafe { libc::waitpid(workload, &mut status, libc::WCONTINUED) },
                workload
            );
            assert!(libc::WIFCONTINUED(status));
            ready_parent.write_all(b"g").unwrap();
            assert_eq!(unsafe { libc::waitpid(workload, &mut status, 0) }, workload);
            unsafe {
                libc::_exit(i32::from(
                    !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0,
                ))
            };
        }
        drop(child);
        let mut bytes = [0; 4];
        parent.read_exact(&mut bytes).unwrap();
        Self {
            supervisor,
            workload: i32::from_ne_bytes(bytes),
        }
    }

    fn path(&self, path: &Path) -> PathBuf {
        PathBuf::from(format!("/proc/{}/root", self.workload)).join(path.strip_prefix("/").unwrap())
    }

    fn stopped(&self) {
        let status = std::fs::read_to_string(format!("/proc/{}/status", self.workload)).unwrap();
        assert!(
            status
                .lines()
                .any(|line| line.starts_with("State:") && line.contains("T (stopped)")),
            "{status}"
        );
    }

    fn finish(mut self) {
        assert_eq!(unsafe { libc::kill(self.workload, libc::SIGCONT) }, 0);
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(self.supervisor, &mut status, 0) },
            self.supervisor
        );
        self.supervisor = 0;
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "receiver exit {status}"
        );
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        if self.supervisor != 0 {
            // SAFETY: terminate only the owned receiver; its PID-namespace children exit with it.
            unsafe {
                libc::kill(self.workload, libc::SIGKILL);
                libc::waitpid(self.supervisor, std::ptr::null_mut(), 0);
            }
        }
    }
}

fn arrival_case(restricted: bool, grant_parent: bool) {
    isolated(|| {
        let mut fixture = Fixture::new();
        fixture.grant_parent = grant_parent;
        let same = Receiver::start(&fixture, false, true, restricted);
        let separate = Receiver::start(&fixture, true, true, restricted);
        let private = Receiver::start(&fixture, false, false, restricted);
        if !restricted && !grant_parent {
            record_topology(
                "ready-before-arrival",
                &fixture,
                &[&same, &separate, &private],
            );
        }
        if restricted {
            mount_syscall(
                Some(&fixture.payload),
                &fixture.payload,
                None,
                libc::MS_BIND,
                None,
            )
            .unwrap();
            mount_syscall(
                None,
                &fixture.payload,
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
        }
        for receiver in [&same, &separate, &private] {
            receiver.stopped();
            assert_eq!(
                std::fs::read(receiver.path(&fixture.selected.join("reverse/value"))).unwrap(),
                b"receiver only"
            );
        }
        assert!(!fixture.selected.join("reverse/value").exists());
        for target in [&fixture.selected, &fixture.second, &fixture.sibling] {
            mount_syscall(
                Some(&fixture.payload),
                target,
                None,
                libc::MS_BIND | libc::MS_REC,
                None,
            )
            .unwrap();
            for receiver in [&same, &separate] {
                receiver.stopped();
                if target == &fixture.sibling {
                    assert!(!receiver.path(&target.join("value")).exists());
                } else {
                    assert_eq!(
                        std::fs::read(receiver.path(&target.join("value"))).unwrap(),
                        b"arrived"
                    );
                }
            }
        }
        mount_syscall(
            Some(&fixture.nested),
            &fixture.selected.join("nested"),
            None,
            libc::MS_BIND,
            None,
        )
        .unwrap();
        for receiver in [&same, &separate] {
            assert_eq!(
                std::fs::read(receiver.path(&fixture.selected.join("nested/value"))).unwrap(),
                b"nested"
            );
            receiver.stopped();
        }
        assert!(!private.path(&fixture.selected.join("value")).exists());
        if !restricted && !grant_parent {
            record_topology(
                "mount-returned-receivers-still-stopped",
                &fixture,
                &[&same, &separate, &private],
            );
        }
        same.finish();
        separate.finish();
        private.finish();
        assert!(fixture.directory.path().exists());
    });
}

#[test]
fn stopped_workloads_receive_root_and_nested_mounts_without_siblings_or_reverse_events() {
    arrival_case(false, false);
}

#[test]
fn incoming_read_only_and_noexec_mounts_keep_their_source_restrictions() {
    arrival_case(true, false);
}

fn identities(path: &Path) -> BTreeMap<PathBuf, ObjectIdentity> {
    [(
        path.to_path_buf(),
        ObjectIdentity::from_metadata(&std::fs::metadata(path).unwrap()),
    )]
    .into()
}

#[test]
fn a_private_publisher_is_refused_before_any_mount_is_exposed() {
    isolated(|| {
        let fixture = Fixture::new();
        mount_syscall(
            None,
            &fixture.directory.path().join("source"),
            None,
            libc::MS_PRIVATE | libc::MS_REC,
            None,
        )
        .unwrap();
        let error = capture(
            std::slice::from_ref(&fixture.selected),
            &identities(&fixture.selected),
        )
        .err()
        .unwrap();
        assert!(
            error.to_string().contains("no connected one-way upstream"),
            "{error}"
        );
    });
}

#[test]
fn missing_mount_authority_refuses_setup() {
    isolated(|| {
        let fixture = Fixture::new();
        let view = MountView::plan_receiving_mounts(
            &fixture.config(),
            std::slice::from_ref(&fixture.selected),
        )
        .unwrap();
        authority::drop_all_capabilities().unwrap();
        let error = view.materialize().unwrap_err();
        assert!(
            error.to_string().contains("Operation not permitted"),
            "{error}"
        );
    });
}

#[test]
fn configured_sources_use_approved_identity_under_a_covering_parent_grant() {
    isolated(|| {
        let mut fixture = Fixture::new();
        fixture.grant_parent = true;
        let directory = File::open(&fixture.selected).unwrap();
        let config = fixture
            .config()
            .receive_mounts_from(&fixture.selected, &directory)
            .unwrap();
        let restored = ContainmentConfig::from_json(&config.to_json().unwrap()).unwrap();
        let view = MountView::plan(&restored).unwrap();
        assert_eq!(view.incoming_mounts, vec![fixture.selected.clone()]);
        assert_eq!(
            view.grant_identities[&fixture.selected],
            ObjectIdentity::from_metadata(&directory.metadata().unwrap())
        );
        assert!(
            restored
                .authorizations()
                .iter()
                .all(|grant| grant.resolved != fixture.selected)
        );
        // A still-connected replacement under the same permitted parent cannot replace the
        // object Core approved. The parent grant's own identity remains unchanged.
        mount_syscall(
            Some(&fixture.payload),
            &fixture.selected,
            None,
            libc::MS_BIND,
            None,
        )
        .unwrap();
        mount_syscall(None, &fixture.selected, None, libc::MS_PRIVATE, None).unwrap();
        mount_syscall(None, &fixture.selected, None, libc::MS_SHARED, None).unwrap();
        let current = File::open(&fixture.selected).unwrap();
        require_connection(&current, false, &fixture.selected).unwrap();
        let error = MountView::plan(&restored).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed after its directory was approved"),
            "{error}"
        );
        let replacement = fixture
            .config()
            .receive_mounts_from(&fixture.selected, &current)
            .unwrap();
        MountView::plan(&replacement).unwrap();
    });
}

#[test]
fn ordinary_plans_leave_mount_receiving_disabled() {
    isolated(|| {
        let fixture = Fixture::new();
        assert!(
            MountView::plan(&fixture.config())
                .unwrap()
                .incoming_mounts
                .is_empty()
        );
        for operation in [Operation::Exec, Operation::Write] {
            let incomplete = ContainmentConfig::new()
                .allow(&fixture.selected, Operation::Read, Scope::Root)
                .unwrap()
                .allow(&fixture.selected, operation, Scope::Root)
                .unwrap();
            let error = MountView::plan_receiving_mounts(
                &incomplete,
                std::slice::from_ref(&fixture.selected),
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("unrestricted writable and executable directory grant"),
                "{error}"
            );
        }
        let nested = fixture.selected.join("nested");
        mount_syscall(Some(&nested), &nested, None, libc::MS_BIND, None).unwrap();
        mount_syscall(None, &nested, None, libc::MS_PRIVATE, None).unwrap();
        mount_syscall(None, &nested, None, libc::MS_SHARED, None).unwrap();
        MountView::plan_receiving_mounts(&fixture.config(), std::slice::from_ref(&nested)).unwrap();
        for paths in [
            [fixture.selected.clone(), nested.clone()],
            [nested.clone(), fixture.selected.clone()],
        ] {
            let error = MountView::plan_receiving_mounts(&fixture.config(), &paths).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("invalid or overlapping incoming mount path"),
                "{error}"
            );
        }
    });
}

#[test]
fn storage_already_mounted_read_only_and_noexec_keeps_its_permissions_at_startup() {
    for grant_parent in [false, true] {
        isolated(|| {
            let mut fixture = Fixture::new();
            fixture.grant_parent = grant_parent;
            mount_syscall(
                Some(&fixture.payload),
                &fixture.payload,
                None,
                libc::MS_BIND,
                None,
            )
            .unwrap();
            mount_syscall(
                None,
                &fixture.payload,
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
            for target in [&fixture.selected, &fixture.second] {
                mount_syscall(
                    Some(&fixture.payload),
                    target,
                    None,
                    libc::MS_BIND | libc::MS_REC,
                    None,
                )
                .unwrap();
            }
            let same = Receiver::start(&fixture, false, true, true);
            let separate = Receiver::start(&fixture, true, true, true);
            mount_syscall(
                Some(&fixture.nested),
                &fixture.selected.join("nested"),
                None,
                libc::MS_BIND,
                None,
            )
            .unwrap();
            for receiver in [&same, &separate] {
                receiver.stopped();
                assert_eq!(
                    std::fs::read(receiver.path(&fixture.selected.join("nested/value"))).unwrap(),
                    b"nested"
                );
            }
            same.finish();
            separate.finish();
        });
    }
}

// Each barrier stops setup at the named syscall interval. Root replacement before
// the identity check is an explicit startup refusal; it is not successful receipt.
#[test]
fn setup_time_arrivals_are_received_or_explicitly_refused_without_a_stale_view() {
    for separate_user in [false, true] {
        for root_arrival in [false, true] {
            for stage in [
                SetupStage::AfterCapture,
                SetupStage::BeforeBind,
                SetupStage::AfterBind,
                SetupStage::BeforePivot,
            ] {
                isolated(|| setup_arrival_case(stage, root_arrival, separate_user, false));
            }
        }
    }
}

fn setup_arrival_case(
    stage: SetupStage,
    root_arrival: bool,
    separate_user: bool,
    same_identity: bool,
) {
    let fixture = Fixture::new();
    let (mut publisher, mut receiver) = UnixStream::pair().unwrap();
    // SAFETY: the supervisor and namespace child are owned by this isolated test.
    let supervisor = unsafe { libc::fork() };
    assert!(supervisor >= 0);
    if supervisor == 0 {
        drop(publisher);
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) },
            0
        );
        if separate_user {
            user_namespace();
        }
        assert_eq!(
            unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWPID) },
            0
        );
        mount_syscall(
            Some(Path::new("tmpfs")),
            Path::new("/tmp"),
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            Some("size=8m"),
        )
        .unwrap();
        let view = MountView::plan_receiving_mounts(
            &fixture.config(),
            std::slice::from_ref(&fixture.selected),
        )
        .unwrap();
        let workload = unsafe { libc::fork() };
        assert!(workload >= 0);
        if workload == 0 {
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) },
                0
            );
            SETUP_BARRIER
                .with_borrow_mut(|barrier| *barrier = Some((stage, receiver.try_clone().unwrap())));
            let result = view.materialize();
            let expected_refusal = root_arrival && stage != SetupStage::BeforePivot;
            match result {
                Err(error) => {
                    assert!(expected_refusal, "unexpected refusal at {stage:?}: {error}");
                    assert!(error.to_string().contains("changed"), "{error}");
                    eprintln!(
                        "setup arrival {stage:?}, separate_user={separate_user}: root replacement refused: {error}"
                    );
                    receiver.write_all(b"r").unwrap();
                }
                Ok(()) => {
                    assert!(
                        !expected_refusal,
                        "expected root replacement refusal at {stage:?}"
                    );
                    assert_eq!(
                        std::fs::read(fixture.selected.join("nested/value")).unwrap(),
                        b"nested"
                    );
                    if root_arrival {
                        assert_eq!(
                            std::fs::read(fixture.selected.join("value")).unwrap(),
                            b"arrived"
                        );
                    }
                    eprintln!(
                        "setup arrival {stage:?}, separate_user={separate_user}: {} received",
                        if root_arrival {
                            "root and nested mounts"
                        } else {
                            "nested mount"
                        }
                    );
                    receiver.write_all(b"v").unwrap();
                }
            }
            unsafe { libc::_exit(0) };
        }
        drop(receiver);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(workload, &mut status, 0) }, workload);
        unsafe {
            libc::_exit(i32::from(
                !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0,
            ))
        };
    }
    drop(receiver);
    let mut message = [0];
    publisher.read_exact(&mut message).unwrap();
    assert_eq!(&message, b"b");
    if root_arrival {
        mount_syscall(
            Some(if same_identity {
                &fixture.selected
            } else {
                &fixture.payload
            }),
            &fixture.selected,
            None,
            libc::MS_BIND | libc::MS_REC,
            None,
        )
        .unwrap();
    }
    mount_syscall(
        Some(&fixture.nested),
        &fixture.selected.join("nested"),
        None,
        libc::MS_BIND,
        None,
    )
    .unwrap();
    publisher.write_all(b"g").unwrap();
    publisher.read_exact(&mut message).unwrap();
    assert_eq!(
        &message,
        if root_arrival && stage != SetupStage::BeforePivot {
            b"r"
        } else {
            b"v"
        }
    );
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(supervisor, &mut status, 0) },
        supervisor
    );
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "setup receiver exit {status}"
    );
}

#[test]
fn ordinary_siblings_stay_private_under_a_covering_directory_grant() {
    arrival_case(false, true);
}

fn record_topology(label: &str, fixture: &Fixture, receivers: &[&Receiver]) {
    for process in std::iter::once(unsafe { libc::getpid() })
        .chain(receivers.iter().map(|receiver| receiver.workload))
    {
        let table = std::fs::read_to_string(format!("/proc/{process}/mountinfo")).unwrap();
        eprintln!(
            "mount topology {label}, pid={process}:\n{}",
            table
                .lines()
                .filter(
                    |line| line.contains(fixture.directory.path().to_str().unwrap())
                        || line.split_whitespace().nth(4) == Some("/")
                )
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

#[test]
fn a_new_mount_with_the_same_directory_identity_still_refuses_the_pin_to_bind_race() {
    for separate_user in [false, true] {
        isolated(|| setup_arrival_case(SetupStage::BeforeBind, true, separate_user, true));
    }
}

#[test]
fn a_private_intermediate_mount_breaks_the_receiving_chain() {
    isolated(|| {
        let fixture = Fixture::new();
        mount_syscall(
            Some(&fixture.selected),
            &fixture.selected,
            None,
            libc::MS_BIND,
            None,
        )
        .unwrap();
        mount_syscall(None, &fixture.selected, None, libc::MS_PRIVATE, None).unwrap();
        let error = capture(
            std::slice::from_ref(&fixture.selected),
            &identities(&fixture.selected),
        )
        .err()
        .unwrap();
        assert!(
            error.to_string().contains("no connected one-way upstream"),
            "{error}"
        );
    });
}

#[test]
fn an_ordinary_directory_beneath_a_shared_ancestor_is_not_a_supported_source() {
    isolated(|| {
        let fixture = Fixture::new();
        let path = fixture.selected.join("nested");
        let error = capture(std::slice::from_ref(&path), &identities(&path))
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("dedicated mount point"),
            "{error}"
        );
    });
}

#[test]
fn existing_nested_receiving_mounts_keep_receiving_new_children_after_pivot() {
    isolated(|| {
        let mut fixture = Fixture::new();
        fixture.preexisting_nested = true;
        for path in [&fixture.selected, &fixture.second] {
            mount_syscall(
                Some(&fixture.payload),
                path,
                None,
                libc::MS_BIND | libc::MS_REC,
                None,
            )
            .unwrap();
        }
        mount_syscall(
            Some(&fixture.nested),
            &fixture.nested,
            None,
            libc::MS_BIND,
            None,
        )
        .unwrap();
        mount_syscall(None, &fixture.nested, None, libc::MS_SHARED, None).unwrap();
        mount_syscall(
            Some(&fixture.nested),
            &fixture.selected.join("nested"),
            None,
            libc::MS_BIND | libc::MS_REC,
            None,
        )
        .unwrap();
        mount_syscall(
            None,
            &fixture.selected.join("nested"),
            None,
            libc::MS_SLAVE | libc::MS_REC,
            None,
        )
        .unwrap();
        let same = Receiver::start(&fixture, false, true, false);
        let separate = Receiver::start(&fixture, true, true, false);
        record_topology(
            "existing-child-before-arrival",
            &fixture,
            &[&same, &separate],
        );
        let grandchild = fixture.directory.path().join("grandchild");
        std::fs::create_dir(&grandchild).unwrap();
        std::fs::write(grandchild.join("value"), b"grandchild").unwrap();
        mount_syscall(
            Some(&grandchild),
            &fixture.nested.join("nested"),
            None,
            libc::MS_BIND,
            None,
        )
        .unwrap();
        for receiver in [&same, &separate] {
            receiver.stopped();
            assert_eq!(
                std::fs::read(receiver.path(&fixture.selected.join("nested/nested/value")))
                    .unwrap(),
                b"grandchild"
            );
            assert!(
                !receiver
                    .path(&fixture.second.join("nested/nested/value"))
                    .exists()
            );
        }
        record_topology(
            "existing-child-grandchild-mount-returned",
            &fixture,
            &[&same, &separate],
        );
        same.finish();
        separate.finish();
    });
}

#[test]
fn final_checks_reject_outside_propagation_and_a_disconnected_selected_root() {
    isolated(|| {
        let fixture = Fixture::new();
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
            mount_syscall(
                None,
                Path::new("/"),
                None,
                libc::MS_SLAVE | libc::MS_REC,
                None,
            )
            .unwrap();
            let error = verify_final(std::slice::from_ref(&fixture.selected)).unwrap_err();
            assert!(
                error.to_string().contains("outside the selected"),
                "{error}"
            );
            mount_syscall(
                None,
                &fixture.selected,
                None,
                libc::MS_PRIVATE | libc::MS_REC,
                None,
            )
            .unwrap();
            let error = verify_final(std::slice::from_ref(&fixture.selected)).unwrap_err();
            assert!(
                error.to_string().contains("no connected one-way upstream"),
                "{error}"
            );
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "final validator child status {status}"
        );
    });
}

#[test]
fn a_failed_post_pivot_connection_or_isolation_check_refuses_materialization() {
    for outside in [false, true] {
        isolated(|| {
            let fixture = Fixture::new();
            let supervisor = unsafe { libc::fork() };
            assert!(supervisor >= 0);
            if supervisor == 0 {
                assert_eq!(
                    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) },
                    0
                );
                assert_eq!(
                    unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWPID) },
                    0
                );
                mount_syscall(
                    Some(Path::new("tmpfs")),
                    Path::new("/tmp"),
                    Some("tmpfs"),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    Some("size=8m"),
                )
                .unwrap();
                let view = MountView::plan_receiving_mounts(
                    &fixture.config(),
                    std::slice::from_ref(&fixture.selected),
                )
                .unwrap();
                let workload = unsafe { libc::fork() };
                assert!(workload >= 0);
                if workload == 0 {
                    assert_eq!(
                        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) },
                        0
                    );
                    let selected = fixture.selected.clone();
                    let ordinary = fixture.ordinary.clone();
                    AFTER_PIVOT_ACTION.with_borrow_mut(|action| {
                        *action = Some(Box::new(move || {
                            if outside {
                                mount_syscall(
                                    Some(&selected),
                                    &ordinary,
                                    None,
                                    libc::MS_BIND | libc::MS_REC,
                                    None,
                                )
                                .unwrap();
                            } else {
                                mount_syscall(
                                    None,
                                    &selected,
                                    None,
                                    libc::MS_PRIVATE | libc::MS_REC,
                                    None,
                                )
                                .unwrap();
                            }
                        }))
                    });
                    let error = view.materialize().unwrap_err();
                    assert!(
                        error.to_string().contains(if outside {
                            "outside the selected"
                        } else {
                            "no connected one-way upstream"
                        }),
                        "{error}"
                    );
                    unsafe { libc::_exit(0) };
                }
                let mut status = 0;
                assert_eq!(unsafe { libc::waitpid(workload, &mut status, 0) }, workload);
                unsafe {
                    libc::_exit(i32::from(
                        !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0,
                    ))
                };
            }
            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(supervisor, &mut status, 0) },
                supervisor
            );
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "post-pivot refusal child status {status}"
            );
        });
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum ChildMountCase {
    Bindable,
    StackedBindable,
    UnbindableAtCapture,
    UnbindableAtBind,
    UnbindableOnlyDuringBind,
    StackedUnbindableOnlyDuringBind,
}

#[test]
fn materialization_preserves_bindable_children_and_refuses_unbindable_omissions() {
    for separate_user in [false, true] {
        for case in [
            ChildMountCase::Bindable,
            ChildMountCase::StackedBindable,
            ChildMountCase::UnbindableAtCapture,
            ChildMountCase::UnbindableAtBind,
            ChildMountCase::UnbindableOnlyDuringBind,
            ChildMountCase::StackedUnbindableOnlyDuringBind,
        ] {
            isolated(|| child_mount_case(case, separate_user));
        }
    }
}

fn child_mount_case(case: ChildMountCase, separate_user: bool) {
    let fixture = Fixture::new();
    let child = fixture.selected.join("nested");
    std::fs::write(child.join("covered"), b"must stay covered").unwrap();
    mount_syscall(Some(&fixture.payload), &child, None, libc::MS_BIND, None).unwrap();
    mount_syscall(None, &child, None, libc::MS_PRIVATE, None).unwrap();
    mount_syscall(
        None,
        &child,
        None,
        libc::MS_BIND
            | libc::MS_REMOUNT
            | libc::MS_RDONLY
            | libc::MS_NOEXEC
            | libc::MS_NOSUID
            | libc::MS_NODEV,
        None,
    )
    .unwrap();
    if matches!(
        case,
        ChildMountCase::StackedBindable | ChildMountCase::StackedUnbindableOnlyDuringBind
    ) {
        // The visible top and covered lower mount have the same object and flags.
        // Counting only distinct path names would miss omission of the top mount.
        mount_syscall(Some(&child), &child, None, libc::MS_BIND, None).unwrap();
        mount_syscall(None, &child, None, libc::MS_PRIVATE, None).unwrap();
    }
    // The publisher keeps its connected source namespace alive throughout setup.
    let supervisor = unsafe { libc::fork() };
    assert!(supervisor >= 0);
    if supervisor == 0 {
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) },
            0
        );
        if separate_user {
            user_namespace();
        }
        assert_eq!(
            unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWPID) },
            0
        );
        mount_syscall(
            Some(Path::new("tmpfs")),
            Path::new("/tmp"),
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            Some("size=8m"),
        )
        .unwrap();
        // Prepare while the child is bindable so the refusal cases exercise materialize.
        let view = MountView::plan_receiving_mounts(
            &fixture.config(),
            std::slice::from_ref(&fixture.selected),
        )
        .unwrap();
        let workload = unsafe { libc::fork() };
        assert!(workload >= 0);
        if workload == 0 {
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) },
                0
            );
            if case == ChildMountCase::UnbindableAtCapture {
                mount_syscall(None, &child, None, libc::MS_UNBINDABLE, None).unwrap();
            }
            let changing_child = child.clone();
            SETUP_ACTION.with_borrow_mut(|action| {
                *action = Some(Box::new(move |stage| {
                    if stage == SetupStage::BeforeBind
                        && matches!(
                            case,
                            ChildMountCase::UnbindableAtBind
                                | ChildMountCase::UnbindableOnlyDuringBind
                                | ChildMountCase::StackedUnbindableOnlyDuringBind
                        )
                    {
                        mount_syscall(None, &changing_child, None, libc::MS_UNBINDABLE, None)
                            .unwrap();
                    }
                    if stage == SetupStage::AfterBind
                        && matches!(
                            case,
                            ChildMountCase::UnbindableOnlyDuringBind
                                | ChildMountCase::StackedUnbindableOnlyDuringBind
                        )
                    {
                        // A flag-only postcheck misses this omission: restore bindability after copy.
                        mount_syscall(None, &changing_child, None, libc::MS_PRIVATE, None).unwrap();
                    }
                }));
            });
            let result = view.materialize();
            if matches!(
                case,
                ChildMountCase::Bindable | ChildMountCase::StackedBindable
            ) {
                result.unwrap();
                assert_eq!(std::fs::read(child.join("value")).unwrap(), b"arrived");
                assert!(!child.join("covered").exists());
                assert_eq!(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(child.join("value"))
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::EROFS)
                );
                let program = File::open(child.join("program")).unwrap();
                // SAFETY: request a file mapping without executing any fixture bytes.
                assert_eq!(
                    unsafe {
                        libc::mmap(
                            std::ptr::null_mut(),
                            4096,
                            libc::PROT_READ | libc::PROT_EXEC,
                            libc::MAP_PRIVATE,
                            program.as_raw_fd(),
                            0,
                        )
                    },
                    libc::MAP_FAILED
                );
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EPERM)
                );
                let root = File::open(&fixture.selected).unwrap();
                require_connection(&root, true, &fixture.selected).unwrap();
                eprintln!(
                    "child copy {case:?}, separate_user={separate_user}: mounted contents retained, covered contents hidden, write EROFS, executable mapping EPERM"
                );
            } else {
                let error = result.expect_err("materialization exposed a pruned child mount");
                // A less privileged namespace cannot prune an inherited locked child;
                // the kernel rejects the bind before the copied-tree postcheck can run.
                let kernel_refusal = separate_user && case != ChildMountCase::UnbindableAtCapture;
                let reason = if kernel_refusal {
                    "attaching incoming mount"
                } else if matches!(
                    case,
                    ChildMountCase::UnbindableOnlyDuringBind
                        | ChildMountCase::StackedUnbindableOnlyDuringBind
                ) {
                    "did not preserve"
                } else {
                    "unbindable"
                };
                if kernel_refusal {
                    assert!(
                        error.to_string().contains("Operation not permitted"),
                        "{error}"
                    );
                }
                assert!(
                    error.to_string().contains(reason),
                    "wrong refusal for {case:?}: {error}"
                );
                eprintln!(
                    "child copy {case:?}, separate_user={separate_user}: startup refused: {error}"
                );
            }
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(workload, &mut status, 0) }, workload);
        unsafe {
            libc::_exit(i32::from(
                !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0,
            ))
        };
    }
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(supervisor, &mut status, 0) },
        supervisor
    );
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child copy {case:?}, separate_user={separate_user}: receiver status {status}"
    );
}

#[test]
fn ordinary_grants_outside_selected_subtrees_keep_requested_permissions() {
    for restriction in [0, libc::MS_RDONLY, libc::MS_NOEXEC] {
        for sibling in [false, true] {
            for selected in [false, true] {
                isolated(|| {
                    let mut fixture = Fixture::new();
                    fixture.grant_parent = true;
                    let ordinary = if sibling {
                        mount_syscall(
                            Some(&fixture.sibling),
                            &fixture.sibling,
                            None,
                            libc::MS_BIND,
                            None,
                        )
                        .unwrap();
                        fixture.sibling.clone()
                    } else {
                        fixture.directory.path().join("source")
                    };
                    std::fs::copy("/bin/true", ordinary.join("program")).unwrap();
                    mount_syscall(
                        None,
                        &ordinary,
                        None,
                        libc::MS_REMOUNT
                            | libc::MS_BIND
                            | restriction
                            | libc::MS_NOSUID
                            | libc::MS_NODEV,
                        None,
                    )
                    .unwrap();
                    // The new user namespace locks the publisher's mount restrictions,
                    // so an incompatible ordinary grant must refuse setup.
                    let supervisor = unsafe { libc::fork() };
                    assert!(supervisor >= 0);
                    if supervisor == 0 {
                        assert_eq!(
                            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) },
                            0
                        );
                        user_namespace();
                        assert_eq!(
                            unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWPID) },
                            0
                        );
                        mount_syscall(
                            Some(Path::new("tmpfs")),
                            Path::new("/tmp"),
                            Some("tmpfs"),
                            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                            Some("size=8m"),
                        )
                        .unwrap();
                        let paths = if selected {
                            vec![fixture.selected.clone()]
                        } else {
                            vec![]
                        };
                        let view =
                            MountView::plan_receiving_mounts(&fixture.config(), &paths).unwrap();
                        let workload = unsafe { libc::fork() };
                        assert!(workload >= 0);
                        if workload == 0 {
                            assert_eq!(
                                unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) },
                                0
                            );
                            let result = view.materialize();
                            if restriction == 0 {
                                result.unwrap();
                                std::fs::write(ordinary.join("probe"), b"writable").unwrap();
                                let program = File::open(ordinary.join("program")).unwrap();
                                // SAFETY: map the fixture without executing its contents.
                                let mapped = unsafe {
                                    libc::mmap(
                                        std::ptr::null_mut(),
                                        4096,
                                        libc::PROT_READ | libc::PROT_EXEC,
                                        libc::MAP_PRIVATE,
                                        program.as_raw_fd(),
                                        0,
                                    )
                                };
                                assert_ne!(
                                    mapped,
                                    libc::MAP_FAILED,
                                    "{}",
                                    std::io::Error::last_os_error()
                                );
                                assert_eq!(unsafe { libc::munmap(mapped, 4096) }, 0);
                                eprintln!(
                                    "ordinary grant sibling={sibling} selected={selected}: write and executable mapping succeed"
                                );
                            } else {
                                let error = result.expect_err(
                                    "an ordinary grant silently lost requested permissions",
                                );
                                assert!(error.to_string().contains("remounting"), "{error}");
                                assert!(
                                    error.to_string().contains("Operation not permitted"),
                                    "{error}"
                                );
                                eprintln!(
                                    "ordinary grant restriction={restriction} sibling={sibling} selected={selected}: startup refused: {error}"
                                );
                            }
                            unsafe { libc::_exit(0) };
                        }
                        let mut status = 0;
                        assert_eq!(unsafe { libc::waitpid(workload, &mut status, 0) }, workload);
                        unsafe {
                            libc::_exit(i32::from(
                                !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0,
                            ))
                        };
                    }
                    let mut status = 0;
                    assert_eq!(
                        unsafe { libc::waitpid(supervisor, &mut status, 0) },
                        supervisor
                    );
                    assert!(
                        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                        "ordinary grant restriction={restriction} sibling={sibling} selected={selected}: status={status}"
                    );
                });
            }
        }
    }
}

#[test]
fn kernel_mounts_with_empty_sources_and_unicode_paths_remain_usable() {
    isolated(|| {
        let directory = tempfile::tempdir_in("/var/tmp").unwrap();
        let point = directory.path().join("café\u{a0}data two words");
        std::fs::create_dir(&point).unwrap();
        mount_syscall(Some(Path::new("")), &point, Some("tmpfs"), 0, None).unwrap();
        mount_syscall(None, &point, None, libc::MS_SHARED, None).unwrap();
        let mounted = File::open(&point).unwrap();
        let identity = mountinfo::mount_id(&mounted).unwrap();
        let table = mountinfo::read().unwrap();
        assert!(
            table.lines().any(|line| {
                line.starts_with(&format!("{identity} ")) && line.contains(" - tmpfs  ")
            }),
            "the kernel did not produce an empty source column"
        );
        let rows = mountinfo::parse(&table).unwrap();
        assert!(
            rows.iter()
                .any(|row| row.identity == identity && row.point == point)
        );
        assert!(targets::mount_ids().unwrap().contains(&identity));
        require_connection(&mounted, false, &point).unwrap();
        std::fs::write(point.join("value"), b"writable").unwrap();
        remount_recursive(
            &targets::descriptor_path(&mounted),
            &point,
            libc::MS_REMOUNT
                | libc::MS_BIND
                | libc::MS_RDONLY
                | libc::MS_NOEXEC
                | libc::MS_NOSUID
                | libc::MS_NODEV,
            "for the empty-source regression",
        )
        .unwrap();
        assert_eq!(
            std::fs::write(point.join("value"), b"blocked")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EROFS)
        );
        eprintln!(
            "kernel empty source and Unicode mountpoint: identity, propagation, target inventory and read-only remount succeeded"
        );
    });
}
