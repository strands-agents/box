//! Normal launcher controls for independently pending storage roots and receiver cleanup.

use super::super::{NamespaceBackend, failure_tests};
use crate::backend::ContainmentBackend as _;
use crate::storage::{ControllerCommand, HelperEvent, StorageLayout, StorageTarget, VERSION};
use crate::{ContainmentConfig, Operation, Scope};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(8);
const MOUNT_CAPABILITIES: u64 = (1 << 18) | (1 << 21);

fn mount_tmpfs(path: &Path) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: the outer fixture owns its private mount namespace and every named mountpoint.
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
    let temporary = path.with_extension("pending");
    std::fs::write(&temporary, contents).unwrap();
    std::fs::rename(temporary, path).unwrap();
}

fn wait_marker(path: &Path) {
    let deadline = Instant::now() + WAIT;
    while !path.exists() {
        assert!(Instant::now() < deadline, "waiting for {}", path.display());
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn capability(status: &str, field: &str) -> u64 {
    let value = status
        .lines()
        .find(|line| line.starts_with(field))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    u64::from_str_radix(value, 16).unwrap()
}

fn assert_capabilities(status: &str, expected: u64) {
    for field in ["CapPrm:", "CapEff:"] {
        assert_eq!(capability(status, field), expected, "{field}");
    }
    for field in ["CapInh:", "CapBnd:", "CapAmb:"] {
        assert_eq!(capability(status, field), 0, "{field}");
    }
    assert!(
        status
            .lines()
            .any(|line| line.starts_with("NoNewPrivs:") && line.ends_with('1'))
    );
}

fn assert_no_private_descriptors() {
    let descriptors = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .parse::<i32>()
                .unwrap()
        })
        .filter(|descriptor| *descriptor > 2)
        .collect::<Vec<_>>();
    for descriptor in descriptors {
        // SAFETY: F_GETFD observes a descriptor number; the enumeration descriptor is already closed.
        assert_eq!(
            unsafe { libc::fcntl(descriptor, libc::F_GETFD) },
            -1,
            "workload inherited private descriptor {descriptor}"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
    }
}

fn assert_pending(roots: &[PathBuf]) {
    for root in roots {
        assert!(
            std::fs::read(root.join("underlay")).is_err(),
            "pending source bytes became visible at {}",
            root.display()
        );
        assert!(
            std::fs::read_dir(root).unwrap().next().is_none(),
            "pending source names became visible at {}",
            root.display()
        );
        assert!(
            std::fs::write(root.join("new-file"), b"forbidden").is_err(),
            "pending source became writable at {}",
            root.display()
        );
    }
}

fn children_of(parent: libc::pid_t) -> Vec<libc::pid_t> {
    std::fs::read_to_string(format!("/proc/{parent}/task/{parent}/children"))
        .unwrap()
        .split_whitespace()
        .map(|value| value.parse().unwrap())
        .collect()
}

struct WatchedProcess {
    pid: libc::pid_t,
    descriptor: OwnedFd,
}

impl WatchedProcess {
    fn open(pid: libc::pid_t) -> Self {
        // SAFETY: this live process is an unreaped descendant owned by the fixture's launcher.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(
            descriptor >= 0,
            "pidfd_open {pid}: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: successful pidfd_open returned this newly owned descriptor.
        Self {
            pid,
            descriptor: unsafe { OwnedFd::from_raw_fd(descriptor as i32) },
        }
    }

    fn wait_exit(&self) {
        let deadline = Instant::now() + WAIT;
        let mut event = libc::pollfd {
            fd: self.descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "process {} did not exit", self.pid);
            // SAFETY: the event contains an owned pidfd and remains valid throughout poll.
            let ready = unsafe { libc::poll(&mut event, 1, remaining.as_millis() as i32) };
            if ready < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            assert!(
                ready > 0 && event.revents & libc::POLLIN != 0,
                "process {} exit wait: result {ready}, events {}",
                self.pid,
                event.revents
            );
            return;
        }
    }
}

struct Launcher(libc::pid_t);

impl Launcher {
    fn wait(&mut self) {
        let mut status = 0;
        // SAFETY: the fixture owns this unreaped launcher child.
        assert_eq!(unsafe { libc::waitpid(self.0, &mut status, 0) }, self.0);
        self.0 = 0;
        assert!(libc::WIFEXITED(status), "launcher status {status}");
        assert_eq!(libc::WEXITSTATUS(status), 0, "launcher status {status}");
    }
}

impl Drop for Launcher {
    fn drop(&mut self) {
        if self.0 > 0 {
            // SAFETY: this guard owns the unreaped child; its established parent-death chain stops descendants.
            unsafe { libc::kill(self.0, libc::SIGKILL) };
            loop {
                // SAFETY: wait only for the same owned launcher child.
                let result = unsafe { libc::waitpid(self.0, std::ptr::null_mut(), 0) };
                if result >= 0
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                {
                    break;
                }
            }
        }
    }
}

fn pending_receiver_processes(launcher: libc::pid_t) -> Vec<WatchedProcess> {
    let query = std::fs::read_to_string(format!("/proc/{launcher}/status")).unwrap();
    assert_capabilities(&query, 1 << 19);
    let receivers = children_of(launcher)
        .into_iter()
        .filter(|pid| {
            let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
            capability(&status, "CapEff:") == MOUNT_CAPABILITIES
        })
        .collect::<Vec<_>>();
    assert_eq!(
        receivers.len(),
        1,
        "one persistent receiver must own mount authority"
    );
    let receiver = receivers[0];
    assert_capabilities(
        &std::fs::read_to_string(format!("/proc/{receiver}/status")).unwrap(),
        MOUNT_CAPABILITIES,
    );
    let deadline = Instant::now() + WAIT;
    let workers = loop {
        let children = children_of(receiver);
        if children.len() == 2 {
            break children;
        }
        assert!(
            children.len() < 2 && Instant::now() < deadline,
            "receiver should retain one acquisition worker per pending root: {children:?}"
        );
        std::thread::sleep(Duration::from_millis(2));
    };
    let mut watched = vec![WatchedProcess::open(receiver)];
    for worker in workers {
        assert_capabilities(
            &std::fs::read_to_string(format!("/proc/{worker}/status")).unwrap(),
            MOUNT_CAPABILITIES,
        );
        watched.push(WatchedProcess::open(worker));
    }
    watched
}

fn layout(roots: Vec<PathBuf>) -> StorageLayout {
    let targets = roots
        .iter()
        .map(|root| StorageTarget {
            path: root.clone(),
            scope: Scope::Root,
        })
        .collect::<Vec<_>>();
    StorageLayout {
        version: VERSION,
        roots,
        masks: targets.clone(),
        targets,
    }
}

fn two_pending_roots(controller_disappears: bool) {
    mount_tmpfs(Path::new("/mnt"));
    // SAFETY: propagation changes are confined to this fixture's private tmpfs mount.
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
    let roots = vec![PathBuf::from("/mnt/first"), PathBuf::from("/mnt/second")];
    let output = PathBuf::from("/mnt/output");
    std::fs::create_dir(&output).unwrap();
    for root in &roots {
        std::fs::create_dir(root).unwrap();
        mount_tmpfs(root);
        std::fs::write(root.join("underlay"), b"INITIAL-BYTES-MUST-STAY-HIDDEN").unwrap();
    }
    let config = ContainmentConfig::new()
        .allow("/mnt", Operation::Read, Scope::Root)
        .unwrap()
        .allow(&output, Operation::Write, Scope::Root)
        .unwrap();
    let (controller, inherited) = UnixStream::pair().unwrap();
    controller.set_read_timeout(Some(WAIT)).unwrap();
    controller.set_write_timeout(Some(WAIT)).unwrap();
    // This bounded frame fits in the local socket before fork; only the child consumes it.
    crate::storage::send_command(
        &controller,
        &ControllerCommand::Initialize(layout(roots.clone())),
    )
    .unwrap();
    // SAFETY: the fresh isolated test forks a launcher child which exits instead of returning.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        drop(controller);
        let descriptor = inherited.into_raw_fd();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            NamespaceBackend::with_probe_result(true)
                .apply(&config, None, None, None, Some(descriptor))
                .unwrap();
            assert_eq!(unsafe { libc::getpid() }, 2);
            assert_no_private_descriptors();
            assert_capabilities(&std::fs::read_to_string("/proc/self/status").unwrap(), 0);
            assert_capabilities(&std::fs::read_to_string("/proc/1/status").unwrap(), 0);
            assert_pending(&roots);
            publish_marker(&output.join("started"), b"both sources remain pending");
            let deadline = Instant::now() + WAIT;
            let mut checks = 0;
            loop {
                assert!(
                    Instant::now() < deadline,
                    "workload did not receive fixture finish signal"
                );
                assert_pending(&roots);
                checks += 1;
                if output.join("finish").exists() {
                    publish_marker(&output.join("passed"), checks.to_string());
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }));
        // SAFETY: the contained child must never return to the test harness.
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 20 }) };
    }
    let mut launcher = Launcher(child);
    drop(inherited);
    let owner = crate::storage::receive_owner(&controller).unwrap();
    assert_ne!(
        unsafe { libc::fcntl(owner.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    assert_eq!(
        crate::storage::receive_event(&controller).unwrap(),
        HelperEvent::ViewReady
    );
    let view = crate::storage::receive_fd(&controller).unwrap();
    assert_ne!(
        unsafe { libc::fcntl(view.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    for root in &roots {
        let name = std::ffi::CString::new(
            root.strip_prefix("/")
                .unwrap()
                .as_os_str()
                .as_encoded_bytes(),
        )
        .unwrap();
        let descriptor = unsafe {
            libc::openat(
                view.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(
            descriptor >= 0,
            "the retained view root reaches its empty pending mask"
        );
        let held = unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor) };
        assert!(
            std::fs::read_dir(format!("/proc/self/fd/{}", held.as_raw_fd()))
                .unwrap()
                .next()
                .is_none(),
            "the parent must not read the nonempty ambient underlay through the view handle"
        );
    }
    wait_marker(&output.join("started"));
    let watched = pending_receiver_processes(child);
    if controller_disappears {
        drop(controller);
        for process in &watched {
            process.wait_exit();
        }
        publish_marker(
            &output.join("finish"),
            b"receiver exited after controller EOF",
        );
    } else {
        publish_marker(&output.join("finish"), b"normal workload completion");
        assert_eq!(
            crate::storage::receive_event(&controller).unwrap(),
            HelperEvent::Complete,
            "tmpfs placeholders must never emit a captured-source event"
        );
    }
    wait_marker(&output.join("passed"));
    assert!(
        std::fs::read_to_string(output.join("passed"))
            .unwrap()
            .parse::<usize>()
            .unwrap()
            > 0
    );
    launcher.wait();
    for process in watched {
        process.wait_exit();
    }
    for root in &roots {
        assert_eq!(
            std::fs::read(root.join("underlay")).unwrap(),
            b"INITIAL-BYTES-MUST-STAY-HIDDEN"
        );
        assert!(!root.join("new-file").exists());
    }
    // SAFETY: detach only the private fixture tmpfs after every launcher descendant has exited.
    assert_eq!(
        unsafe { libc::umount2(c"/mnt".as_ptr(), libc::MNT_DETACH) },
        0
    );
}

#[test]
fn normal_apply_starts_with_two_pending_roots_and_completes_after_workload_exit() {
    failure_tests::in_fresh_process_with_user_namespace(true, || two_pending_roots(false));
}

#[test]
fn normal_apply_keeps_both_pending_masks_after_the_controller_disappears() {
    failure_tests::in_fresh_process_with_user_namespace(true, || two_pending_roots(true));
}

#[test]
fn initialization_rejects_unmasked_overlapping_and_wrong_kind_destinations() {
    let initial = layout(vec![
        PathBuf::from("/storage/first"),
        PathBuf::from("/storage/second"),
    ]);
    initial.validate().unwrap();
    let mut invalid = initial.clone();
    invalid.masks.pop();
    assert!(invalid.validate().is_err());
    let mut invalid = initial.clone();
    invalid.roots[1] = invalid.roots[0].join("nested");
    assert!(invalid.validate().is_err());
    let mut invalid = initial.clone();
    invalid.targets[0].scope = Scope::File;
    assert!(invalid.validate().is_err());
    let mut invalid = initial.clone();
    invalid.targets[0].path = PathBuf::from("/unmasked/destination");
    assert!(invalid.validate().is_err());
    let mut invalid = initial.clone();
    invalid.masks[0].path = PathBuf::from("relative/path");
    assert!(invalid.validate().is_err());
    let mut invalid = initial;
    invalid.version += 1;
    assert!(invalid.validate().is_err());
}
