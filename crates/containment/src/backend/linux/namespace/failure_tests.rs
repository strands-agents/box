//! Real syscall failures, confined to a freshly executed unit-test process.

use super::*;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};
use std::collections::BTreeMap;

#[path = "../../../../tests/support/signals.rs"]
mod signals;

/// Re-execute exactly this test before applying irreversible restrictions.
pub(super) fn in_fresh_process(body: impl FnOnce()) {
    in_fresh_process_with_user_namespace(false, body);
}

pub(super) fn in_fresh_process_with_user_namespace(user_namespace: bool, body: impl FnOnce()) {
    in_fresh_process_expecting_exit(user_namespace, None, None, body);
}

fn namespace_command() -> std::process::Command {
    let mut command = std::process::Command::new("unshare");
    command.env("LC_ALL", "C").args([
        "--user",
        "--map-root-user",
        "--mount",
        "--net",
        "--ipc",
        "--uts",
        "--",
    ]);
    command
}

fn namespace_test_is_permitted() -> bool {
    // Creating a user namespace alone does not prove that this host permits ID mapping.
    // Probe the exact prerequisites without running any production code or test body.
    let output = namespace_command().arg("/bin/true").output().unwrap();
    if output.status.success() {
        return true;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let denied = output.status.code() == Some(1)
        && output.stdout.is_empty()
        && matches!(
            stderr.trim(),
            "unshare: unshare failed: Operation not permitted"
                | "unshare: write failed /proc/self/uid_map: Operation not permitted"
                | "unshare: write failed /proc/self/gid_map: Operation not permitted"
        );
    assert!(
        denied,
        "unexpected namespace prerequisite failure: {output:?}"
    );
    eprintln!(
        "skipping: namespace test prerequisite denied: {}",
        stderr.trim()
    );
    false
}

fn in_fresh_process_expecting_exit(
    user_namespace: bool,
    expected_exit: Option<i32>,
    expected_stderr: Option<&str>,
    body: impl FnOnce(),
) {
    const CHILD: &str = "BOX_UNIT_SYSCALL_FAILURE_CHILD";
    let thread = std::thread::current();
    let name = thread.name().expect("a named unit test");
    if std::env::var(CHILD).as_deref() == Ok(name) {
        if expected_exit.is_some() {
            eprintln!("entered expected-exit test body");
        }
        body();
        return;
    }
    if user_namespace && !namespace_test_is_permitted() {
        return;
    }
    let executable = std::env::current_exe().unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let mut command = if user_namespace {
        // util-linux enters the user namespace before the Rust harness creates threads.
        let mut command = namespace_command();
        command.arg(&executable);
        command
    } else {
        std::process::Command::new(&executable)
    };
    let mut child = command
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name)
        .env("TMPDIR", temporary.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("isolated test timed out: {output:?}");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    if let Some(expected) = expected_stderr {
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "missing {expected:?}: {output:?}"
        );
    }
    if let Some(code) = expected_exit {
        assert_eq!(output.status.code(), Some(code), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("entered expected-exit test body"),
            "the selected child test must reach its body: {output:?}"
        );
    } else {
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed; 0 ignored"),
            "the selected child test must actually run: {output:?}"
        );
    }
    for text in [&output.stdout, &output.stderr] {
        for line in String::from_utf8_lossy(text)
            .lines()
            .filter(|line| line.contains("skipping:"))
        {
            eprintln!("{line}");
        }
    }
}

/// Make one real kernel call return EACCES. The production error handling still runs.
pub(super) fn refuse_syscall(number: libc::c_long, argument: Option<(u8, u64)>) {
    let rules = match argument {
        None => Vec::new(),
        Some((index, value)) => vec![
            SeccompRule::new(vec![
                SeccompCondition::new(index, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, value)
                    .unwrap(),
            ])
            .unwrap(),
        ],
    };
    let filter = SeccompFilter::new(
        BTreeMap::from([(number, rules)]),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EACCES as u32),
        std::env::consts::ARCH.try_into().unwrap(),
    )
    .unwrap();
    let program: BpfProgram = filter.try_into().unwrap();
    seccompiler::apply_filter(&program).unwrap();
}

fn refusal_names(error: ContainmentError, expected: &str) {
    assert!(matches!(error, ContainmentError::ApplyFailed { .. }));
    assert!(error.to_string().contains(expected), "{error}");
}

#[test]
fn unreadable_descriptor_directory_refuses_launch() {
    in_fresh_process(|| {
        refuse_syscall(libc::SYS_openat, None);
        refusal_names(
            authority::close_inherited_descriptors(&[0, 1, 2]).unwrap_err(),
            "enumerating /proc/self/fd",
        );
    });
}

#[test]
fn failed_bounding_capability_drop_refuses_launch() {
    in_fresh_process(|| {
        refuse_syscall(libc::SYS_prctl, Some((0, libc::PR_CAPBSET_DROP as u64)));
        refusal_names(
            authority::drop_all_capabilities().unwrap_err(),
            "bounding set",
        );
    });
}

#[test]
fn failed_capability_clear_refuses_launch() {
    in_fresh_process_with_user_namespace(true, || {
        refuse_syscall(libc::SYS_capset, None);
        refusal_names(
            authority::drop_all_capabilities().unwrap_err(),
            "clearing the capability sets",
        );
    });
}

#[test]
fn failed_no_new_privileges_refuses_launch() {
    in_fresh_process(|| {
        refuse_syscall(libc::SYS_prctl, Some((0, libc::PR_SET_NO_NEW_PRIVS as u64)));
        refusal_names(
            authority::set_no_new_privileges().unwrap_err(),
            "setting no_new_privs",
        );
    });
}

#[test]
fn failed_loopback_control_socket_refuses_network_setup() {
    in_fresh_process(|| {
        refuse_syscall(libc::SYS_socket, None);
        refusal_names(
            netns::bring_up_loopback().unwrap_err(),
            "opening a control socket",
        );
    });
}

#[test]
fn failed_loopback_flag_read_refuses_network_setup() {
    in_fresh_process(|| {
        refuse_syscall(libc::SYS_ioctl, Some((1, libc::SIOCGIFFLAGS)));
        refusal_names(
            netns::bring_up_loopback().unwrap_err(),
            "reading loopback's interface flags",
        );
    });
}

#[test]
fn failed_loopback_flag_write_refuses_network_setup() {
    in_fresh_process(|| {
        refuse_syscall(libc::SYS_ioctl, Some((1, libc::SIOCSIFFLAGS)));
        refusal_names(
            netns::bring_up_loopback().unwrap_err(),
            "bringing loopback up",
        );
    });
}

#[test]
fn a_bound_loopback_port_cannot_be_silently_shared() {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    refusal_names(
        netns::listen_on_loopback(port).unwrap_err(),
        "binding 127.0.0.1",
    );
}

#[test]
fn failed_descriptor_transfer_refuses_network_setup() {
    in_fresh_process(|| {
        let (sender, _receiver) = std::os::unix::net::UnixStream::pair().unwrap();
        let descriptor = netns::listen_on_loopback(0).unwrap();
        refuse_syscall(libc::SYS_sendmsg, None);
        refusal_names(
            netns::send_descriptor(&sender, &descriptor).unwrap_err(),
            "passing the listening descriptor",
        );
    });
}

#[test]
fn denied_namespace_creation_changes_the_support_probe_result() {
    in_fresh_process(|| {
        refuse_syscall(libc::SYS_unshare, None);
        assert!(!probe::user_namespace_is_permitted());
        refusal_names(
            enter_namespaces(false).unwrap_err(),
            "creating a user namespace",
        );
    });
}

#[test]
fn namespace_setup_stops_at_each_failed_operation_in_both_network_modes() {
    for join_host_network in [false, true] {
        let remaining = libc::CLONE_NEWNS
            | libc::CLONE_NEWIPC
            | libc::CLONE_NEWUTS
            | if join_host_network {
                0
            } else {
                libc::CLONE_NEWNET
            };
        let expected = [
            format!("unshare {}", libc::CLONE_NEWUSER),
            "write /proc/self/setgroups deny".into(),
            "write /proc/self/uid_map 0 1234 1".into(),
            "write /proc/self/gid_map 0 5678 1".into(),
            format!("unshare {remaining}"),
        ];
        let failures = [
            "creating a user namespace",
            "denying setgroups",
            "writing the UID map",
            "writing the GID map",
            if join_host_network {
                "creating the mount, IPC, UTS namespaces"
            } else {
                "creating the mount, IPC, UTS, and network namespaces"
            },
        ];
        // Index 5 is the successful control. Every earlier index injects one I/O failure.
        for fail_at in 0..=5 {
            let calls = std::cell::RefCell::new(Vec::new());
            let record = |call: String| {
                let mut calls = calls.borrow_mut();
                calls.push(call);
                if calls.len() - 1 == fail_at {
                    Err(std::io::Error::from_raw_os_error(libc::EACCES))
                } else {
                    Ok(())
                }
            };
            let result = enter_namespaces_using(
                join_host_network,
                1234,
                5678,
                |flags| record(format!("unshare {flags}")),
                |path, value| record(format!("write {path} {value}")),
            );
            if fail_at < 5 {
                refusal_names(result.unwrap_err(), failures[fail_at]);
            } else {
                result.unwrap();
            }
            assert_eq!(*calls.borrow(), expected[..(fail_at + 1).min(5)]);
        }
    }
}

#[test]
fn failed_reaper_channel_refuses_setup_before_forking() {
    in_fresh_process(|| {
        let view = view::MountView::plan(&ContainmentConfig::new()).unwrap();
        refuse_syscall(libc::SYS_socketpair, None);
        refusal_names(
            establish_pid_namespace_and_reaper(&view, &[0, 1, 2], None).unwrap_err(),
            "creating reaper lifetime channel",
        );
    });
}

#[test]
fn failed_pid_namespace_refuses_setup_before_forking() {
    in_fresh_process(|| {
        let view = view::MountView::plan(&ContainmentConfig::new()).unwrap();
        refuse_syscall(libc::SYS_unshare, Some((0, libc::CLONE_NEWPID as u64)));
        refusal_names(
            establish_pid_namespace_and_reaper(&view, &[0, 1, 2], None).unwrap_err(),
            "creating a PID namespace",
        );
    });
}

#[test]
fn failed_filter_installation_refuses_launch() {
    in_fresh_process(|| {
        let filters = syscall::SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .unwrap();
        refuse_syscall(libc::SYS_prctl, Some((0, libc::PR_SET_NO_NEW_PRIVS as u64)));
        refusal_names(
            install_syscall_filters(&filters).unwrap_err(),
            "installing the namespace permit filter",
        );
    });
}

#[test]
fn a_failed_wait_is_not_reported_as_workload_success() {
    in_fresh_process(|| {
        refuse_syscall(libc::SYS_wait4, None);
        assert_eq!(reaper::supervise(12345), 125);
    });
}

#[test]
fn a_reaper_with_no_children_exits_successfully() {
    in_fresh_process(|| assert_eq!(reaper::supervise(12345), 0));
}

#[test]
fn a_failed_parent_death_arm_refuses_the_handshake() {
    in_fresh_process(|| {
        let (_parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
        refuse_syscall(libc::SYS_prctl, Some((0, libc::PR_SET_PDEATHSIG as u64)));
        assert!(!reaper::arm_parent_death(&child));
    });
}

#[test]
fn an_unavailable_child_status_makes_the_namespace_probe_refuse_support() {
    in_fresh_process(|| {
        // The kernel reaps the child automatically, so waitpid cannot collect its status.
        assert_ne!(
            unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) },
            libc::SIG_ERR
        );
        assert!(!probe::user_namespace_is_permitted());
    });
}

#[test]
fn a_signalled_probe_child_does_not_establish_namespace_support() {
    in_fresh_process(|| {
        let core_limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core_limit) },
            0
        );
        let filter = SeccompFilter::new(
            BTreeMap::from([(libc::SYS_unshare, Vec::new())]),
            SeccompAction::Allow,
            SeccompAction::KillProcess,
            std::env::consts::ARCH.try_into().unwrap(),
        )
        .unwrap();
        let program: BpfProgram = filter.try_into().unwrap();
        seccompiler::apply_filter(&program).unwrap();
        assert!(!probe::user_namespace_is_permitted());
    });
}

#[test]
fn a_failed_fork_does_not_establish_namespace_support() {
    in_fresh_process(|| {
        refuse_syscall(libc::SYS_clone, None);
        refuse_syscall(libc::SYS_clone3, None);
        #[cfg(target_arch = "x86_64")]
        refuse_syscall(libc::SYS_fork, None);
        assert!(!probe::user_namespace_is_permitted());
    });
}

#[test]
fn interrupted_lifetime_handshakes_retry_and_complete() {
    in_fresh_process(|| {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        let _signal = signals::arm();
        let (mut parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
        let descriptor = child.as_raw_fd();
        let (ready, started) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            ready
                .send(unsafe {
                    (
                        libc::syscall(libc::SYS_gettid) as libc::pid_t,
                        libc::pthread_self(),
                    )
                })
                .unwrap();
            reaper::confirm_parent_death(&child)
        });
        let (tid, thread) = started.recv().unwrap();
        signals::interrupt_blocked(tid, thread, libc::SYS_read, descriptor);
        parent.write_all(&[1]).unwrap();
        let mut acknowledgment = [0];
        parent.read_exact(&mut acknowledgment).unwrap();
        assert_eq!(acknowledgment, [1]);
        assert!(worker.join().unwrap());
    });
}

#[test]
fn interrupted_confirmation_writes_retry_and_deliver_once() {
    in_fresh_process(|| {
        signals::interrupted_write(
            |descriptor| write_confirm_byte(Some(descriptor), APPLY_FAILURE_BYTE),
            APPLY_FAILURE_BYTE,
        );
    });
}

#[test]
fn an_unwritable_confirmation_descriptor_does_not_retry_forever() {
    in_fresh_process(|| {
        use std::io::{Read, Write};
        use std::os::fd::{AsRawFd, FromRawFd};
        let mut ends = [0; 2];
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        let mut reader = unsafe { std::fs::File::from_raw_fd(ends[0]) };
        let mut writer = unsafe { std::fs::File::from_raw_fd(ends[1]) };
        write_confirm_byte(Some(reader.as_raw_fd()), APPLY_FAILURE_BYTE);
        writer.write_all(&[7]).unwrap();
        let mut observed = [0];
        reader.read_exact(&mut observed).unwrap();
        assert_eq!(observed, [7]);
    });
}

fn assert_reaper_wait_sequence(results: &[Result<libc::c_int, libc::c_int>], expected: i32) {
    let mut calls = 0;
    let code = reaper_exit_code(|status| {
        let result = results[calls];
        calls += 1;
        match result {
            Ok(value) => {
                *status = value;
                Ok(())
            }
            Err(error) => Err(std::io::Error::from_raw_os_error(error)),
        }
    });
    assert_eq!(calls, results.len());
    assert_eq!(code, expected);
}

#[test]
fn interrupted_reaper_waits_resume_until_a_normal_exit() {
    assert_reaper_wait_sequence(&[Err(libc::EINTR), Err(libc::EINTR), Ok(37 << 8)], 37);
}

#[test]
fn failed_reaper_waits_and_abnormal_exits_return_setup_failure() {
    for error in [libc::ECHILD, libc::EIO, libc::ESRCH] {
        assert_reaper_wait_sequence(&[Err(error)], 125);
    }
    assert_reaper_wait_sequence(&[Ok(libc::SIGKILL)], 125);
    for code in [0, 255] {
        assert_reaper_wait_sequence(&[Ok(code << 8)], code);
    }
}

#[test]
fn a_failed_second_filter_installation_reports_the_restriction_stage() {
    in_fresh_process(|| {
        let mut filters = syscall::SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .unwrap();
        filters.restrictions.clear();
        refusal_names(
            install_syscall_filters(&filters).unwrap_err(),
            "installing the namespace restriction filter",
        );
    });
}

#[test]
fn failed_reaper_creation_refuses_launch_before_any_child_starts() {
    in_fresh_process_with_user_namespace(true, || {
        let view = view::MountView::plan(&ContainmentConfig::new()).unwrap();
        refuse_syscall(libc::SYS_clone, None);
        refuse_syscall(libc::SYS_clone3, None);
        #[cfg(target_arch = "x86_64")]
        refuse_syscall(libc::SYS_fork, None);
        refusal_names(
            establish_pid_namespace_and_reaper(&view, &[0, 1, 2], None).unwrap_err(),
            "forking the namespace reaper",
        );
    });
}

#[test]
fn failed_reaper_handshake_terminates_the_launcher_before_materialization() {
    in_fresh_process_expecting_exit(true, Some(127), None, || {
        let view = view::MountView::plan(&ContainmentConfig::new()).unwrap();
        refuse_syscall(libc::SYS_sendto, Some((2, 1)));
        let _ = establish_pid_namespace_and_reaper(&view, &[0, 1, 2], None);
        unsafe { libc::_exit(98) };
    });
}

#[test]
fn failed_native_reaper_wait_reports_setup_failure() {
    in_fresh_process_expecting_exit(true, Some(125), None, || {
        let view = view::MountView::plan(&ContainmentConfig::new()).unwrap();
        refuse_syscall(libc::SYS_sendto, Some((2, 1)));
        refuse_syscall(libc::SYS_wait4, None);
        let _ = establish_pid_namespace_and_reaper(&view, &[0, 1, 2], None);
        unsafe { libc::_exit(98) };
    });
}

#[test]
fn a_descriptor_that_survives_cleanup_terminates_the_namespace_reaper() {
    use std::os::fd::AsRawFd as _;
    in_fresh_process_expecting_exit(
        true,
        Some(127),
        Some("namespace reaper could not close descriptors"),
        || {
            let victim = std::fs::File::open("/dev/null").unwrap();
            let view = view::MountView::plan(&ContainmentConfig::new()).unwrap();
            refuse_syscall(libc::SYS_close, Some((0, victim.as_raw_fd() as u64)));
            let _ = establish_pid_namespace_and_reaper(&view, &[0, 1, 2], None);
            unsafe { libc::_exit(98) };
        },
    );
}

#[test]
fn a_reaper_that_cannot_clear_capabilities_terminates_its_namespace() {
    in_fresh_process_expecting_exit(
        true,
        Some(127),
        Some("namespace reaper could not drop its own authority"),
        || {
            let view = view::MountView::plan(&ContainmentConfig::new()).unwrap();
            refuse_syscall(libc::SYS_capset, None);
            let _ = establish_pid_namespace_and_reaper(&view, &[0, 1, 2], None);
            unsafe { libc::_exit(98) };
        },
    );
}

#[test]
fn a_reaper_that_cannot_lock_privileges_terminates_its_namespace() {
    in_fresh_process_expecting_exit(
        true,
        Some(127),
        Some("namespace reaper could not drop its own authority"),
        || {
            let view = view::MountView::plan(&ContainmentConfig::new()).unwrap();
            refuse_syscall(libc::SYS_prctl, Some((0, libc::PR_SET_NO_NEW_PRIVS as u64)));
            let _ = establish_pid_namespace_and_reaper(&view, &[0, 1, 2], None);
            unsafe { libc::_exit(98) };
        },
    );
}

#[test]
fn a_failed_workload_fork_terminates_the_namespace_reaper() {
    in_fresh_process_expecting_exit(true, Some(126), None, || {
        let view = view::MountView::plan(&ContainmentConfig::new()).unwrap();
        let threads = std::fs::read_dir("/proc/self/task").unwrap().count();
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut limit) },
            0
        );
        // Leave room for the reaper, but not its workload, in this fresh user namespace.
        limit.rlim_cur = (threads + 1) as libc::rlim_t;
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &limit) }, 0);
        let _ = establish_pid_namespace_and_reaper(&view, &[0, 1, 2], None);
        unsafe { libc::_exit(98) };
    });
}

#[test]
fn a_configured_path_that_disappears_refuses_the_device_check() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("granted");
    std::fs::write(&path, b"fixture").unwrap();
    let config = ContainmentConfig::new()
        .allow(&path, Operation::Read, Scope::File)
        .unwrap();
    std::fs::rename(&path, directory.path().join("moved")).unwrap();
    refusal_names(
        require_no_configured_devices(&config).unwrap_err(),
        "reading configured path",
    );
}

#[test]
fn a_traced_child_stop_is_not_reported_as_a_successful_exit() {
    in_fresh_process(|| {
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // Only syscalls run in the forked child.
            unsafe {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                    libc::_exit(90);
                }
                if libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                ) == -1
                {
                    libc::_exit(91);
                }
                libc::raise(libc::SIGSTOP);
                libc::_exit(92);
            }
        }
        let code = reaper::supervise(child);
        if code == 91 {
            println!("skipping: this host refuses PTRACE_TRACEME");
            return;
        }
        // The stop did not reap the child. Terminate and collect it before asserting.
        unsafe { libc::kill(child, libc::SIGKILL) };
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(code, 125);
        assert!(libc::WIFSIGNALED(status));
    });
}
