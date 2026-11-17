use super::*;
use std::os::fd::{AsRawFd, IntoRawFd};

#[path = "../../../tests/support/signals.rs"]
mod signals;

fn request() -> Args {
    Args {
        config: "/containment-unit-absent-config".into(),
        config_fd: None,
        config_sha256: [0; 32],
        target_env_json: "{}".into(),
        setup_status_fd: None,
        relay_control_fd: None,
        launch_gate_fd: None,
        command: vec!["/containment-unit-absent-program".into()],
        argv0: None,
    }
}

fn in_child(expected_stderr: &str, body: impl FnOnce()) {
    const CHILD: &str = "BOX_UNIT_TRAMPOLINE_FAILURE_CHILD";
    let thread = std::thread::current();
    let name = thread.name().unwrap();
    if std::env::var(CHILD).as_deref() == Ok(name) {
        body();
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
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
            panic!(
                "isolated launcher test timed out: {:?}",
                child.wait_with_output().unwrap()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed; 0 ignored"),
        "{output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected_stderr),
        "{output:?}"
    );
    for text in [&output.stdout, &output.stderr] {
        for line in String::from_utf8_lossy(text)
            .lines()
            .filter(|line| line.contains("skipping:"))
        {
            eprintln!("{line}");
        }
    }
}

fn refuse_syscall(number: libc::c_long, argument: Option<(u8, u64)>) {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule,
    };
    let rules = argument
        .map(|(index, value)| {
            vec![
                SeccompRule::new(vec![
                    SeccompCondition::new(index, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, value)
                        .unwrap(),
                ])
                .unwrap(),
            ]
        })
        .unwrap_or_default();
    let filter = SeccompFilter::new(
        std::collections::BTreeMap::from([(number, rules)]),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EACCES as u32),
        std::env::consts::ARCH.try_into().unwrap(),
    )
    .unwrap();
    let program: BpfProgram = filter.try_into().unwrap();
    seccompiler::apply_filter(&program).unwrap();
}

#[test]
fn the_entry_point_reports_usage_errors_with_exit_code_two() {
    in_child("unknown flag \"--exact\"", || {
        // The child harness supplies --exact, which is not a launcher argument.
        assert_eq!(main(), ExitCode::from(2));
    });
}

#[test]
fn descriptor_sweep_closes_unpreserved_handles_when_proc_is_unavailable() {
    in_child("", || {
        let victim = std::fs::File::open("/dev/null").unwrap().into_raw_fd();
        let kept = std::fs::File::open("/dev/null").unwrap();
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        limit.rlim_cur = 64;
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        refuse_syscall(libc::SYS_openat, None);
        assert!(open_descriptors().is_none());
        close_inherited_descriptors(&[kept.as_raw_fd()]).unwrap();
        assert_eq!(unsafe { libc::fcntl(victim, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
        assert_ne!(unsafe { libc::fcntl(kept.as_raw_fd(), libc::F_GETFD) }, -1);
    });
}

#[test]
fn a_close_error_refuses_setup_before_configuration_loading() {
    in_child("cannot close inherited descriptors", || {
        let victim = std::fs::File::open("/dev/null").unwrap().into_raw_fd();
        refuse_syscall(libc::SYS_close, Some((0, victim as u64)));
        assert_eq!(
            close_ignoring_ebadf(victim).unwrap_err().raw_os_error(),
            Some(libc::EACCES)
        );
        assert_eq!(run(&request()), ExitCode::from(2));
    });
}

#[test]
fn failure_to_set_close_on_exec_refuses_the_status_channel() {
    in_child("cannot arm setup status channel", || {
        let file = std::fs::File::open("/dev/null").unwrap();
        refuse_syscall(libc::SYS_fcntl, Some((1, libc::F_SETFD as u64)));
        assert_eq!(
            SetupStatus::arm(Some(file.as_raw_fd()))
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        let mut args = request();
        args.setup_status_fd = Some(file.as_raw_fd());
        assert_eq!(run(&args), ExitCode::from(2));
    });
}

#[test]
fn launch_gate_refuses_a_closed_peer_and_a_failed_write_timeout() {
    in_child("", || {
        let (parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(parent);
        assert_eq!(
            wait_for_launch(child.into_raw_fd()).unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        let (_parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
        refuse_syscall(libc::SYS_setsockopt, Some((2, libc::SO_SNDTIMEO as u64)));
        assert_eq!(
            wait_for_launch(child.into_raw_fd())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
    });
}

#[test]
fn execution_enters_the_explicit_working_directory_before_attempting_exec() {
    in_child("exec ", || {
        let directory = tempfile::tempdir().unwrap();
        let mut args = request();
        args.target_env_json = serde_json::json!({"PWD": directory.path()}).to_string();
        assert_eq!(
            exec_command(&args, &SetupStatus::arm(None).unwrap()),
            ExitCode::from(4)
        );
        assert_eq!(std::env::current_dir().unwrap(), directory.path());
    });
}

#[test]
fn launch_acknowledgment_precedes_configuration_loading() {
    in_child("cannot read config file", || {
        use std::io::{Read, Write};
        let (mut parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
        parent.write_all(b"G").unwrap();
        let mut args = request();
        args.launch_gate_fd = Some(child.into_raw_fd());
        // Preserve the test peer through the close pass. No relay applies with a missing config.
        args.relay_control_fd = Some(parent.as_raw_fd());
        assert_eq!(run(&args), ExitCode::from(2));
        let mut ready = [0];
        parent.read_exact(&mut ready).unwrap();
        assert_eq!(ready, *b"R");
    });
}

#[test]
fn a_refused_launch_acknowledgment_prevents_configuration_loading() {
    in_child("parent refused launch", || {
        use std::io::{Read, Write};
        let (mut parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
        parent.write_all(b"X").unwrap();
        let mut args = request();
        args.launch_gate_fd = Some(child.into_raw_fd());
        args.relay_control_fd = Some(parent.as_raw_fd());
        assert_eq!(run(&args), ExitCode::from(2));
        let mut ready = [0];
        parent.read_exact(&mut ready).unwrap();
        assert_eq!(ready, *b"R");
    });
}

#[test]
fn interrupted_setup_reports_retry_and_deliver_the_stage_once() {
    in_child("", || {
        signals::interrupted_write(
            |descriptor| {
                SetupStatus::arm(Some(descriptor))
                    .unwrap()
                    .report(SetupStage::Exec);
            },
            SetupStage::Exec as u8,
        );
    });
}
