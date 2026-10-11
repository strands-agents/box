//! The seccomp notification path end to end: the trampoline hands the listener to its box side,
//! refusals still return EPERM, and nothing of the path survives into the workload.

#![cfg(target_os = "linux")]

use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use containment::refusal::{Handoff, Next, describe, receive_handoff};
use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest as _, Sha256};

const RELAY: i32 = 101;

struct Launch {
    command: Command,
    box_side: UnixStream,
    /// The child's end, held until `spawn` returns and then dropped, so the box side sees EOF
    /// once every process of the launch has closed it.
    child_side: Option<UnixStream>,
    _config: tempfile::NamedTempFile,
    _work: tempfile::TempDir,
}

/// A trampoline launch of the probe with `probe_args`, its relay-control descriptor at `RELAY`.
fn launch(probe_args: &[&str]) -> Launch {
    let probe = Path::new(env!("CARGO_BIN_EXE_containment-test-probe"));
    let work = tempfile::tempdir().expect("work directory");
    let config = ContainmentConfig::new()
        .allow(probe, Operation::Read, Scope::File)
        .expect("read probe")
        .allow(probe, Operation::Exec, Scope::File)
        .expect("exec probe")
        .allow(work.path(), Operation::Read, Scope::Root)
        .expect("read work")
        .to_json()
        .expect("config json");
    let digest = Sha256::digest(config.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let file = tempfile::NamedTempFile::new().expect("config file");
    std::fs::write(file.path(), &config).expect("write config");

    let (box_side, child_side) = UnixStream::pair().expect("relay pair");
    let child_fd = child_side.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"));
    command
        .current_dir(work.path())
        .arg("--config")
        .arg(file.path())
        .arg("--config-sha256")
        .arg(digest)
        .arg("--target-env-json")
        .arg("{}")
        .arg("--relay-control-fd")
        .arg(RELAY.to_string())
        .arg("--")
        .arg(probe)
        .args(probe_args);
    // SAFETY: dup2 and fcntl only, between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(child_fd, RELAY) < 0 || libc::fcntl(RELAY, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Launch {
        command,
        box_side,
        child_side: Some(child_side),
        _config: file,
        _work: work,
    }
}

/// The refusals the box side saw: syscall, decoded arguments, and pid.
type Seen = Vec<(String, Option<String>, u32)>;

/// Act as the box: take the handoff and answer every refusal until the launch ends.
fn serve(box_side: &UnixStream) -> (Option<i32>, Seen) {
    match receive_handoff(box_side).expect("handoff") {
        Handoff::Observed(listener) => {
            let mut seen = Vec::new();
            loop {
                match listener.next(Duration::from_millis(200)).expect("next") {
                    Next::Notification(n) => {
                        let d = describe(n.syscall, &n.args);
                        let valid = listener.still_valid(n.id);
                        listener.refuse(n.id).ok();
                        if valid {
                            seen.push((d.syscall, d.arguments, n.pid));
                        }
                    }
                    Next::Idle => continue,
                    Next::Ended => return (None, seen),
                }
            }
        }
        Handoff::Unobserved { errno } => (Some(errno), Vec::new()),
        Handoff::Absent => panic!("the workload never reached the install"),
    }
}

#[test]
fn a_refused_call_still_answers_eperm_and_reaches_the_listener() {
    if !host_can_build_a_view() {
        println!("skipping: no namespace view on this host");
        return;
    }
    let mut l = launch(&["--refused-calls"]);
    let child = l
        .command
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    drop(l.child_side.take());
    let served = std::thread::spawn({
        let s = l.box_side.try_clone().unwrap();
        move || serve(&s)
    });
    let output = child.wait_with_output().expect("wait");
    let (fallback, seen) = served.join().expect("serve");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        fallback, None,
        "the observed install must succeed on this host"
    );
    assert!(stdout.contains("socket rc=-1 errno=1"), "{stdout}");
    assert!(stdout.contains("bpf rc=-1 errno=1"), "{stdout}");
    assert!(
        seen.iter().any(
            |(s, a, _)| s == "socket" && a.as_deref() == Some("family=AF_PACKET type=SOCK_RAW")
        ),
        "{seen:?}"
    );
    assert!(
        seen.iter().any(|(s, a, _)| s == "bpf" && a.is_none()),
        "{seen:?}"
    );
    // K4: the pid is in this process's view, so its exe resolves to the probe while it is alive.
    // It has exited by now; a nonzero pid is what can be pinned here.
    assert!(seen.iter().all(|(_, _, pid)| *pid != 0), "{seen:?}");
}

/// **P1 and P5**: after `exec`, the workload holds neither the listener nor the relay socket.
#[test]
fn the_workload_holds_no_listener_and_no_relay_descriptor() {
    if !host_can_build_a_view() {
        println!("skipping: no namespace view on this host");
        return;
    }
    let relay = RELAY.to_string();
    let mut l = launch(&["--report-handles", &relay]);
    let child = l
        .command
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    drop(l.child_side.take());
    let served = std::thread::spawn({
        let s = l.box_side.try_clone().unwrap();
        move || serve(&s)
    });
    let output = child.wait_with_output().expect("wait");
    served.join().expect("serve");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("listeners=0 relay_open=false"), "{stdout}");
}

/// **K3**: once the box's listener is gone, a refused call answers ENOSYS — still a refusal.
#[test]
fn a_closed_listener_answers_enosys() {
    if !host_can_build_a_view() {
        println!("skipping: no namespace view on this host");
        return;
    }
    let mut l = launch(&["--refused-calls"]);
    let child = l
        .command
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    drop(l.child_side.take());
    match receive_handoff(&l.box_side).expect("handoff") {
        Handoff::Observed(listener) => drop(listener),
        other => panic!("expected the listener, got {other:?}"),
    }
    let stdout =
        String::from_utf8_lossy(&child.wait_with_output().expect("wait").stdout).to_string();
    assert!(stdout.contains("socket rc=-1 errno=38"), "{stdout}");
    assert!(stdout.contains("bpf rc=-1 errno=38"), "{stdout}");
}

/// Install `program` as an outer filter on the trampoline, before it runs, so the box's own filters
/// stack beneath it.
fn under_outer_filter(command: &mut Command, program: Vec<libc::sock_filter>) {
    // SAFETY: prctl and seccomp only, between fork and exec; `program` is moved into the closure.
    unsafe {
        command.pre_exec(move || {
            let fprog = libc::sock_fprog {
                len: program.len() as u16,
                filter: program.as_ptr().cast_mut(),
            };
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0, &fprog) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn statement(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

const LOAD_NR: u16 = 0x20;
const JEQ: u16 = 0x15;
const JSET: u16 = 0x45;
const RET: u16 = 0x06;

/// Run `probe_args` under `outer`, and return what the box side saw and the probe's two streams.
fn run_under(
    outer: Vec<libc::sock_filter>,
    probe_args: &[&str],
) -> (Option<i32>, Seen, String, String) {
    let mut l = launch(probe_args);
    under_outer_filter(&mut l.command, outer);
    let child = l
        .command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    drop(l.child_side.take());
    let (fallback, seen) = serve(&l.box_side);
    let output = child.wait_with_output().expect("wait");
    (
        fallback,
        seen,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// **Fallback**: when the kernel refuses the observed install (here EACCES from an outer filter on
/// `seccomp(…NEW_LISTENER…)`), the workload starts under the refusing pair, says so, and refusals
/// still answer EPERM.
#[test]
fn a_refused_observed_install_falls_back_to_the_refusing_filters() {
    if !host_can_build_a_view() {
        println!("skipping: no namespace view on this host");
        return;
    }
    let refuse_listener = vec![
        statement(LOAD_NR, 0),
        jump(JEQ, libc::SYS_seccomp as u32, 0, 3),
        statement(LOAD_NR, 24),
        jump(JSET, libc::SECCOMP_FILTER_FLAG_NEW_LISTENER as u32, 0, 1),
        statement(RET, libc::SECCOMP_RET_ERRNO | libc::EACCES as u32),
        statement(RET, libc::SECCOMP_RET_ALLOW),
    ];
    let (fallback, seen, stdout, stderr) = run_under(refuse_listener, &["--refused-calls"]);
    assert_eq!(fallback, Some(libc::EACCES));
    assert!(seen.is_empty());
    assert!(stdout.contains("socket rc=-1 errno=1"), "{stdout}");
    assert!(stdout.contains("bpf rc=-1 errno=1"), "{stdout}");
    assert!(
        stderr.contains("warning: seccomp refusals are not observed: EACCES"),
        "{stderr}"
    );
}

/// **Copy-check fallback**: when PID 1 cannot copy a descriptor out of the workload (here EACCES on
/// `pidfd_getfd`, as Yama scope 2 would give), it says so before the workload installs anything,
/// and the workload starts under the refusing pair with refusals still at EPERM.
#[test]
fn a_refused_listener_copy_falls_back_before_the_observed_install() {
    if !host_can_build_a_view() {
        println!("skipping: no namespace view on this host");
        return;
    }
    let refuse_copy = vec![
        statement(LOAD_NR, 0),
        jump(JEQ, libc::SYS_pidfd_getfd as u32, 0, 1),
        statement(RET, libc::SECCOMP_RET_ERRNO | libc::EACCES as u32),
        statement(RET, libc::SECCOMP_RET_ALLOW),
    ];
    let (fallback, seen, stdout, stderr) = run_under(refuse_copy, &["--refused-calls"]);
    assert_eq!(fallback, Some(libc::EACCES));
    assert!(seen.is_empty());
    assert!(stdout.contains("socket rc=-1 errno=1"), "{stdout}");
    assert!(stdout.contains("bpf rc=-1 errno=1"), "{stdout}");
    assert!(
        stderr.contains("warning: seccomp refusals are not observed: EACCES"),
        "{stderr}"
    );
}

fn host_can_build_a_view() -> bool {
    // SAFETY: the child uses syscalls only and calls `_exit`.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return true;
    }
    if child == 0 {
        // SAFETY: syscall-only child.
        unsafe {
            let namespaces = libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID;
            if libc::unshare(namespaces) != 0 {
                libc::_exit(10);
            }
            let inner = libc::fork();
            if inner < 0 {
                libc::_exit(12);
            }
            if inner == 0 {
                if libc::mount(
                    c"proc".as_ptr(),
                    c"/proc".as_ptr(),
                    c"proc".as_ptr(),
                    0,
                    std::ptr::null(),
                ) != 0
                {
                    libc::_exit(11);
                }
                libc::_exit(0);
            }
            let mut inner_status = 0;
            libc::waitpid(inner, &mut inner_status, 0);
            let mounted = libc::WIFEXITED(inner_status) && libc::WEXITSTATUS(inner_status) == 0;
            libc::_exit(if mounted { 0 } else { 11 });
        }
    }

    let mut status = 0;
    // SAFETY: wait for this process's child.
    unsafe { libc::waitpid(child, &mut status, 0) };
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

/// **Late failure fails closed**: once the observed filter is installed nothing can be stacked over
/// it, so when PID 1 cannot send the copied listener to the box (here EACCES on `sendmsg`, the
/// first send of a launch with no network), the apply is refused and the workload never runs.
#[test]
fn a_listener_that_cannot_reach_the_box_refuses_the_apply() {
    if !host_can_build_a_view() {
        println!("skipping: no namespace view on this host");
        return;
    }
    let refuse_send = vec![
        statement(LOAD_NR, 0),
        jump(JEQ, libc::SYS_sendmsg as u32, 0, 1),
        statement(RET, libc::SECCOMP_RET_ERRNO | libc::EACCES as u32),
        statement(RET, libc::SECCOMP_RET_ALLOW),
    ];
    let mut l = launch(&["--refused-calls"]);
    under_outer_filter(&mut l.command, refuse_send);
    let child = l
        .command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    drop(l.child_side.take());
    assert!(matches!(
        receive_handoff(&l.box_side).expect("handoff"),
        Handoff::Absent
    ));
    let output = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stdout}\n{stderr}");
    assert!(!stdout.contains("rc="), "the workload ran: {stdout}");
    assert!(
        stderr.contains("could not hand the seccomp listener to the box"),
        "{stderr}"
    );
}
