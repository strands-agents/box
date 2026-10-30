//! Setup status from the real Linux trampoline.
#![cfg(all(target_os = "linux", target_arch = "aarch64"))]

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    Bounding,
    Capabilities,
    Privileges,
    Filter,
    KillFilter,
    StatusClose,
    Environment,
    Exec,
}

struct Run {
    child: Child,
    status: UnixStream,
    _directory: tempfile::TempDir,
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn inherit(fd: RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn start(fault: Fault, script: &str, gate: Option<RawFd>) -> Run {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    };
    let directory = tempfile::tempdir().unwrap();
    let shell = std::fs::canonicalize("/bin/sh").unwrap();
    let config = ContainmentConfig::new()
        .allow(&shell, Operation::Exec, Scope::File)
        .unwrap()
        .allow(&shell, Operation::Read, Scope::File)
        .unwrap();
    let json = config.to_json().unwrap();
    let config_path = directory.path().join("config.json");
    std::fs::write(&config_path, &json).unwrap();
    let digest = Sha256::digest(json.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let (status, writer) = UnixStream::pair().unwrap();
    status
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    let descriptor = writer.as_raw_fd();
    let syscall = match fault {
        Fault::Bounding => Some((libc::SYS_prctl, Some(libc::PR_CAPBSET_DROP))),
        Fault::Capabilities => Some((libc::SYS_capset, None)),
        Fault::Privileges => Some((libc::SYS_prctl, Some(libc::PR_SET_NO_NEW_PRIVS))),
        Fault::Filter | Fault::KillFilter => Some((libc::SYS_seccomp, None)),
        Fault::StatusClose => Some((libc::SYS_close, Some(descriptor))),
        _ => None,
    };
    let filter: Option<seccompiler::BpfProgram> = syscall.map(|(number, argument)| {
        let rules = argument
            .map(|value| {
                vec![
                    SeccompRule::new(vec![
                        SeccompCondition::new(
                            0,
                            SeccompCmpArgLen::Qword,
                            SeccompCmpOp::Eq,
                            value as u64,
                        )
                        .unwrap(),
                    ])
                    .unwrap(),
                ]
            })
            .unwrap_or_default();
        SeccompFilter::new(
            std::collections::BTreeMap::from([(number, rules)]),
            SeccompAction::Allow,
            if matches!(fault, Fault::KillFilter) {
                SeccompAction::KillProcess
            } else {
                SeccompAction::Errno(libc::EACCES as u32)
            },
            std::env::consts::ARCH.try_into().unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap()
    });
    let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"));
    command.args([
        "--config",
        config_path.to_str().unwrap(),
        "--config-sha256",
        &digest,
        "--target-env-json",
        if matches!(fault, Fault::Environment) {
            "{"
        } else {
            "{}"
        },
        "--setup-status-fd",
        &descriptor.to_string(),
    ]);
    if let Some(gate) = gate {
        command.args(["--launch-gate-fd", &gate.to_string()]);
    }
    command
        .arg("--")
        .arg(if matches!(fault, Fault::Exec) {
            "/setup-reporting-missing".as_ref()
        } else {
            shell.as_os_str()
        })
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            inherit(descriptor)?;
            if let Some(gate) = gate {
                inherit(gate)?;
            }
            if let Some(filter) = &filter {
                seccompiler::apply_filter(filter).map_err(std::io::Error::other)?;
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    drop(writer);
    Run {
        child,
        status,
        _directory: directory,
    }
}

fn finish(run: &mut Run) -> (std::process::ExitStatus, String, String) {
    let deadline = Instant::now() + Duration::from_secs(8);
    let exit = loop {
        if let Some(status) = run.child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "launcher did not exit");
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    run.child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    run.child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (exit, stdout, stderr)
}

fn check_failure(fault: Fault, expected: u8) {
    let mut run = start(fault, "printf WORKLOAD_RAN", None);
    let mut bytes = Vec::new();
    run.status.read_to_end(&mut bytes).unwrap();
    let (exit, stdout, stderr) = finish(&mut run);
    eprintln!("fault={fault:?} status={bytes:?} exit={exit} stderr={stderr:?}");
    assert!(stdout.is_empty(), "{fault:?}: workload ran: {stdout}");
    assert!(!exit.success());
    assert!(
        bytes.contains(&expected),
        "{fault:?}: expected stage {expected}, got {bytes:?}: {stderr}"
    );
    assert!(bytes.iter().all(|b| *b == expected || *b == 128 || *b == 6));
    if !matches!(fault, Fault::Exec) {
        assert!(!bytes.contains(&128), "premature completion: {fault:?}");
    }
}

#[test]
fn bounding_failure_reports_apply() {
    check_failure(Fault::Bounding, 3);
}
#[test]
fn capability_failure_reports_apply() {
    check_failure(Fault::Capabilities, 3);
}
#[test]
fn privilege_failure_reports_apply() {
    check_failure(Fault::Privileges, 3);
}
#[test]
fn filter_failure_reports_apply() {
    check_failure(Fault::Filter, 3);
}
#[test]
fn environment_failure_reports_decode() {
    check_failure(Fault::Environment, 4);
}
#[test]
fn executable_failure_reports_exec() {
    check_failure(Fault::Exec, 5);
}

#[test]
fn streaming_setup_finishes_before_workload_exit() {
    let mut run = start(
        Fault::None,
        "read value; printf '%s' \"$value\"; exit 5",
        None,
    );
    let mut bytes = Vec::new();
    run.status.read_to_end(&mut bytes).unwrap();
    bytes.sort_unstable();
    assert_eq!(bytes, [6, 128]);
    assert!(
        run.child.try_wait().unwrap().is_none(),
        "workload must still await stdin"
    );
    run.child
        .stdin
        .take()
        .unwrap()
        .write_all(b"STREAM_OK\n")
        .unwrap();
    let (exit, stdout, stderr) = finish(&mut run);
    assert_eq!(exit.code(), Some(5), "{stderr}");
    assert_eq!(stdout, "STREAM_OK");
}

#[test]
fn buffered_success_keeps_ordinary_workload_exit_codes() {
    for code in [0, 3, 4, 5, 42] {
        let mut run = start(Fault::None, &format!("printf BUFFER_OK; exit {code}"), None);
        let (exit, stdout, stderr) = finish(&mut run);
        let mut bytes = Vec::new();
        run.status.read_to_end(&mut bytes).unwrap();
        bytes.sort_unstable();
        assert_eq!(bytes, [6, 128], "{stderr}");
        assert_eq!(exit.code(), Some(code), "{stderr}");
        assert_eq!(stdout, "BUFFER_OK");
    }
}

#[test]
fn abrupt_launcher_death_has_no_setup_completion() {
    let (mut parent, gate) = UnixStream::pair().unwrap();
    parent
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    let mut run = start(Fault::None, "printf WORKLOAD_RAN", Some(gate.as_raw_fd()));
    drop(gate);
    let mut ready = [0];
    parent.read_exact(&mut ready).unwrap();
    assert_eq!(ready, *b"R");
    run.child.kill().unwrap();
    let mut bytes = Vec::new();
    run.status.read_to_end(&mut bytes).unwrap();
    let (exit, stdout, _) = finish(&mut run);
    assert!(!exit.success());
    assert!(bytes.is_empty());
    assert!(stdout.is_empty());
}

#[test]
fn abrupt_death_during_filter_installation_has_no_setup_completion() {
    let mut run = start(Fault::KillFilter, "printf WORKLOAD_RAN", None);
    let mut bytes = Vec::new();
    run.status.read_to_end(&mut bytes).unwrap();
    let (exit, stdout, _) = finish(&mut run);
    assert!(!exit.success());
    assert!(!bytes.contains(&128));
    assert!(bytes.iter().all(|b| *b == 6));
    assert!(stdout.is_empty());
}

#[test]
fn an_unclosed_supervisor_writer_reports_failure_without_waiting_for_workload_exit() {
    let mut run = start(Fault::StatusClose, "read value", None);
    let mut bytes = Vec::new();
    run.status.read_to_end(&mut bytes).unwrap();
    assert!(bytes.contains(&3), "{bytes:?}");
    let (exit, stdout, _) = finish(&mut run);
    assert!(!exit.success());
    assert!(stdout.is_empty());
}
