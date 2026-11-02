//! Linux end-to-end proof for namespace supervisor memory isolation.

#![cfg(all(target_os = "linux", target_arch = "aarch64"))]

use std::path::Path;
use std::process::Command;

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest as _, Sha256};

#[test]
fn workload_cannot_write_namespace_supervisor_memory() {
    // SAFETY: capture the host identity before entering a user namespace.
    let launcher_uid = unsafe { libc::getuid() };
    let ptrace_scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope").ok();
    if !supervisor_memory_guard_is_conclusive(launcher_uid, ptrace_scope.as_deref()) {
        println!("skipping: root supervisor memory proof requires verified Yama ptrace_scope=0");
        return;
    }
    run_memory_probe(
        "--attempt-supervisor-memory-write",
        "SUPERVISOR_MEMORY_DENIED",
    );
}

#[test]
fn proc_mem_cannot_write_executable_memory() {
    run_memory_probe(
        "--attempt-executable-memory-write",
        "EXECUTABLE_MEMORY_DENIED",
    );
}

fn run_memory_probe(mode: &str, marker: &str) {
    if !the_host_can_build_a_view() {
        println!("skipping: this host cannot build a namespace mount view");
        return;
    }

    let probe = Path::new(env!("CARGO_BIN_EXE_containment-test-probe"));
    let probe_dir = tempfile::tempdir().expect("probe directory");
    let staged_probe = probe_dir.path().join("containment-test-probe");
    std::fs::copy(probe, &staged_probe).expect("stage probe for the launch identity");
    let probe = staged_probe.as_path();
    let work_dir = tempfile::tempdir().expect("work directory");
    let config = ContainmentConfig::new()
        .allow(probe, Operation::Read, Scope::File)
        .expect("read probe")
        .allow(probe, Operation::Exec, Scope::File)
        .expect("execute probe")
        .allow(work_dir.path(), Operation::Read, Scope::Root)
        .expect("read working directory")
        .allow(work_dir.path(), Operation::Write, Scope::Root)
        .expect("write working directory");
    let config_json = config.to_json().expect("config json");
    let config_sha256 = Sha256::digest(config_json.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let config_file = tempfile::NamedTempFile::new().expect("config file");
    std::fs::write(config_file.path(), config_json).expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"))
        .current_dir(work_dir.path())
        .arg("--config")
        .arg(config_file.path())
        .arg("--config-sha256")
        .arg(config_sha256)
        .arg("--target-env-json")
        .arg("{}")
        .arg("--")
        .arg(probe)
        .arg(mode)
        // SAFETY: capture the host identity before the trampoline enters its user namespace.
        .arg(unsafe { libc::getuid() }.to_string())
        .output()
        .expect("launch the real containment trampoline");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{mode} failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains(marker),
        "{mode} did not report {marker}:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

fn supervisor_memory_guard_is_conclusive(
    launcher_uid: libc::uid_t,
    ptrace_scope: Option<&str>,
) -> bool {
    launcher_uid != 0 || ptrace_scope.is_some_and(|scope| scope.trim() == "0")
}

#[test]
fn root_memory_proof_requires_a_verified_permissive_host() {
    for scope in [
        Some("0"),
        Some("0\n"),
        Some("1"),
        Some("2"),
        Some("3"),
        Some(""),
        None,
    ] {
        assert!(supervisor_memory_guard_is_conclusive(1000, scope));
        assert_eq!(
            supervisor_memory_guard_is_conclusive(0, scope),
            matches!(scope, Some("0" | "0\n")),
            "root prerequisite for {scope:?}"
        );
    }
}

fn the_host_can_build_a_view() -> bool {
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
