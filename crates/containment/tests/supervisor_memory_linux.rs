//! Linux end-to-end proof for namespace supervisor memory isolation.

#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::Command;

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest as _, Sha256};

#[test]
fn workload_cannot_write_namespace_supervisor_memory() {
    if !the_host_can_build_a_view() {
        println!("skipping: this host cannot build a namespace mount view");
        return;
    }

    let probe = Path::new(env!("CARGO_BIN_EXE_containment-test-probe"));
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
        .arg("--attempt-supervisor-memory-write")
        .output()
        .expect("launch the real containment trampoline");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "supervisor memory proof failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("SUPERVISOR_MEMORY_DENIED"),
        "the probe did not observe EACCES for /proc/1/mem:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
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
