//! Linux end-to-end proof for no inherited handles.

#![cfg(target_os = "linux")]

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::path::Path;
use std::process::Command;

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest as _, Sha256};

fn duplicate_at_or_above(source: i32, minimum: i32) -> OwnedFd {
    // SAFETY: `source` is open, and `F_DUPFD` returns a new owned descriptor.
    let descriptor = unsafe { libc::fcntl(source, libc::F_DUPFD, minimum) };
    assert!(
        descriptor >= minimum,
        "duplicate descriptor at or above {minimum}"
    );
    // SAFETY: `F_DUPFD` returned a new descriptor that this value now owns.
    unsafe { OwnedFd::from_raw_fd(descriptor) }
}

#[test]
fn containment_and_reexec_remove_inherited_handles() {
    if !the_host_can_build_a_view() {
        println!("skipping: this host cannot build a namespace mount view");
        return;
    }

    let sentinel = tempfile::tempfile().expect("sentinel file");
    let ordinary = duplicate_at_or_above(sentinel.as_raw_fd(), 10);
    let high = duplicate_at_or_above(sentinel.as_raw_fd(), 900);

    for descriptor in [&ordinary, &high] {
        // SAFETY: clear close-on-exec on a descriptor that this test owns.
        assert_eq!(
            unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, 0) },
            0,
            "clear FD_CLOEXEC"
        );
    }

    let probe = Path::new(env!("CARGO_BIN_EXE_containment-test-probe"));
    let ordinary_arg = ordinary.as_raw_fd().to_string();
    let high_arg = high.as_raw_fd().to_string();
    let uncontained = Command::new(probe)
        .args([
            "--verify-no-inherited-handles",
            "initial",
            &ordinary_arg,
            &high_arg,
        ])
        .output()
        .expect("launch the uncontained negative control");
    let uncontained_stderr = String::from_utf8_lossy(&uncontained.stderr);
    assert_eq!(
        uncontained.status.code(),
        Some(1),
        "the negative control did not receive the planted descriptors:\n{uncontained_stderr}"
    );
    assert!(
        uncontained_stderr.contains(&format!(
            "descriptors remained readable during initial: [{}, {}]",
            ordinary.as_raw_fd(),
            high.as_raw_fd()
        )),
        "the negative control did not observe both planted descriptors:\n{uncontained_stderr}"
    );

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
        .arg("--")
        .arg(probe)
        .args([
            "--verify-no-inherited-handles",
            "initial",
            &ordinary_arg,
            &high_arg,
        ])
        .output()
        .expect("launch the real containment trampoline");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "descriptor proof failed:\n{stderr}"
    );
    assert!(
        stderr.contains("no inherited handles survived containment or re-exec"),
        "the probe did not complete its post-reexec check:\n{stderr}"
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
