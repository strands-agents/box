//! Linux end-to-end proof that a contained workload can return to a saved working folder, and that
//! `fchdir` opens no way around folder permission or the inherited-handle cleanup.

#![cfg(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]

use std::ffi::OsStr;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::path::Path;
use std::process::{Command, Output};

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest as _, Sha256};

/// Go's `testing.T.Chdir` saves the working folder as an open descriptor and goes back to it with
/// `fchdir` when the test ends. A refused `fchdir` panics every Go test that changes folder.
#[test]
fn a_workload_returns_to_its_saved_folder_with_fchdir() {
    if !the_host_can_build_a_view() {
        println!("skipping: this host cannot build a namespace mount view");
        return;
    }
    let work_dir = tempfile::tempdir().expect("work directory");
    let output = launch_contained(
        work_dir.path(),
        [
            OsStr::new("--return-to-saved-folder"),
            work_dir.path().as_os_str(),
        ],
    );
    assert_success_with(&output, "RETURNED_TO_SAVED_FOLDER");
}

/// `fchdir` on a saved folder handle still checks search permission on that folder, so a handle
/// does not keep a way into a folder after its permission is removed.
#[test]
fn fchdir_into_a_saved_folder_still_checks_its_permission() {
    if !the_host_can_build_a_view() {
        println!("skipping: this host cannot build a namespace mount view");
        return;
    }
    let work_dir = tempfile::tempdir().expect("work directory");
    let output = launch_contained(
        work_dir.path(),
        [
            OsStr::new("--return-to-locked-folder"),
            work_dir.path().as_os_str(),
        ],
    );
    assert_success_with(&output, "LOCKED_FOLDER_REFUSED_ENTRY");
}

/// A folder handle the launcher inherits does not reach the workload, so `fchdir` cannot enter a
/// folder outside the grants through it.
#[test]
fn an_inherited_folder_handle_cannot_be_entered_with_fchdir() {
    if !the_host_can_build_a_view() {
        println!("skipping: this host cannot build a namespace mount view");
        return;
    }
    let outside = tempfile::tempdir().expect("folder outside the grants");
    let canary = outside.path().join("canary");
    std::fs::write(&canary, "outside").expect("write canary");
    let folder = std::fs::File::open(outside.path()).expect("open folder outside the grants");
    // SAFETY: `folder` is open, and `F_DUPFD` returns a new descriptor without close-on-exec.
    let raw = unsafe { libc::fcntl(folder.as_raw_fd(), libc::F_DUPFD, 900) };
    assert!(raw >= 900, "duplicate the folder handle at or above 900");
    // SAFETY: `F_DUPFD` returned a new descriptor that this value now owns.
    let inherited = unsafe { OwnedFd::from_raw_fd(raw) };
    let descriptor = inherited.as_raw_fd().to_string();
    let args = [
        OsStr::new("--enter-inherited-folder"),
        OsStr::new(&descriptor),
        canary.as_os_str(),
    ];

    let probe = Path::new(env!("CARGO_BIN_EXE_containment-test-probe"));
    let uncontained = Command::new(probe)
        .args(args)
        .output()
        .expect("launch the uncontained control");
    assert_success_with(&uncontained, "fchdir: ok\ncanary: ok\n");

    let work_dir = tempfile::tempdir().expect("work directory");
    let contained = launch_contained(work_dir.path(), args);
    assert_success_with(
        &contained,
        &format!("fchdir: {}\ncanary: {}\n", libc::EBADF, libc::ENOENT),
    );
    drop(inherited);
}

/// Run the probe with `probe_args` through the real trampoline, with read and write on `work_dir`.
fn launch_contained<'a>(
    work_dir: &Path,
    probe_args: impl IntoIterator<Item = &'a OsStr>,
) -> Output {
    let probe = Path::new(env!("CARGO_BIN_EXE_containment-test-probe"));
    let probe_dir = tempfile::tempdir().expect("probe directory");
    let staged_probe = probe_dir.path().join("containment-test-probe");
    std::fs::copy(probe, &staged_probe).expect("stage probe for the launch identity");
    let probe = staged_probe.as_path();
    let config = ContainmentConfig::new()
        .allow(probe, Operation::Read, Scope::File)
        .expect("read probe")
        .allow(probe, Operation::Exec, Scope::File)
        .expect("execute probe")
        .allow(work_dir, Operation::Read, Scope::Root)
        .expect("read working directory")
        .allow(work_dir, Operation::Write, Scope::Root)
        .expect("write working directory");
    let config_json = config.to_json().expect("config json");
    let config_sha256 = Sha256::digest(config_json.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let config_file = tempfile::NamedTempFile::new().expect("config file");
    std::fs::write(config_file.path(), config_json).expect("write config");

    Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"))
        .current_dir(work_dir)
        .arg("--config")
        .arg(config_file.path())
        .arg("--config-sha256")
        .arg(config_sha256)
        .arg("--target-env-json")
        .arg("{}")
        .arg("--")
        .arg(probe)
        .args(probe_args)
        .output()
        .expect("launch the real containment trampoline")
}

fn assert_success_with(output: &Output, expected: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains(expected),
        "expected {expected:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
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
