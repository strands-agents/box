//! Linux x86_64 end-to-end proof that the permit filter closes the x86-64-only kernel surface.
//!
//! A refusal inside a box proves nothing alone, so the probe first runs without containment, and
//! every call this test expects the box to refuse must answer something other than `EPERM` there.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest as _, Sha256};

/// The calls the permit filter must refuse on x86_64.
const REFUSED: [&str; 5] = ["x32-open", "modify_ldt", "iopl", "ioperm", "uselib"];

/// Read the probe's `<label> rc <rc> errno <errno>` lines.
fn answers(stdout: &[u8]) -> BTreeMap<String, (i64, i32)> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(
            |line| match line.split(' ').collect::<Vec<_>>().as_slice() {
                [label, "rc", rc, "errno", errno] => {
                    Some((label.to_string(), (rc.parse().ok()?, errno.parse().ok()?)))
                }
                _ => None,
            },
        )
        .collect()
}

#[test]
fn the_x86_64_only_kernel_surface_is_refused_and_a_legacy_spelling_runs() {
    if !the_host_can_build_a_view() {
        println!("skipping: this host cannot build a namespace mount view");
        return;
    }

    let probe = Path::new(env!("CARGO_BIN_EXE_containment-test-probe"));
    let work_dir = tempfile::tempdir().expect("work directory");
    let readable = work_dir.path().join("readable");
    std::fs::write(&readable, "granted\n").expect("write the readable file");
    let readable_arg = readable.to_str().expect("the work directory is UTF-8");

    let uncontained = Command::new(probe)
        .args(["--x86-64-syscall-surface", readable_arg])
        .output()
        .expect("launch the uncontained control");
    assert!(
        uncontained.status.success(),
        "the uncontained control failed:\n{}",
        String::from_utf8_lossy(&uncontained.stderr)
    );
    let control = answers(&uncontained.stdout);
    for label in REFUSED {
        let (_, errno) = control
            .get(label)
            .unwrap_or_else(|| panic!("the uncontained control did not report '{label}'"));
        assert_ne!(
            *errno,
            libc::EPERM,
            "uncontained '{label}' already answers EPERM, so a refusal inside the box would prove nothing"
        );
    }

    let config = ContainmentConfig::new()
        .allow(probe, Operation::Read, Scope::File)
        .expect("read probe")
        .allow(probe, Operation::Exec, Scope::File)
        .expect("execute probe")
        .allow(work_dir.path(), Operation::Read, Scope::Root)
        .expect("read working directory");
    let config_json = config.to_json().expect("config json");
    let config_sha256 = Sha256::digest(config_json.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let config_file = tempfile::NamedTempFile::new().expect("config file");
    std::fs::write(config_file.path(), config_json).expect("write config");

    let contained = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"))
        .current_dir(work_dir.path())
        .arg("--config")
        .arg(config_file.path())
        .arg("--config-sha256")
        .arg(config_sha256)
        .arg("--target-env-json")
        .arg("{}")
        .arg("--")
        .arg(probe)
        .args(["--x86-64-syscall-surface", readable_arg])
        .output()
        .expect("launch the real containment trampoline");
    assert_eq!(
        contained.status.code(),
        Some(0),
        "the contained probe failed:\n{}",
        String::from_utf8_lossy(&contained.stderr)
    );
    let inside = answers(&contained.stdout);

    let (descriptor, errno) = inside
        .get("open")
        .copied()
        .expect("the probe reported 'open'");
    assert!(
        descriptor >= 0 && errno == 0,
        "the legacy open(2) of a granted file failed inside the box: rc {descriptor} errno {errno}"
    );
    for label in REFUSED {
        assert_eq!(
            inside.get(label).map(|answer| answer.1),
            Some(libc::EPERM),
            "'{label}' was not refused inside the box: {:?}",
            inside.get(label)
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
