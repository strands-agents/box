//! Direct Linux file-permission enforcement through the production trampoline.
#![cfg(all(target_os = "linux", target_arch = "aarch64"))]

use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

use containment::{ContainmentConfig, Operation, Scope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const FCHMODAT2: libc::c_long = 452;
const MARKER: &str = "FILE_PERMISSION_RESULTS=";
const MODES: [u64; 8] = [
    0o755,
    0o4755,
    0o2755,
    0o6755,
    (1 << 32) | 0o755,
    (1 << 32) | 0o4755,
    (1 << 32) | 0o2755,
    (1 << 32) | 0o6755,
];

#[derive(Debug, Serialize, Deserialize)]
struct Outcome {
    operation: String,
    requested: u64,
    result: i64,
    errno: i32,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    before_mode: Option<u32>,
    before_uid: Option<u32>,
    before_gid: Option<u32>,
}

#[test]
fn file_permission_probe() {
    let Some(directory) = std::env::var_os("BOX_PERMISSION_PROBE") else {
        return;
    };
    let directory = Path::new(&directory);
    let mut outcomes = Vec::new();
    for operation in [
        "fchmod",
        "fchmodat",
        "fchmodat2",
        "openat",
        "openat-tmpfile",
        "openat-unused-mode",
        "mkdirat",
        "openat2",
        "mknodat",
        "fchown",
        "fchownat",
    ] {
        for mode in MODES {
            if matches!(operation, "openat2" | "mknodat") && mode > u32::MAX as u64 {
                continue;
            }
            let path = directory.join(format!("{operation}-{mode:o}"));
            let target = if operation == "openat-tmpfile" {
                directory
            } else {
                &path
            };
            let name = CString::new(target.as_os_str().as_encoded_bytes()).unwrap();
            let existing = !matches!(
                operation,
                "openat" | "openat-tmpfile" | "mkdirat" | "openat2" | "mknodat"
            );
            let file =
                existing.then(|| std::fs::File::create(&path).expect("create owned fixture"));
            let before = file.as_ref().map(|file| file.metadata().unwrap());
            let open_how = [
                (libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY) as u64,
                mode,
                0,
            ];
            // SAFETY: strings remain live and each descriptor belongs to its fixture.
            let result = unsafe {
                match operation {
                    "fchmod" => {
                        libc::syscall(libc::SYS_fchmod, file.as_ref().unwrap().as_raw_fd(), mode)
                    }
                    "fchmodat" => {
                        libc::syscall(libc::SYS_fchmodat, libc::AT_FDCWD, name.as_ptr(), mode)
                    }
                    "fchmodat2" => libc::syscall(FCHMODAT2, libc::AT_FDCWD, name.as_ptr(), mode, 0),
                    "openat" => libc::syscall(
                        libc::SYS_openat,
                        libc::AT_FDCWD,
                        name.as_ptr(),
                        libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
                        mode,
                    ),
                    "openat-tmpfile" => libc::syscall(
                        libc::SYS_openat,
                        libc::AT_FDCWD,
                        name.as_ptr(),
                        libc::O_TMPFILE | libc::O_RDWR,
                        mode,
                    ),
                    "openat-unused-mode" => libc::syscall(
                        libc::SYS_openat,
                        libc::AT_FDCWD,
                        name.as_ptr(),
                        libc::O_RDONLY,
                        mode,
                    ),
                    "mkdirat" => {
                        libc::syscall(libc::SYS_mkdirat, libc::AT_FDCWD, name.as_ptr(), mode)
                    }
                    "openat2" => libc::syscall(
                        libc::SYS_openat2,
                        libc::AT_FDCWD,
                        name.as_ptr(),
                        open_how.as_ptr(),
                        std::mem::size_of_val(&open_how),
                    ),
                    "mknodat" => libc::syscall(
                        libc::SYS_mknodat,
                        libc::AT_FDCWD,
                        name.as_ptr(),
                        libc::S_IFREG as u64 | mode,
                        0,
                    ),
                    "fchown" => libc::syscall(
                        libc::SYS_fchown,
                        file.as_ref().unwrap().as_raw_fd(),
                        libc::getuid(),
                        libc::getgid(),
                    ),
                    "fchownat" => libc::syscall(
                        libc::SYS_fchownat,
                        libc::AT_FDCWD,
                        name.as_ptr(),
                        libc::getuid(),
                        libc::getgid(),
                        0,
                    ),
                    _ => unreachable!(),
                }
            };
            let errno = if result < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap()
            } else {
                0
            };
            let metadata = if operation == "openat-tmpfile" && result >= 0 {
                use std::os::fd::FromRawFd;
                // SAFETY: the successful open returned an owned descriptor.
                let temporary = unsafe { std::fs::File::from_raw_fd(result as i32) };
                let metadata = temporary.metadata().ok();
                std::mem::forget(temporary);
                metadata
            } else if operation == "openat-tmpfile" {
                None
            } else {
                std::fs::metadata(&path).ok()
            };
            if operation.starts_with("openat") && result >= 0 {
                // SAFETY: the successful open returned an owned descriptor.
                unsafe { libc::close(result as i32) };
            }
            outcomes.push(Outcome {
                operation: operation.to_owned(),
                requested: mode,
                result,
                errno,
                mode: metadata.as_ref().map(|m| m.mode() & 0o7777),
                uid: metadata.as_ref().map(|m| m.uid()),
                gid: metadata.as_ref().map(|m| m.gid()),
                before_mode: before.as_ref().map(|m| m.mode() & 0o7777),
                before_uid: before.as_ref().map(|m| m.uid()),
                before_gid: before.as_ref().map(|m| m.gid()),
            });
        }
    }
    let path = directory.join("ordinary-write");
    std::fs::write(&path, b"ordinary writes still work").expect("ordinary write");
    assert_eq!(std::fs::read(path).unwrap(), b"ordinary writes still work");
    println!("{MARKER}{}", serde_json::to_string(&outcomes).unwrap());
}

fn run_probe(directory: &Path, contained: bool, owner_group: Option<u32>) -> Vec<Outcome> {
    for operation in ["fchown", "fchownat"] {
        for mode in MODES {
            let file =
                std::fs::File::create(directory.join(format!("{operation}-{mode:o}"))).unwrap();
            if let Some(group) = owner_group {
                // SAFETY: the descriptor belongs to an owned temporary file.
                assert_eq!(
                    unsafe { libc::fchown(file.as_raw_fd(), u32::MAX, group) },
                    0
                );
            }
        }
    }
    let executable = std::env::current_exe().unwrap();
    let config_file = tempfile::NamedTempFile::new().unwrap();
    let mut command;
    if contained {
        let config = ContainmentConfig::new()
            .allow(&executable, Operation::Read, Scope::File)
            .unwrap()
            .allow(&executable, Operation::Exec, Scope::File)
            .unwrap()
            .allow(directory, Operation::Read, Scope::Root)
            .unwrap()
            .allow(directory, Operation::Write, Scope::Root)
            .unwrap();
        let json = config.to_json().unwrap();
        std::fs::write(config_file.path(), &json).unwrap();
        let digest = Sha256::digest(json.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        command = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"));
        command
            .arg("--config")
            .arg(config_file.path())
            .arg("--config-sha256")
            .arg(digest)
            .arg("--target-env-json")
            .arg(serde_json::json!({"BOX_PERMISSION_PROBE": directory}).to_string())
            .arg("--")
            .arg(&executable);
    } else {
        command = Command::new(&executable);
        command.env("BOX_PERMISSION_PROBE", directory);
    }
    let output = command
        .current_dir(directory)
        .args([
            "--exact",
            "file_permission_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "probe failed: {stdout}\n{stderr}");
    let json = stdout
        .lines()
        .find_map(|line| line.split_once(MARKER).map(|(_, value)| value))
        .expect("probe completed");
    println!(
        "{} {json}",
        if contained {
            "CONTAINED_RESULTS="
        } else {
            "CONTROL_RESULTS="
        }
    );
    serde_json::from_str(json).unwrap()
}

#[test]
fn direct_file_permissions_preserve_writes_and_refuse_special_modes() {
    let host = tempfile::tempdir().unwrap();
    let boxed = tempfile::tempdir().unwrap();
    // CN-F-02 and CN-F-03 require ordinary-operation controls and final stored metadata.
    // SAFETY: a zero-sized getgroups call only returns the required array length.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    assert!(count >= 0);
    let mut groups = vec![0; count as usize];
    // SAFETY: groups has the size reported by getgroups in this single-threaded fixture setup.
    assert_eq!(
        unsafe { libc::getgroups(count, groups.as_mut_ptr()) },
        count
    );
    // SAFETY: getgid has no arguments or memory effects.
    let owner_group = groups
        .into_iter()
        .find(|group| *group != unsafe { libc::getgid() });
    if owner_group.is_none() {
        eprintln!(
            "No supplementary group: ownership controls use the current group without a group transfer"
        );
    }
    let controls = run_probe(host.path(), false, owner_group);
    let outcomes = run_probe(boxed.path(), true, owner_group);
    assert_eq!(controls.len(), outcomes.len());
    let mut failures = Vec::new();
    for (control, outcome) in controls.iter().zip(&outcomes) {
        let special = outcome.requested & 0o6000 != 0;
        let owner_change = matches!(outcome.operation.as_str(), "fchown" | "fchownat");
        let unlisted = matches!(outcome.operation.as_str(), "openat2" | "mknodat");
        let denied =
            owner_change || unlisted || (special && outcome.operation != "openat-unused-mode");
        let unavailable = control.result == -1
            && ((matches!(control.operation.as_str(), "fchmodat2" | "openat2")
                && control.errno == libc::ENOSYS)
                || (control.operation == "openat-tmpfile" && control.errno == libc::EOPNOTSUPP));
        if unavailable {
            eprintln!(
                "host prerequisite absent for {}: errno {}; denial checks still run",
                control.operation, control.errno
            );
        }
        assert!(
            control.result >= 0 || unavailable,
            "host control unavailable: {control:?}"
        );
        if special
            && !unavailable
            && matches!(
                control.operation.as_str(),
                "fchmod" | "fchmodat" | "fchmodat2" | "openat" | "openat-tmpfile"
            )
        {
            assert_eq!(
                u64::from(control.mode.unwrap()) & 0o6000,
                control.requested & 0o6000,
                "host must retain requested bits: {control:?}"
            );
        }
        if owner_change && owner_group.is_some() {
            assert_ne!(
                control.before_gid, control.gid,
                "host control must change the owned file group"
            );
        }
        if denied {
            if outcome.result != -1
                || outcome.errno != libc::EPERM
                || outcome.mode.unwrap_or(0) & 0o6000 != 0
                || (outcome.before_mode.is_some() && outcome.mode != outcome.before_mode)
                || (owner_change
                    && (outcome.uid != outcome.before_uid || outcome.gid != outcome.before_gid))
            {
                failures.push(format!("expected refusal without stored bits: {outcome:?}"));
            }
            if matches!(
                outcome.operation.as_str(),
                "openat" | "mkdirat" | "openat2" | "mknodat"
            ) && outcome.mode.is_some()
            {
                failures.push(format!("refused creation left a host entry: {outcome:?}"));
            }
        } else if (unavailable && (outcome.result != -1 || outcome.errno != control.errno))
            || (!unavailable && outcome.result < 0)
            || outcome.mode != control.mode
        {
            failures.push(format!(
                "ordinary operation changed: {outcome:?}; host {control:?}"
            ));
        }
        let path = boxed
            .path()
            .join(format!("{}-{:o}", outcome.operation, outcome.requested));
        if outcome.operation == "openat-tmpfile" {
            continue;
        }
        if denied && outcome.before_mode.is_none() {
            let error = std::fs::symlink_metadata(&path)
                .expect_err("refused creation must leave no host entry");
            assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        } else {
            let metadata =
                std::fs::metadata(&path).expect("existing fixture must remain on the host");
            assert_eq!(
                Some(metadata.mode() & 0o7777),
                outcome.mode,
                "host must see the same stored mode"
            );
            assert_eq!(
                metadata.uid(),
                std::fs::metadata(boxed.path()).unwrap().uid()
            );
            let expected_gid = if owner_change {
                owner_group.unwrap_or_else(|| std::fs::metadata(boxed.path()).unwrap().gid())
            } else {
                std::fs::metadata(boxed.path()).unwrap().gid()
            };
            assert_eq!(
                metadata.gid(),
                expected_gid,
                "host ownership must remain unchanged"
            );
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
