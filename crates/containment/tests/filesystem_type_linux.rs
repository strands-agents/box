//! Linux filesystem type queries preserve the namespace's file access restrictions.
#![cfg(all(target_os = "linux", target_arch = "aarch64"))]

use std::ffi::CString;
use std::io;
use std::mem::MaybeUninit;
use std::path::Path;
use std::process::Command;

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest, Sha256};

const MARKER: &str = "FILESYSTEM_TYPE_RESULT=";

fn filesystem_type(path: &Path) -> io::Result<libc::c_long> {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let mut information = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: the path remains live and the kernel receives space for one statfs result.
    let result =
        unsafe { libc::syscall(libc::SYS_statfs, path.as_ptr(), information.as_mut_ptr()) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: statfs initialized the complete result after a successful call.
    Ok(unsafe { information.assume_init() }.f_type)
}

#[test]
fn filesystem_type_probe() {
    let Some(directory) = std::env::var_os("BOX_FILESYSTEM_TYPE_PROBE") else {
        return;
    };
    let directory = Path::new(&directory);
    let granted = directory.join("granted");
    let ungranted = directory.join("operator-note");
    let file = granted.join("read-only.txt");
    let kind = filesystem_type(&granted).expect("query the granted directory's filesystem type");
    let hidden_type =
        filesystem_type(&ungranted).expect_err("ungranted file stays outside the view");
    let hidden_read = std::fs::read(&ungranted).expect_err("ungranted content stays unreadable");
    assert_eq!(std::fs::read(&file).unwrap(), b"original bytes");
    let write = std::fs::write(&file, b"unexpected replacement")
        .expect_err("a filesystem query must not make a read grant writable");
    println!(
        "{MARKER}{}",
        serde_json::json!({
            "filesystem_type": kind,
            "ungranted_statfs_errno": hidden_type.raw_os_error(),
            "ungranted_read_errno": hidden_read.raw_os_error(),
            "read_only_write_errno": write.raw_os_error(),
        })
    );
}

#[test]
fn filesystem_type_queries_preserve_file_access_restrictions() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let granted = root.join("granted");
    std::fs::create_dir(&granted).unwrap();
    let file = granted.join("read-only.txt");
    let ungranted = root.join("operator-note");
    std::fs::write(&file, b"original bytes").unwrap();
    std::fs::write(&ungranted, b"operator bytes").unwrap();
    let expected_type = filesystem_type(&granted).expect("host filesystem query must work");
    assert_eq!(filesystem_type(&ungranted).unwrap(), expected_type);
    assert_eq!(std::fs::read(&ungranted).unwrap(), b"operator bytes");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&file)
        .expect("the host file must be writable before containment");

    let executable = std::env::current_exe().unwrap();
    let config = ContainmentConfig::new()
        .allow(&executable, Operation::Read, Scope::File)
        .unwrap()
        .allow(&executable, Operation::Exec, Scope::File)
        .unwrap()
        .allow(&granted, Operation::Read, Scope::Root)
        .unwrap();
    let json = config.to_json().unwrap();
    let config_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(config_file.path(), &json).unwrap();
    let digest = Sha256::digest(json.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let output = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"))
        .arg("--config")
        .arg(config_file.path())
        .arg("--config-sha256")
        .arg(digest)
        .arg("--target-env-json")
        .arg(serde_json::json!({"BOX_FILESYSTEM_TYPE_PROBE": root}).to_string())
        .arg("--")
        .arg(&executable)
        .args([
            "--exact",
            "filesystem_type_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .current_dir(&granted)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "contained probe failed: {stdout}\n{stderr}"
    );
    let report = stdout
        .lines()
        .find_map(|line| line.split_once(MARKER).map(|(_, report)| report))
        .expect("the contained filesystem probe completed");
    let report: serde_json::Value = serde_json::from_str(report).unwrap();
    assert_eq!(report["filesystem_type"].as_i64(), Some(expected_type));
    assert_eq!(report["ungranted_statfs_errno"], libc::ENOENT);
    assert_eq!(report["ungranted_read_errno"], libc::ENOENT);
    assert_eq!(report["read_only_write_errno"], libc::EROFS);
    assert_eq!(std::fs::read(file).unwrap(), b"original bytes");
    assert_eq!(std::fs::read(ungranted).unwrap(), b"operator bytes");
}
