//! Linux filesystem grants through the production trampoline under root and nonroot launch identities.
#![cfg(all(target_os = "linux", target_arch = "aarch64"))]

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Output};

const RESULT: &str = "ROOT_FILE_RESULT=";

fn launch(directory: &Path, directory_write: bool) -> Output {
    let outside = tempfile::NamedTempFile::new_in("/var/tmp").unwrap();
    std::fs::write(outside.path(), b"OUTSIDE").unwrap();
    std::os::unix::fs::symlink(outside.path(), directory.join("outside-link")).unwrap();
    assert_eq!(std::fs::read(outside.path()).unwrap(), b"OUTSIDE");
    let executable = std::env::current_exe().unwrap();
    let mut config = ContainmentConfig::new()
        .allow(&executable, Operation::Read, Scope::File)
        .unwrap()
        .allow(&executable, Operation::Exec, Scope::File)
        .unwrap()
        .allow(directory, Operation::Read, Scope::Root)
        .unwrap();
    config = if directory_write {
        config
            .allow(directory, Operation::Write, Scope::Root)
            .unwrap()
    } else {
        config
            .allow(directory.join("existing"), Operation::Write, Scope::File)
            .unwrap()
    };
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
        .args(["--config-sha256", &digest, "--target-env-json"])
        .arg(serde_json::json!({"BOX_ROOT_FILE_PROBE": directory, "BOX_OUTSIDE_FILE_PROBE": outside.path()}).to_string())
        .arg("--")
        .arg(executable)
        .args([
            "--exact",
            "root_file_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .current_dir(directory)
        .output()
        .unwrap();
    assert_eq!(std::fs::read(outside.path()).unwrap(), b"OUTSIDE");
    output
}

fn fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("existing"), b"PRIVATE").unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(
        directory.path().join("existing"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    directory
}

#[test]
fn root_file_probe() {
    let Some(directory) = std::env::var_os("BOX_ROOT_FILE_PROBE") else {
        return;
    };
    let directory = Path::new(&directory);
    let outside = std::env::var_os("BOX_OUTSIDE_FILE_PROBE").unwrap();
    let outside_read_refused = std::fs::read(&outside).is_err();
    let outside_write_refused = std::fs::write(&outside, b"CHANGED").is_err();
    let outside_link_read_refused = std::fs::read(directory.join("outside-link")).is_err();
    let outside_link_write_refused =
        std::fs::write(directory.join("outside-link"), b"CHANGED").is_err();
    let read = std::fs::read(directory.join("existing")).ok().as_deref() == Some(b"PRIVATE");
    let write = std::fs::write(directory.join("existing"), b"UPDATED").is_ok();
    std::fs::set_permissions(
        directory.join("existing"),
        std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    let special_bits_refused = std::fs::set_permissions(
        directory.join("existing"),
        std::fs::Permissions::from_mode(0o4640),
    )
    .is_err()
        && std::fs::metadata(directory.join("existing"))
            .unwrap()
            .mode()
            & 0o7777
            == 0o640;
    let create = std::fs::write(directory.join("new-file"), b"NEW").is_ok();
    let symlink = std::os::unix::fs::symlink("existing", directory.join("new-link")).is_ok();
    let temporary = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::write(temporary.path().join("file"), b"PRIVATE-TEMP").unwrap();
    std::os::unix::fs::symlink("file", temporary.path().join("link")).unwrap();
    let private_tmp = std::fs::read(temporary.path().join("link")).unwrap() == b"PRIVATE-TEMP";
    std::fs::write("/dev/null", b"DEVICE-CONTROL").unwrap();
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let capabilities_clear = ["CapEff:", "CapPrm:", "CapInh:", "CapBnd:", "CapAmb:"]
        .iter()
        .all(|name| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .is_some_and(|value| value.trim().chars().all(|character| character == '0'))
        });
    println!(
        "{RESULT}{}",
        serde_json::json!({"read":read,"write":write,"create":create,"symlink":symlink,"private_tmp":private_tmp,"capabilities_clear":capabilities_clear,"special_bits_refused":special_bits_refused,"outside_read_refused":outside_read_refused,"outside_write_refused":outside_write_refused,"outside_link_read_refused":outside_link_read_refused,"outside_link_write_refused":outside_link_write_refused})
    );
}

fn observations(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = stdout
        .lines()
        .find_map(|line| line.split_once(RESULT).map(|(_, value)| value))
        .expect("workload completed its observations");
    serde_json::from_str(value).unwrap()
}

#[test]
fn file_grants_preserve_private_access_and_refuse_new_host_entries() {
    let directory = fixture();
    let result = observations(&launch(directory.path(), false));
    assert_eq!(
        result,
        serde_json::json!({"read":true,"write":true,"create":false,"symlink":false,"private_tmp":true,"capabilities_clear":true,"special_bits_refused":true,"outside_read_refused":true,"outside_write_refused":true,"outside_link_read_refused":true,"outside_link_write_refused":true})
    );
    assert_eq!(
        std::fs::read(directory.path().join("existing")).unwrap(),
        b"UPDATED"
    );
    assert!(!directory.path().join("new-file").exists());
    assert!(std::fs::symlink_metadata(directory.path().join("new-link")).is_err());
}

#[test]
fn nonroot_directory_grants_preserve_creation() {
    // SAFETY: getuid only reads this process's real user ID.
    assert_ne!(
        unsafe { libc::getuid() },
        0,
        "run this control as a non-root account"
    );
    let directory = fixture();
    let result = observations(&launch(directory.path(), true));
    assert_eq!(
        result,
        serde_json::json!({"read":true,"write":true,"create":true,"symlink":true,"private_tmp":true,"capabilities_clear":true,"special_bits_refused":true,"outside_read_refused":true,"outside_write_refused":true,"outside_link_read_refused":true,"outside_link_write_refused":true})
    );
}

fn in_root_namespace(test: &str) -> bool {
    // SAFETY: getuid only reads the launcher's current user ID.
    if unsafe { libc::getuid() } == 0 {
        return true;
    }
    if std::env::var("BOX_TEST_ROOT_NAMESPACE").as_deref() == Ok(test) {
        // SAFETY: getuid only reads the identity prepared by the unshare helper.
        assert_eq!(unsafe { libc::getuid() }, 0);
        return true;
    }
    let output = Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user", "--"])
        .arg(std::env::current_exe().unwrap())
        .env("BOX_TEST_ROOT_NAMESPACE", test)
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    false
}

#[test]
fn root_file_grants_preserve_private_access_and_temporary_storage() {
    if in_root_namespace("root_file_grants_preserve_private_access_and_temporary_storage") {
        file_grants_preserve_private_access_and_refuse_new_host_entries();
    }
}

#[test]
fn root_directory_grants_preserve_creation() {
    if !in_root_namespace("root_directory_grants_preserve_creation") {
        return;
    }
    let directory = fixture();
    let result = observations(&launch(directory.path(), true));
    assert_eq!(
        result,
        serde_json::json!({"read":true,"write":true,"create":true,"symlink":true,"private_tmp":true,"capabilities_clear":true,"special_bits_refused":true,"outside_read_refused":true,"outside_write_refused":true,"outside_link_read_refused":true,"outside_link_write_refused":true})
    );
    assert_eq!(
        std::fs::read(directory.path().join("new-file")).unwrap(),
        b"NEW"
    );
    assert_eq!(
        std::fs::read(directory.path().join("new-link")).unwrap(),
        b"UPDATED"
    );
    assert_eq!(
        std::fs::metadata(directory.path().join("new-file"))
            .unwrap()
            .uid(),
        0
    );
}
