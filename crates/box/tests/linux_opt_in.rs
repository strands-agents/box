//! Linux startup requires explicit operator consent before configuration access.

#![cfg(target_os = "linux")]

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt;
use std::process::{Command, Output};

const OPT_IN: &str = "EXPERIMENTAL_LINUX_SUPPORT";

fn command(value: Option<&OsStr>, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box"));
    command.env_remove(OPT_IN).args(args);
    if let Some(value) = value {
        command.env(OPT_IN, value);
    }
    command.output().expect("execute the Box command")
}

#[test]
fn linux_run_refuses_absent_or_invalid_opt_in_before_reading_configuration() {
    let invalid = [
        None,
        Some(OsString::from("")),
        Some(OsString::from("true")),
        Some(OsString::from("1")),
        Some(OsString::from("FALSE")),
        Some(OsString::from(" TRUE")),
        Some(OsString::from("TRUE ")),
        Some(OsString::from_vec(vec![0xff])),
    ];
    for value in invalid {
        let output = command(
            value.as_deref(),
            &["run", "--config", "/missing-linux-opt-in.toml"],
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{stderr}");
        assert!(
            stderr.contains("Linux support is experimental."),
            "{stderr}"
        );
        assert!(
            stderr.contains("EXPERIMENTAL_LINUX_SUPPORT=TRUE"),
            "{stderr}"
        );
        assert!(!stderr.contains("missing-linux-opt-in.toml"), "{stderr}");
    }
}

#[test]
fn explicit_linux_opt_in_reaches_configuration_validation() {
    let output = command(
        Some(OsStr::new("TRUE")),
        &["run", "--config", "/missing-linux-opt-in.toml"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("missing-linux-opt-in.toml"), "{stderr}");
    assert!(
        !stderr.contains("Linux support is experimental."),
        "{stderr}"
    );
}

#[test]
fn linux_schema_generation_also_requires_opt_in() {
    let directory = tempfile::tempdir().expect("create output parent");
    let destination = directory.path().join("schema");
    let output = command(
        None,
        &[
            "policy",
            "generate-schema",
            "--config",
            "/missing-linux-opt-in.toml",
            "--output-dir",
            destination.to_str().expect("UTF-8 temporary path"),
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("Linux support is experimental."),
        "{stderr}"
    );
    assert!(!destination.exists());
}

#[test]
fn linux_help_and_version_remain_available_without_opt_in() {
    for args in [&["--help"][..], &["--version"][..], &["run", "--help"][..]] {
        let output = command(None, args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty());
    }
}
