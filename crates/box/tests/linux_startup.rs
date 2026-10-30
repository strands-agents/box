//! Linux commands validate configuration without an environment opt-in.

#![cfg(target_os = "linux")]

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt;
use std::process::{Command, Output};

const LEGACY_OPT_IN: &str = "EXPERIMENTAL_LINUX_SUPPORT";

fn command(value: Option<&OsStr>, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box"));
    command.env_remove(LEGACY_OPT_IN).args(args);
    if let Some(value) = value {
        command.env(LEGACY_OPT_IN, value);
    }
    command.output().expect("execute the Box command")
}

fn legacy_values() -> Vec<Option<OsString>> {
    vec![
        None,
        Some(OsString::from("")),
        Some(OsString::from("TRUE")),
        Some(OsString::from("true")),
        Some(OsString::from("1")),
        Some(OsString::from("FALSE")),
        Some(OsString::from(" TRUE")),
        Some(OsString::from("TRUE ")),
        Some(OsString::from_vec(vec![0xff])),
    ]
}

#[test]
fn linux_run_validates_configuration_regardless_of_legacy_opt_in() {
    let directory = tempfile::tempdir().expect("create configuration parent");
    let config = directory.path().join("missing-linux-config.toml");
    for value in legacy_values() {
        let output = command(
            value.as_deref(),
            &[
                "run",
                "--config",
                config.to_str().expect("UTF-8 temporary path"),
            ],
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{stderr}");
        assert!(stderr.contains("missing-linux-config.toml"), "{stderr}");
        assert!(!stderr.contains(LEGACY_OPT_IN), "{stderr}");
    }
}

#[test]
fn linux_schema_validates_configuration_regardless_of_legacy_opt_in() {
    let directory = tempfile::tempdir().expect("create output parent");
    let destination = directory.path().join("schema");
    let config = directory.path().join("missing-linux-schema.toml");
    for value in legacy_values() {
        let output = command(
            value.as_deref(),
            &[
                "policy",
                "generate-schema",
                "--config",
                config.to_str().expect("UTF-8 temporary path"),
                "--output-dir",
                destination.to_str().expect("UTF-8 temporary path"),
            ],
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{stderr}");
        assert!(stderr.contains("missing-linux-schema.toml"), "{stderr}");
        assert!(!stderr.contains(LEGACY_OPT_IN), "{stderr}");
        assert!(!destination.exists());
    }
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
