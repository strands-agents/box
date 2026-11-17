//! Linux x86 commands require explicit operator consent before startup.

#![cfg(target_os = "linux")]

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt;
use std::process::{Command, Output};

const LEGACY_OPT_IN: &str = "EXPERIMENTAL_LINUX_SUPPORT";
const X86_OPT_IN: &str = "EXPERIMENTAL_X86_SUPPORT";
const X86_REFUSAL: &str = "strands-box: refusing to run: x86 support on Linux is experimental. Set EXPERIMENTAL_X86_SUPPORT=TRUE to enable it.\n";

fn command(legacy: Option<&OsStr>, x86: Option<&OsStr>, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box"));
    command
        .env_remove(LEGACY_OPT_IN)
        .env_remove(X86_OPT_IN)
        .args(args);
    if let Some(value) = legacy {
        command.env(LEGACY_OPT_IN, value);
    }
    if let Some(value) = x86 {
        command.env(X86_OPT_IN, value);
    }
    command.output().expect("execute the Box command")
}

fn values() -> Vec<Option<OsString>> {
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
    for value in values() {
        let output = command(
            value.as_deref(),
            Some(OsStr::new("TRUE")),
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
        assert!(!stderr.contains(X86_OPT_IN), "{stderr}");
    }
}

#[test]
fn linux_schema_validates_configuration_regardless_of_legacy_opt_in() {
    let directory = tempfile::tempdir().expect("create output parent");
    let destination = directory.path().join("schema");
    let config = directory.path().join("missing-linux-schema.toml");
    for value in values() {
        let output = command(
            value.as_deref(),
            Some(OsStr::new("TRUE")),
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
        assert!(!stderr.contains(X86_OPT_IN), "{stderr}");
        assert!(!destination.exists());
    }
}

#[test]
fn linux_commands_require_exact_x86_opt_in_only_on_x86() {
    let directory = tempfile::tempdir().expect("create configuration parent");
    let config = directory.path().join("missing-platform-config.toml");
    let destination = directory.path().join("schema");
    let config_text = config.to_str().expect("UTF-8 temporary path");
    let destination_text = destination.to_str().expect("UTF-8 temporary path");
    for value in values() {
        let admitted =
            !cfg!(target_arch = "x86_64") || value.as_deref() == Some(OsStr::new("TRUE"));
        for args in [
            vec!["run", "--config", config_text],
            vec![
                "policy",
                "generate-schema",
                "--config",
                config_text,
                "--output-dir",
                destination_text,
            ],
        ] {
            let output = command(Some(OsStr::new("TRUE")), value.as_deref(), &args);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "{stderr}");
            if admitted {
                assert!(stderr.contains("missing-platform-config.toml"), "{stderr}");
                assert!(!stderr.contains(X86_OPT_IN), "{stderr}");
            } else {
                assert_eq!(stderr, X86_REFUSAL, "value: {value:?}");
                assert!(!stderr.contains("missing-platform-config.toml"), "{stderr}");
            }
            assert!(!destination.exists());
        }
    }
}

#[test]
fn linux_help_and_version_remain_available_without_opt_in() {
    for args in [
        &["--help"][..],
        &["--version"][..],
        &["run", "--help"][..],
        &["policy", "generate-schema", "--help"][..],
    ] {
        let output = command(None, None, args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty());
    }
}
