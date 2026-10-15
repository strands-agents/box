//! Ordinary builds must not activate experimental native enforcement implicitly.
#![cfg(target_os = "macos")]

use std::process::Command;

#[path = "support/bounded_output.rs"]
mod bounded_output;

fn run(selection: &str) -> (tempfile::TempDir, std::process::Output) {
    let directory = tempfile::tempdir().unwrap();
    let output = run_in(directory.path(), selection);
    (directory, output)
}

fn run_in(directory: &std::path::Path, selection: &str) -> std::process::Output {
    let root = directory.canonicalize().unwrap();
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let quote =
        |path: &std::path::Path| toml::Value::String(path.display().to_string()).to_string();
    let config = format!(
        "name = \"native-opt-in\"\nbox_dir = {}\n{selection}\n[agent]\ncommand = [\"/bin/echo\", \"WORKLOAD_STARTED\"]\nworkspace = {}\n",
        quote(&root.join("box")),
        quote(&workspace),
    );
    let path = root.join("box.toml");
    std::fs::write(&path, config).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box"));
    command
        .args(["run", "--config"])
        .arg(path)
        .env("HOME", &root)
        .current_dir(&workspace);
    bounded_output::bounded_output(command)
}

#[test]
fn ordinary_build_does_not_require_native_enforcement() {
    for selection in [
        "",
        "[experimental-features]\nnative-filesystem-policy = false",
    ] {
        let (_directory, output) = run(selection);
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("WORKLOAD_STARTED"),
            "{output:?}"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("macOS file enforcement ready"),
            "{output:?}"
        );
    }
}

#[test]
fn opted_in_unsigned_build_refuses_before_workload_start() {
    let (_directory, output) = run("[experimental-features]\nnative-filesystem-policy = true");
    assert!(!output.status.success(), "{output:?}");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("WORKLOAD_STARTED"),
        "{output:?}"
    );
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    if cfg!(all(
        target_os = "macos",
        feature = "native-filesystem-policy"
    )) {
        assert!(
            diagnostic.contains("native filesystem policy"),
            "{output:?}"
        );
    } else {
        assert!(
            diagnostic.contains("experimental feature `native-filesystem-policy` requires"),
            "{output:?}"
        );
    }
}

#[test]
fn refused_activation_keeps_the_previous_record_and_allows_ordinary_restart() {
    let (directory, output) = run("");
    assert!(output.status.success(), "{output:?}");
    let record = directory.path().join("box/private/box.toml");
    let previous = std::fs::read(&record).unwrap();
    let output = run_in(
        directory.path(),
        "[experimental-features]\nnative-filesystem-policy = true",
    );
    assert!(!output.status.success(), "{output:?}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("WORKLOAD_STARTED"));
    assert_eq!(std::fs::read(&record).unwrap(), previous);
    let output = run_in(
        directory.path(),
        "[experimental-features]\nnative-filesystem-policy = false",
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read(&record).unwrap(), previous);
}
