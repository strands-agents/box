#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output};

fn clean(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_box"))
        .arg("clean")
        .args(args)
        .arg("--no-ask")
        .env_clear()
        .env("HOME", home)
        .env("TERM", "dumb")
        .current_dir(home)
        .output()
        .expect("box runs")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Hold the run folder `name` as `box run` does while its box runs.
fn running(runs: &Path, name: &str) -> std::fs::File {
    let file = std::fs::File::open(runs.join(name)).expect("a run folder");
    file.try_lock().expect("the run lock");
    file
}

#[test]
fn a_clean_of_every_box_names_each_running_box_it_keeps() {
    let home = tempfile::tempdir().expect("a home");
    let runs = home.path().join(".strands/box/r");
    for name in ["claude-01", "codex-02", "kiro-03"] {
        std::fs::create_dir_all(runs.join(name).join("box")).expect("a run");
    }
    let _codex = running(&runs, "codex-02");
    let _kiro = running(&runs, "kiro-03");

    let output = clean(home.path(), &["--all"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("removed 1 box from"),
        "{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("kept 2 boxes that are still running: codex-02, kiro-03"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_clean_of_every_box_with_none_saved_says_so() {
    let home = tempfile::tempdir().expect("a home");
    let output = clean(home.path(), &["--all"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no saved boxes in"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_clean_of_every_box_reports_what_it_did_before_a_failure() {
    let home = tempfile::tempdir().expect("a home");
    let runs = home.path().join(".strands/box/r");
    for name in ["claude-01", "codex-02", "kiro-03"] {
        std::fs::create_dir_all(runs.join(name).join("box")).expect("a run");
    }
    let stuck = runs.join("kiro-03/box");
    std::fs::write(stuck.join("state"), "").expect("a file");
    std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o500)).expect("read-only");
    let _codex = running(&runs, "codex-02");

    let output = clean(home.path(), &["--all"]);
    std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o700)).expect("writable");
    assert!(!output.status.success(), "{}", stderr(&output));
    for line in [
        "removed 1 box from",
        "kept 1 box that is still running: codex-02",
        "box: error:",
    ] {
        assert!(
            stderr(&output).contains(line),
            "{line}: {}",
            stderr(&output)
        );
    }
}
