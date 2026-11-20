#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CLAUDE_A: &str = "b-0123456789abcdef";
const CLAUDE_B: &str = "b-fedcba9876543210";
const CODEX_A: &str = "b-00112233445566aa";

struct Home {
    _root: tempfile::TempDir,
    path: PathBuf,
}

impl Home {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("a home");
        let path = root.path().to_path_buf();
        Self { _root: root, path }
    }

    fn runs(&self) -> PathBuf {
        self.path.join(".strands/box/r")
    }

    fn saved(&self, id: &str, profile: Option<&str>) {
        let run = self.runs().join(id);
        std::fs::create_dir_all(run.join("box")).expect("a run");
        if let Some(profile) = profile {
            std::fs::write(run.join("profile-name"), format!("{profile}\n")).expect("a record");
        }
    }

    fn exists(&self, id: &str) -> bool {
        self.runs().join(id).exists()
    }

    fn clean(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_box"))
            .args(["profile", "clean"])
            .args(args)
            .env_clear()
            .env("HOME", &self.path)
            .env("TERM", "dumb")
            .current_dir(&self.path)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("box runs")
    }
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
fn a_profile_clean_removes_only_the_boxes_that_profile_made() {
    let home = Home::new();
    home.saved(CLAUDE_A, Some("claude"));
    home.saved(CLAUDE_B, Some("claude"));
    home.saved(CODEX_A, Some("codex"));
    home.saved("b-aaaaaaaaaaaaaaaa", Some("codex"));
    home.saved("b-short", Some("claude"));
    home.saved("b-bbbbbbbbbbbbbbbb", None);
    home.saved("b-0123456789abcde0", Some("claudette"));
    let profile = home.path.join(".strands/box/profiles/claude/profile.toml");
    let storage = home.path.join(".strands/box/storage/claude/default/state");
    for file in [&profile, &storage] {
        std::fs::create_dir_all(file.parent().unwrap()).expect("a folder");
        std::fs::write(file, "kept\n").expect("a file");
    }

    let output = home.clean(&["claude", "--no-ask"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("box: removed 2 boxes of profile claude"),
        "{}",
        stderr(&output)
    );
    assert!(!home.exists(CLAUDE_A) && !home.exists(CLAUDE_B));
    for kept in [
        CODEX_A,
        "b-aaaaaaaaaaaaaaaa",
        "b-short",
        "b-bbbbbbbbbbbbbbbb",
        "b-0123456789abcde0",
    ] {
        assert!(home.exists(kept), "{kept} is not a box of claude");
    }
    assert!(
        profile.exists() && storage.exists(),
        "the profile and its storage stay"
    );
}

#[test]
fn a_profile_clean_takes_several_profiles() {
    let home = Home::new();
    home.saved(CLAUDE_A, Some("claude"));
    home.saved(CODEX_A, Some("codex"));
    home.saved("b-0123456789abcde1", Some("kiro"));

    let output = home.clean(&["claude", "codex", "--no-ask"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!home.exists(CLAUDE_A) && !home.exists(CODEX_A));
    assert!(home.exists("b-0123456789abcde1"));
}

#[test]
fn a_profile_clean_of_all_removes_every_saved_box() {
    let home = Home::new();
    home.saved(CLAUDE_A, Some("claude"));
    home.saved(CODEX_A, Some("codex"));
    home.saved("orphan-01", None);

    let output = home.clean(&["--all", "--no-ask"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("box: removed all 3 boxes"),
        "{}",
        stderr(&output)
    );
    assert!(std::fs::read_dir(home.runs()).unwrap().next().is_none());
}

#[test]
fn a_running_box_stops_the_clean_and_nothing_is_removed() {
    for args in [&["claude", "--no-ask"][..], &["--all", "--no-ask"][..]] {
        let home = Home::new();
        home.saved(CLAUDE_A, Some("claude"));
        home.saved(CLAUDE_B, Some("claude"));
        let _held = running(&home.runs(), CLAUDE_B);

        let output = home.clean(args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?}: {}",
            stderr(&output)
        );
        let message = stderr(&output);
        assert!(
            message.contains("is still running, so nothing was removed")
                && message.contains(CLAUDE_B)
                && !message.contains(CLAUDE_A),
            "{args:?}: {message}"
        );
        assert!(home.exists(CLAUDE_A) && home.exists(CLAUDE_B), "{args:?}");
    }
}

#[test]
fn a_profile_clean_with_no_boxes_says_so() {
    let home = Home::new();
    home.saved(CODEX_A, Some("codex"));
    let named = home.clean(&["claude", "--no-ask"]);
    assert!(named.status.success(), "{}", stderr(&named));
    assert!(
        stderr(&named).contains("box: no boxes found for profile claude"),
        "{}",
        stderr(&named)
    );

    let empty = Home::new();
    let all = empty.clean(&["--all", "--no-ask"]);
    assert!(all.status.success(), "{}", stderr(&all));
    assert!(
        stderr(&all).contains("box: no boxes found"),
        "{}",
        stderr(&all)
    );
}

#[test]
fn a_profile_clean_needs_names_or_all_but_not_both() {
    let home = Home::new();
    home.saved(CLAUDE_A, Some("claude"));
    for (args, message) in [
        (&["--no-ask"][..], "<NAMES|--all>"),
        (
            &["claude", "--all", "--no-ask"][..],
            "cannot be used with '--all'",
        ),
    ] {
        let output = home.clean(args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(message),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(home.exists(CLAUDE_A), "{args:?}");
    }
}

#[test]
fn a_profile_clean_refuses_a_name_that_no_box_can_record() {
    let home = Home::new();
    home.saved(CLAUDE_A, Some("claude"));
    for name in ["base", "../claude", ".hidden"] {
        let output = home.clean(&[name, "--no-ask"]);
        assert_eq!(output.status.code(), Some(1), "{name}: {}", stderr(&output));
        assert!(
            stderr(&output).contains("invalid profile name"),
            "{name}: {}",
            stderr(&output)
        );
    }
    assert!(home.exists(CLAUDE_A));
}

#[test]
fn a_profile_clean_without_a_terminal_asks_and_removes_nothing() {
    let home = Home::new();
    home.saved(CLAUDE_A, Some("claude"));
    let output = home.clean(&["claude"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("pass --no-ask"),
        "{}",
        stderr(&output)
    );
    assert!(home.exists(CLAUDE_A));
}

#[test]
fn a_profile_clean_reports_what_it_removed_before_a_failure() {
    use std::os::unix::fs::PermissionsExt as _;
    let home = Home::new();
    home.saved(CLAUDE_A, Some("claude"));
    home.saved(CLAUDE_B, Some("claude"));
    let stuck = home.runs().join(CLAUDE_B).join("box");
    std::fs::write(stuck.join("state"), "").expect("a file");
    std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o500)).expect("read-only");

    let output = home.clean(&["claude", "--no-ask"]);
    std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o700)).expect("writable");
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("box: removed 1 of 2 boxes of profile claude"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_profile_clean_leaves_a_linked_run_folder_alone() {
    let home = Home::new();
    let elsewhere = home.path.join("elsewhere");
    std::fs::create_dir_all(elsewhere.join("box")).expect("a folder");
    std::fs::write(elsewhere.join("profile-name"), "claude\n").expect("a record");
    std::fs::create_dir_all(home.runs()).expect("the runs");
    std::os::unix::fs::symlink(&elsewhere, home.runs().join(CLAUDE_A)).expect("a link");

    let output = home.clean(&["claude", "--no-ask"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("box: no boxes found for profile claude"),
        "{}",
        stderr(&output)
    );
    assert!(home.runs().join(CLAUDE_A).symlink_metadata().is_ok());
    assert!(elsewhere.join("profile-name").exists());
}

#[test]
fn a_profile_clean_stops_when_a_profile_record_cannot_be_read() {
    use std::os::unix::fs::PermissionsExt as _;
    let home = Home::new();
    home.saved(CLAUDE_A, Some("claude"));
    home.saved(CLAUDE_B, Some("claude"));
    let record = home.runs().join(CLAUDE_B).join("profile-name");
    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o000)).expect("unreadable");

    let output = home.clean(&["claude", "--no-ask"]);
    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).expect("readable");
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        home.exists(CLAUDE_A) && home.exists(CLAUDE_B),
        "nothing is removed"
    );
}

/// `box profile clean` under an open-file limit of `soft` and `hard`.
fn clean_with_file_limit(home: &Home, args: &[&str], soft: u64, hard: u64) -> Output {
    use std::os::unix::process::CommandExt as _;
    let mut command = Command::new(env!("CARGO_BIN_EXE_box"));
    command
        .args(["profile", "clean"])
        .args(args)
        .env_clear()
        .env("HOME", &home.path)
        .env("TERM", "dumb")
        .current_dir(&home.path)
        .stdin(std::process::Stdio::null());
    // SAFETY: setrlimit is async-signal-safe, and the closure allocates nothing.
    unsafe {
        command.pre_exec(move || {
            nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE, soft, hard)
                .map_err(std::io::Error::from)
        });
    }
    command.output().expect("box runs")
}

fn many_boxes(home: &Home, count: usize) {
    for index in 0..count {
        home.saved(&format!("b-{index:016x}"), Some("claude"));
    }
}

#[test]
fn a_profile_clean_raises_a_low_open_file_limit_to_hold_every_box() {
    let home = Home::new();
    many_boxes(&home, 150);
    let output = clean_with_file_limit(&home, &["claude", "--no-ask"], 64, 4096);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("box: removed 150 boxes of profile claude"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_profile_clean_refuses_more_boxes_than_the_open_file_limit_allows() {
    let home = Home::new();
    many_boxes(&home, 150);
    for args in [&["claude", "--no-ask"][..], &["--all", "--no-ask"][..]] {
        let output = clean_with_file_limit(&home, args, 64, 64);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?}: {}",
            stderr(&output)
        );
        let message = stderr(&output);
        assert!(
            message.contains("cannot remove 150 boxes at once") && message.contains("ulimit -n"),
            "{args:?}: {message}"
        );
        assert_eq!(
            std::fs::read_dir(home.runs()).unwrap().count(),
            150,
            "{args:?}: nothing is removed"
        );
    }
}

#[test]
fn a_profile_clean_names_every_running_box() {
    let home = Home::new();
    home.saved(CLAUDE_A, Some("claude"));
    home.saved(CLAUDE_B, Some("claude"));
    let _a = running(&home.runs(), CLAUDE_A);
    let _b = running(&home.runs(), CLAUDE_B);

    let output = home.clean(&["claude", "--no-ask"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let message = stderr(&output);
    assert!(
        message.contains("these boxes are still running, so nothing was removed")
            && message.contains(CLAUDE_A)
            && message.contains(CLAUDE_B),
        "{message}"
    );
}

#[test]
fn a_profile_clean_of_several_profiles_with_no_boxes_names_them() {
    let home = Home::new();
    let output = home.clean(&["claude", "codex", "--no-ask"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("box: no boxes found for profiles claude, codex"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_profile_clean_names_only_the_profiles_that_own_boxes() {
    let home = Home::new();
    home.saved(CLAUDE_A, Some("claude"));
    let output = home.clean(&["claude", "nosuch", "--no-ask"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let message = stderr(&output);
    assert!(
        message.contains("box: no boxes found for profile nosuch")
            && message.contains("box: removed 1 box of profile claude")
            && !message.contains("profiles claude, nosuch"),
        "{message}"
    );
}

#[test]
fn a_profile_clean_with_a_box_id_removes_only_that_box() {
    let home = Home::new();
    home.saved(CLAUDE_A, Some("claude"));
    home.saved(CLAUDE_B, Some("claude"));
    home.saved(CODEX_A, Some("codex"));

    let output = home.clean(&["claude", "--box-id", CLAUDE_A, "--no-ask"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains(&format!("box: removed box {CLAUDE_A} of profile claude")),
        "{}",
        stderr(&output)
    );
    assert!(!home.exists(CLAUDE_A));
    assert!(home.exists(CLAUDE_B) && home.exists(CODEX_A));
}

#[test]
fn a_profile_clean_with_a_box_id_works_while_another_box_of_the_profile_runs() {
    let home = Home::new();
    home.saved(CLAUDE_A, Some("claude"));
    home.saved(CLAUDE_B, Some("claude"));
    let _running = running(&home.runs(), CLAUDE_B);

    let output = home.clean(&["claude", "--box-id", CLAUDE_A, "--no-ask"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!home.exists(CLAUDE_A));
    assert!(home.exists(CLAUDE_B), "the running box stays");
}

#[test]
fn a_profile_clean_with_a_box_id_refuses_a_box_it_cannot_remove() {
    let home = Home::new();
    home.saved(CLAUDE_A, Some("claude"));
    home.saved(CLAUDE_B, Some("claude"));
    home.saved(CODEX_A, Some("codex"));
    home.saved("b-2222222222222222", Some("claudette"));
    home.saved("b-3333333333333333", None);
    let _running = running(&home.runs(), CLAUDE_B);
    for (args, message) in [
        (
            vec!["claude", "--box-id", CODEX_A, "--no-ask"],
            "is not a box of profile claude",
        ),
        (
            vec!["claude", "--box-id", "b-2222222222222222", "--no-ask"],
            "is not a box of profile claude",
        ),
        (
            vec!["claude", "--box-id", "b-3333333333333333", "--no-ask"],
            "is not a box of profile claude",
        ),
        (
            vec!["claude", "--box-id", CLAUDE_B],
            "is still running, so nothing was removed",
        ),
        (
            vec!["claude", "--box-id", "b-1111111111111111", "--no-ask"],
            "no run",
        ),
        (
            vec!["claude", "--box-id", "../x", "--no-ask"],
            "invalid box ID",
        ),
        (
            vec!["claude", "--box-id", CLAUDE_B, "--no-ask"],
            "is still running, so nothing was removed",
        ),
        (vec!["claude", "--box-id", CLAUDE_A], "pass --no-ask"),
    ] {
        let output = home.clean(&args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?}: {}",
            stderr(&output)
        );
        let said = stderr(&output)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(said.contains(message), "{args:?}: {said}");
    }
    for id in [
        CLAUDE_A,
        CLAUDE_B,
        CODEX_A,
        "b-2222222222222222",
        "b-3333333333333333",
    ] {
        assert!(home.exists(id), "{id}: nothing is removed");
    }
}

#[test]
fn a_profile_clean_box_id_needs_one_name_and_one_id_and_no_all() {
    let home = Home::new();
    home.saved(CLAUDE_A, Some("claude"));
    home.saved(CLAUDE_B, Some("claude"));
    for (args, message) in [
        (vec!["--box-id", CLAUDE_A, "--no-ask"], "<NAMES|--all>"),
        (
            vec!["--all", "--box-id", CLAUDE_A, "--no-ask"],
            "cannot be used with",
        ),
        (
            vec![
                "claude", "--box-id", CLAUDE_A, "--box-id", CLAUDE_B, "--no-ask",
            ],
            "cannot be used multiple times",
        ),
        (
            vec!["claude", "codex", "--box-id", CLAUDE_A, "--no-ask"],
            "name exactly one profile",
        ),
    ] {
        let output = home.clean(&args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        let said = stderr(&output)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(said.contains(message), "{args:?}: {said}");
    }
    assert!(home.exists(CLAUDE_A) && home.exists(CLAUDE_B));
}

#[test]
fn a_profile_clean_with_a_box_id_reads_only_the_named_box() {
    use std::os::unix::fs::PermissionsExt as _;
    let home = Home::new();
    home.saved(CLAUDE_A, Some("claude"));
    home.saved(CODEX_A, Some("codex"));
    let record = home.runs().join(CODEX_A).join("profile-name");
    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o000)).expect("unreadable");

    let output = home.clean(&["claude", "--box-id", CLAUDE_A, "--no-ask"]);
    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).expect("readable");
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!home.exists(CLAUDE_A));
    assert!(home.exists(CODEX_A), "the other profile's box stays");
}
