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

    fn box_home(&self) -> PathBuf {
        self.path.join(".strands/box")
    }

    fn runs(&self) -> PathBuf {
        self.box_home().join("r")
    }

    fn profile(&self, name: &str) -> PathBuf {
        let folder = self.box_home().join("profiles").join(name);
        std::fs::create_dir_all(&folder).expect("a profile folder");
        std::fs::write(folder.join("profile.toml"), "packs = []\n").expect("a profile");
        folder
    }

    fn storage(&self, name: &str) -> PathBuf {
        let folder = self.box_home().join("storage").join(name);
        let settings = folder.join("default/config/settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).expect("a storage folder");
        std::fs::write(&settings, "{}\n").expect("settings");
        folder
    }

    fn saved(&self, id: &str, profile: &str) {
        let run = self.runs().join(id);
        std::fs::create_dir_all(run.join("box")).expect("a run");
        std::fs::write(run.join("profile-name"), format!("{profile}\n")).expect("a record");
    }

    fn exists(&self, id: &str) -> bool {
        self.runs().join(id).exists()
    }

    fn profile_command(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_box"))
            .arg("profile")
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
fn a_delete_removes_the_profile_its_boxes_and_its_storage() {
    let home = Home::new();
    let claude = home.profile("claude");
    let storage = home.storage("claude");
    home.saved(CLAUDE_A, "claude");
    home.saved(CLAUDE_B, "claude");
    let codex = home.profile("codex");
    let codex_storage = home.storage("codex");
    home.saved(CODEX_A, "codex");

    let output = home.profile_command(&["delete", "claude", "--no-ask"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("box: deleted profile claude, with 2 boxes and its storage"),
        "{}",
        stderr(&output)
    );
    assert!(!claude.exists() && !storage.exists());
    assert!(!home.exists(CLAUDE_A) && !home.exists(CLAUDE_B));
    assert!(codex.exists() && codex_storage.exists() && home.exists(CODEX_A));
}

#[test]
fn a_delete_also_removes_the_record_of_the_profile_file_that_owned_the_name() {
    let home = Home::new();
    let storage = home.storage("claude");
    std::fs::write(storage.join(".profile-source"), "/work/profile.toml\n").expect("a record");

    let output = home.profile_command(&["delete", "claude", "--no-ask"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("box: deleted what is left of profile claude, with its storage"),
        "{}",
        stderr(&output)
    );
    assert!(!storage.exists());
}

#[test]
fn a_delete_of_all_removes_every_profile_box_and_storage() {
    let home = Home::new();
    home.profile("claude");
    home.storage("claude");
    home.storage("orphan");
    home.saved(CLAUDE_A, "claude");
    home.saved("b-1111111111111111", "gone");

    let output = home.profile_command(&["delete", "--all", "--no-ask"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("box: deleted every profile, with 2 boxes and all storage"),
        "{}",
        stderr(&output)
    );
    for folder in ["profiles/claude", "storage/claude", "storage/orphan"] {
        assert!(!home.box_home().join(folder).exists(), "{folder}");
    }
    assert!(std::fs::read_dir(home.runs()).unwrap().next().is_none());
}

#[test]
fn a_delete_with_nothing_to_delete_says_so() {
    let home = Home::new();
    let named = home.profile_command(&["delete", "nosuch", "--no-ask"]);
    assert!(named.status.success(), "{}", stderr(&named));
    assert!(
        stderr(&named).contains("box: no profile nosuch found"),
        "{}",
        stderr(&named)
    );
    let all = home.profile_command(&["delete", "--all", "--no-ask"]);
    assert!(all.status.success(), "{}", stderr(&all));
    assert!(
        stderr(&all).contains("box: no profiles found"),
        "{}",
        stderr(&all)
    );
}

#[test]
fn a_running_box_stops_a_delete_and_nothing_is_deleted() {
    let home = Home::new();
    let claude = home.profile("claude");
    let storage = home.storage("claude");
    home.saved(CLAUDE_A, "claude");
    home.saved(CLAUDE_B, "claude");
    let _held = running(&home.runs(), CLAUDE_B);

    let output = home.profile_command(&["delete", "claude", "--no-ask"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let message = stderr(&output);
    assert!(
        message.contains("is still running, so nothing was removed")
            && message.contains(CLAUDE_B)
            && message.contains("box profile delete again"),
        "{message}"
    );
    assert!(claude.exists() && storage.exists());
    assert!(home.exists(CLAUDE_A) && home.exists(CLAUDE_B));
}

#[test]
fn a_reset_removes_only_the_storage_and_keeps_the_name_record() {
    let home = Home::new();
    let claude = home.profile("claude");
    let storage = home.storage("claude");
    std::fs::write(storage.join(".profile-source"), "/work/profile.toml\n").expect("a record");
    home.saved(CLAUDE_A, "claude");
    let codex_storage = home.storage("codex");

    let output = home.profile_command(&["reset", "claude", "--no-ask"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("box: deleted the storage of profile claude"),
        "{}",
        stderr(&output)
    );
    assert!(
        !storage.join("default").exists(),
        "the agent's storage is gone"
    );
    assert!(
        storage.join(".profile-source").exists(),
        "the name stays bound to its profile file"
    );
    assert!(
        claude.exists() && home.exists(CLAUDE_A),
        "the profile and its box stay"
    );
    assert!(codex_storage.join("default").exists());
}

#[test]
fn a_reset_of_all_removes_the_storage_of_every_profile() {
    let home = Home::new();
    let claude = home.storage("claude");
    let codex = home.storage("codex");

    let output = home.profile_command(&["reset", "--all", "--no-ask"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("box: deleted the storage of every profile"),
        "{}",
        stderr(&output)
    );
    assert!(!claude.join("default").exists() && !codex.join("default").exists());
}

#[test]
fn a_reset_with_no_storage_says_so() {
    let home = Home::new();
    home.profile("claude");
    let named = home.profile_command(&["reset", "claude", "--no-ask"]);
    assert!(named.status.success(), "{}", stderr(&named));
    assert!(
        stderr(&named).contains("box: no storage found for profile claude"),
        "{}",
        stderr(&named)
    );
    let all = home.profile_command(&["reset", "--all", "--no-ask"]);
    assert!(all.status.success(), "{}", stderr(&all));
    assert!(
        stderr(&all).contains("box: no storage found"),
        "{}",
        stderr(&all)
    );
}

#[test]
fn a_running_box_stops_a_reset_and_its_storage_stays() {
    let home = Home::new();
    let storage = home.storage("claude");
    home.saved(CLAUDE_A, "claude");
    let _held = running(&home.runs(), CLAUDE_A);

    let output = home.profile_command(&["reset", "claude", "--no-ask"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let message = stderr(&output);
    assert!(
        message.contains("is still running, so nothing was removed")
            && message.contains("box profile reset again"),
        "{message}"
    );
    assert!(storage.join("default/config/settings.json").exists());
}

#[test]
fn delete_and_reset_need_names_or_all_but_not_both() {
    let home = Home::new();
    let claude = home.profile("claude");
    let storage = home.storage("claude");
    for command in ["delete", "reset"] {
        for (args, message) in [
            (vec![command, "--no-ask"], "<NAMES|--all>"),
            (
                vec![command, "claude", "--all", "--no-ask"],
                "cannot be used with '--all'",
            ),
        ] {
            let output = home.profile_command(&args);
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
        }
    }
    assert!(claude.exists() && storage.join("default").exists());
}

#[test]
fn delete_and_reset_refuse_a_name_that_no_profile_can_have() {
    let home = Home::new();
    for command in ["delete", "reset"] {
        for name in ["base", "../claude", ".hidden"] {
            let output = home.profile_command(&[command, name, "--no-ask"]);
            assert_eq!(
                output.status.code(),
                Some(1),
                "{command} {name}: {}",
                stderr(&output)
            );
            assert!(
                stderr(&output).contains("invalid profile name"),
                "{command} {name}: {}",
                stderr(&output)
            );
        }
    }
}

#[test]
fn delete_and_reset_without_a_terminal_ask_and_change_nothing() {
    let home = Home::new();
    let claude = home.profile("claude");
    let storage = home.storage("claude");
    for command in ["delete", "reset"] {
        let output = home.profile_command(&[command, "claude"]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{command}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("pass --no-ask"),
            "{command}: {}",
            stderr(&output)
        );
    }
    assert!(claude.exists() && storage.join("default").exists());
}

#[test]
fn a_running_box_of_another_profile_does_not_stop_a_delete_or_reset() {
    let home = Home::new();
    home.profile("claude");
    home.storage("claude");
    home.saved(CLAUDE_A, "claude");
    home.saved(CODEX_A, "codex");
    let _codex = running(&home.runs(), CODEX_A);

    let reset = home.profile_command(&["reset", "claude", "--no-ask"]);
    assert!(reset.status.success(), "{}", stderr(&reset));
    let delete = home.profile_command(&["delete", "claude", "--no-ask"]);
    assert!(delete.status.success(), "{}", stderr(&delete));
    assert!(!home.exists(CLAUDE_A));
    assert!(home.exists(CODEX_A), "the running box of codex stays");
}

#[test]
fn a_delete_removes_the_boxes_left_by_a_profile_that_is_already_gone() {
    let home = Home::new();
    home.saved(CLAUDE_A, "claude");
    home.saved(CLAUDE_B, "claude");

    let output = home.profile_command(&["delete", "claude", "--no-ask"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("box: deleted what is left of profile claude, with 2 boxes"),
        "{}",
        stderr(&output)
    );
    assert!(!home.exists(CLAUDE_A) && !home.exists(CLAUDE_B));
}

#[test]
fn a_reset_of_a_storage_folder_that_holds_only_the_name_record_finds_no_storage() {
    let home = Home::new();
    let folder = home.box_home().join("storage/claude");
    std::fs::create_dir_all(&folder).expect("a storage folder");
    std::fs::write(folder.join(".profile-source"), "/work/profile.toml\n").expect("a record");

    let output = home.profile_command(&["reset", "claude", "--no-ask"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("box: no storage found for profile claude"),
        "{}",
        stderr(&output)
    );
    assert!(folder.join(".profile-source").exists());
}

#[test]
fn several_running_boxes_are_named_and_stop_a_delete_or_reset() {
    for command in ["delete", "reset"] {
        let home = Home::new();
        let claude = home.profile("claude");
        let storage = home.storage("claude");
        home.saved(CLAUDE_A, "claude");
        home.saved(CLAUDE_B, "claude");
        let _a = running(&home.runs(), CLAUDE_A);
        let _b = running(&home.runs(), CLAUDE_B);

        let output = home.profile_command(&[command, "claude", "--no-ask"]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{command}: {}",
            stderr(&output)
        );
        let message = stderr(&output)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            message.contains("these boxes are still running, so nothing was removed")
                && message.contains(CLAUDE_A)
                && message.contains(CLAUDE_B)
                && message.contains(&format!("box profile {command} again")),
            "{command}: {message}"
        );
        assert!(
            claude.exists() && storage.join("default").exists(),
            "{command}"
        );
    }
}

#[test]
fn a_stray_storage_folder_does_not_stop_delete_or_reset_of_all() {
    for command in ["reset", "delete"] {
        let home = Home::new();
        let claude = home.storage("claude");
        let stray = home.box_home().join("storage/My Stuff");
        std::fs::create_dir_all(&stray).expect("a stray folder");

        let output = home.profile_command(&[command, "--all", "--no-ask"]);
        assert!(output.status.success(), "{command}: {}", stderr(&output));
        assert!(!claude.join("default").exists(), "{command}");
        assert!(
            stray.exists(),
            "{command}: box leaves a folder that names no profile"
        );
    }
}

#[test]
fn a_name_with_nothing_to_remove_is_named_beside_the_others() {
    let home = Home::new();
    home.profile("claude");
    home.storage("claude");
    let delete = home.profile_command(&["delete", "claude", "nosuch", "--no-ask"]);
    assert!(delete.status.success(), "{}", stderr(&delete));
    assert!(
        stderr(&delete).contains("box: no profile nosuch found"),
        "{}",
        stderr(&delete)
    );

    home.storage("codex");
    let reset = home.profile_command(&["reset", "codex", "nosuch", "--no-ask"]);
    assert!(reset.status.success(), "{}", stderr(&reset));
    assert!(
        stderr(&reset).contains("box: no storage found for profile nosuch"),
        "{}",
        stderr(&reset)
    );
}

#[test]
fn a_delete_of_all_removes_a_profile_folder_that_lost_its_profile_file() {
    let home = Home::new();
    let broken = home.box_home().join("profiles/claude");
    std::fs::create_dir_all(&broken).expect("a profile folder");
    std::fs::write(broken.join("policy.dw"), "x\n").expect("a policy");

    let output = home.profile_command(&["delete", "--all", "--no-ask"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("box: deleted every profile"),
        "{}",
        stderr(&output)
    );
    assert!(
        !broken.exists(),
        "nothing is left for box profile create to refuse"
    );
}
