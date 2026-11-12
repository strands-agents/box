//! Native FSEvents and direct filesystem refusals through the shipped Box launcher.
#![cfg(all(target_os = "macos", feature = "test-support"))]

use std::fs::File;
use std::io::{Read, Seek};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[path = "support/fixture.rs"]
mod fixture;

struct WatchBox {
    _root: tempfile::TempDir,
    _compiled: tempfile::TempDir,
    workspace: PathBuf,
    config: PathBuf,
}

impl WatchBox {
    fn new(agent_selection: Option<bool>, tool_selection: Option<bool>) -> Self {
        let root = fixture::short_temporary_home();
        let directory = root.path().canonicalize().unwrap();
        let workspace = directory.join("workspace");
        std::fs::create_dir_all(workspace.join("denied")).unwrap();
        std::fs::write(workspace.join("denied/seed"), "secret").unwrap();
        std::fs::write(workspace.join("allowed"), "readable").unwrap();
        std::fs::write(workspace.join("modified"), "before").unwrap();
        // Keep compiled probes on the same filesystem as Cargo's test binary.
        let test_binary = std::env::current_exe().unwrap();
        let compiled = tempfile::Builder::new()
            .prefix("file-watch-probe-")
            .tempdir_in(test_binary.parent().unwrap())
            .unwrap();
        let probe = compiled.path().join("watcher");
        let build = Command::new("/usr/bin/cc")
            .args([
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-deprecated-declarations",
            ])
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/file_watch_probe.c"))
            .args(["-framework", "CoreServices", "-o"])
            .arg(&probe)
            .output()
            .unwrap();
        assert!(build.status.success(), "{build:?}");
        let setting = |value: Option<bool>| {
            value.map_or(String::new(), |v| format!("native-file-watching = {v}\n"))
        };
        let grants = format!(
            "read = [{workspace:?}]\nwrite = [{workspace:?}]\n\
             deny = [{denied:?}]\n",
            denied = workspace.join("denied")
        );
        let command = if tool_selection.is_some() {
            vec![
                "/bin/bash".to_string(),
                "-c".into(),
                format!("bash -c 'watcher {}'", workspace.display()),
            ]
        } else {
            vec![
                probe.to_str().unwrap().to_string(),
                workspace.to_str().unwrap().to_string(),
            ]
        };
        let policy = directory.join("policy.dw");
        std::fs::write(
            &policy,
            "permit(principal, action == Box::Action::\"shell:exec\", resource);\n\
             permit(principal, action == Box::Action::\"shell:spawn\", resource);\n",
        )
        .unwrap();
        let mut text = format!(
            "name = \"watch\"\nbox_dir = {box_dir:?}\npolicy = {policy:?}\n\
             [agent]\ncommand = {command:?}\nworkspace = {workspace:?}\n\
             env = {{ PATH = \"/usr/bin:/bin\" }}\n\
             {selection}[agent.filesystem]\n{grants}",
            box_dir = directory.join("box"),
            selection = setting(agent_selection),
        );
        if tool_selection.is_some() {
            text.push_str(&format!(
                "[tool.watcher]\ncommand = [{probe:?}, {workspace:?}]\n\
                 env = {{ PATH = \"/usr/bin:/bin\" }}\n\
                 {selection}[tool.watcher.filesystem]\n{grants}",
                selection = setting(tool_selection),
            ));
        }
        let config = directory.join("box.toml");
        std::fs::write(&config, text).unwrap();
        Self {
            _root: root,
            _compiled: compiled,
            workspace,
            config,
        }
    }

    fn start(&self) -> Watching {
        let stderr = tempfile::tempfile().unwrap();
        let child = Command::new(fixture::box_binary())
            .args(["run", "--config"])
            .arg(&self.config)
            .current_dir(&self.workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr.try_clone().unwrap())
            .process_group(0)
            .spawn()
            .unwrap();
        Watching {
            child,
            progress: self.workspace.join("watch-progress"),
            lines_read: 0,
            transcript: String::new(),
            stderr,
        }
    }

    fn changes(&self, running: &mut Watching) {
        running.expect("WATCH_READY", None);
        let first = self.workspace.join("created");
        std::fs::write(&first, "one").unwrap();
        running.expect("EVENT created ", Some(0x100));
        std::fs::write(self.workspace.join("modified"), "after").unwrap();
        running.expect("EVENT modified ", Some(0x1000));
        let renamed = self.workspace.join("renamed");
        std::fs::rename(first, &renamed).unwrap();
        running.expect("EVENT renamed ", Some(0x800));
        std::fs::remove_file(renamed).unwrap();
        running.expect("EVENT renamed ", Some(0x200));
        std::fs::write(self.workspace.join("finish"), "").unwrap();
        running.expect("ACCESS_OK", None);
    }
}

struct Watching {
    child: Child,
    progress: PathBuf,
    lines_read: usize,
    transcript: String,
    stderr: File,
}

impl Watching {
    fn stderr(&mut self) -> String {
        self.stderr.rewind().unwrap();
        let mut text = String::new();
        self.stderr.read_to_string(&mut text).unwrap();
        text
    }

    fn expect(&mut self, prefix: &str, flag: Option<u32>) {
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            let progress = std::fs::read_to_string(&self.progress).unwrap_or_default();
            for line in progress
                .split_inclusive('\n')
                .take_while(|line| line.ends_with('\n'))
                .skip(self.lines_read)
            {
                self.lines_read += 1;
                let line = line.trim_end_matches('\n');
                self.transcript.push_str(line);
                self.transcript.push('\n');
                if line.starts_with(prefix)
                    && flag.is_none_or(|flag| {
                        line.split_whitespace()
                            .last()
                            .unwrap()
                            .parse::<u32>()
                            .is_ok_and(|flags| flags & flag != 0)
                    })
                {
                    return;
                }
            }
            let exited = self.child.try_wait().unwrap().is_some();
            if exited && std::fs::read_to_string(&self.progress).unwrap_or_default() != progress {
                continue;
            }
            if Instant::now() >= deadline || exited {
                let stderr = self.stderr();
                panic!("missing {prefix:?}: {}\n{stderr}", self.transcript);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn finish(&mut self) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                let stderr = self.stderr();
                assert!(status.success(), "{}\n{stderr}", self.transcript);
                return stderr;
            }
            assert!(Instant::now() < deadline, "Box did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Watching {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            // SAFETY: the live child leads the private process group created by this test.
            unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn an_agent_must_opt_in_before_fsevents_starts() {
    for selection in [None, Some(false)] {
        let fixture = WatchBox::new(selection, None);
        let mut running = fixture.start();
        running.expect("ACCESS_OK", None);
        running.expect("WATCH_REFUSED", None);
        assert!(!running.finish().contains("native file watching:"));
    }
}

#[test]
fn an_opted_in_agent_watches_changes_and_keeps_direct_denials() {
    let fixture = WatchBox::new(Some(true), None);
    let mut running = fixture.start();
    running.expect("ACCESS_OK", None);
    fixture.changes(&mut running);
    let stderr = running.finish();
    assert!(stderr.contains("[agent] native file watching:"));
    assert!(stderr.contains("outside the workspace and from past events"));
    assert_eq!(
        std::fs::read_to_string(fixture.workspace.join("denied/seed")).unwrap(),
        "secret"
    );
}

#[test]
fn an_opted_in_tool_watches_without_enabling_its_agent() {
    let fixture = WatchBox::new(None, Some(true));
    let mut running = fixture.start();
    running.expect("ACCESS_OK", None);
    fixture.changes(&mut running);
    let stderr = running.finish();
    assert!(stderr.contains("[tool.watcher] native file watching:"));
    assert!(!stderr.contains("[agent] native file watching:"));
}

#[test]
fn an_agent_opt_in_does_not_enable_a_tool() {
    let fixture = WatchBox::new(Some(true), Some(false));
    let mut running = fixture.start();
    running.expect("ACCESS_OK", None);
    running.expect("WATCH_REFUSED", None);
    let stderr = running.finish();
    assert!(stderr.contains("[agent] native file watching:"));
    assert!(!stderr.contains("[tool.watcher] native file watching:"));
}
