use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use nix::libc;

struct Host {
    _root: tempfile::TempDir,
    home: PathBuf,
    project: PathBuf,
}

impl Host {
    fn new(starter: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let shared = home.join(".strands/box/packs/helper");
        let project = root.path().join("project");
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            shared.join("pack.toml"),
            "[pack]\nname = \"helper\"\nversion = 1\nkind = \"agent\"\n\
             [run]\ncommand = [\"/usr/bin/true\"]\n",
        )
        .unwrap();
        if starter {
            let folder = home.join(".strands/box/starters/helper");
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(
                folder.join("starter.toml"),
                "[starter]\nname = \"helper\"\nlabel = \"Helper\"\npacks = [\"helper\"]\n\
                 policy = \"@box/scoped\"\n",
            )
            .unwrap();
            std::fs::write(
                home.join(".strands/box/config.toml"),
                "[starters]\nonly = [\"helper\"]\n",
            )
            .unwrap();
        }
        Self {
            _root: root,
            home,
            project,
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_box"));
        command
            .args(args)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", "/usr/bin:/bin")
            .env("TERM", "xterm-256color")
            .env("NO_COLOR", "1")
            .current_dir(&self.project);
        command
    }

    fn profile(&self) -> PathBuf {
        self.home.join(".strands/box/profiles/helper/profile.toml")
    }

    fn create(&self) {
        let output = self
            .command(&[
                "profile", "create", "helper", "--with", "helper", "--policy", "scoped", "--tools",
                "git",
            ])
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }

    /// Run `args` in a pseudo-terminal, send each step's keys once the screen shows its text, and
    /// return the last screen.
    fn drive(&self, args: &[&str], steps: &[(&str, &str)], exit: i32) -> String {
        let size = libc::winsize {
            ws_row: 40,
            ws_col: 120,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pair = nix::pty::openpty(Some(&size), None).unwrap();
        let mut master = File::from(pair.master);
        let slave = File::from(pair.slave);
        // SAFETY: master owns this descriptor throughout the test.
        assert_eq!(
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let mut child = self
            .command(args)
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave)
            .spawn()
            .unwrap();
        let mut parser = vt100::Parser::new(40, 120, 0);
        let mut next = 0;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let mut bytes = [0; 8192];
            if let Ok(count) = master.read(&mut bytes) {
                parser.process(&bytes[..count]);
                while let Some((expected, keys)) = steps.get(next)
                    && words(&parser.screen().contents()).contains(&words(expected))
                {
                    master.write_all(keys.as_bytes()).unwrap();
                    next += 1;
                    if !keys.is_empty() {
                        break;
                    }
                }
            }
            if let Some(status) = child.try_wait().unwrap() {
                while let Ok(count) = master.read(&mut bytes) {
                    if count == 0 {
                        break;
                    }
                    parser.process(&bytes[..count]);
                }
                let screen = parser.screen().contents();
                assert_eq!(next, steps.len(), "{screen}");
                assert_eq!(status.code(), Some(exit), "{screen}");
                return screen;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("step {next}: {}", parser.screen().contents());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

fn words(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn saved_profile_edit_errors_return_to_the_saved_profile() {
    let host = Host::new(false);
    host.drive(
        &[
            "profile", "create", "helper", "--with", "helper", "--policy", "scoped", "--tools",
            "git",
        ],
        &[
            ("Save this profile?", "\r"),
            ("Profile saved", "\x1b[B\r"),
            ("guided setup is not available", "\x1b"),
            ("Profile saved", "\x1b"),
        ],
        0,
    );
    assert!(host.profile().is_file());
}

#[test]
fn bare_profile_prints_help_at_a_terminal() {
    let host = Host::new(true);
    let screen = host.drive(&["profile"], &[], 2);
    assert!(screen.contains("Usage: box profile <COMMAND>"), "{screen}");
    for command in ["create", "edit", "list", "show", "clean", "reset", "delete"] {
        assert!(
            screen
                .lines()
                .any(|line| line.split_whitespace().next() == Some(command)),
            "help must list {command}: {screen}"
        );
    }
    assert!(!screen.contains("Manage profiles"), "{screen}");
}

#[test]
fn edit_reopens_a_saved_profile_and_shows_its_summary() {
    let host = Host::new(true);
    host.create();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(host.profile())
        .unwrap();
    writeln!(file, "# kept by edit").unwrap();
    let policy = host.profile().with_file_name("policy.dw");
    let before = read(&policy);
    host.drive(
        &["profile", "edit", "helper"],
        &[
            ("Keep current policy", "\x1b[B\r"),
            ("Save changes to this profile?", "\r"),
            ("Profile saved", ""),
            ("> Run", ""),
            ("  Edit", ""),
            ("  Exit", "\x1b[B\x1b[B\r"),
        ],
        0,
    );
    assert_eq!(read(&policy), before);
    let profile = read(&host.profile());
    assert!(
        profile.contains("policies = [\"policy-1.dw\"]"),
        "{profile}"
    );
    assert!(profile.contains("# kept by edit"), "{profile}");
    let chosen = read(&host.profile().with_file_name("policy-1.dw"));
    assert!(chosen.contains("@box/open"), "{chosen}");
}

#[test]
fn a_cancelled_edit_leaves_the_profile_unchanged() {
    let host = Host::new(true);
    host.create();
    let before = read(&host.profile());
    let screen = host.drive(
        &["profile", "edit", "helper"],
        &[
            ("Keep current policy", "\r"),
            ("Save changes to this profile?", "\x1b[B\x1b[B\r"),
        ],
        1,
    );
    assert!(
        screen.contains("Cancelled. The profile is unchanged."),
        "{screen}"
    );
    assert_eq!(read(&host.profile()), before);
}

#[test]
fn edit_without_a_terminal_names_the_file_to_edit() {
    let host = Host::new(true);
    host.create();
    let before = read(&host.profile());
    let modified = std::fs::metadata(host.profile())
        .unwrap()
        .modified()
        .unwrap();
    let output = host
        .command(&["profile", "edit", "helper"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("box profile edit needs a terminal"),
        "{stderr}"
    );
    let unwrapped: String = stderr.split_whitespace().collect();
    assert!(
        unwrapped.contains(host.profile().to_str().unwrap()),
        "{stderr}"
    );
    assert_eq!(read(&host.profile()), before);
    assert_eq!(
        std::fs::metadata(host.profile())
            .unwrap()
            .modified()
            .unwrap(),
        modified
    );
}

#[test]
fn edit_refuses_a_missing_profile() {
    let host = Host::new(true);
    let output = host
        .command(&["profile", "edit", "helper"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("no profile named helper"), "{stderr}");
    assert!(!host.profile().exists());
}

#[test]
fn edit_refuses_a_profile_without_a_starter() {
    let host = Host::new(false);
    host.create();
    let output = host
        .command(&["profile", "edit", "helper"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    let words = stderr.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(words.contains("guided setup is not available"), "{stderr}");
}
