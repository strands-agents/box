//! `box run` against a real engine.
#![cfg(any(target_os = "macos", all(target_os = "linux", target_arch = "aarch64")))]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// A profile that runs `bash` as the agent. The corpus's scripted layer runs the same file.
const PROBE: &str = include_str!("../../../../test-corpus/profiles/probe/profile.toml");

/// The probe's own policy, which lets the box's shell run. `box` writes no such rule: the policy
/// starters hold it.
const PROBE_POLICY: &str =
    r#"@id("probe_shell") permit (principal, action == Box::Action::"shell:exec", resource);"#;

/// The `@box/scoped` policy starter, which `box profile create --policy scoped` copies.
const SCOPED_STARTER: &str = include_str!("../../../../resources/policies/scoped/policy.dw");

/// The `@box/locked` policy starter, which `box profile create --policy locked` copies.
const LOCKED_STARTER: &str = include_str!("../../../../resources/policies/locked/policy.dw");

/// A home, a workspace below it, and a directory outside it.
struct Scene {
    _root: tempfile::TempDir,
    _outside: tempfile::TempDir,
    root: PathBuf,
    outside: PathBuf,
}

impl Scene {
    /// A scene.
    fn new() -> Self {
        let parent = PathBuf::from(std::env::var_os("HOME").expect("HOME")).join(".cache");
        std::fs::create_dir_all(&parent).expect("a cache directory");
        let directory = tempfile::Builder::new()
            .prefix("bx")
            .tempdir_in(parent)
            .expect("a temporary root");
        let outside = tempfile::Builder::new()
            .prefix("bx")
            .tempdir_in("/tmp")
            .expect("a directory outside the home");
        let scene = Self {
            root: directory.path().canonicalize().expect("a canonical root"),
            outside: outside
                .path()
                .canonicalize()
                .expect("a canonical directory"),
            _root: directory,
            _outside: outside,
        };
        std::fs::create_dir_all(scene.workspace()).expect("a workspace");
        scene.profile("probe", PROBE, PROBE_POLICY);
        scene
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn workspace(&self) -> PathBuf {
        self.home().join("project")
    }

    fn outside(&self) -> PathBuf {
        self.outside.clone()
    }

    /// Write the profile `name`, with the `[project] access = "write"` that `box profile create`
    /// writes when `text` holds no `[project]`.
    fn profile(&self, name: &str, text: &str, policy: &str) {
        let folder = self.home().join(".strands/box/profiles").join(name);
        std::fs::create_dir_all(&folder).expect("a profile folder");
        let text = if text.contains("[project]") {
            text.to_string()
        } else {
            format!("{text}\n\n[project]\naccess = \"write\"\n")
        };
        let text = if policy.is_empty() {
            text
        } else {
            format!("policies = [\"policy.dw\"]\n{text}")
        };
        std::fs::write(folder.join("profile.toml"), text).expect("a profile");
        if !policy.is_empty() {
            std::fs::write(folder.join("policy.dw"), policy).expect("a policy");
        }
    }

    /// Write the operator pack `~/.strands/box/packs/<name>`.
    fn pack(&self, name: &str, text: &str) {
        let folder = self.home().join(".strands/box/packs").join(name);
        std::fs::create_dir_all(&folder).expect("a pack folder");
        std::fs::write(folder.join("pack.toml"), text).expect("a pack");
    }

    fn process(&self, program: &Path) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("HOME", self.home())
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null());
        command
    }

    fn command(&self, workspace: &Path, profile: &str, args: &[&str]) -> Command {
        self.command_with(workspace, profile, &[], args)
    }

    /// `box run <profile> <flags> -- <args>` in `workspace`.
    fn command_with(
        &self,
        workspace: &Path,
        profile: &str,
        flags: &[&str],
        args: &[&str],
    ) -> Command {
        let mut command = self.process(Path::new(env!("CARGO_BIN_EXE_box")));
        command
            .arg("run")
            .arg(profile)
            .args(flags)
            .arg("--")
            .args(args)
            .current_dir(workspace);
        command
    }

    /// Run `script` in bash in a new box in `workspace`.
    fn probe(&self, workspace: &Path, script: &str) -> Output {
        self.command(workspace, "probe", &["-c", script])
            .output()
            .expect("box runs")
    }

    fn runs(&self) -> Vec<PathBuf> {
        let mut runs: Vec<PathBuf> = std::fs::read_dir(self.home().join(".strands/box/r"))
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default();
        runs.sort();
        runs
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn succeeded(output: &Output) {
    assert!(
        output.status.success(),
        "status: {}\n{}\n{}",
        output.status,
        stdout(output),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn box_core_accepts_the_shell_size_limits_a_profile_sets() {
    for limits in [
        "max_input = 524288\nmax_output = 131072\nmax_stdin = 1048576\n",
        "max_input = 0\nmax_output = 0\nmax_stdin = 1\n",
    ] {
        let scene = Scene::new();
        scene.profile(
            "probe",
            &format!("{PROBE}\n[limits.shell]\n{limits}"),
            PROBE_POLICY,
        );
        let output = scene.probe(&scene.workspace(), "bash -c 'echo ready'");
        succeeded(&output);
        assert_eq!(stdout(&output), "ready\n");

        let config: toml::Table = std::fs::read_to_string(scene.runs()[0].join("box.toml"))
            .expect("compiled config")
            .parse()
            .expect("TOML");
        let expected =
            toml::Value::Table(format!("{limits}timeout = false\n").parse().expect("TOML"));
        assert_eq!(config["limits"]["shell"], expected, "{limits}");
    }
}

#[test]
fn an_npm_tool_with_installation_layouts_passes_core_validation() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let scene = Scene::new();
    let install = scene.root.join("hostedtoolcache/node/22/arm64");
    let bin = install.join("bin");
    let package = install.join("lib/node_modules/npm");
    std::fs::create_dir_all(&bin).expect("node bin");
    std::fs::create_dir_all(package.join("bin")).expect("npm package");
    std::fs::copy("/bin/echo", bin.join("node")).expect("a native executable");
    let npm = package.join("bin/npm-cli.js");
    std::fs::write(&npm, "#!/usr/bin/env node\n").expect("npm entry point");
    std::fs::set_permissions(&npm, std::fs::Permissions::from_mode(0o755)).expect("executable npm");
    symlink("../lib/node_modules/npm/bin/npm-cli.js", bin.join("npm")).expect("npm link");
    scene.profile(
        "npm",
        &format!("packs = [\"@box/npm\"]\n{PROBE}"),
        PROBE_POLICY,
    );

    let output = scene
        .command(&scene.workspace(), "npm", &["-c", "printf accepted"])
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .output()
        .expect("box runs");
    succeeded(&output);
    assert_eq!(stdout(&output), "accepted");

    let config: toml::Table = std::fs::read_to_string(scene.runs()[0].join("box.toml"))
        .expect("compiled config")
        .parse()
        .expect("TOML");
    let filesystem = &config["tool"]["npm"]["filesystem"];
    let node_bin = toml::Value::String(bin.canonicalize().unwrap().display().to_string());
    assert!(
        filesystem["read"].as_array().unwrap().contains(&node_bin),
        "node's folder comes through npm's #! line: {filesystem}"
    );
    let package = toml::Value::String(
        package
            .parent()
            .unwrap()
            .canonicalize()
            .unwrap()
            .display()
            .to_string(),
    );
    assert!(
        filesystem["read"].as_array().unwrap().contains(&package),
        "{filesystem}"
    );
}

#[test]
fn a_helper_python_outside_homebrew_passes_core_validation() {
    use std::os::unix::fs::symlink;

    let scene = Scene::new();
    let python = scene
        .root
        .join("Python.framework/Versions/3.12/bin/python3.12");
    let python_bin = python.parent().expect("python's bin").to_path_buf();
    std::fs::create_dir_all(&python_bin).expect("python bin");
    std::fs::create_dir_all(python_bin.with_file_name("lib/python3.12")).expect("python lib");
    std::fs::copy("/bin/echo", &python).expect("a native executable");
    symlink("python3.12", python_bin.join("python3")).expect("python3 link");
    let uv_bin = scene.root.join("hostedtoolcache/uv/0.13.7/aarch64");
    std::fs::create_dir_all(&uv_bin).expect("uv folder");
    std::fs::copy("/bin/echo", uv_bin.join("uvx")).expect("a native executable");
    scene.profile(
        "uvx",
        &format!("packs = [\"@box/uvx\"]\n{PROBE}"),
        PROBE_POLICY,
    );

    let output = scene
        .command(&scene.workspace(), "uvx", &["-c", "printf accepted"])
        .env(
            "PATH",
            format!(
                "{}:{}:/usr/bin:/bin",
                uv_bin.display(),
                python_bin.display()
            ),
        )
        .output()
        .expect("box runs");
    succeeded(&output);
    assert_eq!(stdout(&output), "accepted");

    let config: toml::Table = std::fs::read_to_string(scene.runs()[0].join("box.toml"))
        .expect("compiled config")
        .parse()
        .expect("TOML");
    let filesystem = &config["tool"]["uvx"]["filesystem"];
    // The helper is granted by the name `PATH` finds it by, which Box Core shows its file at.
    let python = toml::Value::String(
        python_bin
            .canonicalize()
            .unwrap()
            .join("python3")
            .display()
            .to_string(),
    );
    assert!(
        filesystem["read"].as_array().unwrap().contains(&python),
        "{filesystem}"
    );
    assert!(filesystem.get("read_file").is_none(), "{filesystem}");
}

fn wait_for_output(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().expect("the process status").is_none() {
        if Instant::now() >= deadline {
            Command::new("/bin/kill")
                .args(["-TERM", &child.id().to_string()])
                .status()
                .expect("ask Box to stop the timed-out run");
            let grace = Instant::now() + Duration::from_secs(5);
            while child.try_wait().expect("the process status").is_none() {
                if Instant::now() >= grace {
                    child.kill().expect("stop the unresponsive process");
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            child.wait().expect("reap the timed-out run");
            panic!("the run exceeded 60 seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().expect("the run output")
}

#[test]
fn profile_edits_wait_for_a_manual_reload_and_policy_off_records_its_rule() {
    use std::io::{Read as _, Write as _};
    use std::os::unix::{fs::MetadataExt as _, process::CommandExt as _};
    use std::sync::mpsc;

    let scene = Scene::new();
    let folder = scene.home().join(".strands/box/profiles/probe");
    let allow = "permit (principal, action, resource);";
    let deny = format!(
        "{allow}\nforbid (principal, action == Box::Action::\"fs:read\", resource) \
         when {{ context.input.path like \"*/target.txt\" }};"
    );
    scene.profile("probe", PROBE, &deny);
    std::fs::write(scene.workspace().join("target.txt"), "content").unwrap();
    let script = r#"printf 'READY\n'
while IFS= read -r request; do
  [ "$request" = quit ] && break
  if bash -c 'cat target.txt' >/dev/null 2>&1; then result=OK; else result=DENIED; fi
  printf '%s %s %s\n' "$result" "$request" "$$"
done"#;
    let size = nix::pty::Winsize {
        ws_row: 40,
        ws_col: 120,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pair = nix::pty::openpty(Some(&size), None).unwrap();
    let mut input = std::fs::File::from(pair.master);
    let mut output = input.try_clone().unwrap();
    let slave = std::fs::File::from(pair.slave);
    let mut command = scene.command(&scene.workspace(), "probe", &["-c", script]);
    command
        .env("TERM", "xterm-256color")
        .stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave);
    // SAFETY: only async-signal-safe terminal setup runs between fork and exec.
    unsafe {
        command.pre_exec(|| {
            if nix::libc::setsid() < 0 || nix::libc::ioctl(0, nix::libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    drop(command);
    let (send, received) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = [0; 8192];
        while let Ok(count) = output.read(&mut bytes) {
            if count == 0 || send.send(bytes[..count].to_vec()).is_err() {
                break;
            }
        }
    });
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut screen = vt100::Parser::new(40, 120, 0);
        let mut wait = |needle: &str| {
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                let text = screen.screen().contents();
                if text.contains(needle) {
                    return text;
                }
                let bytes = received
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .unwrap_or_else(|error| panic!("{error}: missing {needle:?}\n{text}"));
                screen.process(&bytes);
            }
        };
        wait("READY");
        let mut request = 0;
        let mut keys = input.try_clone().unwrap();
        let mut check = |outcome: &str| {
            request += 1;
            writeln!(keys, "{request}").unwrap();
            format!("{outcome} {request} ")
        };
        let first = wait(&check("DENIED"));
        let pid = first
            .lines()
            .find_map(|line| line.strip_prefix("DENIED 1 "))
            .unwrap()
            .to_string();
        let run = new_run(&[], &scene.runs());
        let snapshot = || {
            ["box.toml", "policy.dw"].map(|name| {
                let path = run.join(name);
                (
                    std::fs::read(&path).unwrap(),
                    std::fs::metadata(path).unwrap().ino(),
                )
            })
        };
        let original = snapshot();
        let edit = |path: &Path, text: &str| {
            let temporary = path.with_extension("saving");
            std::fs::write(&temporary, text).unwrap();
            std::fs::rename(temporary, path).unwrap();
        };
        std::fs::create_dir(folder.join("rules")).unwrap();
        let nested = folder.join("rules/extra.dw");
        std::fs::write(&nested, allow).unwrap();
        let profile_path = folder.join("profile.toml");
        let profile = std::fs::read_to_string(&profile_path).unwrap();
        edit(
            &profile_path,
            &profile.replace("policy.dw", "rules/extra.dw"),
        );
        wait("UPDATE READY");
        wait(&check("DENIED"));
        input.write_all(b"\x1b\x12").unwrap();
        wait("POLICY RELOADED");
        wait(&check("OK"));
        edit(&nested, &deny);
        wait("UPDATE READY");
        wait(&check("OK"));
        input.write_all(b"\x1b\x12").unwrap();
        wait("POLICY RELOADED");
        let outcome = check("DENIED");
        assert!(wait(&outcome).contains(&format!("{outcome}{pid}")));
        edit(&nested, "invalid policy");
        wait("POLICY ON (update failed)");
        wait(&check("DENIED"));
        assert_eq!(snapshot(), original);
        input.write_all(b"\x1c").unwrap();
        wait("POLICY OFF");
        wait(&check("OK"));
    }));
    let _ = input.write_all(b"quit\n");
    let output = wait_for_output(child);
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
    succeeded(&output);
    let run = new_run(&[], &scene.runs());
    let decisions = decisions(&run);
    assert!(
        decisions
            .iter()
            .any(|(action, path, rule)| action == "fs:read"
                && path.ends_with("/target.txt")
                && rule == "policy_off"),
        "{decisions:?}"
    );
    let records = std::fs::read_to_string(run.join("records.jsonl")).expect("records");
    assert!(records.contains(r#""policy is off""#), "{records}");
    assert!(
        records.contains(
            r#""key":"strands.box.control.subject","value":{"stringValue":"policy off"}"#
        ),
        "{records}"
    );
}

/// **Policy off keeps the rules `box` writes**: with a profile policy that permits everything, the
/// box's shell cannot append to the profile's `policy.dw` with policy on or off, so a run cannot
/// plant rules that the next run loads.
#[test]
fn policy_off_still_refuses_a_write_to_the_profiles_policy() {
    use std::io::{Read as _, Write as _};
    use std::os::unix::process::CommandExt as _;
    use std::sync::mpsc;

    let scene = Scene::new();
    let target = scene.home().join(".strands/box/profiles/probe/policy.dw");
    scene.profile("probe", PROBE, "permit (principal, action, resource);");
    let script = format!(
        r#"printf 'READY\n'
while IFS= read -r request; do
  [ "$request" = quit ] && break
  if bash -c 'printf "\n// planted\n" >> {}' >/dev/null 2>&1; then result=WROTE; else result=REFUSED; fi
  printf '%s %s\n' "$result" "$request"
done"#,
        target.display()
    );
    let size = nix::pty::Winsize {
        ws_row: 40,
        ws_col: 120,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pair = nix::pty::openpty(Some(&size), None).unwrap();
    let mut input = std::fs::File::from(pair.master);
    let mut output = input.try_clone().unwrap();
    let slave = std::fs::File::from(pair.slave);
    let mut command = scene.command(&scene.workspace(), "probe", &["-c", &script]);
    command
        .env("TERM", "xterm-256color")
        .stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave);
    // SAFETY: only async-signal-safe terminal setup runs between fork and exec.
    unsafe {
        command.pre_exec(|| {
            if nix::libc::setsid() < 0 || nix::libc::ioctl(0, nix::libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    drop(command);
    let (send, received) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = [0; 8192];
        while let Ok(count) = output.read(&mut bytes) {
            if count == 0 || send.send(bytes[..count].to_vec()).is_err() {
                break;
            }
        }
    });
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut screen = vt100::Parser::new(40, 120, 0);
        let mut wait = |needle: &str| {
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                let text = screen.screen().contents();
                if text.contains(needle) {
                    return;
                }
                let bytes = received
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .unwrap_or_else(|error| panic!("{error}: missing {needle:?}\n{text}"));
                screen.process(&bytes);
            }
        };
        wait("READY");
        writeln!(input, "1").unwrap();
        wait("REFUSED 1");
        input.write_all(b"\x1c").unwrap();
        wait("POLICY OFF");
        writeln!(input, "2").unwrap();
        wait("REFUSED 2");
    }));
    let _ = input.write_all(b"quit\n");
    let output = wait_for_output(child);
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
    succeeded(&output);
    let text = std::fs::read_to_string(&target).unwrap();
    assert!(!text.contains("planted"), "{text}");
}

/// Run `box run probe <flags> -- -c <script>` at a 40x200 pseudo-terminal with the banner on. Wait
/// for each of `needles` in order on the screen, then send a line so the script can finish. Return
/// the screen as it was when the last needle appeared.
fn banner_run(scene: &Scene, flags: &[&str], script: &str, needles: &[&str]) -> String {
    use std::io::{Read as _, Write as _};
    use std::os::unix::process::CommandExt as _;
    use std::sync::mpsc;

    let size = nix::pty::Winsize {
        ws_row: 40,
        ws_col: 200,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pair = nix::pty::openpty(Some(&size), None).unwrap();
    let mut input = std::fs::File::from(pair.master);
    let mut output = input.try_clone().unwrap();
    let slave = std::fs::File::from(pair.slave);
    let mut command = scene.command_with(&scene.workspace(), "probe", flags, &["-c", script]);
    command
        .env("TERM", "xterm-256color")
        .stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave);
    // SAFETY: only async-signal-safe terminal setup runs between fork and exec.
    unsafe {
        command.pre_exec(|| {
            if nix::libc::setsid() < 0 || nix::libc::ioctl(0, nix::libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    drop(command);
    let (send, received) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = [0; 8192];
        while let Ok(count) = output.read(&mut bytes) {
            if count == 0 || send.send(bytes[..count].to_vec()).is_err() {
                break;
            }
        }
    });
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut screen = vt100::Parser::new(40, 200, 0);
        for needle in needles {
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                let text = screen.screen().contents();
                if text.contains(needle) {
                    break;
                }
                let bytes = received
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .unwrap_or_else(|error| panic!("{error}: missing {needle:?}\n{text}"));
                screen.process(&bytes);
            }
        }
        screen.screen().contents()
    }));
    let _ = input.write_all(b"done\n");
    let output = wait_for_output(child);
    match result {
        Ok(screen) => {
            succeeded(&output);
            screen
        }
        Err(error) => std::panic::resume_unwind(error),
    }
}

#[test]
fn the_banner_counts_every_denial_of_a_burst_that_the_records_hold() {
    const FILES: usize = 120;
    let scene = Scene::new();
    scene.profile(
        "probe",
        PROBE,
        "permit (principal, action, resource);\n@id(\"no_denied\")\nforbid (principal, \
         action == Box::Action::\"fs:read\", resource) when { context.input.path like \
         \"*.denied\" };",
    );
    let names: Vec<String> = (0..FILES).map(|index| format!("f{index}.denied")).collect();
    for name in &names {
        std::fs::write(scene.workspace().join(name), "secret").unwrap();
    }
    let script = format!(
        "printf 'READY\\n'\nbash -c 'for name in {}; do cat \"$name\"; done' >/dev/null 2>&1\n\
         printf 'DONE\\n'\nIFS= read -r request\n",
        names.join(" ")
    );
    let counted = format!("{FILES} operations denied");
    let _ = banner_run(
        &scene,
        &[],
        &script,
        &["READY", "BLOCKED fs:read ", ".denied", "DONE", &counted],
    );
    let run = new_run(&[], &scene.runs());
    let refused = decisions(&run)
        .into_iter()
        .filter(|(action, path, rule)| {
            action == "fs:read" && path.ends_with(".denied") && rule == "no_denied"
        })
        .count();
    assert_eq!(refused, FILES, "the records hold one refusal per file");

    // A rerun of the same box starts from the denials that history lists. That none of them shows
    // as a new denial is pinned by the banner's unit test: the notice lasts 5 seconds, and a debug
    // box can take longer than that to draw its first frame.
    let id = box_id(&run);
    let _ = banner_run(
        &scene,
        &["--box-id", &id],
        "printf 'AGAIN\\n'\nIFS= read -r request\n",
        &["AGAIN", &counted],
    );
}

#[test]
fn fifo_profile_sources_are_refused_without_blocking() {
    for name in ["policy.dw", "profile.toml"] {
        let scene = Scene::new();
        let path = scene.home().join(".strands/box/profiles/probe").join(name);
        std::fs::remove_file(&path).unwrap();
        assert!(
            Command::new("/usr/bin/mkfifo")
                .arg(path)
                .status()
                .unwrap()
                .success()
        );
        let output = wait_for_output(
            scene
                .command(&scene.workspace(), "probe", &[])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        failed_with(&output, "not a regular file");
    }
}

/// Each `(action, path, rule)` policy decision in a run's records.
fn decisions(run: &Path) -> Vec<(String, String, String)> {
    let mut found = Vec::new();
    let text = std::fs::read_to_string(run.join("records.jsonl")).unwrap_or_default();
    for line in text.lines() {
        let value: serde_json::Value = serde_json::from_str(line).expect("a JSON record");
        collect(&value, &mut found);
    }
    found
}

fn collect(value: &serde_json::Value, found: &mut Vec<(String, String, String)>) {
    match value {
        serde_json::Value::Object(map) => {
            let name = map.get("name").and_then(serde_json::Value::as_str);
            if let (Some(name), true) = (name, map.contains_key("spanId"))
                && let Some(action) = name.strip_prefix("policy ")
            {
                let attribute = |suffix: &str| {
                    map.get("attributes")
                        .and_then(serde_json::Value::as_array)
                        .into_iter()
                        .flatten()
                        .find(|item| {
                            item["key"]
                                .as_str()
                                .is_some_and(|key| key.ends_with(suffix))
                        })
                        .and_then(|item| item["value"]["stringValue"].as_str())
                        .unwrap_or_default()
                        .to_string()
                };
                found.push((action.to_string(), attribute(".path"), attribute(".rule")));
            }
            for item in map.values() {
                collect(item, found);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect(item, found);
            }
        }
        _ => {}
    }
}

/// `check` prints `<label>: yes` when `test` succeeds in bash, and `<label>: no` otherwise.
fn check(label: &str, test: &str) -> String {
    format!("{{ {test}; }} 2>/dev/null && echo '{label}: yes' || echo '{label}: no'\n")
}

#[test]
fn the_agent_writes_the_workspace_and_nothing_a_later_run_trusts() {
    let scene = Scene::new();
    let home = scene.home().display().to_string();
    let script = [
        check("workspace write", "echo ok > written.txt"),
        check("create .box", "echo bad > .box"),
        check("write outside", &format!("echo bad > {home}/outside.txt")),
        check(
            "read profile",
            &format!("read -r line < {home}/.strands/box/profiles/probe/profile.toml"),
        ),
        check(
            "write profile",
            &format!("echo bad >> {home}/.strands/box/profiles/probe/profile.toml"),
        ),
    ]
    .concat();
    let output = scene.probe(&scene.workspace(), &script);
    succeeded(&output);
    assert_eq!(
        stdout(&output),
        "workspace write: yes\ncreate .box: no\nwrite outside: no\nread profile: no\n\
         write profile: no\n"
    );
    assert!(scene.workspace().join("written.txt").is_file());
    assert_only_the_linux_project_configuration(&scene.workspace().join(".box"));
    assert!(!scene.home().join("outside.txt").exists());
}

#[test]
fn project_access_decides_what_the_agent_reaches_in_the_project() {
    for (access, expected) in [
        (Some("write"), "read: yes\nwrite: yes\n"),
        (Some("read"), "read: yes\nwrite: no\n"),
        (Some("none"), "read: no\nwrite: no\n"),
        (None, "read: no\nwrite: no\n"),
    ] {
        let scene = Scene::new();
        std::fs::write(scene.workspace().join("README.md"), "marker\n").expect("a file");
        let text = match access {
            Some(access) => PROBE.replace("access = \"write\"", &format!("access = {access:?}")),
            None => PROBE.replace("[project]\naccess = \"write\"\n", ""),
        };
        assert!(access == Some("write") || text != PROBE, "{access:?}");
        // Written here, as `Scene::profile` adds `[project]` to a profile without one.
        let folder = scene.home().join(".strands/box/profiles/probe");
        std::fs::create_dir_all(&folder).expect("a profile folder");
        std::fs::write(
            folder.join("profile.toml"),
            format!("policies = [\"policy.dw\"]\n{text}"),
        )
        .expect("a profile");
        std::fs::write(folder.join("policy.dw"), PROBE_POLICY).expect("a policy");
        let script = [
            check("read", "read -r line < README.md"),
            check("write", "echo ok > written.txt"),
        ]
        .concat();
        let output = scene.probe(&scene.workspace(), &script);
        succeeded(&output);
        assert_eq!(stdout(&output), expected, "{access:?}: {}", stderr(&output));
        assert_eq!(
            scene.workspace().join("written.txt").exists(),
            access == Some("write"),
            "{access:?}"
        );
    }
}

/// `touch -d 2000-01-02T03:04:05Z` on a workspace file, run as the agent of a box with `top` above
/// the profile's tables, and whether the file then holds that time.
fn set_times(scene: &Scene, top: &str) -> (Output, bool) {
    use std::os::unix::fs::MetadataExt as _;
    let file = scene.workspace().join("stamped.txt");
    std::fs::write(&file, "ok\n").expect("a file");
    scene.profile(
        "touch",
        &format!(
            "{top}[agent]\ncommand = [\"/usr/bin/touch\", \"-d\", \"2000-01-02T03:04:05Z\", \
             \"stamped.txt\"]\nenv.PATH = \"/usr/bin:/bin\"\n"
        ),
        "",
    );
    let output = scene
        .command(&scene.workspace(), "touch", &[])
        .output()
        .expect("box runs");
    let mtime = std::fs::metadata(&file).expect("the file").mtime();
    (output, mtime == 946_782_245)
}

#[test]
fn a_box_sets_file_times_in_the_workspace_unless_box_runs_as_root() {
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let scene = Scene::new();
    let (output, stamped) = set_times(&scene, "");
    succeeded(&output);
    assert!(stamped, "{}", stderr(&output));
}

#[test]
fn a_profile_that_turns_file_attributes_off_cannot_set_file_times_on_macos() {
    let scene = Scene::new();
    let (output, stamped) = set_times(&scene, "file-attributes = false\n");
    if cfg!(target_os = "macos") {
        let text = stderr(&output);
        assert!(!output.status.success(), "{text}");
        assert!(
            text.contains("strands-box: note[B0302]: starting workload"),
            "{text}"
        );
        assert!(
            text.contains("stamped.txt: Operation not permitted"),
            "{text}"
        );
        assert!(!stamped, "{text}");
    } else {
        succeeded(&output);
        assert!(stamped, "{}", stderr(&output));
    }
}

#[test]
fn the_agent_cannot_write_into_an_existing_project_configuration() {
    let scene = Scene::new();
    std::fs::create_dir(scene.workspace().join(".box")).expect("a .box directory");
    let output = scene.probe(
        &scene.workspace(),
        &check("write .box/profile.toml", "echo bad > .box/profile.toml"),
    );
    succeeded(&output);
    assert_eq!(stdout(&output), "write .box/profile.toml: no\n");
    assert!(!scene.workspace().join(".box/profile.toml").exists());
}

#[test]
fn the_shell_cannot_write_the_project_configuration() {
    let scene = Scene::new();
    for (workspace, spelled) in [
        (scene.workspace(), "~/project".to_string()),
        (scene.outside(), scene.outside().display().to_string()),
    ] {
        std::fs::create_dir_all(workspace.join(".box")).expect("a .box directory");
        let script = [
            check("shell workspace write", "bash -c 'echo ok > via-shell.txt'"),
            check("shell .box write", "bash -c 'echo bad > .box/profile.toml'"),
            check("shell .box delete", "bash -c 'rm -rf .box'"),
            check("shell .box move", "bash -c 'mv .box moved'"),
        ]
        .concat();
        let before = scene.runs();
        let output = scene.probe(&workspace, &script);
        succeeded(&output);
        assert_eq!(
            stdout(&output),
            "shell workspace write: yes\nshell .box write: no\nshell .box delete: no\n\
             shell .box move: no\n",
            "{spelled}"
        );
        assert!(workspace.join(".box").is_dir(), "{spelled}");
        let run = scene
            .runs()
            .into_iter()
            .find(|run| !before.contains(run))
            .expect("a new run");
        let decisions = decisions(&run);
        for (action, path, rule) in [
            (
                "fs:write",
                format!("{spelled}/via-shell.txt"),
                "project_write",
            ),
            (
                "fs:write",
                format!("{spelled}/.box/profile.toml"),
                "project_configuration_write",
            ),
            (
                "fs:delete",
                format!("{spelled}/.box"),
                "project_configuration_delete",
            ),
        ] {
            assert!(
                decisions.iter().any(|found| (
                    found.0.as_str(),
                    found.1.as_str(),
                    found.2.as_str()
                ) == (action, path.as_str(), rule)),
                "{action} {path} {rule} in {decisions:?}"
            );
        }
        assert!(
            decisions.iter().any(
                |(action, _, rule)| action == "fs:move" && rule == "project_configuration_move"
            ),
            "{decisions:?}"
        );
    }
}

#[test]
fn the_scoped_starter_lets_the_shell_use_dev_null_and_nothing_else_outside_the_workspace() {
    let scene = Scene::new();
    scene.profile("probe", PROBE, SCOPED_STARTER);
    let elsewhere = scene.home().join("elsewhere.txt");
    std::fs::write(&elsewhere, "x").expect("a file outside the workspace");
    let elsewhere = elsewhere.display().to_string();
    let script = [
        check("shell read /dev/null", "bash -c 'cat < /dev/null'"),
        check("shell write /dev/null", "bash -c 'echo x > /dev/null'"),
        check(
            "shell read elsewhere",
            &format!("bash -c 'read -r line < {elsewhere}'"),
        ),
        check(
            "shell write elsewhere",
            &format!("bash -c 'echo y > {elsewhere}'"),
        ),
    ]
    .concat();
    let output = scene.probe(&scene.workspace(), &script);
    succeeded(&output);
    assert_eq!(
        stdout(&output),
        "shell read /dev/null: yes\nshell write /dev/null: yes\nshell read elsewhere: no\n\
         shell write elsewhere: no\n"
    );
    assert_eq!(std::fs::read_to_string(&elsewhere).expect("the file"), "x");
}

#[test]
fn listed_policy_files_form_one_program_in_either_order() {
    let scene = Scene::new();
    let folder = scene.home().join(".strands/box/profiles/probe");
    std::fs::create_dir(folder.join("policies")).expect("a policy folder");
    std::fs::write(
        scene.home().join("permitted.txt"),
        "outside the workspace\n",
    )
    .expect("a permitted file");
    std::fs::write(scene.workspace().join("restricted.txt"), "restricted\n")
        .expect("a restricted file");
    let permit = &[
        SCOPED_STARTER,
        "\n// service policy\r\n\
        @id(\"authored_read\") permit (principal, action == Box::Action::\"fs:read\", resource) \
        when { context.input.path == \"~/permitted.txt\" || \
        context.input.path == \"~/project/restricted.txt\" };\n\
        \t// final comment without a newline",
    ]
    .concat();
    let forbid = "\t// workspace restrictions\n\
        @id(\"authored_forbid\") forbid (principal, action == Box::Action::\"fs:read\", resource) \
        when { context.input.path == \"~/project/restricted.txt\" };";
    std::fs::write(folder.join("policies/service.dw"), format!("\n{permit}")).expect("permits");
    std::fs::write(
        folder.join("policies/workspace.dw"),
        format!("{forbid}\n\n "),
    )
    .expect("forbid");
    std::fs::write(folder.join("policy.dw"), "unlisted adjacent text").expect("ignored policy");
    for (references, first, second) in [
        (
            ["policies/service.dw", "policies/workspace.dw"],
            permit.as_str(),
            forbid,
        ),
        (
            ["policies/workspace.dw", "policies/service.dw"],
            forbid,
            permit,
        ),
    ] {
        scene.profile("probe", &format!("policies = {references:?}\n{PROBE}"), "");
        let script = [
            check(
                "authored permit",
                "bash -c 'cat ~/permitted.txt > /dev/null'",
            ),
            check(
                "authored forbid",
                "bash -c 'cat restricted.txt > /dev/null'",
            ),
        ]
        .concat();
        let before = scene.runs();
        let output = scene.probe(&scene.workspace(), &script);
        succeeded(&output);
        assert_eq!(
            stdout(&output),
            "authored permit: yes\nauthored forbid: no\n",
            "{references:?}"
        );
        let run = scene
            .runs()
            .into_iter()
            .find(|run| !before.contains(run))
            .expect("a new run");
        let policy = std::fs::read_to_string(run.join("policy.dw")).expect("rendered policy");
        assert!(
            policy.starts_with(&format!("{first}\n\n{second}\n\n")),
            "{policy}"
        );
        assert!(policy.contains("@id(\"project_read\") permit"), "{policy}");
        assert!(!policy.contains("unlisted adjacent text"), "{policy}");
        let decisions = decisions(&run);
        for (path, rule) in [
            ("~/permitted.txt", "authored_read"),
            ("~/project/restricted.txt", "authored_forbid"),
        ] {
            assert!(
                decisions.iter().any(|found| (
                    found.0.as_str(),
                    found.1.as_str(),
                    found.2.as_str()
                ) == ("fs:read", path, rule)),
                "{path} {rule} in {decisions:?}"
            );
        }
    }
}

#[test]
fn absent_and_empty_policy_lists_ignore_an_adjacent_file_and_leave_the_shell_no_permit() {
    let scene = Scene::new();
    let folder = scene.home().join(".strands/box/profiles/probe");
    std::fs::write(folder.join("policy.dw"), "unlisted adjacent text").expect("ignored policy");
    for header in ["", "policies = []\n"] {
        scene.profile("probe", &format!("{header}{PROBE}"), "");
        let before = scene.runs();
        let output = scene.probe(
            &scene.workspace(),
            "bash -c 'echo shell-ran' || echo shell-refused",
        );
        succeeded(&output);
        assert_eq!(stdout(&output), "shell-refused\n", "{header:?}");
        let run = scene
            .runs()
            .into_iter()
            .find(|run| !before.contains(run))
            .expect("a new run");
        let policy = std::fs::read_to_string(run.join("policy.dw")).expect("rendered policy");
        assert!(!policy.contains("unlisted adjacent text"), "{policy}");
        assert!(!policy.contains("shell:exec"), "{policy}");
        assert!(
            decisions(&run)
                .iter()
                .any(|(action, _, _)| action == "shell:exec"),
            "{header:?}: {:?}",
            decisions(&run)
        );
    }
}

#[test]
fn three_runs_of_one_profile_run_at_the_same_time() {
    let scene = Scene::new();
    let script = r#"echo > "started-$1"
while (( SECONDS < 60 )); do
  [[ -e started-a && -e started-b && -e started-c ]] && break
done
[[ -e started-a && -e started-b && -e started-c ]] && echo together || echo alone"#;
    let children: Vec<_> = ["a", "b", "c"]
        .into_iter()
        .map(|name| {
            scene
                .command(&scene.workspace(), "probe", &["-c", script, "probe", name])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("box runs")
        })
        .collect();
    for child in children {
        let output = child.wait_with_output().expect("a run");
        succeeded(&output);
        assert_eq!(stdout(&output), "together\n");
    }
    let runs = scene.runs();
    assert_eq!(runs.len(), 3, "{runs:?}");
    for run in &runs {
        assert!(run.join("box.toml").is_file());
        assert!(run.join("box/private").is_dir(), "{}", run.display());
    }
}

#[test]
fn the_trailing_arguments_reach_the_agent() {
    let scene = Scene::new();
    let output = scene
        .command(
            &scene.workspace(),
            "probe",
            &["-c", r#"echo "$0|$1|$2""#, "first", "two words", "--flag"],
        )
        .output()
        .expect("box runs");
    succeeded(&output);
    assert_eq!(stdout(&output), "first|two words|--flag\n");
}

#[test]
fn a_run_needs_no_opt_in_from_the_operator_and_the_agent_does_not_see_one() {
    let scene = Scene::new();
    let output = scene.probe(
        &scene.workspace(),
        r#"echo "opt-in:${EXPERIMENTAL_LINUX_SUPPORT-unset}""#,
    );
    succeeded(&output);
    assert_eq!(stdout(&output), "opt-in:unset\n");
}

#[test]
fn the_profile_agent_args_reach_the_agent_before_the_trailing_arguments() {
    let scene = Scene::new();
    scene.pack(
        "shell",
        "env.PATH = \"/usr/bin:/bin\"\nenv.TMPDIR = \"${{ workspace }}\"\n[pack]\n\
         name = \"shell\"\nversion = 1\nkind = \"agent\"\n[run]\n\
         command = [\"/bin/bash\", \"--noprofile\", \"--norc\", { slot = \"agent-args\" }]",
    );
    scene.profile(
        "saved",
        "packs = [\"shell\"]\nagent-args = [\"-c\", 'echo \"$0|$1\"', \"saved\"]",
        PROBE_POLICY,
    );
    let output = scene
        .command(&scene.workspace(), "saved", &["typed"])
        .output()
        .expect("box runs");
    succeeded(&output);
    assert_eq!(stdout(&output), "saved|typed\n");
}

#[test]
fn the_workloads_exit_status_and_streams_reach_the_caller() {
    let scene = Scene::new();
    let output = scene.probe(
        &scene.workspace(),
        "printf 'agent-out\\n'; printf 'agent-err\\n' >&2; exit 37",
    );
    assert_eq!(output.status.code(), Some(37));
    assert_eq!(stdout(&output), "agent-out\n");
    assert!(String::from_utf8_lossy(&output.stderr).contains("agent-err\n"));
    let run = new_run(&[], &scene.runs());
    assert_eq!(core_box_id(&run), box_id(&run));
    assert!(run.join("records.jsonl").is_file());
}

#[test]
fn a_run_without_a_profile_asks_the_starter_and_without_a_terminal_creates_nothing() {
    let scene = Scene::new();
    let output = scene
        .command(&scene.workspace(), "claude", &[])
        .output()
        .expect("box runs");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Creating one from the claude starter."),
        "{stderr}"
    );
    assert!(
        stderr.contains("box profile create claude needs an answer to"),
        "{stderr}"
    );
    assert!(stderr.contains("--with bedrock"), "{stderr}");
    assert!(!scene.home().join(".strands/box/profiles/claude").exists());
    assert!(scene.runs().is_empty());
}

#[test]
fn a_placeholder_resolves_when_the_run_starts() {
    let scene = Scene::new();
    scene.pack(
        "scratch",
        r#"
[pack]
name = "scratch"
version = 1
kind = "support"

[inputs.scratch.name]
description = "The scratch folder in the workspace."
pattern = "[a-z]+"
default = "tmp"

[agent.env]
SCRATCH = "${{ workspace }}/.${{ inputs.scratch.name }}"
"#,
    );
    let agent = r#"
[agent]
command = ["/bin/bash", "--noprofile", "--norc"]
"#;
    scene.profile(
        "terminal",
        &format!("packs = [\"@box/base\", \"scratch\"]\n{agent}"),
        "",
    );
    scene.profile(
        "pinned",
        &format!(
            "packs = [\"@box/base\", \"scratch\"]\n\n[options]\nterminal.term = \"vt100\"\n\
             scratch.name = \"cache\"\n{agent}"
        ),
        "",
    );
    let script = r#"echo "$TERM|$COLORTERM|${PATH#*/box/bin:}|$SCRATCH""#;
    let workspace = scene.workspace().display().to_string();
    for (profile, term, expected) in [
        (
            "terminal",
            Some("xterm-run-time"),
            format!("xterm-run-time|truecolor|/usr/bin:/bin|{workspace}/.tmp"),
        ),
        (
            "terminal",
            None,
            format!("xterm-256color|truecolor|/usr/bin:/bin|{workspace}/.tmp"),
        ),
        (
            "pinned",
            Some("xterm-run-time"),
            format!("vt100|truecolor|/usr/bin:/bin|{workspace}/.cache"),
        ),
    ] {
        let mut command = scene.command(&scene.workspace(), profile, &["-c", script]);
        if let Some(term) = term {
            command.env("TERM", term);
        }
        let output = command.output().expect("box runs");
        succeeded(&output);
        assert_eq!(
            stdout(&output),
            format!("{expected}\n"),
            "{profile} {term:?}"
        );
    }
}

/// `git` through `@box/git`, with `/usr/bin` first on `PATH`, where macOS has Apple's stub.
#[test]
fn the_agent_runs_git_through_the_git_pack() {
    let scene = Scene::new();
    scene.profile(
        "git",
        &format!("packs = [\"@box/base\", \"@box/git\"]\n{PROBE}"),
        PROBE_POLICY,
    );
    let output = scene
        .command(
            &scene.workspace(),
            "git",
            &[
                "-c",
                "bash -c 'git init -q && git status --short && echo clean'",
            ],
        )
        .output()
        .expect("box runs");
    succeeded(&output);
    assert_eq!(stdout(&output), "clean\n", "{}", stderr(&output));
    assert!(scene.workspace().join(".git").is_dir());
}

/// A profile's `[filesystem] deny_write` lets the agent run a program from a project folder that
/// `@box/git` can also write, and Box Core keeps the folder read-only while the rest of the project
/// stays writable.
#[test]
fn a_profile_deny_write_folder_runs_and_stays_read_only() {
    let scene = Scene::new();
    let bin = scene.workspace().join(".venv/bin");
    std::fs::create_dir_all(&bin).expect("a venv");
    std::fs::copy("/usr/bin/true", bin.join("hello")).expect("a program");
    let program = std::fs::read(bin.join("hello")).expect("the program");
    scene.profile(
        "venv",
        &format!(
            "packs = [\"@box/base\", \"@box/git\"]\n{PROBE}\
             filesystem.exec = [\"${{{{ workspace }}}}/.venv\"]\n\
             [filesystem]\ndeny_write = [\"${{{{ workspace }}}}/.venv\"]\n"
        ),
        PROBE_POLICY,
    );
    let script = [
        check("run", ".venv/bin/hello"),
        check("write venv", "echo bad > .venv/bin/hello"),
        check("add to venv", "echo bad > .venv/new"),
        check("write project", "echo ok > written.txt"),
    ]
    .concat();
    let output = scene
        .command(&scene.workspace(), "venv", &["-c", &script])
        .output()
        .expect("box runs");
    succeeded(&output);
    assert_eq!(
        stdout(&output),
        "run: yes\nwrite venv: no\nadd to venv: no\nwrite project: yes\n",
        "{}",
        stderr(&output)
    );
    assert_eq!(
        std::fs::read(bin.join("hello")).expect("the program"),
        program
    );
    assert!(!scene.workspace().join(".venv/new").exists());
}

/// A run stops when an entry beneath a write grant became a link after the run before it.
#[test]
fn a_run_refuses_an_entry_that_became_a_link_beneath_a_write_grant() {
    let scene = Scene::new();
    let out = scene.home().join("notes/out");
    let unnamed = scene.home().join("unnamed");
    std::fs::create_dir_all(&out).expect("a folder beneath the grant");
    std::fs::create_dir_all(&unnamed).expect("a folder that no entry names");
    scene.profile(
        "notes",
        &format!(
            "{PROBE}filesystem.read = [\"${{{{ home }}}}/notes/out\"]\n\
             filesystem.write = [\"${{{{ home }}}}/notes\"]\n"
        ),
        PROBE_POLICY,
    );
    let write = |folder: &Path| format!("echo ok > {}/written.txt", folder.display());
    let first = scene
        .command(&scene.workspace(), "notes", &["-c", &write(&out)])
        .output()
        .expect("box runs");
    succeeded(&first);
    assert!(out.join("written.txt").is_file());

    std::fs::remove_dir_all(&out).expect("remove the folder");
    std::os::unix::fs::symlink(&unnamed, &out).expect("a link where the folder was");
    let second = scene
        .command(&scene.workspace(), "notes", &["-c", &write(&unnamed)])
        .output()
        .expect("box runs");
    failed_with(&second, "resolves through a link");
    assert!(!unnamed.join("written.txt").exists());
}

/// **A resources directory outside the box home is forbidden to the Shell and Monty**, even under
/// an operator permit on every write, and Box Core accepts the rules.
#[test]
fn a_permit_on_every_write_leaves_the_resources_directory_forbidden() {
    let scene = Scene::new();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../resources");
    let resources = scene.outside().join("resources");
    let copied = Command::new("/bin/cp")
        .arg("-R")
        .arg(&source)
        .arg(&resources)
        .status()
        .expect("cp runs");
    assert!(copied.success(), "a copy of the resources");
    scene.profile(
        "open",
        PROBE,
        &format!(
            "{PROBE_POLICY}\n\
             @id(\"write_everything\")\n\
             permit (principal, action == Box::Action::\"fs:write\", resource);"
        ),
    );
    let output = scene
        .command(&scene.workspace(), "open", &["-c", "true"])
        .env("BOX_RESOURCES", &resources)
        .output()
        .expect("box runs");
    succeeded(&output);
    let run = scene.runs().pop().expect("a run directory");
    let policy = std::fs::read_to_string(run.join("policy.dw")).expect("the run's policy");
    let root = resources.display();
    let rule = format!(
        "@id(\"resources_write\") forbid (principal, action == Box::Action::\"fs:write\", \
         resource) when {{ context.input.path == \"{root}\" || context.input.path like \
         \"{root}/*\" }};"
    );
    assert!(policy.contains(&rule), "{rule}\n{policy}");
    assert!(
        policy.contains("@id(\"resources_folder_move\")"),
        "{policy}"
    );
}

/// A profile's `[filesystem] deny` keeps a project folder from the agent and from `@box/git`, and
/// Box Core accepts the rules that `box` writes for the Shell and Monty.
#[test]
fn a_profile_deny_folder_is_out_of_reach() {
    let scene = Scene::new();
    let secrets = scene.workspace().join("secrets");
    std::fs::create_dir_all(&secrets).expect("a folder");
    std::fs::write(secrets.join("key"), "secret\n").expect("a file");
    scene.profile(
        "deny",
        &format!(
            "packs = [\"@box/base\", \"@box/git\"]\n{PROBE}\
             [filesystem]\ndeny = [\"${{{{ workspace }}}}/secrets\"]\n"
        ),
        PROBE_POLICY,
    );
    let script = [
        check("read", "read -r line < secrets/key"),
        check("list", "ls secrets >/dev/null"),
        check("write", "echo bad > secrets/new"),
        check("shell reads", "bash -c 'cat secrets/key' >/dev/null"),
        check(
            "shell reads the project",
            "bash -c 'cat written.txt' >/dev/null",
        ),
        check(
            "git reads",
            "bash -c 'git hash-object secrets/key' >/dev/null",
        ),
        check(
            "git reads the project",
            "bash -c 'git hash-object written.txt' >/dev/null",
        ),
        check(
            "git lists",
            "bash -c 'test -n \"$(git ls-files -o -- secrets)\"'",
        ),
        check(
            "git lists the project",
            "bash -c 'test -n \"$(git ls-files -o -- written.txt)\"'",
        ),
        check("git writes", "bash -c 'git init -q secrets/repo'"),
        check("write project", "echo ok > written.txt"),
    ]
    .concat();
    let output = scene
        .command(
            &scene.workspace(),
            "deny",
            &[
                "-c",
                &format!(
                    "echo ok > written.txt\nbash -c 'git init -q'\n\
                     bash -c 'cat secrets/key' || true\n{script}"
                ),
            ],
        )
        .output()
        .expect("box runs");
    succeeded(&output);
    assert_eq!(
        stdout(&output),
        "read: no\nlist: no\nwrite: no\nshell reads: no\nshell reads the project: yes\n\
         git reads: no\ngit reads the project: yes\ngit lists: no\ngit lists the project: yes\n\
         git writes: no\nwrite project: yes\n",
        "{}",
        stderr(&output)
    );
    assert!(!secrets.join("new").exists());
    assert!(!secrets.join("repo").exists());
    assert!(
        stderr(&output).contains(
            "[policy: filesystem_deny_read_0]: The profile's [filesystem] deny keeps this path out \
             of the box."
        ),
        "a Shell denial names the profile's list: {}",
        stderr(&output)
    );
    let [run] = scene.runs().try_into().expect("one run");
    let policy = std::fs::read_to_string(run.join("policy.dw")).expect("the run's policy");
    assert!(
        policy.contains("@id(\"filesystem_deny_read_0\")"),
        "Box Core started the box with the rules: {policy}"
    );
}

/// `[tool.git.network] contain_egress = false` reaches Box Core, which runs git with native egress.
#[test]
fn a_tool_with_native_egress_runs_and_box_core_records_it() {
    let scene = Scene::new();
    scene.profile(
        "git",
        &format!(
            "packs = [\"@box/base\", \"@box/git\"]\n{PROBE}\n[tool.git.network]\ncontain_egress = false"
        ),
        PROBE_POLICY,
    );
    let output = scene
        .command(&scene.workspace(), "git", &["-c", "bash -c 'git init -q'"])
        .output()
        .expect("box runs");
    succeeded(&output);
    let run = scene.runs().pop().expect("a run");
    let config = std::fs::read_to_string(run.join("box.toml")).expect("box.toml");
    assert!(
        config.contains("[tool.git.network]\ncontain_egress = false"),
        "{config}"
    );
    let records = std::fs::read_to_string(run.join("records.jsonl")).expect("records");
    assert!(records.contains("egress:native"), "{records}");
}

#[test]
fn run_and_show_take_no_option() {
    for command in [
        &["run", "probe", "--option", "a=b"][..],
        &["profile", "show", "probe", "--option", "a=b"],
        &["profile", "show", "--full", "probe", "--option", "a=b"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_box"))
            .args(command)
            .env("HOME", "/nonexistent")
            .stdin(Stdio::null())
            .output()
            .expect("box runs");
        assert!(!output.status.success(), "{command:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unexpected argument '--option'"),
            "{command:?}: {stderr}"
        );
    }
}

#[test]
fn show_prints_the_options_and_full_adds_the_configuration() {
    let scene = Scene::new();
    scene.profile(
        "probe",
        &format!(
            "packs = [\"@box/base\"]\n\n[options]\nterminal.term = \"vt100\"\n{PROBE}\n\
             [egress.login]\ndestinations = [\"login.example.com\", \"auth.example.com:8443\"]\n\n\
             [egress.api]\ndestinations = [\"api.example.com\"]\nsecret.ref = \"env://API_TOKEN\"\n"
        ),
        "",
    );
    let show = |args: &[&str]| {
        let output = scene
            .process(Path::new(env!("CARGO_BIN_EXE_box")))
            .args(["profile", "show"])
            .args(args)
            .current_dir(scene.workspace())
            .output()
            .expect("box runs");
        succeeded(&output);
        stdout(&output)
    };
    let short = show(&["probe"]);
    assert!(
        short.starts_with(
            "box: Profile probe\n\n✓ Resolves for this directory\n  packs     @box/base 1\n"
        ),
        "{short}"
    );
    assert!(
        short.lines().any(|line| {
            line.split_whitespace().collect::<Vec<_>>()
                == ["terminal.term", "\"vt100\"", "(your", "profile)"]
        }),
        "{short}"
    );
    assert!(
        short.contains(
            "  ! route login: login.example.com, auth.example.com:8443 (no credential, open to every program in the box)\n"
        ),
        "{short}"
    );
    assert!(!short.contains("route api"), "{short}");
    assert!(!short.contains("# box.toml"), "{short}");
    let full = show(&["--full", "probe"]);
    let report = short.split("\nFull configuration:").next().unwrap();
    assert!(full.starts_with(report), "{full}");
    assert!(full.contains("\n# box.toml\n"), "{full}");
    assert!(full.contains("\n# policy.dw\n"), "{full}");
    assert!(full.contains("TERM = \"vt100\""), "{full}");
    assert!(full.contains("[limits.shell]\ntimeout = false\n"), "{full}");
    let output = Command::new(env!("CARGO_BIN_EXE_box"))
        .args(["profile", "check", "probe"])
        .env("HOME", scene.home())
        .stdin(Stdio::null())
        .output()
        .expect("box runs");
    assert!(!output.status.success(), "`profile check` is not a command");
}

#[test]
fn show_format_json_prints_one_document_with_what_the_text_and_full_print() {
    let scene = Scene::new();
    scene.profile(
        "probe",
        &format!(
            "packs = [\"@box/base\"]\n\n[options]\nterminal.term = \"vt100\"\n{PROBE}\n\
             [mcp.fetch]\ntype = \"stdio\"\ncommand = [\"mcp-fetch-missing\"]\n\n\
             [egress.login]\ndestinations = [\"login.example.com\", \"auth.example.com:8443\"]\n\n\
             [storage]\ndirectories = [\"config\"]\n\n[[storage.files]]\n\
             source = \"${{{{ home }}}}/settings.json\"\ntarget = \"config/settings.json\"\n\
             kind = \"json\"\nkeep = [[\"model\"]]\n"
        ),
        PROBE_POLICY,
    );
    std::fs::write(
        scene.home().join("settings.json"),
        r#"{"model": "opus", "Smith, John": 1}"#,
    )
    .expect("a host file");
    let show = |args: &[&str]| {
        let output = scene
            .process(Path::new(env!("CARGO_BIN_EXE_box")))
            .env("PATH", "/usr/bin:/bin:relative/bin")
            .args(["profile", "show"])
            .args(args)
            .current_dir(scene.workspace())
            .output()
            .expect("box runs");
        succeeded(&output);
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        stdout(&output)
    };
    let storage = scene.home().join(".strands/box/storage/probe/default");
    let destinations = "login.example.com, auth.example.com:8443";
    let unstarted = "box finds no mcp-fetch-missing on your PATH";
    let dropped = "\"relative/bin\" from the PATH of each MCP server that inherits your PATH: \
                   it is not a full path, so it finds programs in the project";
    let text = show(&["probe"]);
    assert_eq!(show(&["--format", "text", "probe"]), text);
    assert_eq!(
        text,
        format!(
            "box: Profile probe\n\n\u{2713} Resolves for this directory\n  packs     @box/base 1\n  \
             policies  policy.dw\n  storage   {}\n  project   read and write\n\nOptions\n  \
             terminal.colorterm  \"truecolor\"  (default)\n  \
             terminal.term       \"vt100\"  (your profile)\n  \
             ! route login: {destinations} (no credential, open to every program in the box)\n  \
             copy ~/settings.json -> agent/config/settings.json (will copy)\n  \
             keeps    model in agent/config/settings.json\n  \
             drops    \"Smith, John\" in agent/config/settings.json\n  \
             ! no permit to start MCP server fetch: {unstarted}\n  ! dropped {dropped}\n\n\
             Full configuration: box profile show probe --full\n",
            storage.display()
        )
    );
    let report = text
        .strip_suffix("\nFull configuration: box profile show probe --full\n")
        .expect("a pointer to --full");
    let full = show(&["--full", "probe"]);
    let (summary, configuration) = full.split_once("\n# box.toml\n").expect("a box.toml");
    assert_eq!(summary, report);
    let (box_toml, policy) = configuration
        .split_once("\n# policy.dw\n")
        .expect("a policy.dw");

    let json_document = |args: &[&str]| -> serde_json::Value {
        let printed = show(args);
        assert_eq!(printed.lines().count(), 1, "{printed}");
        serde_json::from_str(&printed).expect("one JSON document")
    };
    let summary = json_document(&["--format", "json", "probe"]);
    let document = json_document(&["--format", "json", "--full", "probe"]);
    let keys = |value: &serde_json::Value| -> Vec<String> {
        value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect()
    };
    let report_keys = [
        "profile",
        "packs",
        "plugins",
        "sources",
        "policies",
        "storage",
        "project",
        "inputs",
        "skipped",
        "dropped",
        "open_routes",
        "copies",
        "links",
        "parts",
        "mcp",
        "warnings",
    ];
    assert_eq!(keys(&summary), report_keys, "no box.toml without --full");
    assert_eq!(
        keys(&document),
        [&report_keys[..], &["box_toml", "policy"]].concat()
    );
    let mut reported = document.clone();
    for key in ["box_toml", "policy"] {
        reported.as_object_mut().expect("an object").remove(key);
    }
    assert_eq!(summary, reported, "--full adds only box_toml and policy");
    assert_eq!(
        keys(&document["mcp"]),
        [
            "unstarted",
            "servers",
            "dropped",
            "unchecked",
            "path_dropped",
            "skipped",
            "unread"
        ]
    );
    assert_eq!(document["profile"], "probe");
    assert_eq!(
        document["packs"],
        serde_json::json!([{"name": "@box/base", "version": "1"}])
    );
    assert_eq!(document["policies"], serde_json::json!(["policy.dw"]));
    assert_eq!(document["storage"], storage.display().to_string());
    assert_eq!(document["project"], serde_json::json!({"access": "write"}));
    assert_eq!(
        document["inputs"],
        serde_json::json!([
            {"name": "terminal.colorterm", "value": "truecolor", "source": "default"},
            {"name": "terminal.term", "value": "vt100", "source": "your profile"},
        ])
    );
    assert_eq!(
        document["open_routes"],
        serde_json::json!([{
            "route": "login",
            "destinations": ["login.example.com", "auth.example.com:8443"],
        }])
    );
    assert_eq!(
        document["mcp"]["unstarted"],
        serde_json::json!([{"server": "fetch", "reason": unstarted}])
    );
    assert_eq!(
        document["mcp"]["path_dropped"],
        serde_json::json!([dropped])
    );
    assert_eq!(
        document["copies"],
        serde_json::json!([{
            "source": "~/settings.json",
            "target": "agent/config/settings.json",
            "action": "will copy",
        }])
    );
    assert_eq!(
        document["parts"],
        serde_json::json!([
            {"what": "keeps", "target": "agent/config/settings.json", "names": [["model"]]},
            {"what": "drops", "target": "agent/config/settings.json", "names": [["Smith, John"]]},
        ])
    );
    for empty in [
        "plugins", "sources", "skipped", "dropped", "links", "warnings",
    ] {
        assert_eq!(document[empty], serde_json::json!([]), "{empty}");
    }
    for empty in ["servers", "dropped", "skipped", "unread"] {
        assert_eq!(document["mcp"][empty], serde_json::json!([]), "mcp {empty}");
    }
    let parsed: toml::Table = toml::from_str(box_toml).expect("TOML");
    assert_eq!(
        document["box_toml"],
        serde_json::to_value(parsed).expect("JSON")
    );
    assert_eq!(
        keys(&document["box_toml"])[..3],
        ["name", "box_dir", "policy"],
        "the document order of box.toml"
    );
    assert_eq!(
        document["policy"].as_str().map(|text| format!("{text}\n")),
        Some(policy.to_string())
    );
    assert!(policy.starts_with(PROBE_POLICY), "{policy}");
}

#[test]
fn show_format_json_refuses_a_profile_with_the_text_error_and_prints_nothing() {
    let scene = Scene::new();
    scene.profile("broken", PROBE, "permit (principal, action, resource)");
    for profile in ["broken", "missing"] {
        let show = |flags: &[&str]| {
            scene
                .process(Path::new(env!("CARGO_BIN_EXE_box")))
                .args(["profile", "show", profile])
                .args(flags)
                .current_dir(scene.workspace())
                .output()
                .expect("box runs")
        };
        let text = show(&[]);
        let json = show(&["--format", "json"]);
        for output in [&text, &json] {
            assert_eq!(output.status.code(), Some(1), "{profile}");
        }
        assert!(json.stdout.is_empty(), "{profile}: {}", stdout(&json));
        let stderr = String::from_utf8_lossy(&json.stderr);
        assert!(stderr.starts_with("box: error: "), "{profile}: {stderr}");
        assert_eq!(json.stderr, text.stderr, "{profile}");
    }
}

/// A support pack whose CloudWatch target reads its region from a variable, and its log group and
/// log stream from two keys of a `key=value` list, in the shape that AgentCore Runtime sets.
const RUNTIME_PACK: &str = r#"
[pack]
name = "runtime"
version = 1
kind = "support"

[inputs.runtime.region]
from = "env:AWS_REGION"

[inputs.runtime.log_group]
from = "env:OTEL_EXPORTER_OTLP_LOGS_HEADERS"
key = "x-aws-log-group"

[inputs.runtime.log_stream]
from = "env:OTEL_EXPORTER_OTLP_LOGS_HEADERS"
key = "x-aws-log-stream"

[telemetry.runtime]
kind = "cloudwatch_logs"
region = "${{ inputs.runtime.region }}"
log_group = "${{ inputs.runtime.log_group }}"
log_stream = "${{ inputs.runtime.log_stream }}"
secret.ref = "aws://default"
"#;

/// A support pack whose CloudWatch traces target reads its region from a variable.
const TRACES_PACK: &str = r#"
[pack]
name = "runtime"
version = 1
kind = "support"

[inputs.runtime.region]
from = "env:AWS_REGION"

[telemetry.runtime]
kind = "cloudwatch_traces"
region = "${{ inputs.runtime.region }}"
secret.ref = "aws://default"
"#;

/// A log group name of the shape that AgentCore Runtime gives a runtime.
const RUNTIME_LOG_GROUP: &str = "/aws/bedrock-agentcore/runtimes/probe-5b8e3d70c9-DEFAULT";

/// The list variable that holds the log group and the log stream.
const LOG_HEADERS: &str = "OTEL_EXPORTER_OTLP_LOGS_HEADERS";

/// `LOG_HEADERS` as AgentCore Runtime sets it, with `group` as the log group.
fn log_headers(group: &str) -> String {
    format!(
        "x-aws-log-group={group},x-aws-log-stream=otel-rt-logs,\
         x-aws-metric-namespace=bedrock-agentcore"
    )
}

/// A scene whose `probe` profile uses `pack` as the pack `runtime`.
fn runtime_scene(pack: &str) -> Scene {
    let scene = Scene::new();
    scene.pack("runtime", pack);
    scene.profile(
        "probe",
        &format!("packs = [\"@box/base\", \"runtime\"]\n{PROBE}"),
        PROBE_POLICY,
    );
    scene
}

#[test]
fn show_format_json_fills_a_cloudwatch_target_from_variables_and_refuses_one_unset() {
    let scene = runtime_scene(RUNTIME_PACK);
    let show = |variables: &[(&str, String)], flags: &[&str]| {
        scene
            .process(Path::new(env!("CARGO_BIN_EXE_box")))
            .envs(variables.iter().map(|(name, value)| (name, value)))
            .args(["profile", "show"])
            .args(flags)
            .arg("probe")
            .current_dir(scene.workspace())
            .output()
            .expect("box runs")
    };
    let set = [
        ("AWS_REGION", "us-west-2".to_string()),
        (LOG_HEADERS, log_headers(RUNTIME_LOG_GROUP)),
    ];
    let output = show(&set, &["--format", "json", "--full"]);
    succeeded(&output);
    let document: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("one JSON document");
    assert_eq!(
        document["box_toml"]["telemetry"]["runtime"],
        serde_json::json!({
            "kind": "cloudwatch_logs",
            "region": "us-west-2",
            "log_group": RUNTIME_LOG_GROUP,
            "log_stream": "otel-rt-logs",
            "secret": {"ref": "aws://default"},
        })
    );
    let mut inputs: Vec<&serde_json::Value> = document["inputs"]
        .as_array()
        .expect("a list")
        .iter()
        .filter(|input| {
            input["name"]
                .as_str()
                .is_some_and(|name| name.starts_with("runtime."))
        })
        .collect();
    inputs.sort_by_key(|input| input["name"].as_str().map(str::to_string));
    assert_eq!(
        inputs,
        [
            &serde_json::json!({
                "name": "runtime.log_group",
                "value": RUNTIME_LOG_GROUP,
                "source": "env:OTEL_EXPORTER_OTLP_LOGS_HEADERS",
            }),
            &serde_json::json!({
                "name": "runtime.log_stream",
                "value": "otel-rt-logs",
                "source": "env:OTEL_EXPORTER_OTLP_LOGS_HEADERS",
            }),
            &serde_json::json!({
                "name": "runtime.region",
                "value": "us-west-2",
                "source": "env:AWS_REGION",
            }),
        ]
    );
    let region = ("AWS_REGION", "us-west-2".to_string());
    for (variables, message) in [
        (
            vec![(LOG_HEADERS, log_headers(RUNTIME_LOG_GROUP))],
            "`telemetry.runtime.region`: `inputs.runtime.region` has no value; set \
             `runtime.region` in your profile's `[options]`"
                .to_string(),
        ),
        (
            vec![region.clone()],
            format!(
                "`telemetry.runtime.log_group`: `inputs.runtime.log_group` has no value: \
                 `{LOG_HEADERS}` is not set or is empty, so it holds no value for \
                 `x-aws-log-group`; set `runtime.log_group` in your profile's `[options]`"
            ),
        ),
        (
            vec![
                region.clone(),
                (LOG_HEADERS, format!("x-aws-log-group={RUNTIME_LOG_GROUP}")),
            ],
            format!(
                "`telemetry.runtime.log_stream`: `inputs.runtime.log_stream` has no value: \
                 `{LOG_HEADERS}` holds no value for `x-aws-log-stream`; set \
                 `runtime.log_stream` in your profile's `[options]`"
            ),
        ),
    ] {
        let text = show(&variables, &["--full"]);
        let json = show(&variables, &["--format", "json", "--full"]);
        for output in [&text, &json] {
            assert_eq!(output.status.code(), Some(1), "{message}");
        }
        assert!(json.stdout.is_empty(), "{message}: {}", stdout(&json));
        assert_eq!(json.stderr, text.stderr, "{message}");
        assert!(stderr(&json).starts_with("box: error: "), "{message}");
        failed_with(&json, &message);
    }
}

#[test]
fn box_core_refuses_a_region_or_log_name_that_a_variable_fills_with_a_bad_name() {
    for (pack, region, headers, refusal) in [
        (
            RUNTIME_PACK,
            "EU-CENTRAL-1",
            log_headers(RUNTIME_LOG_GROUP),
            "a `cloudwatch_logs` target needs `region`, an AWS region such as `us-west-2`",
        ),
        (
            TRACES_PACK,
            "example.com#",
            log_headers(RUNTIME_LOG_GROUP),
            "a `cloudwatch_traces` target needs `region`, an AWS region such as `us-west-2`",
        ),
        (
            RUNTIME_PACK,
            "us-west-2",
            log_headers("runtime%20logs"),
            "`log_group` \"runtime logs\" is not a CloudWatch Logs group name",
        ),
        (
            RUNTIME_PACK,
            "us-west-2",
            format!("x-aws-log-group={RUNTIME_LOG_GROUP},x-aws-log-stream=otel%0Alogs"),
            "`log_stream` \"otel\\nlogs\" is not a CloudWatch Logs stream name",
        ),
    ] {
        let scene = runtime_scene(pack);
        let output = scene
            .command(&scene.workspace(), "probe", &["-c", "true"])
            .env("AWS_REGION", region)
            .env(LOG_HEADERS, headers)
            .output()
            .expect("box runs");
        failed_with(&output, refusal);
    }
}

#[test]
fn the_base_name_is_not_a_profile() {
    let scene = Scene::new();
    scene.profile("base", PROBE, PROBE_POLICY);
    let output = scene
        .command(&scene.workspace(), "base", &[])
        .output()
        .expect("box runs");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("`base` is reserved"), "{stderr}");
    assert!(scene.runs().is_empty());
}

#[test]
fn the_agent_writes_its_own_storage_and_no_other_part_of_the_box_home() {
    let scene = Scene::new();
    scene.profile(
        "stateful",
        r#"
[storage]
directories = ["state"]

[agent]
command = ["/bin/bash", "--noprofile", "--norc"]
env.PATH = "/usr/bin:/bin"
env.STATE = "${{ storage.state }}"
"#,
        PROBE_POLICY,
    );
    let home = scene.home().display().to_string();
    let script = [
        check("storage write", r#"echo ok > "$STATE/kept.txt""#),
        check(
            "box home write",
            &format!("echo bad > {home}/.strands/box/other.txt"),
        ),
        check(
            "profile write",
            &format!("echo bad >> {home}/.strands/box/profiles/stateful/profile.toml"),
        ),
    ]
    .concat();
    let output = scene
        .command(&scene.workspace(), "stateful", &["-c", &script])
        .output()
        .expect("box runs");
    succeeded(&output);
    assert_eq!(
        stdout(&output),
        "storage write: yes\nbox home write: no\nprofile write: no\n"
    );
    let storage = scene
        .home()
        .join(".strands/box/storage/stateful/default/agent");
    let folders: Vec<PathBuf> = std::fs::read_dir(&storage)
        .expect("the profile's storage")
        .flatten()
        .map(|entry| entry.path())
        .collect();
    assert_eq!(
        folders,
        [storage.join("state")],
        "one storage for the profile"
    );
    assert!(storage.join("state/kept.txt").is_file());
    assert!(!scene.home().join(".strands/box/other.txt").exists());
    let made: Vec<PathBuf> = std::fs::read_dir(scene.workspace())
        .expect("list")
        .flatten()
        .map(|entry| entry.path())
        .collect();
    let configuration = scene.workspace().join(".box");
    assert_eq!(
        made,
        if cfg!(target_os = "linux") {
            vec![configuration.clone()]
        } else {
            Vec::new()
        },
        "box creates nothing in the workspace but the Linux .box"
    );
    assert_only_the_linux_project_configuration(&configuration);
}

/// On Linux, `.box` is the empty directory `box` creates so the run can deny it. Elsewhere it
/// does not exist.
fn assert_only_the_linux_project_configuration(configuration: &Path) {
    if cfg!(target_os = "linux") {
        assert!(configuration.is_dir(), "{}", configuration.display());
        assert_eq!(
            std::fs::read_dir(configuration).expect("list").count(),
            0,
            "the box wrote nothing into .box"
        );
    } else {
        assert!(!configuration.exists(), "{}", configuration.display());
    }
}

#[test]
fn a_forbid_in_the_profile_policy_beats_a_permit_that_box_writes() {
    let scene = Scene::new();
    scene.profile(
        "probe",
        PROBE,
        &format!(
            "{PROBE_POLICY}\n\n@id(\"no_blocked\")\n@description(\"blocked.txt is read-only\")\n\
             forbid (principal, action == Box::Action::\"fs:write\", resource) \
             when {{ context.input.path like \"*blocked.txt\" }};\n"
        ),
    );
    let script = [
        check("shell workspace write", "bash -c 'echo ok > kept.txt'"),
        check("shell forbidden write", "bash -c 'echo bad > blocked.txt'"),
    ]
    .concat();
    let output = scene.probe(&scene.workspace(), &script);
    succeeded(&output);
    assert_eq!(
        stdout(&output),
        "shell workspace write: yes\nshell forbidden write: no\n"
    );
    assert!(scene.workspace().join("kept.txt").is_file());
    assert!(!scene.workspace().join("blocked.txt").exists());
    let run = scene.runs().pop().expect("a run");
    let decisions = decisions(&run);
    for (path, rule) in [
        ("~/project/kept.txt", "project_write"),
        ("~/project/blocked.txt", "no_blocked"),
    ] {
        assert!(
            decisions.iter().any(
                |found| (found.0.as_str(), found.1.as_str(), found.2.as_str())
                    == ("fs:write", path, rule)
            ),
            "fs:write {path} {rule} in {decisions:?}"
        );
    }
}

/// The Box Core binary: `BOX_ENGINE`, else the `strands-box` that `just build` puts beside
/// `box`, else `None`. A `BOX_ENGINE` that names no file fails the test.
fn engine() -> Option<PathBuf> {
    if let Some(engine) = std::env::var_os("BOX_ENGINE").map(PathBuf::from) {
        assert!(
            engine.is_file(),
            "BOX_ENGINE names no file: {}",
            engine.display()
        );
        return Some(engine);
    }
    Path::new(env!("CARGO_BIN_EXE_box"))
        .parent()
        .map(|directory| directory.join("strands-box"))
        .filter(|engine| engine.is_file())
}

/// A stdio MCP server that answers each `initialize` and `tools/list` until its input ends.
const FIXTURE_SERVER: &str = r#"#!/bin/sh
while IFS= read -r line; do
  id=${line#*\"id\":}
  id=${id%%[,\}]*}
  case "$line" in
    *'"method":"initialize"'*)
      printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"fixture\",\"version\":\"0.1\"}}}" ;;
    *'"method":"tools/list"'*)
      printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"tools\":[{\"name\":\"echo_text\",\"description\":\"Echo the text.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\"}},\"required\":[\"text\"]}}]}}" ;;
  esac
done
"#;

#[test]
fn box_core_starts_a_detected_server_whose_argument_names_a_workspace_file() {
    let scene = Scene::new();
    let bin = scene.outside().join("bin");
    std::fs::create_dir_all(&bin).expect("a program directory");
    let program = bin.join("box-fixture-db");
    let fixture = FIXTURE_SERVER.replacen(
        "#!/bin/sh\n",
        "#!/bin/sh\n[ \"$1\" = --db-path ] && [ -f \"$2\" ] || exit 1\n",
        1,
    );
    std::fs::write(&program, fixture).expect("a server");
    std::fs::set_permissions(
        &program,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("an executable server");
    let database = scene.workspace().join("data.sqlite");
    std::fs::write(&database, "").expect("a project file");
    std::fs::write(
        scene.home().join(".claude.json"),
        format!(
            r#"{{"mcpServers": {{"db": {{"command": "box-fixture-db", "args": ["--db-path", "{}"]}}}}}}"#,
            database.display()
        ),
    )
    .expect("a host MCP configuration");
    scene.pack(
        "servers",
        r#"
[pack]
name = "servers"
version = 1
kind = "support"

[[mcp-servers]]
file = "${{ home }}/.claude.json"
kind = "json"
key = ["mcpServers"]
"#,
    );
    scene.profile(
        "mcp",
        &format!("packs = [\"servers\"]\n{PROBE}"),
        PROBE_POLICY,
    );
    let search_path = format!("{}:/usr/bin:/bin", bin.display());
    let exchange = format!(
        r#"replies=mcp-replies.jsonl
: > "$replies"
await() {{ t=$SECONDS; until [[ $(<"$replies") == *"$1"* ]] || (( SECONDS - t > 30 )); do :; done; }}
{{ printf '%s\n' '{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05","capabilities":{{}},"clientInfo":{{"name":"probe","version":"0"}}}}}}'
await '"id":1'
printf '%s\n' '{{"jsonrpc":"2.0","method":"notifications/initialized"}}' '{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}'
await '"id":2'; }} | box-fixture-db --db-path {database} > "$replies"
printf '%s\n' "$(<"$replies")""#,
        database = database.display()
    );
    let output = scene
        .command(&scene.workspace(), "mcp", &["-c", &exchange])
        .env("PATH", &search_path)
        .output()
        .expect("box runs");
    succeeded(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("box: MCP server db declared from ~/.claude.json"),
        "{stderr}"
    );
    assert!(
        stdout(&output).contains(r#""name":"echo_text""#),
        "Box Core accepts the config and the server reads its argument file and lists its tool\n{}\n{stderr}",
        stdout(&output)
    );
}

#[test]
fn box_core_forwards_caller_values_for_detected_server_argument_variables() {
    let scene = Scene::new();
    let bin = scene.outside().join("bin");
    std::fs::create_dir_all(&bin).expect("a program directory");
    let program = bin.join("box-fixture-args");
    let captured = scene.workspace().join("mcp-arguments.txt");
    let fixture = FIXTURE_SERVER.replacen(
        "#!/bin/sh\n",
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\n",
            captured.display()
        ),
        1,
    );
    std::fs::write(&program, fixture).expect("a server");
    std::fs::set_permissions(
        &program,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("an executable server");
    std::fs::write(
        scene.home().join(".claude.json"),
        r#"{"mcpServers": {"args": {"command": "box-fixture-args",
            "args": ["--fixed", "${BOX_ARG}", "prefix-${BOX_DEFAULT:-fallback}", "${BOX_ARG}"]}}}"#,
    )
    .expect("a host MCP configuration");
    scene.pack(
        "servers",
        r#"
[pack]
name = "servers"
version = 1
kind = "support"

[[mcp-servers]]
file = "${{ home }}/.claude.json"
kind = "json"
key = ["mcpServers"]
env-var-locations = { args = "references" }
env-var-syntax = "${NAME}"
"#,
    );
    scene.profile(
        "mcp",
        &format!("packs = [\"servers\"]\n{PROBE}"),
        PROBE_POLICY,
    );
    let exchange = r#"set -eo pipefail
BOX_ARG=caller-value
replies=mcp-replies.jsonl
: > "$replies"
await() {
  local t=$SECONDS
  until [[ $(<"$replies") == *"$1"* ]]; do
    if (( SECONDS - t > 30 )); then return 1; fi
  done
}
{ printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}'
await '"id":1'
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
await '"id":2'; } | box-fixture-args --fixed "$BOX_ARG" "prefix-${BOX_DEFAULT:-fallback}" '${BOX_ARG}' > "$replies"
printf '%s\n' "$(<"$replies")"
if box-fixture-args --changed "$BOX_ARG" prefix-fallback '${BOX_ARG}' </dev/null; then exit 1; fi
if box-fixture-args --fixed "$BOX_ARG" prefix-fallback </dev/null; then exit 1; fi"#;
    let output = scene
        .command(&scene.workspace(), "mcp", &["-c", exchange])
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("BOX_ARG", "host-value")
        .output()
        .expect("box runs");
    succeeded(&output);
    assert!(
        stdout(&output).contains(r#""name":"echo_text""#),
        "the agent starts the detected server through its alias and lists its tool\n{}\n{}",
        stdout(&output),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(captured).expect("the server captures its arguments"),
        "--fixed\ncaller-value\nprefix-fallback\n${BOX_ARG}\n",
        "the server receives the caller's arguments once; a changed fixed argument or count does not reach the server"
    );
    let run = scene.runs().pop().expect("the run's folder");
    let records = std::fs::read_to_string(run.join("records.jsonl")).unwrap_or_default();
    let unmatched = records
        .matches(r#""eventName":"strands.box.mcp.unmatched""#)
        .count();
    assert_eq!(
        unmatched, 2,
        "records.jsonl keeps each call that matches no server\n{records}"
    );
}

#[test]
fn box_core_accepts_a_remote_server_with_a_key() {
    let scene = Scene::new();
    std::fs::write(
        scene.home().join(".agent.json"),
        r#"{"mcpServers": {"bearer": {"url": "https://bearer.example.com/mcp", "token": "BOX_BEARER_KEY"},
            "header": {"url": "https://header.example.com/mcp", "headers": {"X-Api-Key": "key-${BOX_HEADER_KEY:-header-default}"}},
            "query": {"url": "https://query.example.com/mcp?api_key=${BOX_QUERY_KEY:-query-default}"},
            "fallback": {"url": "https://fallback.example.com/mcp", "headers": {"X-Api-Key": "${BOX_ABSENT_KEY:-literal-default}"}},
            "insecure": {"url": "http://insecure.example.com/mcp", "token": "BOX_HTTP_KEY"}}}"#,
    )
    .expect("a host MCP configuration");
    scene.pack(
        "servers",
        r#"
[pack]
name = "servers"
version = 1
kind = "support"

[[mcp-servers]]
file = "${{ home }}/.agent.json"
kind = "json"
key = ["mcpServers"]
env-var-locations = { token = "bearer-variable", headers = "header-references" }
env-var-syntax = "${NAME}"
"#,
    );
    scene.profile(
        "keyed",
        &format!("packs = [\"servers\"]\n{PROBE}"),
        PROBE_POLICY,
    );
    let output = scene
        .command(&scene.workspace(), "keyed", &["-c", "true"])
        .env("BOX_BEARER_KEY", "a-bearer-key")
        .env("BOX_HEADER_KEY", "a-header-key")
        .env("BOX_QUERY_KEY", "a-query-key")
        .env("BOX_HTTP_KEY", "a-http-key")
        .output()
        .expect("box runs");
    succeeded(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in [
        "box: MCP server bearer declared from ~/.agent.json, with the key in BOX_BEARER_KEY",
        "box: MCP server header declared from ~/.agent.json, with the key in BOX_HEADER_KEY",
        "box: MCP server query declared from ~/.agent.json, with the key in BOX_QUERY_KEY",
        "box: MCP server fallback declared from ~/.agent.json",
        "box: no automatic MCP declaration for insecure (from ~/.agent.json): takes a key over http://",
    ] {
        assert!(stderr.contains(line), "{line}\nin\n{stderr}");
    }
    assert!(!stderr.contains("literal-default"), "{stderr}");
    let run = scene.runs().into_iter().next().expect("a run");
    let file: toml::Table =
        toml::from_str(&std::fs::read_to_string(run.join("box.toml")).expect("box.toml"))
            .expect("TOML");
    assert!(file["mcp"]["fallback"].get("secret").is_none());
    assert!(file["mcp"].get("insecure").is_none());
}

#[test]
fn box_core_accepts_a_keyed_remote_server_whose_addition_lists_destinations() {
    let scene = Scene::new();
    std::fs::write(
        scene.home().join(".agent.json"),
        r#"{"mcpServers": {"docs": {"url": "https://docs.example.com/mcp", "headers": {"Authorization": "Bearer ${BOX_DOCS_KEY}"}}}}"#,
    )
    .expect("a host MCP configuration");
    scene.pack(
        "servers",
        r#"
[pack]
name = "servers"
version = 1
kind = "support"

[[mcp-servers]]
file = "${{ home }}/.agent.json"
kind = "json"
key = ["mcpServers"]
env-var-locations = { headers = "header-references" }
env-var-syntax = "${NAME}"
"#,
    );
    scene.profile(
        "keyed",
        &format!(
            "packs = [\"servers\"]\n{PROBE}\n[mcp.docs]\ndestinations = [\"cdn.example.com\"]\n"
        ),
        PROBE_POLICY,
    );
    let output = scene
        .command(&scene.workspace(), "keyed", &["-c", "true"])
        .env("BOX_DOCS_KEY", "a-docs-key")
        .output()
        .expect("box runs");
    succeeded(&output);
    let run = scene
        .runs()
        .into_iter()
        .find(|run| run.join("box.toml").is_file())
        .expect("a run directory");
    let file: toml::Table =
        toml::from_str(&std::fs::read_to_string(run.join("box.toml")).expect("a box.toml"))
            .expect("TOML");
    assert_eq!(
        file["mcp"]["docs"]["destinations"],
        toml::Value::from(vec!["docs.example.com", "cdn.example.com"]),
        "Box Core accepts the server's own host and the added host"
    );
}

#[test]
fn box_core_accepts_a_route_and_a_remote_server_on_this_machine() {
    let scene = Scene::new();
    std::fs::write(
        scene.home().join(".agent.json"),
        r#"{"mcpServers": {"local": {"url": "http://localhost:3000/mcp"}}}"#,
    )
    .expect("a host MCP configuration");
    scene.pack(
        "servers",
        r#"
[pack]
name = "servers"
version = 1
kind = "support"

[[mcp-servers]]
file = "${{ home }}/.agent.json"
kind = "json"
key = ["mcpServers"]
"#,
    );
    scene.profile(
        "local",
        &format!(
            "packs = [\"servers\"]\n{PROBE}\n\
             [egress.model]\ndestinations = [\"localhost:11434\", \"127.0.0.1:8080\"]\n"
        ),
        PROBE_POLICY,
    );
    let output = scene
        .command(&scene.workspace(), "local", &["-c", "true"])
        .output()
        .expect("box runs");
    succeeded(&output);
    let run = scene
        .runs()
        .into_iter()
        .find(|run| run.join("box.toml").is_file())
        .expect("a run directory");
    let file: toml::Table =
        toml::from_str(&std::fs::read_to_string(run.join("box.toml")).expect("a box.toml"))
            .expect("TOML");
    assert_eq!(
        file["mcp"]["local"]["destinations"],
        toml::Value::from(vec!["localhost:3000"]),
        "Box Core accepts a remote server on this machine"
    );
    let policy = std::fs::read_to_string(run.join("policy.dw")).expect("rendered policy");
    assert!(
        policy.contains("route_model_connect") && policy.contains("localhost"),
        "{policy}"
    );
}

/// A stdio MCP server whose one tool's description holds its `BOX_LOCAL_KEY` and its `HOME`.
const KEYED_SERVER: &str = r#"#!/bin/sh
while IFS= read -r line; do
  id=${line#*\"id\":}
  id=${id%%[,\}]*}
  case "$line" in
    *'"method":"initialize"'*)
      printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"keyed\",\"version\":\"0.1\"}}}" ;;
    *'"method":"tools/list"'*)
      printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"tools\":[{\"name\":\"show_key\",\"description\":\"key=$BOX_LOCAL_KEY home=$HOME\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}}]}}" ;;
  esac
done
"#;

#[test]
fn box_core_starts_a_local_server_with_its_key_and_the_agent_never_holds_it() {
    let scene = Scene::new();
    let bin = scene.outside().join("bin");
    std::fs::create_dir_all(&bin).expect("a program directory");
    let program = bin.join("box-keyed-mcp");
    std::fs::write(&program, KEYED_SERVER).expect("a server");
    std::fs::set_permissions(
        &program,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("an executable server");
    std::fs::create_dir_all(scene.home().join("server-home")).expect("a server home");
    std::fs::write(
        scene.home().join(".claude.json"),
        r#"{"mcpServers": {"keyed": {"command": "box-keyed-mcp",
            "env": {"BOX_LOCAL_KEY": "${BOX_LOCAL_KEY}", "HOME": "~/server-home", "HTTPS_PROXY": "http://proxy.example.com"}},
            "nested": {"command": "box-keyed-mcp", "env": {"HOME": "server-home"}}}}"#,
    )
    .expect("a host MCP configuration");
    scene.pack(
        "servers",
        r#"
[pack]
name = "servers"
version = 1
kind = "support"

[[mcp-servers]]
file = "${{ home }}/.claude.json"
kind = "json"
key = ["mcpServers"]
env-var-locations = { command = "references", args = "references", env = "references" }
env-var-syntax = "${NAME}"
"#,
    );
    scene.profile(
        "keyed",
        &format!("packs = [\"servers\"]\n{PROBE}"),
        PROBE_POLICY,
    );
    let search_path = format!("{}:/usr/bin:/bin", bin.display());
    let exchange = r#"printf 'agent=[%s]\n' "${BOX_LOCAL_KEY-}"
replies=mcp-replies.jsonl
: > "$replies"
await() { t=$SECONDS; until [[ $(<"$replies") == *"$1"* ]] || (( SECONDS - t > 30 )); do :; done; }
{ printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}'
await '"id":1'
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
await '"id":2'; } | box-keyed-mcp > "$replies"
printf '%s\n' "$(<"$replies")""#;
    let output = scene
        .command(&scene.workspace(), "keyed", &["-c", exchange])
        .env("PATH", &search_path)
        .env("BOX_LOCAL_KEY", "a-local-key")
        .output()
        .expect("box runs");
    succeeded(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in [
        "box: MCP server keyed declared from ~/.claude.json, with BOX_LOCAL_KEY, HOME",
        "box: dropped HTTPS_PROXY from MCP server keyed (from ~/.claude.json): the box sets it \
         itself",
        "box: no automatic MCP declaration for nested (from ~/.claude.json): its HOME \"server-home\" is not \
         a full path, which the box refuses",
    ] {
        assert!(stderr.contains(line), "{line}\nin\n{stderr}");
    }
    let replies = stdout(&output);
    assert!(
        replies.contains("agent=[]"),
        "the agent does not hold the server's key\n{replies}"
    );
    assert!(
        replies.contains(&format!(
            "key=a-local-key home={}",
            scene.home().join("server-home").display()
        )),
        "the server holds its real key and its HOME outside the project\n{replies}\n{stderr}"
    );
    let run = scene
        .runs()
        .into_iter()
        .find(|run| run.join("box.toml").is_file())
        .expect("a run directory");
    let file: toml::Table =
        toml::from_str(&std::fs::read_to_string(run.join("box.toml")).expect("a box.toml"))
            .expect("TOML");
    assert_eq!(
        file["mcp"]["keyed"]["env"]["BOX_LOCAL_KEY"].as_str(),
        Some("a-local-key"),
        "the run's box.toml holds the server's real key"
    );
}

#[test]
fn box_core_starts_a_codex_server_with_optional_environment() {
    let scene = Scene::new();
    let bin = scene.outside().join("bin");
    std::fs::create_dir_all(&bin).expect("a program directory");
    let program = bin.join("box-optional-mcp");
    std::fs::write(&program, KEYED_SERVER).expect("a server");
    std::fs::set_permissions(
        &program,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("an executable server");
    std::fs::write(
        scene.home().join("mcp.toml"),
        r#"[mcp_servers.optional]
command = "box-optional-mcp"
env_vars = ["BOX_UNSET", { name = "BOX_LOCAL_KEY", source = "local" }, { name = "BOX_EMPTY" }]
"#,
    )
    .expect("a host MCP configuration");
    scene.pack(
        "servers",
        r#"[pack]
name = "servers"
version = 1
kind = "support"

[[mcp-servers]]
file = "${{ home }}/mcp.toml"
kind = "toml"
key = ["mcp_servers"]
env-var-locations = { env_vars = "variable-names" }
"#,
    );
    scene.profile(
        "optional",
        &format!("packs = [\"servers\"]\n{PROBE}"),
        PROBE_POLICY,
    );
    let exchange = r#"printf 'agent=[%s]\n' "${BOX_LOCAL_KEY-}"
replies=mcp-replies.jsonl
: > "$replies"
await() { t=$SECONDS; until [[ $(<"$replies") == *"$1"* ]] || (( SECONDS - t > 30 )); do :; done; }
{ printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}'
await '"id":1'
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
await '"id":2'; } | box-optional-mcp > "$replies"
printf '%s\n' "$(<"$replies")""#;
    let output = scene
        .command(&scene.workspace(), "optional", &["-c", exchange])
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("BOX_LOCAL_KEY", "a-local-key")
        .env("BOX_EMPTY", "")
        .output()
        .expect("box runs");
    succeeded(&output);
    let replies = stdout(&output);
    assert!(replies.contains("agent=[]"), "{replies}");
    assert!(replies.contains("key=a-local-key"), "{replies}");
    let run = scene.runs().into_iter().next().expect("a run");
    let file: toml::Table =
        toml::from_str(&std::fs::read_to_string(run.join("box.toml")).expect("box.toml"))
            .expect("TOML");
    let env = file["mcp"]["optional"]["env"]
        .as_table()
        .expect("server env");
    assert_eq!(env["BOX_EMPTY"].as_str(), Some(""));
    assert!(!env.contains_key("BOX_UNSET"));
}

#[test]
fn box_core_accepts_and_starts_each_detected_mcp_server() {
    let scene = Scene::new();
    let prefix = scene.outside();
    let keg = prefix.join("Cellar/python-fixture/1");
    let bin = keg.join("bin");
    let dependency = prefix.join("Cellar/fixture-data/1");
    let unrelated = prefix.join("Cellar/unrelated/1");
    for directory in [&bin, &dependency, &unrelated, &prefix.join("opt")] {
        std::fs::create_dir_all(directory).expect("an installation directory");
    }
    std::fs::write(
        keg.join("INSTALL_RECEIPT.json"),
        r#"{"runtime_dependencies":[{"full_name":"fixture-data"}]}"#,
    )
    .unwrap();
    std::fs::write(
        dependency.join("INSTALL_RECEIPT.json"),
        r#"{"runtime_dependencies":[]}"#,
    )
    .unwrap();
    std::fs::write(dependency.join("message"), "available\n").unwrap();
    std::fs::write(unrelated.join("secret"), "unrelated\n").unwrap();
    std::os::unix::fs::symlink(&dependency, prefix.join("opt/fixture-data")).unwrap();
    let program = bin.join("box-fixture-mcp");
    let checks = format!(
        "read -r message < '{}' || exit 10\n[ \"$message\" = available ] || exit 11\naccess_marker=unrelated_denied\nif (read -r secret < '{}') 2>/dev/null; then access_marker=unrelated_read_was_allowed; fi\n",
        dependency.join("message").display(),
        unrelated.join("secret").display()
    );
    std::fs::write(
        &program,
        FIXTURE_SERVER
            .replace("Echo the text.", "$access_marker")
            .replacen("#!/bin/sh\n", &format!("#!/bin/sh\n{checks}"), 1),
    )
    .expect("a server that needs its dependency but cannot read an unrelated keg");
    std::fs::set_permissions(
        &program,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("an executable server");
    std::fs::write(
        scene.home().join(".claude.json"),
        r#"{"mcpServers": {"fixture": {"type": "stdio", "command": "box-fixture-mcp", "args": []},
            "launched": {"command": "docker", "args": ["run", "-i", "some-server"]}}}"#,
    )
    .expect("a host MCP configuration");
    scene.pack(
        "servers",
        r#"
[pack]
name = "servers"
version = 1
kind = "support"

[[mcp-servers]]
file = "${{ home }}/.claude.json"
kind = "json"
key = ["mcpServers"]
"#,
    );
    scene.profile(
        "mcp",
        &format!("packs = [\"servers\"]\n{PROBE}"),
        PROBE_POLICY,
    );
    let search_path = format!("{}:/usr/bin:/bin", bin.display());
    let exchange = r#"replies=mcp-replies.jsonl
: > "$replies"
await() { t=$SECONDS; until [[ $(<"$replies") == *"$1"* ]] || (( SECONDS - t > 30 )); do :; done; }
{ printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}'
await '"id":1'
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
await '"id":2'; } | box-fixture-mcp > "$replies"
printf '%s\n' "$(<"$replies")""#;
    let output = scene
        .command(&scene.workspace(), "mcp", &["-c", exchange])
        .env("PATH", &search_path)
        .output()
        .expect("box runs");
    succeeded(&output);
    assert!(
        stdout(&output).contains(r#""name":"echo_text""#),
        "the agent starts the server through its alias in the box and lists its tool\n{}\n{}",
        stdout(&output),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout(&output).contains("unrelated_denied"),
        "the server must not read an unrelated keg: {}",
        stdout(&output)
    );
    let run = scene
        .runs()
        .into_iter()
        .find(|run| run.join("box.toml").is_file())
        .expect("a run directory");
    let text = std::fs::read_to_string(run.join("box.toml")).unwrap();
    let config: toml::Value = toml::from_str(&text).unwrap();
    assert!(
        text.contains("# installation mcp.fixture homebrew: "),
        "{text}"
    );
    assert!(
        config.get("tool").is_none(),
        "no interpreter tool is exposed"
    );
    if cfg!(target_os = "macos") {
        assert_eq!(
            config["mcp"]["fixture"]["filesystem"]["list"][0].as_str(),
            prefix.join("opt").to_str()
        );
    }
    let rules: Vec<String> = decisions(&run)
        .into_iter()
        .map(|(action, _, rule)| format!("{action} {rule}"))
        .collect();
    for rule in ["mcp_fixture_spawn", "mcp_fixture_call"] {
        assert!(
            rules.iter().any(|decision| decision.ends_with(rule)),
            "{rule} in {rules:?}"
        );
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in [
        "box: MCP server fixture declared from ~/.claude.json",
        "box: no automatic MCP declaration for launched (from ~/.claude.json): runs docker, a launcher that \
         fetches the server when it starts",
    ] {
        assert!(stderr.contains(line), "{line}\nin\n{stderr}");
    }
    let Some(engine) = engine() else {
        eprintln!(
            "skipping: `strands-box policy generate-schema` on a detected server needs the \
             `strands-box` binary; run `just build` or set BOX_ENGINE"
        );
        return;
    };
    let schema = scene.outside().join("schema");
    let output = scene
        .process(&engine)
        .args(["policy", "generate-schema", "--config"])
        .arg(run.join("box.toml"))
        .arg("--output-dir")
        .arg(&schema)
        .current_dir(scene.workspace())
        .env("PATH", &search_path)
        .output()
        .expect("the engine runs");
    succeeded(&output);
    let actions =
        std::fs::read_to_string(schema.join("actions.cedarschema")).expect("an action schema");
    assert!(actions.contains("namespace fixture {"), "{actions}");
    assert!(actions.contains(r#"action "echo_text""#), "{actions}");
}

#[test]
fn a_path_entry_that_is_not_a_full_path_leaves_a_detected_server_starting() {
    let scene = Scene::new();
    let bin = fixture_bin(&scene);
    std::fs::write(
        scene.home().join(".claude.json"),
        r#"{"mcpServers": {"fixture": {"type": "stdio", "command": "box-fixture-mcp", "args": []}}}"#,
    )
    .expect("a host MCP configuration");
    scene.pack(
        "servers",
        r#"
[pack]
name = "servers"
version = 1
kind = "support"

[[mcp-servers]]
file = "${{ home }}/.claude.json"
kind = "json"
key = ["mcpServers"]
"#,
    );
    scene.profile(
        "mcp",
        &format!("packs = [\"servers\"]\n{PROBE}"),
        PROBE_POLICY,
    );
    fixture_starts_without_a_relative_path_entry(&scene, &bin);
}

#[test]
fn show_and_run_report_a_profile_replacement_without_claiming_it_has_no_policy() {
    let scene = Scene::new();
    let bin = fixture_bin(&scene);
    let shell = std::fs::canonicalize("/bin/sh").expect("a shell");
    std::fs::write(
        scene.home().join(".claude.json"),
        r#"{"mcpServers": {"fixture": {"command": "box-fixture-mcp", "args": ["--host"]}}}"#,
    )
    .expect("a host MCP configuration");
    scene.pack(
        "servers",
        r#"
[pack]
name = "servers"
version = 1
kind = "support"

[[mcp-servers]]
file = "${{ home }}/.claude.json"
kind = "json"
key = ["mcpServers"]
"#,
    );
    scene.profile(
        "mcp",
        &format!(
            "packs = [\"servers\"]\n{PROBE}\n[mcp.fixture]\ntype = \"stdio\"\n\
             command = [\"box-fixture-mcp\", \"--profile\"]\n\
             filesystem.read = [{bin:?}]\nfilesystem.read_file = [{shell:?}]\n",
            bin = bin.display().to_string(),
            shell = shell.display().to_string(),
        ),
        PROBE_POLICY,
    );
    let search_path = format!("{}:/usr/bin:/bin", bin.display());
    let shown = scene
        .process(Path::new(env!("CARGO_BIN_EXE_box")))
        .args(["profile", "show", "--full", "mcp"])
        .current_dir(scene.workspace())
        .env("PATH", &search_path)
        .output()
        .expect("box shows the profile");
    succeeded(&shown);
    let full = stdout(&shown);
    let (config, policy) = full
        .split_once("\n# box.toml\n")
        .expect("the full configuration")
        .1
        .split_once("\n# policy.dw\n")
        .expect("the full policy");
    let config: toml::Table = toml::from_str(config).expect("TOML");
    assert_eq!(
        config["mcp"]["fixture"]["command"][1].as_str(),
        Some("--profile")
    );
    assert!(policy.contains("@id(\"mcp_fixture_spawn\")"), "{policy}");

    let output = scene
        .command(&scene.workspace(), "mcp", &["-c", "true"])
        .env("PATH", &search_path)
        .output()
        .expect("box runs");
    succeeded(&output);
    let run = scene.runs().into_iter().next().expect("a run");
    let config: toml::Table =
        toml::from_str(&std::fs::read_to_string(run.join("box.toml")).expect("box.toml"))
            .expect("TOML");
    assert_eq!(
        config["mcp"]["fixture"]["command"][1].as_str(),
        Some("--profile")
    );
    let policy = std::fs::read_to_string(run.join("policy.dw")).expect("a policy");
    assert!(policy.contains("@id(\"mcp_fixture_spawn\")"), "{policy}");

    let notice = "no automatic MCP declaration for fixture (from ~/.claude.json): \
                  the profile declares `[mcp.fixture]`, which takes its place";
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(full.contains(&format!("  ! {notice}\n")), "{full}");
    assert!(stderr.contains(&format!("box: {notice}\n")), "{stderr}");
}

#[test]
fn a_path_entry_that_is_not_a_full_path_leaves_a_profile_server_starting() {
    let scene = Scene::new();
    let bin = fixture_bin(&scene);
    let shell = std::fs::canonicalize("/bin/sh").expect("a shell");
    scene.profile(
        "mcp",
        &format!(
            "{PROBE}\n[mcp.fixture]\ntype = \"stdio\"\ncommand = [\"box-fixture-mcp\"]\n\
             filesystem.read = [\"${{{{ workspace }}}}\", {bin:?}]\n\
             filesystem.read_file = [{shell:?}]\nfilesystem.write = [\"${{{{ workspace }}}}\"]\n",
            bin = bin.display().to_string(),
            shell = shell.display().to_string(),
        ),
        PROBE_POLICY,
    );
    fixture_starts_without_a_relative_path_entry(&scene, &bin);
}

/// A folder outside the home that holds the server `box-fixture-mcp`.
fn fixture_bin(scene: &Scene) -> PathBuf {
    let bin = scene.outside().join("bin");
    std::fs::create_dir_all(&bin).expect("a program directory");
    let program = bin.join("box-fixture-mcp");
    std::fs::write(&program, FIXTURE_SERVER).expect("a server");
    std::fs::set_permissions(
        &program,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("an executable server");
    bin
}

/// Run the profile `mcp` with `~/.dotnet/tools` on `PATH`. The server `fixture` starts in the box
/// with only the full entries on its `PATH`, `box` reports the entry, and Box Core accepts the
/// config.
fn fixture_starts_without_a_relative_path_entry(scene: &Scene, bin: &Path) {
    let full = format!("{}:/usr/bin:/bin", bin.display());
    let search_path = format!("{}:~/.dotnet/tools:/usr/bin:/bin", bin.display());
    let exchange = listing("box-fixture-mcp");
    let output = scene
        .command(&scene.workspace(), "mcp", &["-c", &exchange])
        .env("PATH", &search_path)
        .output()
        .expect("box runs");
    succeeded(&output);
    assert!(
        stdout(&output).contains(r#""name":"echo_text""#),
        "the server starts in the box and lists its tool\n{}\n{}",
        stdout(&output),
        String::from_utf8_lossy(&output.stderr)
    );
    let dropped = "\"~/.dotnet/tools\" from the PATH of each MCP server that inherits your PATH: \
                   it is not a full path, so it finds programs in the project";
    let stderr = String::from_utf8_lossy(&output.stderr);
    let line = format!("box: dropped {dropped}");
    assert!(stderr.contains(&line), "{line}\nin\n{stderr}");
    let shown = Command::new(env!("CARGO_BIN_EXE_box"))
        .args(["profile", "show", "mcp"])
        .current_dir(scene.workspace())
        .env_clear()
        .env("HOME", scene.home())
        .env("PATH", &search_path)
        .stdin(Stdio::null())
        .output()
        .expect("box runs");
    succeeded(&shown);
    let line = format!("\n  ! dropped {dropped}\n");
    assert!(
        stdout(&shown).contains(&line),
        "{line}\nin\n{}",
        stdout(&shown)
    );
    let run = scene
        .runs()
        .into_iter()
        .find(|run| run.join("box.toml").is_file())
        .expect("a run directory");
    let config: toml::Table =
        toml::from_str(&std::fs::read_to_string(run.join("box.toml")).expect("a box.toml"))
            .expect("TOML");
    assert_eq!(
        config["mcp"]["fixture"]["env"]["PATH"].as_str(),
        Some(full.as_str())
    );
    let Some(engine) = engine() else {
        eprintln!(
            "skipping: `strands-box policy generate-schema` on a server needs the `strands-box` \
             binary; run `just build` or set BOX_ENGINE"
        );
        return;
    };
    let schema = scene.outside().join("schema");
    let output = Command::new(&engine)
        .args(["policy", "generate-schema", "--config"])
        .arg(run.join("box.toml"))
        .arg("--output-dir")
        .arg(&schema)
        .current_dir(scene.workspace())
        .env_clear()
        .env("HOME", scene.home())
        .env("PATH", &search_path)
        .stdin(Stdio::null())
        .output()
        .expect("the engine runs");
    succeeded(&output);
    let actions =
        std::fs::read_to_string(schema.join("actions.cedarschema")).expect("an action schema");
    assert!(actions.contains(r#"action "echo_text""#), "{actions}");
}

/// The directory of the first `name` on this process's `PATH`.
fn folder_of(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .find(|directory| directory.join(name).is_file())
}

/// A shell script that sends `initialize` and `tools/list` to `command` and prints its replies.
fn listing(command: &str) -> String {
    format!(
        r#"set -o pipefail
replies=mcp-replies.jsonl
finished=mcp-finished
: > "$replies"
: > "$finished"
deadline=$((SECONDS + 120))
await() {{
  until [[ $(<"$replies") == *"$1"* ]]; do
    if [[ -s "$finished" ]]; then
      [[ $(<"$replies") == *"$1"* ]]
      return
    fi
    (( SECONDS < deadline )) || return 1
  done
}}
if {{ printf '%s\n' '{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05","capabilities":{{}},"clientInfo":{{"name":"probe","version":"0"}}}}}}'
await '"id":1' || exit 1
printf '%s\n' '{{"jsonrpc":"2.0","method":"notifications/initialized"}}' '{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}'
await '"id":2'; }} | {{
  if {command}; then status=0; else status=$?; fi
  printf '%s\n' "$status" > "$finished"
  exit "$status"
}} > "$replies"; then status=0; else status=$?; fi
printf '%s\n' "$(<"$replies")"
(( status == 0 )) || exit "$status""#
    )
}

#[test]
fn an_mcp_exchange_stops_when_its_launcher_exits() {
    use std::os::unix::process::CommandExt;

    for (script, expected) in [("exit 23", 23), ("exit 0", 1)] {
        let scene = Scene::new();
        let mut child = Command::new("/bin/bash")
            .args(["-c", &listing(&format!("/bin/bash -c {script:?}"))])
            .current_dir(scene.workspace())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .expect("the exchange runs");
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().expect("exchange status").is_none() {
            if Instant::now() >= deadline {
                let group = nix::unistd::Pid::from_raw(child.id() as i32);
                nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL)
                    .expect("stop the exchange");
                let output = child.wait_with_output().expect("exchange output");
                panic!(
                    "the exchange kept waiting after the launcher exited\n{}\n{}",
                    stdout(&output),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().expect("exchange output");
        assert_eq!(
            output.status.code(),
            Some(expected),
            "the exchange preserves launcher failure and rejects missing replies\n{}\n{}",
            stdout(&output),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// A launcher run with a deadline and output files that a failed child cannot keep open.
fn launcher_output(mut command: Command, scene: &Scene) -> Output {
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};

    let out = scene.root.join("stdout");
    let err = scene.root.join("stderr");
    command
        .process_group(0)
        .stdout(std::fs::File::create(&out).expect("stdout"))
        .stderr(std::fs::File::create(&err).expect("stderr"));
    let mut child = command.spawn().expect("box runs");
    let deadline = Instant::now() + Duration::from_secs(180);
    let status = loop {
        if let Some(status) = child.try_wait().expect("child status") {
            break status;
        }
        if Instant::now() >= deadline {
            let group = nix::unistd::Pid::from_raw(child.id() as i32);
            let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGTERM);
            std::thread::sleep(Duration::from_secs(2));
            let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
            let _ = child.wait();
            panic!(
                "launcher timed out\n{}\n{}",
                std::fs::read_to_string(out).unwrap_or_default(),
                std::fs::read_to_string(err).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Output {
        status,
        stdout: std::fs::read(out).expect("stdout"),
        stderr: std::fs::read(err).expect("stderr"),
    }
}

fn launcher_lists_tools(launcher: &str, runtime: &str, args: &[&str], tool: &str) {
    check_launcher(launcher, runtime, args, tool, LauncherUse::Mcp);
}

#[derive(Clone, Copy, PartialEq)]
enum LauncherUse {
    Mcp,
    Tool,
    Both,
}

fn check_launcher(launcher: &str, runtime: &str, args: &[&str], tool: &str, usage: LauncherUse) {
    let direct = usage == LauncherUse::Tool;
    let launcher_folder = folder_of(launcher).unwrap_or_else(|| {
        panic!(
            "install {launcher} before running the launcher engine tests (docs/dev/engine-tests.md)"
        )
    });
    let runtime_folder = folder_of(runtime).unwrap_or_else(|| {
        panic!(
            "install {runtime} before running the launcher engine tests (docs/dev/engine-tests.md)"
        )
    });
    let scene = Scene::new();
    std::fs::write(
        scene.home().join(".agent.json"),
        serde_json::json!({"mcpServers": {
            "fixture": {"command": launcher, "args": args}
        }})
        .to_string(),
    )
    .expect("a host MCP configuration");
    scene.pack(
        "servers",
        r#"
[pack]
name = "servers"
version = 1
kind = "support"

[[mcp-servers]]
file = "${{ home }}/.agent.json"
kind = "json"
key = ["mcpServers"]
"#,
    );
    let packs = match usage {
        LauncherUse::Tool => vec![format!("@box/{launcher}")],
        LauncherUse::Mcp => vec!["servers".into()],
        LauncherUse::Both => vec!["servers".into(), format!("@box/{launcher}")],
    };
    scene.profile(
        "launched",
        &format!("packs = {packs:?}\n{PROBE}"),
        PROBE_POLICY,
    );
    let path = format!(
        "{}:{}:/usr/bin:/bin",
        launcher_folder.display(),
        runtime_folder.display()
    );
    let invocation = format!("{launcher} {}", args.join(" "));
    let invocation = if direct {
        format!("bash -c {invocation:?}")
    } else {
        invocation
    };
    let script = if direct {
        invocation
    } else {
        listing(&invocation)
    };
    let script = if usage == LauncherUse::Both {
        format!("set -e\nbash -c '{launcher} semver@7.7.4 1.2.3'\n{script}")
    } else {
        script
    };
    let mut command = scene.command(&scene.workspace(), "launched", &["-c", &script]);
    command.env("PATH", &path);
    let output = launcher_output(command, &scene);
    succeeded(&output);
    if direct {
        assert!(stdout(&output).contains(tool), "{}", stdout(&output));
    } else {
        let replies: Vec<serde_json::Value> = stdout(&output)
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        let tools = replies
            .iter()
            .find(|reply| reply["id"] == 2)
            .and_then(|reply| reply["result"]["tools"].as_array());
        assert!(
            tools.is_some_and(|tools| tools.iter().any(|item| item["name"] == tool)),
            "{launcher} lists {tool}\n{}\n{}",
            stdout(&output),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let storage = scene.home().join(".strands/box/storage/launched/default");
    let cached = if direct {
        scene
            .workspace()
            .join(".cache")
            .join(launcher)
            .read_dir()
            .is_ok_and(|mut entries| entries.next().is_some())
    } else {
        storage
            .join("mcp-cache")
            .join(launcher)
            .read_dir()
            .expect("the profile's launcher cache")
            .next()
            .is_some()
    };
    assert!(cached, "{launcher} cached the server in its consumer cache");
    if usage == LauncherUse::Both {
        assert!(stdout(&output).contains("1.2.3"), "{}", stdout(&output));
        assert!(
            scene
                .workspace()
                .join(".cache")
                .join(launcher)
                .read_dir()
                .is_ok_and(|mut entries| entries.next().is_some()),
            "separate tool cache"
        );
    }
    for own in [
        ".npm",
        ".cache/uv",
        ".local/share/uv",
        ".bun",
        ".local/share/pnpm",
    ] {
        assert!(
            !scene.home().join(own).exists(),
            "{launcher} wrote into the operator's {own}"
        );
    }
    let run = scene.runs().pop().expect("a run");
    let config: toml::Value =
        toml::from_str(&std::fs::read_to_string(run.join("box.toml")).expect("config"))
            .expect("TOML");
    if usage == LauncherUse::Mcp {
        assert!(
            config
                .get("tool")
                .and_then(|tools| tools.get(launcher))
                .is_none(),
            "MCP discovery does not grant the launcher as an agent tool"
        );
    }
    let agent = config["agent"]["filesystem"].to_string();
    assert!(
        !agent.contains("mcp-cache"),
        "the launcher cache is not an agent grant"
    );
}

#[test]
fn npx_launcher_tool_downloads_and_runs_a_command() {
    check_launcher(
        "npx",
        "node",
        &["-y", "semver@7.7.4", "1.2.3"],
        "1.2.3",
        LauncherUse::Tool,
    );
}

#[test]
fn pnpx_launcher_tool_downloads_and_runs_a_command() {
    check_launcher(
        "pnpx",
        "node",
        &["semver@7.7.4", "1.2.3"],
        "1.2.3",
        LauncherUse::Tool,
    );
}

#[test]
fn bunx_launcher_tool_downloads_and_runs_a_command() {
    check_launcher(
        "bunx",
        "node",
        &["semver@7.7.4", "1.2.3"],
        "1.2.3",
        LauncherUse::Tool,
    );
}

#[test]
fn uvx_launcher_tool_downloads_and_runs_a_command() {
    check_launcher(
        "uvx",
        "python3",
        &[
            "--from",
            "mcp-server-time==2026.10.28",
            "mcp-server-time",
            "--help",
        ],
        "--local-timezone",
        LauncherUse::Tool,
    );
}

#[test]
fn a_launcher_tool_and_mcp_server_use_separate_caches() {
    check_launcher(
        "pnpx",
        "node",
        &["@modelcontextprotocol/server-memory@1.0.0"],
        "create_entities",
        LauncherUse::Both,
    );
}

#[test]
fn npx_downloads_into_profile_storage_and_lists_tools() {
    launcher_lists_tools(
        "npx",
        "node",
        &["-y", "@modelcontextprotocol/server-memory@1.0.0"],
        "create_entities",
    );
}

#[test]
fn uvx_downloads_into_profile_storage_and_lists_tools() {
    launcher_lists_tools(
        "uvx",
        "python3",
        &["mcp-server-time==2026.10.28"],
        "get_current_time",
    );
}

#[test]
fn bunx_downloads_into_profile_storage_and_lists_tools() {
    launcher_lists_tools(
        "bunx",
        "node",
        &["@modelcontextprotocol/server-memory@1.0.0"],
        "create_entities",
    );
}

#[test]
fn pnpx_downloads_into_profile_storage_and_lists_tools() {
    launcher_lists_tools(
        "pnpx",
        "node",
        &["@modelcontextprotocol/server-memory@1.0.0"],
        "create_entities",
    );
}

/// **An operator permit on the whole home does not let the Shell write a launcher cache**, which
/// the next run's MCP server runs code from. The same permit still opens the rest of the home.
#[test]
fn an_operator_permit_on_the_home_does_not_open_a_launcher_cache() {
    let npx = folder_of("npx").unwrap_or_else(|| {
        panic!("install npx before running the launcher engine tests (docs/dev/engine-tests.md)")
    });
    let node = folder_of("node").unwrap_or_else(|| {
        panic!("install node before running the launcher engine tests (docs/dev/engine-tests.md)")
    });
    let scene = Scene::new();
    std::fs::write(
        scene.home().join(".agent.json"),
        serde_json::json!({"mcpServers": {
            "fixture": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory@1.0.0"]}
        }})
        .to_string(),
    )
    .expect("a host MCP configuration");
    scene.pack(
        "servers",
        r#"
[pack]
name = "servers"
version = 1
kind = "support"

[[mcp-servers]]
file = "${{ home }}/.agent.json"
kind = "json"
key = ["mcpServers"]
"#,
    );
    scene.profile(
        "launched",
        &format!("packs = [\"servers\"]\n{PROBE}"),
        &format!(
            "{PROBE_POLICY}\n@id(\"operator_home_write\")\n\
             permit (principal, action == Box::Action::\"fs:write\", resource)\n\
             when {{ context.input.path like \"~/*\" }};"
        ),
    );
    let cache = scene
        .home()
        .join(".strands/box/storage/launched/default/mcp-cache/npx");
    let planted = cache.join("planted.js");
    let elsewhere = scene.home().join("elsewhere.txt");
    let script = format!(
        "bash -c 'echo planted > {}' || true\nbash -c 'echo ok > {}'",
        planted.display(),
        elsewhere.display()
    );
    let mut command = scene.command(&scene.workspace(), "launched", &["-c", &script]);
    command.env(
        "PATH",
        format!("{}:{}:/usr/bin:/bin", npx.display(), node.display()),
    );
    let output = launcher_output(command, &scene);
    succeeded(&output);
    assert!(cache.is_dir(), "the run makes the server's launcher cache");
    assert!(
        !planted.exists(),
        "the Shell planted code in the launcher cache\n{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("[policy: box_home_write]"),
        "the box home's forbid refuses the write: {}",
        stderr(&output)
    );
    assert!(
        elsewhere.is_file(),
        "the operator permit opens the rest of the home\n{}",
        stderr(&output)
    );
}

/// **An operator permit on the whole home does not let the Shell write `~/.local/bin`**, which a
/// write grant may not reach either, because `install.sh` puts the `box` launcher there.
#[test]
fn an_operator_permit_on_the_home_does_not_open_a_protected_root() {
    let scene = Scene::new();
    scene.profile(
        "permitted",
        PROBE,
        &format!(
            "{PROBE_POLICY}\n@id(\"operator_home_write\")\n\
             permit (principal, action == Box::Action::\"fs:write\", resource)\n\
             when {{ context.input.path like \"~/*\" }};"
        ),
    );
    let local_bin = scene.home().join(".local/bin");
    std::fs::create_dir_all(&local_bin).expect("a ~/.local/bin");
    let planted = local_bin.join("box");
    let elsewhere = scene.home().join("elsewhere.txt");
    let script = format!(
        "bash -c 'echo planted > {}' || true\nbash -c 'echo ok > {}'",
        planted.display(),
        elsewhere.display()
    );
    let output = scene
        .command(&scene.workspace(), "permitted", &["-c", &script])
        .output()
        .expect("box runs");
    succeeded(&output);
    assert!(
        !planted.exists(),
        "the Shell planted a program in ~/.local/bin\n{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("[policy: protected_0_write]"),
        "the protected root's forbid refuses the write: {}",
        stderr(&output)
    );
    assert!(
        elsewhere.is_file(),
        "the operator permit opens the rest of the home\n{}",
        stderr(&output)
    );
}

/// The probe policy, plus a budget of two completed `fs:write` requests in one hour.
const BUDGET_POLICY: &str = r#"@id("probe_shell") permit (principal, action == Box::Action::"shell:exec", resource);
@id("write_budget")
forbid (principal, action == Box::Action::"fs:write", resource)
when { context.input.operation == Box::FsWriteOperation::"write_content" }
when temporal {
  exists (total: Long). (
    (count for (t: Timepoint). where (
      formerly within 1h (
        Box::Action::"fs:write"::request{ input.path: _, input.operation: Box::FsWriteOperation::"write_content" } && tp(t)
      )
    )) == total && total >= 3
  )
};"#;

/// The box ID of the one run in `after` that is not in `before`.
fn new_run(before: &[PathBuf], after: &[PathBuf]) -> PathBuf {
    let new: Vec<&PathBuf> = after.iter().filter(|run| !before.contains(run)).collect();
    assert_eq!(new.len(), 1, "{after:?}");
    new[0].clone()
}

fn box_id(run: &Path) -> String {
    run.file_name()
        .and_then(|name| name.to_str())
        .expect("a run name")
        .to_string()
}

/// The `box_id` that Box Core recorded for the box in `run`.
fn core_box_id(run: &Path) -> String {
    std::fs::read_to_string(run.join("box/private/box.toml"))
        .expect("the box record")
        .lines()
        .find_map(|line| {
            line.strip_prefix("box_id = ")
                .map(|id| id.trim_matches('"').to_string())
        })
        .expect("a box_id")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn failed_with(output: &Output, message: &str) {
    assert!(!output.status.success(), "{}", stderr(output));
    assert!(
        stderr(output)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .contains(message),
        "{}",
        stderr(output)
    );
}

#[test]
fn a_run_prints_the_box_id_that_brings_it_back() {
    let scene = Scene::new();
    let output = scene.probe(&scene.workspace(), "true");
    succeeded(&output);
    let run = new_run(&[], &scene.runs());
    let id = box_id(&run);
    assert_eq!(id.len(), 18, "{id}");
    assert!(id.starts_with("b-"), "{id}");
    assert!(
        stderr(&output).contains(&format!(
            "box: to reuse this box run: box run probe --box-id {id}"
        )),
        "{}",
        stderr(&output)
    );
    assert_eq!(
        core_box_id(&run),
        id,
        "Box Core stores the box ID that box prints"
    );
    assert!(
        stderr(&output).contains(&format!("strands-box: note[B0301]: box {id} created")),
        "{}",
        stderr(&output)
    );
    let records = std::fs::read_to_string(run.join("records.jsonl")).expect("records");
    assert!(
        records.contains(&format!(
            "{{\"key\":\"strands.box.name\",\"value\":{{\"stringValue\":\"{id}\"}}}}"
        )),
        "Box Core labels its records with the box ID\n{records}"
    );
}

#[test]
fn a_box_id_reruns_the_same_box_and_its_history_keeps_counting() {
    let scene = Scene::new();
    scene.profile("probe", PROBE, BUDGET_POLICY);
    let writes = |label: &str, count: usize| -> String {
        (1..=count)
            .map(|index| {
                check(
                    &format!("{label} {index}"),
                    &format!("bash -c 'echo x > {label}-{index}.txt'"),
                )
            })
            .collect()
    };
    let first = scene.probe(&scene.workspace(), &writes("first", 2));
    succeeded(&first);
    assert_eq!(stdout(&first), "first 1: yes\nfirst 2: yes\n");
    let run = new_run(&[], &scene.runs());
    let id = box_id(&run);
    let box_before = core_box_id(&run);
    assert_eq!(box_before, id, "Box Core stores the box ID that box prints");

    let again = scene
        .command_with(
            &scene.workspace(),
            "probe",
            &["--box-id", &id],
            &["-c", &writes("again", 1)],
        )
        .output()
        .expect("box runs");
    succeeded(&again);
    assert!(
        stderr(&again).contains(&format!(
            "box: running profile probe with box ID {id} again (records: "
        )),
        "{}",
        stderr(&again)
    );
    assert!(
        !stderr(&again).contains("to reuse this box run"),
        "{}",
        stderr(&again)
    );
    assert_eq!(
        stdout(&again),
        "again 1: no\n",
        "the budget counts the first run's writes"
    );
    assert_eq!(scene.runs(), vec![run.clone()], "no new run folder");
    assert_eq!(core_box_id(&run), box_before, "the same box");

    let fresh = scene.probe(&scene.workspace(), &writes("fresh", 1));
    succeeded(&fresh);
    assert_eq!(
        stdout(&fresh),
        "fresh 1: yes\n",
        "a run without --box-id starts empty"
    );
}

/// A `BOX_HOME` of `length` bytes below the scene's root, holding a copy of the probe profile.
fn long_box_home(scene: &Scene, length: usize) -> PathBuf {
    let padding = length
        .checked_sub(scene.root.as_os_str().len() + 1)
        .expect("a scene root shorter than the box home");
    let long = scene.root.join("h".repeat(padding));
    let folder = long.join("profiles/probe");
    std::fs::create_dir_all(&folder).expect("a profile folder");
    for file in ["profile.toml", "policy.dw"] {
        std::fs::copy(
            scene.home().join(".strands/box/profiles/probe").join(file),
            folder.join(file),
        )
        .expect("a copy of the probe profile");
    }
    assert_eq!(long.as_os_str().len(), length);
    long
}

#[test]
fn a_run_whose_longest_path_is_exactly_at_the_limit_starts() {
    let scene = Scene::new();
    let long = long_box_home(&scene, 65);
    let output = scene
        .command(&scene.workspace(), "probe", &["-c", "true"])
        .env("BOX_HOME", &long)
        .output()
        .expect("box runs");
    succeeded(&output);
}

#[test]
fn box_core_refuses_a_run_whose_longest_path_is_one_byte_over_the_limit() {
    use std::os::unix::fs::DirBuilderExt as _;

    let scene = Scene::new();
    let at_limit = long_box_home(&scene, 65);
    let first = scene
        .command(&scene.workspace(), "probe", &["-c", "true"])
        .env("BOX_HOME", &at_limit)
        .output()
        .expect("box runs");
    succeeded(&first);
    let runs: Vec<PathBuf> = std::fs::read_dir(at_limit.join("r"))
        .expect("the runs folder")
        .map(|entry| entry.expect("a run").path())
        .collect();
    let id = box_id(&new_run(&[], &runs));
    let records = std::fs::read(runs[0].join("records.jsonl")).expect("recorded history");
    let over = PathBuf::from(format!("{}h", at_limit.display()));
    std::fs::rename(&at_limit, &over).expect("a box home one byte longer");
    let again = scene
        .command_with(
            &scene.workspace(),
            "probe",
            &["--box-id", &id],
            &["-c", "true"],
        )
        .env("BOX_HOME", &over)
        .output()
        .expect("box runs");
    assert!(!again.status.success(), "{}", stderr(&again));
    assert!(
        stderr(&again).contains("its broker socket path exceeds the platform limit"),
        "Box Core refuses the longer path: {}",
        stderr(&again)
    );
    let run = over.join("r").join(&id);
    assert_eq!(core_box_id(&run), id);
    assert_eq!(
        std::fs::read(run.join("records.jsonl")).expect("preserved history"),
        records
    );
    std::fs::remove_dir_all(run.join("box")).expect("remove Core state");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(run.join("box"))
        .expect("an empty Core directory");
    let empty = scene
        .command_with(
            &scene.workspace(),
            "probe",
            &["--box-id", &id],
            &["-c", "true"],
        )
        .env("BOX_HOME", &over)
        .output()
        .expect("box runs");
    failed_with(&empty, "its broker socket path exceeds the platform limit");
    assert!(run.join("box").is_dir(), "the reused empty box stays");
    assert_eq!(
        std::fs::read(run.join("records.jsonl")).expect("preserved history"),
        records
    );
}

#[test]
fn a_new_run_refused_for_path_length_leaves_no_run_folder() {
    let scene = Scene::new();
    let long = long_box_home(&scene, 66);
    let output = scene
        .command(&scene.workspace(), "probe", &["-c", "true"])
        .env("BOX_HOME", &long)
        .output()
        .expect("box runs");
    failed_with(&output, "its broker socket path exceeds the platform limit");
    let leftovers: Vec<PathBuf> = std::fs::read_dir(long.join("r"))
        .expect("the runs folder")
        .map(|entry| entry.expect("a run").path())
        .collect();
    assert!(leftovers.is_empty(), "leftover run folders: {leftovers:?}");
}

#[test]
fn a_folder_too_deep_for_any_profile_name_is_left_to_box_core() {
    let scene = Scene::new();
    let long = long_box_home(&scene, 100);
    let output = scene
        .command(&scene.workspace(), "probe", &["-c", "true"])
        .env("BOX_HOME", &long)
        .output()
        .expect("box runs");
    assert!(!output.status.success(), "{}", stderr(&output));
    for advice in ["BOX_HOME", "profile name", "cannot start"] {
        assert!(
            !stderr(&output).contains(advice),
            "box gives no advice when no profile name would help: {}",
            stderr(&output)
        );
    }
}

#[test]
fn a_long_profile_name_starts_with_a_52_byte_default_home() {
    let scene = Scene::new();
    let padding = 52 - scene.root.as_os_str().len() - 1;
    let home = scene.root.join("h".repeat(padding));
    assert_eq!(home.as_os_str().len(), 52);
    let name = "payments-service-staging-with-a-long-profile-name";
    let profile = home.join(".strands/box/profiles").join(name);
    std::fs::create_dir_all(&profile).expect("a profile folder");
    for file in ["profile.toml", "policy.dw"] {
        std::fs::copy(
            scene.home().join(".strands/box/profiles/probe").join(file),
            profile.join(file),
        )
        .expect("a profile file");
    }
    let output = scene
        .command(&scene.workspace(), name, &["-c", "true"])
        .env("HOME", &home)
        .output()
        .expect("box runs");
    succeeded(&output);
    let run = std::fs::read_dir(home.join(".strands/box/r"))
        .expect("runs")
        .next()
        .expect("one run")
        .expect("run")
        .path();
    assert_eq!(run.join("box/run/box.sock").as_os_str().len(), 103);
    assert_eq!(
        std::fs::read_to_string(run.join("profile-name")).unwrap(),
        format!("{name}\n")
    );
}

#[test]
fn a_box_id_that_names_no_run_is_refused_and_creates_nothing() {
    let scene = Scene::new();
    for id in [
        "b-0000000000000000",
        "../b-0000000000000000",
        "probe/x",
        ".",
    ] {
        let output = scene
            .command_with(
                &scene.workspace(),
                "probe",
                &["--box-id", id],
                &["-c", "true"],
            )
            .output()
            .expect("box runs");
        failed_with(&output, "no run");
        assert!(scene.runs().is_empty(), "{id}");
    }
}

#[test]
fn a_box_id_runs_its_box_from_another_folder_and_keeps_its_history() {
    let scene = Scene::new();
    scene.profile("probe", PROBE, BUDGET_POLICY);
    let workspace = scene.workspace();
    let first = scene.probe(&workspace, &check("first", "bash -c 'echo x > first.txt'"));
    succeeded(&first);
    assert_eq!(stdout(&first), "first: yes\n");
    let run = new_run(&[], &scene.runs());
    let id = box_id(&run);
    let box_before = core_box_id(&run);

    let elsewhere = scene.home().join("elsewhere");
    std::fs::create_dir(&elsewhere).expect("another project");
    let script = [
        check("here", "bash -c 'echo x > here.txt'"),
        check("third", "bash -c 'echo x > third.txt'"),
        check(
            "old",
            &format!("bash -c 'cat {}'", workspace.join("first.txt").display()),
        ),
    ]
    .concat();
    let moved = scene
        .command_with(&elsewhere, "probe", &["--box-id", &id], &["-c", &script])
        .output()
        .expect("box runs");
    succeeded(&moved);
    let report = stderr(&moved);
    assert!(
        report.contains(&format!(
            "box: running profile probe with box ID {id} again (records: "
        )),
        "{report}"
    );
    assert!(
        report.contains(&format!(
            "box: box ID {id} was last set up for {}; it now runs in {}",
            workspace.display(),
            elsewhere.display()
        )),
        "{report}"
    );
    assert_eq!(
        stdout(&moved),
        "here: yes\nthird: no\nold: no\n",
        "the budget counts both runs' writes, and the old folder is not granted"
    );
    assert_eq!(core_box_id(&run), box_before, "the same box");
    assert_eq!(scene.runs(), vec![run.clone()]);

    let sub = workspace.join("sub");
    std::fs::create_dir(&sub).expect("a subfolder");
    let back = scene
        .command_with(&sub, "probe", &["--box-id", &id], &["-c", "true"])
        .output()
        .expect("box runs");
    succeeded(&back);
    assert!(
        stderr(&back).contains(&format!(
            "box: box ID {id} was last set up for {}; it now runs in {}",
            elsewhere.display(),
            sub.display()
        )),
        "{}",
        stderr(&back)
    );
    let same = scene
        .command_with(&sub, "probe", &["--box-id", &id], &["-c", "true"])
        .output()
        .expect("box runs");
    succeeded(&same);
    assert!(
        !stderr(&same).contains("was last set up for"),
        "{}",
        stderr(&same)
    );
}

#[test]
fn a_box_id_of_another_profile_is_refused() {
    let scene = Scene::new();
    scene.profile("other", PROBE, PROBE_POLICY);
    succeeded(&scene.probe(&scene.workspace(), "true"));
    let run = new_run(&[], &scene.runs());
    let id = box_id(&run);
    let config = std::fs::read(run.join("box.toml")).expect("box.toml");

    let other_profile = scene
        .command_with(
            &scene.workspace(),
            "other",
            &["--box-id", &id],
            &["-c", "true"],
        )
        .output()
        .expect("box runs");
    failed_with(&other_profile, "is not a run of profile other");

    assert_eq!(scene.runs(), vec![run.clone()]);
    assert_eq!(
        std::fs::read(run.join("box.toml")).expect("box.toml"),
        config
    );
}

#[test]
fn a_box_id_whose_run_is_still_running_is_refused_and_leaves_that_run_alone() {
    let scene = Scene::new();
    let waiting = scene
        .command(
            &scene.workspace(),
            "probe",
            &[
                "-c",
                "while [[ ! -e go ]] && (( SECONDS < 60 )); do :; done; echo done",
            ],
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("box runs");
    let mut waiting = waiting;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let run = loop {
        if let Some(run) = scene
            .runs()
            .into_iter()
            .find(|run| run.join("box/private/box.toml").is_file())
        {
            break run;
        }
        if std::time::Instant::now() > deadline {
            let _ = waiting.kill();
            panic!("the first run did not open its box within 60 seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    let config = std::fs::read(run.join("box.toml")).expect("box.toml");
    let inode = std::os::unix::fs::MetadataExt::ino(
        &std::fs::metadata(run.join("box.toml")).expect("box.toml"),
    );
    let second = scene
        .command_with(
            &scene.workspace(),
            "probe",
            &["--box-id", &box_id(&run)],
            &["-c", "true"],
        )
        .output()
        .expect("box runs");
    failed_with(&second, "is still running; wait for it to exit");
    assert_eq!(
        std::fs::read(run.join("box.toml")).expect("box.toml"),
        config
    );
    assert_eq!(
        std::os::unix::fs::MetadataExt::ino(
            &std::fs::metadata(run.join("box.toml")).expect("box.toml")
        ),
        inode,
        "box did not rewrite the running box's files"
    );
    std::fs::write(scene.workspace().join("go"), "").expect("release the first run");
    let first = wait_for_output(waiting);
    succeeded(&first);
    assert_eq!(stdout(&first), "done\n");
}

#[test]
fn a_profile_clean_refuses_a_box_that_is_still_running() {
    let scene = Scene::new();
    let waiting = scene
        .command(
            &scene.workspace(),
            "probe",
            &[
                "-c",
                "while [[ ! -e go ]] && (( SECONDS < 60 )); do :; done; echo done",
            ],
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("box runs");
    let mut waiting = waiting;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let run = loop {
        if let Some(run) = scene
            .runs()
            .into_iter()
            .find(|run| run.join("box/private/box.toml").is_file())
        {
            break run;
        }
        if std::time::Instant::now() > deadline {
            let _ = waiting.kill();
            panic!("the run did not open its box within 60 seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    let clean = |args: &[&str]| {
        scene
            .process(Path::new(env!("CARGO_BIN_EXE_box")))
            .args(["profile", "clean"])
            .args(args)
            .arg("--no-ask")
            .output()
            .expect("box runs")
    };

    let asked = scene
        .process(Path::new(env!("CARGO_BIN_EXE_box")))
        .args(["profile", "clean", "probe"])
        .output()
        .expect("box runs");
    failed_with(&asked, "is still running");
    assert!(
        !stderr(&asked).contains("box asks"),
        "refused before it asks: {}",
        stderr(&asked)
    );
    failed_with(&clean(&["probe"]), "is still running");
    let all = clean(&["--all"]);
    failed_with(&all, "is still running");
    assert!(stderr(&all).contains(&box_id(&run)), "{}", stderr(&all));
    assert_eq!(scene.runs(), vec![run.clone()], "the running box stays");

    std::fs::write(scene.workspace().join("go"), "").expect("release the run");
    let first = wait_for_output(waiting);
    succeeded(&first);
    assert_eq!(stdout(&first), "done\n");
    succeeded(&clean(&["probe"]));
    assert!(scene.runs().is_empty(), "a stopped box is removed");
}

#[test]
fn a_rerun_that_cannot_be_prepared_keeps_the_run() {
    let scene = Scene::new();
    succeeded(&scene.probe(&scene.workspace(), "true"));
    let run = new_run(&[], &scene.runs());
    scene.profile("probe", "[agent]\ncommand = []\n", PROBE_POLICY);
    let output = scene
        .command_with(
            &scene.workspace(),
            "probe",
            &["--box-id", &box_id(&run)],
            &["-c", "true"],
        )
        .output()
        .expect("box runs");
    failed_with(&output, "command");
    assert!(
        run.join("box/private/box.toml").is_file(),
        "the box survives"
    );
    assert!(run.join("box.toml").is_file());
}

#[test]
fn a_rerun_whose_policy_box_core_refuses_leaves_the_run_as_it_was() {
    let scene = Scene::new();
    succeeded(&scene.probe(&scene.workspace(), "true"));
    let run = new_run(&[], &scene.runs());
    let read = |name: &str| std::fs::read(run.join(name)).expect("a run file");
    let (config, policy, box_before) = (read("box.toml"), read("policy.dw"), core_box_id(&run));
    scene.profile(
        "probe",
        PROBE,
        &format!("{PROBE_POLICY}\n@id(\"broken\") forbid (principal, action, resource\n"),
    );
    let output = scene
        .command_with(
            &scene.workspace(),
            "probe",
            &["--box-id", &box_id(&run)],
            &["-c", "true"],
        )
        .output()
        .expect("box runs");
    failed_with(&output, "policy.dw");
    assert_eq!(read("box.toml"), config, "box.toml is the earlier run's");
    assert_eq!(read("policy.dw"), policy, "policy.dw is the earlier run's");
    assert_eq!(core_box_id(&run), box_before, "the same box");
}

#[test]
fn a_profile_clean_removes_the_profiles_boxes_and_keeps_it_and_its_storage() {
    let scene = Scene::new();
    succeeded(&scene.probe(&scene.workspace(), "true"));
    let first = new_run(&[], &scene.runs());
    succeeded(&scene.probe(&scene.workspace(), "true"));
    new_run(std::slice::from_ref(&first), &scene.runs());
    let clean = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_box"))
            .args(["profile", "clean"])
            .args(args)
            .current_dir(scene.workspace())
            .env_clear()
            .env("HOME", scene.home())
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .output()
            .expect("box runs")
    };

    let none = clean(&["nosuch", "--no-ask"]);
    succeeded(&none);
    assert!(
        stderr(&none).contains("no boxes found for profile nosuch"),
        "{}",
        stderr(&none)
    );
    let no_terminal = clean(&["probe"]);
    failed_with(&no_terminal, "box asks before it removes anything");
    assert_eq!(
        scene.runs().len(),
        2,
        "nothing is removed without an answer"
    );

    let kept = scene.home().join(".strands/box/storage/probe/default/kept");
    std::fs::create_dir_all(kept.parent().unwrap()).expect("a storage folder");
    std::fs::write(&kept, "").expect("a storage file");
    let removed = clean(&["probe", "--no-ask"]);
    succeeded(&removed);
    assert!(
        stderr(&removed).contains("removed 2 boxes of profile probe"),
        "{}",
        stderr(&removed)
    );
    assert!(scene.runs().is_empty());
    assert!(
        scene
            .home()
            .join(".strands/box/profiles/probe/profile.toml")
            .is_file(),
        "the profile stays"
    );
    assert!(kept.is_file(), "storage stays");
}

#[test]
fn a_profile_clean_takes_profile_names_or_all_and_box_clean_is_gone() {
    let scene = Scene::new();
    succeeded(&scene.probe(&scene.workspace(), "true"));
    let run = new_run(&[], &scene.runs());
    for (args, error) in [
        (vec!["profile", "clean", "--no-ask"], "required"),
        (
            vec!["profile", "clean", "probe", "--all", "--no-ask"],
            "cannot be used with",
        ),
        (
            vec!["profile", "clean", "--all"],
            "box asks before it removes anything",
        ),
        (
            vec!["clean", "--all", "--no-ask"],
            "unrecognized subcommand",
        ),
        (vec!["run", "--clean-up", "--no-ask"], "unexpected argument"),
    ] {
        let output = scene
            .process(Path::new(env!("CARGO_BIN_EXE_box")))
            .args(&args)
            .output()
            .expect("box runs");
        failed_with(&output, error);
        assert_eq!(scene.runs(), vec![run.clone()], "{args:?}");
    }
}

#[test]
fn a_profile_change_reaches_a_rerun_of_the_same_box() {
    let scene = Scene::new();
    succeeded(&scene.probe(&scene.workspace(), "true"));
    let run = new_run(&[], &scene.runs());
    let box_before = core_box_id(&run);
    scene.profile(
        "probe",
        &format!("{PROBE}env.MARK = \"changed\"\n"),
        PROBE_POLICY,
    );
    let output = scene
        .command_with(
            &scene.workspace(),
            "probe",
            &["--box-id", &box_id(&run)],
            &["-c", "echo \"$MARK\""],
        )
        .output()
        .expect("box runs");
    succeeded(&output);
    assert_eq!(stdout(&output), "changed\n");
    assert_eq!(scene.runs(), vec![run.clone()], "no new run folder");
    assert_eq!(core_box_id(&run), box_before, "the same box");
}

#[test]
fn a_box_id_is_refused_when_the_runs_directory_is_a_link() {
    let scene = Scene::new();
    succeeded(&scene.probe(&scene.workspace(), "true"));
    let run = new_run(&[], &scene.runs());
    let id = box_id(&run);
    let runs = scene.home().join(".strands/box/r");
    let moved = scene.home().join("moved-runs");
    std::fs::rename(&runs, &moved).expect("move the runs");
    std::os::unix::fs::symlink(&moved, &runs).expect("link the runs");
    let config = std::fs::read(moved.join(&id).join("box.toml")).expect("box.toml");
    let output = scene
        .command_with(
            &scene.workspace(),
            "probe",
            &["--box-id", &id],
            &["-c", "true"],
        )
        .output()
        .expect("box runs");
    failed_with(&output, "symbolic link");
    assert_eq!(
        std::fs::read(moved.join(&id).join("box.toml")).expect("box.toml"),
        config
    );
}

#[test]
fn a_box_id_of_another_profile_with_the_same_first_15_characters_is_refused() {
    let scene = Scene::new();
    let (team_a, team_b) = ("probe-bedrock-opA-x", "probe-bedrock-opB-x");
    scene.profile(team_a, PROBE, PROBE_POLICY);
    scene.profile(team_b, PROBE, PROBE_POLICY);
    succeeded(
        &scene
            .command(&scene.workspace(), team_a, &["-c", "true"])
            .output()
            .expect("box runs"),
    );
    let run = new_run(&[], &scene.runs());
    let config = std::fs::read(run.join("box.toml")).expect("box.toml");
    let output = scene
        .command_with(
            &scene.workspace(),
            team_b,
            &["--box-id", &box_id(&run)],
            &["-c", "true"],
        )
        .output()
        .expect("box runs");
    failed_with(&output, &format!("is not a run of profile {team_b}"));
    failed_with(&output, "or run without --box-id to start fresh");
    assert_eq!(scene.runs(), vec![run.clone()]);
    assert_eq!(
        std::fs::read(run.join("box.toml")).expect("box.toml"),
        config
    );
}

#[test]
fn imported_profile_and_duplicate_servers_keep_their_environment_private() {
    for (profile_declares_server, full_path) in [(false, false), (true, false), (true, true)] {
        let scene = Scene::new();
        let bin = scene.outside().join("bin");
        std::fs::create_dir_all(&bin).expect("bin");
        let program = bin.join("box-private-mcp");
        let command = if full_path {
            program.display().to_string()
        } else {
            "box-private-mcp".to_string()
        };
        let server = KEYED_SERVER
            .replacen(
                "while IFS=",
                "checked=no\n[ \"$BOX_LOCAL_KEY\" = private-token ] && \
                 [ \"$BOX_PASSED\" = private-passed ] && checked=yes\nwhile IFS=",
                1,
            )
            .replace("key=$BOX_LOCAL_KEY home=$HOME", "configured=$checked");
        std::fs::write(&program, server).expect("server");
        std::fs::set_permissions(
            &program,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("executable");
        let document = serde_json::json!({"mcpServers": {
            "kept": {
                "command": command,
                "env": {"BOX_LOCAL_KEY": if profile_declares_server { "host-token" } else { "private-token" }},
                "env_vars": ["BOX_PASSED"]
            },
            "twin": {
                "command": "box-private-mcp",
                "env": {"BOX_LOCAL_KEY": "unused-token"},
                "env_vars": ["BOX_UNUSED"]
            }
        }});
        std::fs::write(scene.home().join(".mcp.json"), document.to_string()).expect("host config");
        scene.pack(
            "import",
            r#"
[pack]
name = "import"
version = 1
kind = "support"
[storage]
directories = ["config"]
[[mcp-servers]]
file = "${{ home }}/.mcp.json"
kind = "json"
key = ["mcpServers"]
target = "config/mcp.json"
target-key = "mcpServers"
env-var-locations = { env_vars = "variable-names" }
[agent.env]
MCP_CONFIG = "${{ storage.config }}/mcp.json"
"#,
        );
        let declaration = if profile_declares_server {
            let shell = std::fs::canonicalize("/bin/sh").expect("shell");
            format!(
                "\n[mcp.kept]\ntype = \"stdio\"\ncommand = [\"box-private-mcp\"]\n\
                 env.BOX_LOCAL_KEY = \"private-token\"\nenv.BOX_PASSED = \"private-passed\"\n\
                 filesystem.read = [{bin:?}]\nfilesystem.read_file = [{shell:?}]\n",
                bin = bin.display().to_string(),
                shell = shell.display().to_string(),
            )
        } else {
            String::new()
        };
        scene.profile(
            "import",
            &format!("packs = [\"import\"]\n{PROBE}{declaration}"),
            PROBE_POLICY,
        );
        let script = format!(
            r#"set -eo pipefail
config=$(<"$MCP_CONFIG")
[[ $config != *'"env"'* && $config != *'"env_vars"'* ]] || exit 31
[[ -z ${{BOX_LOCAL_KEY-}} && -z ${{BOX_PASSED-}} ]] || exit 32
for name in kept twin; do
entry=${{config#*\"$name\":}}
[[ $entry =~ \"command\":[[:space:]]*\"([^\"]+)\" ]] || exit 33
alias=${{BASH_REMATCH[1]}}
{}
done
"#,
            listing("\"$alias\"")
        );
        let output = scene
            .command(&scene.workspace(), "import", &["-c", &script])
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("BOX_PASSED", "private-passed")
            .output()
            .expect("box runs");
        succeeded(&output);
        assert_eq!(
            stdout(&output).matches("configured=yes").count(),
            2,
            "both imported entries start with the retained declaration's private environment \
             (profile replacement: {profile_declares_server}, full path: {full_path})\n{}\n{}",
            stdout(&output),
            stderr(&output)
        );
        let run = scene.runs().into_iter().next().expect("run");
        let config: toml::Table =
            toml::from_str(&std::fs::read_to_string(run.join("box.toml")).expect("box.toml"))
                .expect("TOML");
        assert!(config["mcp"].get("twin").is_none());
        assert_eq!(
            config["mcp"]["kept"]["env"]["BOX_LOCAL_KEY"].as_str(),
            Some("private-token")
        );
    }
}

#[test]
fn generated_mcp_config_selects_shared_program_servers_with_private_environment() {
    let scene = Scene::new();
    let bin = scene.outside().join("bin");
    std::fs::create_dir_all(&bin).expect("bin");
    let program = bin.join("box-import-mcp");
    let server = KEYED_SERVER
        .replacen("while IFS=", "checked=no\n[ \"$BOX_LOCAL_KEY\" = private-token ] && [ \"$1\" = \"$EXPECTED_ARGUMENT\" ] && checked=yes\nwhile IFS=", 1)
        .replace("key=$BOX_LOCAL_KEY home=$HOME", "configured=$checked")
        .replace("  esac", r#"    *'"method":"tools/call"'*)
      printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"called-$1-$checked\"}]}}" ;;
  esac"#);
    std::fs::write(&program, server).expect("server");
    std::fs::set_permissions(
        &program,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("executable");
    std::fs::write(scene.home().join(".mcp.json"), r#"{"unrelated":"host-state","mcpServers":{"probe":{"command":"${MCP_PROGRAM}","args":["${MCP_ARGUMENT}"],"env":{"BOX_LOCAL_KEY":"${BOX_LOCAL_KEY}","EXPECTED_ARGUMENT":"caller-value"}},"other":{"command":"${MCP_PROGRAM}","args":["second-server"],"env":{"BOX_LOCAL_KEY":"${BOX_LOCAL_KEY}","EXPECTED_ARGUMENT":"second-server"}}}}"#).expect("host config");
    scene.pack(
        "import",
        r#"
[pack]
name = "import"
version = 1
kind = "support"
[storage]
directories = ["config"]
[[mcp-servers]]
file = "${{ home }}/.mcp.json"
kind = "json"
key = ["mcpServers"]
target = "config/mcp.json"
target-key = "mcpServers"
env-var-locations = { command = "references", args = "references", env = "references" }
env-var-syntax = "${NAME}"
[agent.env]
MCP_CONFIG = "${{ storage.config }}/mcp.json"
"#,
    );
    scene.profile(
        "import",
        &format!("packs = [\"import\"]\n{PROBE}"),
        PROBE_POLICY,
    );
    let script = r#"
config=$(<"$MCP_CONFIG")
[[ $config != *private-token* && $config != *host-state* ]] || exit 31
[[ -z ${BOX_LOCAL_KEY-} ]] || exit 32
for name in probe other; do
entry=${config#*\"$name\":}
[[ $entry =~ \"command\":[[:space:]]*\"([^\"]+)\" ]] || exit 33
alias=${BASH_REMATCH[1]}
[[ $entry =~ \"args\":[[:space:]]*\[[[:space:]]*\"([^\"]+)\" ]] || exit 34
argument=${BASH_REMATCH[1]}
if [[ $name == probe ]]; then
  [[ $argument == '${MCP_ARGUMENT}' ]] || exit 35
  argument=caller-value
fi
replies=mcp-replies.jsonl
: > "$replies"
await() { t=$SECONDS; until [[ $(<"$replies") == *"$1"* ]] || (( SECONDS - t > 30 )); do :; done; }
{ printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}'
await '"id":1'
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
await '"id":2'
printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"show_key","arguments":{}}}'
await '"id":3'; } | "$alias" "$argument" > "$replies"
printf '%s\n' "$(<"$replies")"
done
"#;
    let output = scene
        .command(&scene.workspace(), "import", &["-c", script])
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("BOX_LOCAL_KEY", "private-token")
        .env("MCP_PROGRAM", "box-import-mcp")
        .env("MCP_ARGUMENT", "first-server")
        .output()
        .expect("box runs");
    succeeded(&output);
    let report = stderr(&output);
    assert!(
        report.contains("box: MCP server probe declared from ~/.mcp.json"),
        "{report}"
    );
    assert!(
        report.contains("box: Imported MCP settings into "),
        "{report}"
    );
    assert!(
        !report.contains("Adding servers inside the box"),
        "{report}"
    );
    let rerun = scene
        .command(&scene.workspace(), "import", &["-c", "exit 0"])
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("BOX_LOCAL_KEY", "private-token")
        .env("MCP_PROGRAM", "box-import-mcp")
        .env("MCP_ARGUMENT", "first-server")
        .output()
        .expect("box runs again");
    succeeded(&rerun);
    let report = stderr(&rerun);
    for notice in ["MCP settings", "Adding servers inside the box"] {
        assert!(!report.contains(notice), "{report}");
    }

    let source = scene.home().join(".mcp.json");
    let mut changed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&source).unwrap()).unwrap();
    changed["mcpServers"]["new"] = serde_json::json!({"url": "https://new.example.com"});
    std::fs::write(source, changed.to_string()).unwrap();
    let changed = scene
        .command(&scene.workspace(), "import", &["-c", "exit 0"])
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("BOX_LOCAL_KEY", "private-token")
        .env("MCP_PROGRAM", "box-import-mcp")
        .output()
        .expect("box runs with changed source");
    succeeded(&changed);
    let report = stderr(&changed);
    assert!(
        report.contains("differ from the current import: missing \"new\"."),
        "{report}"
    );
    assert!(report.contains("docs/cli/troubleshooting.md"), "{report}");
    assert!(!report.contains("private-token"), "{report}");

    assert!(
        stdout(&output).contains("called-caller-value-yes")
            && stdout(&output).contains("called-second-server-yes"),
        "{}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("configured=yes"),
        "{}",
        stdout(&output)
    );
}

/// A pack that declares the servers in `~/.agent.json`.
const AGENT_SERVERS: &str = r#"
[pack]
name = "servers"
version = 1
kind = "support"

[[mcp-servers]]
file = "${{ home }}/.agent.json"
kind = "json"
key = ["mcpServers"]
"#;

#[test]
fn an_absolute_mcp_command_imports_its_filename_and_starts_the_selected_server() {
    let scene = Scene::new();
    let selected = scene.outside().join("selected server");
    let bin = scene.outside().join("bin");
    std::fs::create_dir_all(&selected).expect("the selected installation");
    std::fs::create_dir_all(&bin).expect("the PATH installation");
    let real = selected.join("server");
    let program = selected.join("box-absolute-mcp");
    let capture = scene.workspace().join("invoked-program");
    let server = KEYED_SERVER
        .replacen(
            "while IFS=",
            "printf '%s\\n' \"$0\" > invoked-program\nchecked=no\n\
             [ \"$BOX_LOCAL_KEY\" = private-token ] && [ \"$1\" = selected-argument ] && checked=yes\n\
             while IFS=",
            1,
        )
        .replace("key=$BOX_LOCAL_KEY home=$HOME", "configured=$checked")
        .replace(
            "  esac",
            r#"    *'"method":"tools/call"'*)
      printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"selected-$1-$checked\"}]}}" ;;
  esac"#,
        );
    std::fs::write(&real, server).expect("the selected server");
    std::fs::set_permissions(&real, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("an executable server");
    std::os::unix::fs::symlink(&real, &program).expect("the selected invocation name");
    let decoy = bin.join("box-absolute-mcp");
    std::fs::write(&decoy, "#!/bin/sh\nprintf 'wrong-server\\n'\nexit 93\n").expect("a PATH decoy");
    std::fs::set_permissions(&decoy, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("an executable decoy");
    let source = scene.home().join(".agent.json");
    let original = serde_json::json!({
        "unrelated": "host-state",
        "mcpServers": {"selected": {
            "command": program,
            "args": ["selected-argument"],
            "env": {"BOX_LOCAL_KEY": "private-token"}
        }}
    })
    .to_string();
    std::fs::write(&source, &original).expect("the host configuration");
    scene.pack(
        "servers",
        &format!(
            "{AGENT_SERVERS}\ntarget = \"config/mcp.json\"\ntarget-key = \"mcpServers\"\n\
             [storage]\ndirectories = [\"config\"]\n\
             [agent.env]\nMCP_CONFIG = \"${{{{ storage.config }}}}/mcp.json\"\n"
        ),
    );
    scene.profile(
        "absolute",
        &format!("packs = [\"servers\"]\n{PROBE}"),
        PROBE_POLICY,
    );
    let script = r#"set -eo pipefail
config=$(<"$MCP_CONFIG")
[[ $config != *private-token* && $config != *host-state* ]] || exit 31
[[ -z ${BOX_LOCAL_KEY-} ]] || exit 32
[[ $config =~ \"command\":[[:space:]]*\"([^\"]+)\" ]] || exit 33
alias=${BASH_REMATCH[1]}
[[ $alias == box-absolute-mcp ]] || exit 34
[[ $config =~ \"args\":[[:space:]]*\[[[:space:]]*\"([^\"]+)\" ]] || exit 35
argument=${BASH_REMATCH[1]}
replies=mcp-replies.jsonl
: > "$replies"
deadline=$((SECONDS + 30))
await() { until [[ $(<"$replies") == *"$1"* ]]; do (( SECONDS < deadline )) || return 1; done; }
{ printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}'
await '"id":1'
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
await '"id":2'
printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"show_key","arguments":{}}}'
await '"id":3'; } | "$alias" "$argument" > "$replies"
printf '%s\n' "$(<"$replies")"
"#;
    let mut command = scene.command_with(&scene.workspace(), "absolute", &[], &["-c", script]);
    command.env("PATH", format!("{}:/usr/bin:/bin", bin.display()));
    let output = launcher_output(command, &scene);
    succeeded(&output);
    assert!(
        stdout(&output).contains("selected-selected-argument-yes"),
        "{}\n{}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(
        std::fs::read_to_string(capture).expect("the selected server's invocation"),
        format!("{}\n", program.display())
    );
    assert_eq!(
        std::fs::read_to_string(source).expect("the host configuration"),
        original
    );
    let run = scene.runs().pop().expect("the run");
    let config: toml::Value =
        toml::from_str(&std::fs::read_to_string(run.join("box.toml")).expect("box.toml"))
            .expect("TOML");
    assert_eq!(
        config["mcp"]["selected"]["command"][0].as_str(),
        program.to_str()
    );
    let stored: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            scene
                .home()
                .join(".strands/box/storage/absolute/default/agent/config/mcp.json"),
        )
        .expect("the imported configuration"),
    )
    .expect("JSON");
    assert_eq!(
        stored["mcpServers"]["selected"]["command"],
        "box-absolute-mcp"
    );
    assert!(stored["mcpServers"]["selected"].get("env").is_none());
    let policy = std::fs::read_to_string(run.join("policy.dw")).expect("policy.dw");
    assert!(
        policy.contains(&format!(
            "context.input.program_path == {:?} && context.input.program == \"box-absolute-mcp\"",
            real.canonicalize()
                .expect("the selected identity")
                .display()
                .to_string()
        )),
        "{policy}"
    );
}

#[test]
fn an_mcp_server_starts_through_a_local_npm_bin_link() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    for (absolute, in_home) in [(false, false), (true, false), (false, true), (true, true)] {
        let scene = Scene::new();
        let root = if in_home {
            scene.home()
        } else {
            scene.root.clone()
        };
        let modules = root.join("installed/node_modules");
        let bin = modules.join(".bin");
        let package = modules.join("fixture/bin");
        std::fs::create_dir_all(&bin).expect("npm bin");
        std::fs::create_dir_all(&package).expect("npm package");
        let program = bin.join("box-fixture-mcp");
        let real = package.join("server");
        let capture = scene.workspace().join("invoked-program");
        let checks_result = scene.workspace().join("installation-checks");
        let dependency = modules.join("@fixture/runtime/data");
        std::fs::create_dir_all(dependency.parent().unwrap()).expect("a sibling package");
        std::fs::write(&dependency, "runtime\n").expect("dependency data");
        let sibling = bin.join("sibling-data");
        std::fs::write(&sibling, "other data\n").expect("another file inside node_modules");
        let secret = root.join("installed/outside-secret");
        std::fs::write(&secret, "private content\n").expect("a file outside node_modules");
        let checks = format!(
            "printf '%s\\n' \"$0\" > '{}'\n\
             fail() {{ printf '%s\\n' \"$1\" > '{}'; exit 91; }}\n\
             read -r value < '{}' || fail 'dependency unreadable'\n\
             [ \"$value\" = runtime ] || fail 'dependency content'\n\
             read -r value < '{}' || fail 'bin sibling unreadable'\n\
             if (printf changed >> '{}') 2>/dev/null; then fail 'installation writable'; fi\n\
             if (read -r value < '{}') 2>/dev/null; then fail 'outside file readable'; fi\n\
             printf 'passed\\n' > '{}'\n",
            capture.display(),
            checks_result.display(),
            dependency.display(),
            sibling.display(),
            dependency.display(),
            secret.display(),
            checks_result.display()
        );
        std::fs::write(
            &real,
            FIXTURE_SERVER.replacen("#!/bin/sh\n", &format!("#!/bin/sh\n{checks}"), 1),
        )
        .expect("an MCP server");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755))
            .expect("an executable server");
        symlink("../fixture/bin/server", &program).expect("npm's command link");
        let selected = if absolute {
            program.display().to_string()
        } else {
            "box-fixture-mcp".to_string()
        };
        std::fs::write(
            scene.home().join(".agent.json"),
            serde_json::json!({"mcpServers": {"fixture": {"command": selected}}}).to_string(),
        )
        .expect("host MCP settings");
        scene.pack("servers", AGENT_SERVERS);
        scene.profile(
            "linked",
            &format!("packs = [\"servers\"]\n{PROBE}"),
            PROBE_POLICY,
        );
        let mut command = scene.command(
            &scene.workspace(),
            "linked",
            &["-c", &listing("box-fixture-mcp")],
        );
        command.env("PATH", format!("{}:/usr/bin:/bin", bin.display()));
        let output = launcher_output(command, &scene);
        assert_eq!(
            std::fs::read_to_string(checks_result).expect("the installation checks"),
            "passed\n",
            "npm installation read boundary: {}",
            stderr(&output)
        );
        succeeded(&output);
        assert!(stdout(&output).contains("echo_text"), "{}", stdout(&output));
        assert_eq!(
            std::fs::read_to_string(capture).expect("the invocation path"),
            format!("{}\n", program.display())
        );
        let run = scene.runs().pop().expect("a run");
        let config: toml::Table = std::fs::read_to_string(run.join("box.toml"))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            config["mcp"]["fixture"]["command"][0].as_str(),
            Some(selected.as_str())
        );
        let reads = config["mcp"]["fixture"]["filesystem"]["read"]
            .as_array()
            .unwrap();
        assert!(
            reads
                .iter()
                .all(|read| !secret.starts_with(read.as_str().unwrap())),
            "the server cannot read the installation's parent directory: {reads:?}"
        );
        assert!(
            reads.iter().any(|read| read.as_str() == modules.to_str()),
            "the complete installation tree is readable: {reads:?}"
        );
        assert_eq!(
            config["mcp"]["fixture"]["filesystem"]["write"],
            toml::Value::try_from(vec![scene.workspace().display().to_string()]).unwrap()
        );
        let lists = config["mcp"]["fixture"]["filesystem"]
            .get("list")
            .and_then(toml::Value::as_array);
        assert!(
            !lists.is_some_and(|paths| paths.iter().any(|path| path.as_str() == bin.to_str())),
            "the installation read already covers the link directory: {lists:?}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn an_mcp_alias_in_a_system_directory_keeps_the_configuration_valid() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let scene = Scene::new();
    let install = scene.root.join("installed");
    std::fs::create_dir(&install).expect("an installation directory");
    let real = install.join("server");
    std::fs::write(&real, FIXTURE_SERVER).expect("an MCP server");
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755))
        .expect("an executable server");
    let program = tempfile::Builder::new()
        .prefix("box-system-root-mcp-")
        .tempfile_in("/tmp")
        .expect("a unique alias path")
        .into_temp_path();
    std::fs::remove_file(&program).expect("remove the alias placeholder");
    symlink(&real, &program).expect("an executable link in the system directory");
    std::fs::write(
        scene.home().join(".agent.json"),
        serde_json::json!({"mcpServers": {"fixture": {"command": program.to_str()}}}).to_string(),
    )
    .expect("host MCP settings");
    scene.pack("servers", AGENT_SERVERS);
    scene.profile(
        "system-alias",
        &format!("packs = [\"servers\"]\n{PROBE}"),
        PROBE_POLICY,
    );
    let command = scene.command(
        &scene.workspace(),
        "system-alias",
        &["-c", "printf 'configuration loaded\\n'"],
    );
    let output = launcher_output(command, &scene);
    succeeded(&output);
    assert!(stdout(&output).contains("configuration loaded"));
    let run = scene.runs().pop().expect("a run");
    let config: toml::Table = std::fs::read_to_string(run.join("box.toml"))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        config["mcp"]["fixture"]["command"][0].as_str(),
        program.to_str()
    );
    assert!(
        config["mcp"]["fixture"]["filesystem"].get("list").is_none(),
        "{config}"
    );
}

/// A run folder of the profile `probe` that holds `box.toml` (naming `workspace`) and an empty
/// `box/`, as each part of `parts` says.
fn fake_run(folder: &Path, workspace: &Path, parts: &[&str]) {
    std::fs::create_dir_all(folder).expect("a run folder");
    std::fs::write(folder.join("profile-name"), "probe\n").expect("the profile record");
    if parts.contains(&"box") {
        std::fs::create_dir(folder.join("box")).expect("a box folder");
    }
    if parts.contains(&"box.toml") {
        std::fs::write(
            folder.join("box.toml"),
            format!(
                "[agent]\nworkspace = {:?}\n",
                workspace.display().to_string()
            ),
        )
        .expect("box.toml");
    }
}

#[test]
fn each_part_of_a_run_folder_is_checked_before_a_box_id_is_reused() {
    let scene = Scene::new();
    succeeded(&scene.probe(&scene.workspace(), "true"));
    let runs = scene.home().join(".strands/box/r");
    let workspace = scene.workspace();
    fake_run(
        &scene.home().join(".strands/box/b-000000000000000a"),
        &workspace,
        &["box", "box.toml"],
    );
    fake_run(&runs.join("b-000000000000000b"), &workspace, &["box.toml"]);
    fake_run(&runs.join("b-000000000000000c"), &workspace, &["box"]);
    fake_run(
        &scene.outside().join("b-000000000000000d"),
        &workspace,
        &["box", "box.toml"],
    );
    std::os::unix::fs::symlink(
        scene.outside().join("b-000000000000000d"),
        runs.join("b-000000000000000d"),
    )
    .expect("a linked run folder");
    fake_run(&runs.join("b-000000000000000e"), &workspace, &["box"]);
    std::fs::write(runs.join("b-000000000000000e/box.toml"), "not toml").expect("box.toml");
    fake_run(
        &runs.join("zzzzzzzzzzzzzzzz"),
        &workspace,
        &["box", "box.toml"],
    );
    fake_run(&runs.join("b-000000000000000f"), &workspace, &["box.toml"]);
    std::fs::create_dir(scene.outside().join("box-elsewhere")).expect("a box folder");
    std::os::unix::fs::symlink(
        scene.outside().join("box-elsewhere"),
        runs.join("b-000000000000000f/box"),
    )
    .expect("a linked box folder");
    fake_run(
        &runs.join("b-0000000000000010"),
        &workspace,
        &["box", "box.toml"],
    );
    std::fs::rename(
        runs.join("b-0000000000000010/box.toml"),
        scene.outside().join("box.toml"),
    )
    .expect("move box.toml");
    std::os::unix::fs::symlink(
        scene.outside().join("box.toml"),
        runs.join("b-0000000000000010/box.toml"),
    )
    .expect("a linked box.toml");
    fake_run(
        &runs.join("b-0000000000000011"),
        &workspace,
        &["box", "box.toml"],
    );
    std::fs::set_permissions(
        runs.join("b-0000000000000011/box.toml"),
        std::os::unix::fs::PermissionsExt::from_mode(0o000),
    )
    .expect("an unreadable box.toml");
    let before = scene.runs();
    for (id, message) in [
        ("../b-000000000000000a", "no run"),
        ("b-000000000000000b", "no run"),
        ("b-000000000000000c", "no run"),
        ("b-000000000000000d", "no run"),
        ("b-000000000000000e", "no run"),
        ("zzzzzzzzzzzzzzzz", "is not a run of profile probe"),
        ("b-000000000000000f", "no run"),
        ("b-0000000000000010", "no run"),
        ("b-0000000000000011", "cannot read"),
    ] {
        let output = scene
            .command_with(&workspace, "probe", &["--box-id", id], &["-c", "true"])
            .output()
            .expect("box runs");
        failed_with(&output, message);
        assert_eq!(scene.runs(), before, "{id}");
        assert!(
            !scene
                .outside()
                .join("b-000000000000000d/box/private")
                .exists(),
            "{id}"
        );
    }
}

#[test]
fn a_long_profile_name_reuses_its_own_box_id() {
    let scene = Scene::new();
    let name = "probe-with-a-long-profile-name";
    scene.profile(name, PROBE, PROBE_POLICY);
    succeeded(
        &scene
            .command(&scene.workspace(), name, &["-c", "true"])
            .output()
            .expect("box runs"),
    );
    let run = new_run(&[], &scene.runs());
    let id = box_id(&run);
    assert_eq!(id.len(), 18, "{id}");
    let again = scene
        .command_with(
            &scene.workspace(),
            name,
            &["--box-id", &id],
            &["-c", "true"],
        )
        .output()
        .expect("box runs");
    succeeded(&again);
    assert!(
        stderr(&again).contains(&format!("with box ID {id} again")),
        "{}",
        stderr(&again)
    );
    assert_eq!(scene.runs(), vec![run]);
}

#[test]
fn a_box_id_names_no_run_after_a_profile_clean() {
    let scene = Scene::new();
    succeeded(&scene.probe(&scene.workspace(), "true"));
    let id = box_id(&new_run(&[], &scene.runs()));
    let clean = Command::new(env!("CARGO_BIN_EXE_box"))
        .args(["profile", "clean", "--all", "--no-ask"])
        .current_dir(scene.workspace())
        .env_clear()
        .env("HOME", scene.home())
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .expect("box runs");
    succeeded(&clean);
    let output = scene
        .command_with(
            &scene.workspace(),
            "probe",
            &["--box-id", &id],
            &["-c", "true"],
        )
        .output()
        .expect("box runs");
    failed_with(&output, "no run");
    assert!(scene.runs().is_empty());
}

#[test]
fn a_box_id_does_not_create_a_profile_from_a_starter() {
    let scene = Scene::new();
    let output = scene
        .command_with(
            &scene.workspace(),
            "claude",
            &["--box-id", "claude-00000000"],
            &[],
        )
        .output()
        .expect("box runs");
    assert!(!output.status.success());
    assert!(
        !stderr(&output).contains("Creating one from the claude starter."),
        "{}",
        stderr(&output)
    );
    failed_with(&output, "no profile named claude");
    assert!(!scene.home().join(".strands/box/profiles/claude").exists());
    assert!(scene.runs().is_empty());
}

/// The operator starter `bashstart`, which runs `bash` and asks nothing.
fn bash_starter(scene: &Scene) {
    scene.pack(
        "bashstart",
        "\n[pack]\nname = \"bashstart\"\nversion = 1\nkind = \"agent\"\nextend = [\"@box/base\"]\n\
         [run]\ncommand = [\"/bin/bash\", \"--noprofile\", \"--norc\"]\n[env]\n\
         PATH = \"/usr/bin:/bin\"\nTMPDIR = \"${{ workspace }}\"\n",
    );
    let folder = scene.home().join(".strands/box/starters/bashstart");
    std::fs::create_dir_all(&folder).expect("a starter folder");
    std::fs::write(
        folder.join("starter.toml"),
        "[starter]\nname = \"bashstart\"\nlabel = \"bash\"\npacks = [\"bashstart\"]\n\
         policy = \"@box/scoped\"\n",
    )
    .expect("a starter");
    std::fs::write(
        scene.home().join(".strands/box/config.toml"),
        "[starters]\nadd = [\"bashstart\"]\n",
    )
    .expect("config.toml");
}

#[test]
fn a_box_id_recreates_a_removed_starter_profile_and_reuses_its_box() {
    let scene = Scene::new();
    bash_starter(&scene);
    let first = scene
        .command(&scene.workspace(), "bashstart", &["-c", "true"])
        .output()
        .expect("box runs");
    succeeded(&first);
    let folder = scene.home().join(".strands/box/profiles/bashstart");
    let profile = std::fs::read_to_string(folder.join("profile.toml")).expect("the profile");
    assert!(
        profile.contains("\npolicies = [\"policy.dw\"]\n"),
        "{profile}"
    );
    let copy = std::fs::read_to_string(folder.join("policy.dw")).expect("the policy copy");
    assert!(copy.starts_with("// Copied from @box/scoped "), "{copy}");
    let show = scene
        .process(Path::new(env!("CARGO_BIN_EXE_box")))
        .args(["profile", "show", "bashstart"])
        .current_dir(scene.workspace())
        .output()
        .expect("box runs");
    succeeded(&show);
    let show = stdout(&show);
    assert!(show.contains("\n  policies  policy.dw\n"), "{show}");
    assert!(show.contains("\n  project   read and write\n"), "{show}");
    assert!(
        profile.contains("\n[project]\naccess = \"write\"\n"),
        "{profile}"
    );
    assert!(!show.contains("\n  policy "), "{show}");
    let run = new_run(&[], &scene.runs());
    let id = box_id(&run);
    let box_before = core_box_id(&run);
    std::fs::remove_dir_all(scene.home().join(".strands/box/profiles/bashstart"))
        .expect("the profile folder is removed by hand, so its box stays");
    let again = scene
        .command_with(
            &scene.workspace(),
            "bashstart",
            &["--box-id", &id],
            &["-c", "true"],
        )
        .output()
        .expect("box runs");
    succeeded(&again);
    assert!(
        stderr(&again).contains("Creating one from the bashstart starter."),
        "{}",
        stderr(&again)
    );
    assert!(
        stderr(&again).contains(&format!("with box ID {id} again")),
        "{}",
        stderr(&again)
    );
    assert_eq!(scene.runs(), vec![run.clone()]);
    assert_eq!(core_box_id(&run), box_before, "the same box");
}

#[test]
fn a_box_id_that_would_be_refused_creates_no_starter_profile() {
    let scene = Scene::new();
    bash_starter(&scene);
    succeeded(&scene.probe(&scene.workspace(), "true"));
    let probe_run = box_id(&new_run(&[], &scene.runs()));
    let elsewhere = scene.home().join("elsewhere");
    std::fs::create_dir(&elsewhere).expect("another project");
    succeeded(
        &scene
            .command(&elsewhere, "bashstart", &["-c", "true"])
            .output()
            .expect("box runs"),
    );
    let other_project = box_id(
        scene
            .runs()
            .iter()
            .find(|run| {
                std::fs::read_to_string(run.join("profile-name"))
                    .is_ok_and(|name| name == "bashstart\n")
            })
            .expect("a bashstart run"),
    );
    std::fs::remove_dir_all(scene.home().join(".strands/box/profiles/bashstart")).expect("reset");
    let broken = scene.home().join(".strands/box/r/b-000000000000000e");
    std::fs::create_dir_all(broken.join("box")).expect("a run folder");
    std::fs::write(broken.join("box.toml"), "not toml").expect("box.toml");
    for (id, message) in [
        (probe_run.as_str(), "is not a run of profile bashstart"),
        ("b-000000000000000e", "no run"),
    ] {
        let output = scene
            .command_with(
                &scene.workspace(),
                "bashstart",
                &["--box-id", id],
                &["-c", "true"],
            )
            .output()
            .expect("box runs");
        assert!(
            !stderr(&output).contains("Creating one from"),
            "{id}: {}",
            stderr(&output)
        );
        failed_with(&output, "no profile named bashstart");
        assert!(
            !scene
                .home()
                .join(".strands/box/profiles/bashstart")
                .exists(),
            "{id}: a refused ID creates no profile ({message})"
        );
    }
    let moved = scene
        .command_with(
            &scene.workspace(),
            "bashstart",
            &["--box-id", &other_project],
            &["-c", "true"],
        )
        .output()
        .expect("box runs");
    succeeded(&moved);
    assert!(
        stderr(&moved).contains("Creating one from the bashstart starter"),
        "an ID from another folder is reusable, so the starter profile comes back: {}",
        stderr(&moved)
    );
}

#[test]
fn box_core_decides_a_tool_by_its_grammar_and_a_forbid_on_an_effect_denies_it() {
    let scene = Scene::new();
    let bin = scene.outside().join("bin");
    std::fs::create_dir_all(&bin).expect("a bin folder");
    std::fs::copy("/usr/bin/true", bin.join("greet")).expect("a greet program");
    scene.pack(
        "greet",
        "[pack]\nname = \"greet\"\nversion = 1\nkind = \"tool\"\n[inputs.greet.path]\n\
         type = \"program\"\nprogram = \"greet\"\nsearch = [{ env = \"PATH\" }]\n[run]\n\
         command = [\"${{ inputs.greet.path }}\"]",
    );
    std::fs::write(
        scene.home().join(".strands/box/packs/greet/grammar.toml"),
        "format = 1\nversion = 1\nname = \"greet\"\nprogram = \"greet\"\n\
         [effects]\nloud = \"Shouts the greeting\"\n\
         [shell.hello]\nusage = \"greet hello [options] [<name>]\"\n\
         options.loud = { flag = [\"--loud\"], adds = [\"loud\"] }\n",
    )
    .expect("a grammar");
    let profile = format!(
        "packs = [\"greet\"]\n[agent]\ncommand = [\"/bin/bash\", \"--noprofile\", \"--norc\"]\n\
         env.PATH = \"{}:/usr/bin:/bin\"\nenv.TMPDIR = \"${{{{ workspace }}}}\"\n",
        bin.display()
    );
    scene.profile(
        "grammar",
        &profile,
        &format!(
            "{PROBE_POLICY}\n\n@id(\"no_loud\")\n\
             forbid (principal, action == Tool::greet::Action::\"hello\", resource) \
             when {{ context.input.effects.contains(Tool::greet::Effect::\"loud\") }};\n"
        ),
    );
    let script = [
        "bash -c 'greet hello world'; echo \"hello: $?\"\n",
        "bash -c 'greet hello --loud world'; echo \"loud: $?\"\n",
        "bash -c 'greet wave'; echo \"wave: $?\"\n",
    ]
    .concat();
    let output = scene
        .command(&scene.workspace(), "grammar", &["-c", &script])
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .output()
        .expect("box runs");
    succeeded(&output);
    assert_eq!(
        stdout(&output),
        "hello: 0\nloud: 126\nwave: 0\n",
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let run = scene.runs().pop().expect("a run");
    let box_toml = std::fs::read_to_string(run.join("box.toml")).unwrap_or_default();
    assert!(box_toml.contains("tool-grammars = true"), "{box_toml}");
    let decisions = decisions(&run);
    for (action, rule) in [
        ("hello", "tool_greet"),
        ("hello", "no_loud"),
        ("unmodeled", "tool_greet"),
    ] {
        assert!(
            decisions
                .iter()
                .any(|found| found.0 == action && found.2 == rule),
            "{action} {rule} in {decisions:?}"
        );
    }
    assert!(
        !decisions
            .iter()
            .any(|found| found.0 == "shell:spawn" && found.1.ends_with("/greet")),
        "{decisions:?}"
    );
}

#[test]
fn a_tool_writes_its_state_outside_the_workspace_and_the_agent_cannot() {
    let scene = Scene::new();
    let bin = scene.outside().join("bin");
    std::fs::create_dir_all(&bin).expect("a bin folder");
    std::os::unix::fs::symlink("/usr/bin/touch", bin.join("stamp")).expect("a stamp program");
    let settings = scene.outside().join("stamp.conf");
    std::fs::write(&settings, "from the host\n").expect("a host file");
    scene.pack(
        "stamp",
        &format!(
            "[pack]\nname = \"stamp\"\nversion = 1\nkind = \"tool\"\n[inputs.stamp.path]\n\
             type = \"program\"\nprogram = \"stamp\"\nsearch = [{{ env = \"PATH\" }}]\n[run]\n\
             command = [\"${{{{ inputs.stamp.path }}}}\"]\n[storage]\ndirectories = [\"state\"]\n\
             [[storage.files]]\nsource = \"{}\"\ntarget = \"state/stamp.conf\"\nmode = \"copy\"\n\
             [filesystem]\nread = [\"${{{{ storage.state }}}}\"]\n\
             write = [\"${{{{ storage.state }}}}\"]\n",
            settings.display()
        ),
    );
    let profile = format!(
        "packs = [\"stamp\"]\n[agent]\ncommand = [\"/bin/bash\", \"--noprofile\", \"--norc\"]\n\
         env.PATH = \"{}:/usr/bin:/bin\"\nenv.TMPDIR = \"${{{{ workspace }}}}\"\n",
        bin.display()
    );
    scene.profile("stamp", &profile, PROBE_POLICY);
    let workspace = scene.workspace();
    let state = scene
        .home()
        .join(".strands/box/storage/stamp/default/tool/stamp/state");
    let script = "bash -c \"stamp $1/by-tool\"; echo \"tool: $?\"\n\
                  echo agent > \"$1/by-agent\"; echo \"agent: $?\"\n\
                  cat \"$1/stamp.conf\"; echo \"agent reads: $?\"\n";
    let output = scene
        .command(
            &workspace,
            "stamp",
            &["-c", script, "probe", &state.display().to_string()],
        )
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .output()
        .expect("box runs");
    succeeded(&output);
    let run = scene.runs().pop().expect("a run");
    assert!(
        stdout(&output).starts_with("tool: 0\nagent: ") && !stdout(&output).contains("agent: 0"),
        "{}\n{}",
        stdout(&output),
        std::fs::read_to_string(run.join("box.toml")).unwrap_or_default()
    );
    assert!(state.join("by-tool").is_file(), "{}", stderr(&output));
    assert!(!state.join("by-agent").exists(), "{}", stdout(&output));
    assert_eq!(
        std::fs::read_to_string(state.join("stamp.conf"))
            .ok()
            .as_deref(),
        Some("from the host\n"),
        "a tool's copy row copies into the tool's own storage"
    );
    assert!(
        !stdout(&output).contains("from the host")
            && stdout(&output).contains("agent reads: ")
            && !stdout(&output).contains("agent reads: 0"),
        "the agent cannot read the tool's copy: {}",
        stdout(&output)
    );
    assert!(!scene.workspace().join(".cache").exists());
}

/// A profile of the probe and `@box/git`, in a repository with one commit.
fn git_scene() -> Scene {
    let scene = Scene::new();
    scene.profile(
        "git",
        &format!("packs = [\"@box/git\"]\n{PROBE}"),
        PROBE_POLICY,
    );
    let script = "set -e\nbash -c 'git init -q -b main'\necho hello > README.md\n\
                  bash -c 'git add README.md'\nbash -c 'git commit -qm first'\n";
    let output = scene.probe_with(&scene.workspace(), "git", script);
    succeeded(&output);
    scene
}

impl Scene {
    /// Run `script` in bash in a new box of `profile` in `workspace`, with the first `git` on this
    /// process's `PATH`.
    fn probe_with(&self, workspace: &Path, profile: &str, script: &str) -> Output {
        let git = folder_of("git").expect("git on PATH (docs/dev/engine-tests.md)");
        let mut command = self.command(workspace, profile, &["-c", script]);
        command.env("PATH", format!("{}:/usr/bin:/bin", git.display()));
        if let Some(prefix) = std::env::var_os("HOMEBREW_PREFIX") {
            command.env("HOMEBREW_PREFIX", prefix);
        }
        command.output().expect("box runs")
    }
}

#[test]
fn box_git_starts_git_as_its_own_child() {
    let scene = git_scene();
    let output = scene.probe_with(
        &scene.workspace(),
        "git",
        "bash -c 'git worktree add -q -b refactor .worktrees/refactor'",
    );
    succeeded(&output);
    assert!(
        scene
            .workspace()
            .join(".worktrees/refactor/README.md")
            .is_file(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn the_locked_starter_starts_a_declared_tool_and_refuses_the_shells_own_commands() {
    let scene = git_scene();
    scene.profile(
        "locked",
        &format!("packs = [\"@box/git\"]\n{PROBE}"),
        LOCKED_STARTER,
    );
    let script = [
        check("git", "bash -c 'git --version 2>/dev/null' >/dev/null"),
        check("git to /dev/null", "bash -c 'git status >/dev/null'"),
        check("cat", "bash -c 'cat README.md'"),
    ]
    .concat();
    let output = scene.probe_with(&scene.workspace(), "locked", &script);
    succeeded(&output);
    assert_eq!(
        stdout(&output),
        "git: yes\ngit to /dev/null: yes\ncat: no\n"
    );
}

#[test]
fn box_git_starts_its_https_remote_helper() {
    let scene = git_scene();
    let output = scene.probe_with(
        &scene.workspace(),
        "git",
        "bash -c 'git push https://boxy-corpus.invalid/missing.git main'",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("unable to access 'https://boxy-corpus.invalid/missing.git/'"),
        "{stderr}"
    );
}

#[test]
fn box_git_rewrites_github_ssh_remotes_to_https() {
    let scene = git_scene();
    let output = scene.probe_with(
        &scene.workspace(),
        "git",
        "set -e\n\
         bash -c 'git remote add scp git@github.com:owner/repo.git'\n\
         bash -c 'git remote add url ssh://git@github.com/owner/repo.git'\n\
         bash -c 'git remote get-url --push scp'\n\
         bash -c 'git remote get-url --push url'\n",
    );
    succeeded(&output);
    assert_eq!(
        stdout(&output),
        "https://github.com/owner/repo.git\nhttps://github.com/owner/repo.git\n"
    );
}
