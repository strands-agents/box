use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "jailbreak-harness-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_workload-oracle"))
}

#[test]
fn agent_waits_for_token() {
    let scratch = Scratch::new();
    let fake = scratch.0.join("strands-box");
    fs::write(&fake, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    let mut child = binary()
        .args([
            "jailbreak",
            "agent-worker",
            "--config",
            "config with spaces",
            "--workspace",
        ])
        .arg(&scratch.0)
        .args(["--prompt", "literal `command` $(command) \"quoted\""])
        .env("PATH", &scratch.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(150));
    assert!(
        child.try_wait().unwrap().is_none(),
        "the worker must wait for its root registration"
    );
    child.stdin.take().unwrap().write_all(b"1").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("agent did not finish after the launch token");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "run\n--config\nconfig with spaces\n--\n--print\n--output-format\nstream-json\n--verbose\n--dangerously-skip-permissions\nliteral `command` $(command) \"quoted\"\n"
    );
}

#[test]
fn agent_needs_token() {
    let scratch = Scratch::new();
    let output = binary()
        .args([
            "jailbreak",
            "agent-worker",
            "--config",
            "unused",
            "--workspace",
        ])
        .arg(&scratch.0)
        .args(["--prompt", "unused"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to fill whole buffer"));
}

#[test]
fn signals_clean_up() {
    for signal in ["-TERM", "-INT"] {
        let scratch = Scratch::new();
        let fake = scratch.0.join("tcpdump");
        fs::write(
            &fake,
            "#!/bin/sh\nprintf '%s' \"$$\" > \"$CAPTURE_PID\"\nexec /bin/sleep 30\n",
        )
        .unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        let pid_file = scratch.0.join("capture.pid");
        let path = format!(
            "{}:{}",
            scratch.0.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut worker = binary()
            .args(["jailbreak", "oracle-worker", "--run-dir"])
            .arg(&scratch.0)
            .env("PATH", path)
            .env("CAPTURE_PID", &pid_file)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !pid_file.is_file() || fs::read_to_string(&pid_file).unwrap_or_default().is_empty() {
            if Instant::now() >= deadline {
                let _ = worker.kill();
                panic!("capture did not start");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let capture_pid = fs::read_to_string(&pid_file).unwrap();
        assert!(
            Command::new("kill")
                .args([signal, &worker.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        while worker.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                let _ = worker.kill();
                let _ = Command::new("kill").args(["-KILL", &capture_pid]).status();
                panic!("oracle did not handle {signal} within three seconds");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = worker.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("shutdown requested"));
        let alive = Command::new("kill")
            .args(["-0", &capture_pid])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success();
        if alive {
            let _ = Command::new("kill").args(["-KILL", &capture_pid]).status();
        }
        assert!(!alive, "capture outlived the oracle after {signal}");
        assert!(!scratch.0.join("oracle/oracle.pid").exists());
        assert!(
            !fs::read_to_string(scratch.0.join("oracle/verdict.json"))
                .unwrap()
                .contains("oracle-final")
        );
    }
}

#[test]
fn brew_lock_retry() {
    use std::os::unix::process::CommandExt;
    let source = include_str!("../../manual/macos/install.sh");
    let start = source.find("install_node() {").unwrap();
    let end = source[start..].find("\n}\n").unwrap() + start + 3;
    for (case, timeout, success, expected_calls) in [
        ("transient", 300, true, 2),
        ("other", 300, false, 1),
        ("locked", 0, false, 1),
    ] {
        let script = format!("set -e\n{}\ninstall_node {timeout}\n", &source[start..end]);
        let scratch = Scratch::new();
        let brew = scratch.0.join("brew");
        let body = match case {
            "transient" => {
                "#!/bin/sh\nif [ ! -f \"$CALLS\" ]; then echo first > \"$CALLS\"; echo 'Error: a brew install process has already locked openssl@3'; exit 1; fi\necho retry >> \"$CALLS\"\necho installed\n"
            }
            "locked" => {
                "#!/bin/sh\necho first >> \"$CALLS\"\necho 'Error: a brew install process has already locked openssl@3'\nexit 1\n"
            }
            _ => {
                "#!/bin/sh\necho first >> \"$CALLS\"\necho 'Error: unrelated download failure'\nexit 1\n"
            }
        };
        fs::write(&brew, body).unwrap();
        fs::set_permissions(&brew, fs::Permissions::from_mode(0o755)).unwrap();
        let sleep = scratch.0.join("sleep");
        fs::write(&sleep, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&sleep, fs::Permissions::from_mode(0o755)).unwrap();
        let calls = scratch.0.join("calls");
        let mut child = Command::new("bash")
            .args(["-c", &script])
            .env("BREW", &brew)
            .env("CALLS", &calls)
            .env("TMPDIR", &scratch.0)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    scratch.0.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                let _ = Command::new("kill")
                    .args(["-KILL", "--", &format!("-{}", child.id())])
                    .status();
                let _ = child.kill();
                let _ = child.wait();
                panic!("installer did not finish fixture {case} within three seconds");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(calls).unwrap().lines().count(),
            expected_calls
        );
    }
}

#[test]
fn native_install_fallback() {
    use std::os::unix::process::CommandExt;
    let source = include_str!("../../manual/macos/install.sh");
    let start = source.find("install_native_claude() {").unwrap();
    let end = source[start..].find("\ninstall_claude\n").unwrap() + start;
    for (case, spec, native) in [
        ("ok", "@2.1.3", true),
        ("ok", "", true),
        ("download", "@2.1.3", false),
        ("missing", "@2.1.3", false),
        ("broken", "@2.1.3", false),
    ] {
        let scratch = Scratch::new();
        let bin = scratch.0.join("bin");
        fs::create_dir(&bin).unwrap();
        let installer = scratch.0.join("installer");
        fs::write(
            &installer,
            "#!/bin/bash\nprintf '%s' \"$1\" > \"$HOME/version\"\n[ \"$INSTALL_CASE\" != missing ] || exit 0\nmkdir -p \"$HOME/.local/bin\"\nstatus=0; [ \"$INSTALL_CASE\" != broken ] || status=1\nprintf '#!/bin/sh\\nexit %s\\n' \"$status\" > \"$HOME/.local/bin/claude\"\nchmod +x \"$HOME/.local/bin/claude\"\n",
        )
        .unwrap();
        for (name, body) in [
            (
                "curl",
                "#!/bin/sh\n[ \"$INSTALL_CASE\" != download ] || exit 1\nwhile [ \"$1\" != -o ]; do shift; done\ncp \"$HOME/installer\" \"$2\"\n",
            ),
            (
                "brew",
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$HOME/brew-calls\"\nif [ \"$1\" = --prefix ]; then printf '%s\\n' \"$HOME\"; fi\n",
            ),
            (
                "npm",
                "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$HOME/npm-calls\"\nprintf '#!/bin/sh\\nexit 0\\n' > \"$HOME/bin/claude\"\nchmod +x \"$HOME/bin/claude\"\n",
            ),
        ] {
            let path = bin.join(name);
            fs::write(&path, body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let script = format!(
            "set -e\n{}\ninstall_claude\nexport PATH=\"$HOME/.local/bin:$PATH\"\nclaude --version\n",
            &source[start..end]
        );
        let mut child = Command::new("bash")
            .args(["-c", &script])
            .env("HOME", &scratch.0)
            .env("INSTALL_CASE", case)
            .env("CLAUDE_SPEC", spec)
            .env("BREW", bin.join("brew"))
            .env("TMPDIR", &scratch.0)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                let _ = Command::new("kill")
                    .args(["-KILL", "--", &format!("-{}", child.id())])
                    .status();
                let _ = child.kill();
                let _ = child.wait();
                panic!("native installer did not finish fixture {case}");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if native {
            assert!(!scratch.0.join("brew-calls").exists());
            assert!(!scratch.0.join("npm-calls").exists());
            assert_eq!(
                fs::read_to_string(scratch.0.join("version")).unwrap(),
                if spec.is_empty() {
                    "latest"
                } else {
                    &spec[1..]
                }
            );
        } else {
            assert_eq!(
                fs::read_to_string(scratch.0.join("npm-calls")).unwrap(),
                format!("install -g @anthropic-ai/claude-code{spec}\n")
            );
        }
    }
}
