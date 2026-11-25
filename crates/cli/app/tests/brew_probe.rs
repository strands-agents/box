//! Probe, not a regression test: with a real Homebrew install of `box` and an operator policy
//! that permits every filesystem action, can the agent, the Shell, or Monty change Homebrew's
//! `bin/box` or `bin` folder? Needs `BREW_PREFIX` and `brew install --cask strands-agents/tap/box`.
//! Run with `cargo test -p strands-box-cli --all-features --test brew_probe -- --nocapture`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const PROBE: &str = include_str!("../../../../test-corpus/profiles/probe/profile.toml");

const POLICY: &str = r#"@id("probe_shell") permit (principal, action == Box::Action::"shell:exec", resource);
@id("read_everything") permit (principal, action == Box::Action::"fs:read", resource);
@id("write_everything") permit (principal, action == Box::Action::"fs:write", resource);
@id("delete_everything") permit (principal, action == Box::Action::"fs:delete", resource);
@id("move_everything") permit (principal, action == Box::Action::"fs:move", resource);
"#;

struct Brew {
    prefix: PathBuf,
    link: PathBuf,
    target: PathBuf,
    real: PathBuf,
    real_bytes: Vec<u8>,
}

impl Brew {
    fn find() -> Self {
        let prefix = PathBuf::from(std::env::var_os("BREW_PREFIX").expect("BREW_PREFIX"));
        let link = prefix.join("bin/box");
        let target = std::fs::read_link(&link).expect("bin/box is a Homebrew link");
        let real = std::fs::canonicalize(&link).expect("bin/box resolves");
        let real_bytes = std::fs::read(&real).expect("the real box reads");
        Self { prefix, link, target, real, real_bytes }
    }

    fn state(&self, home: &Path) -> String {
        let bin = self.prefix.join("bin");
        format!(
            "bin={} bin.old={} bin/box={} newtool={} real-box={} ~/stolen={}",
            bin.is_dir(),
            self.prefix.join("bin.old").exists(),
            std::fs::read_link(&self.link)
                .map(|target| if target == self.target { "brew link".to_string() } else { format!("link to {}", target.display()) })
                .unwrap_or_else(|_| match std::fs::read(&self.link) {
                    Ok(bytes) => format!("file {:?}", String::from_utf8_lossy(&bytes)),
                    Err(_) => "missing".into(),
                }),
            bin.join("newtool").exists(),
            if std::fs::read(&self.real).is_ok_and(|bytes| bytes == self.real_bytes) { "unchanged" } else { "CHANGED" },
            home.join("stolen").exists(),
        )
    }

    /// Put Homebrew back as it was, so that one case's success cannot hide the next one.
    fn restore(&self) {
        let bin = self.prefix.join("bin");
        let aside = self.prefix.join("bin.old");
        if !bin.exists() && aside.exists() {
            std::fs::rename(&aside, &bin).expect("bin back");
        }
        let _ = std::fs::remove_file(bin.join("newtool"));
        if std::fs::read_link(&self.link).ok().as_deref() != Some(self.target.as_path()) {
            let _ = std::fs::remove_file(&self.link);
            std::os::unix::fs::symlink(&self.target, &self.link).expect("bin/box back");
        }
        assert!(
            std::fs::read(&self.real).is_ok_and(|bytes| bytes == self.real_bytes),
            "the real box changed; reinstall the cask"
        );
    }
}

struct Scene {
    _root: tempfile::TempDir,
    root: PathBuf,
}

impl Scene {
    fn new(brew: &Brew) -> Self {
        let parent = PathBuf::from(std::env::var_os("HOME").expect("HOME")).join(".cache");
        std::fs::create_dir_all(&parent).unwrap();
        let directory = tempfile::Builder::new().prefix("bx").tempdir_in(parent).unwrap();
        let scene = Self { root: directory.path().canonicalize().unwrap(), _root: directory };
        let home = scene.home();
        std::fs::create_dir_all(scene.home().join("project")).unwrap();
        std::fs::write(home.join("evil"), "evil").unwrap();
        let prefix = brew.prefix.display().to_string();
        let profile = |name: &str, extra: &str| {
            let folder = home.join(".strands/box/profiles").join(name);
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(folder.join("profile.toml"), format!("policies = [\"policy.dw\"]\n{PROBE}\n{extra}")).unwrap();
            std::fs::write(folder.join("policy.dw"), POLICY).unwrap();
        };
        profile("probe", "");
        profile("grant-bin", &format!("[agent.filesystem]\nwrite = [\"{prefix}/bin\"]\n"));
        profile("grant-prefix", &format!("[agent.filesystem]\nwrite = [\"{prefix}\"]\n"));
        scene
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn run_as(&self, brew: &Brew, profile: &str, script: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_box"))
            .env_clear()
            .env("HOME", self.home())
            .env("PATH", format!("{}/bin:/usr/bin:/bin", brew.prefix.display()))
            .stdin(Stdio::null())
            .arg("run")
            .arg(profile)
            .arg("--")
            .arg("-c")
            .arg(script)
            .current_dir(self.home().join("project"))
            .output()
            .expect("box runs")
    }
}

fn shell(command: &str) -> String {
    format!("bash -c '{command}' 2>&1; echo \"exit=$?\"")
}

fn monty(code: &str) -> String {
    format!("bash -c \"python3 -c \\\"{code}\\\"\" 2>&1; echo \"exit=$?\"")
}

fn agent(command: &str) -> String {
    format!("{{ {command}; }} 2>&1; echo \"exit=$?\"")
}

#[test]
fn probe() {
    let brew = Brew::find();
    println!("prefix={} bin/box -> {} real={}", brew.prefix.display(), brew.target.display(), brew.real.display());
    let cases: Vec<(&str, &str, String)> = vec![
        ("H0 control: shell writes ~/ok", "probe", shell("echo ok > HOME/ok && cat HOME/ok")),
        ("H1 shell: write through P/bin/box", "probe", shell("echo evil > P/bin/box")),
        ("H2 shell: delete P/bin/box", "probe", shell("rm -f P/bin/box")),
        ("H3 shell: move P/bin/box to ~/stolen", "probe", shell("mv P/bin/box HOME/stolen")),
        ("H4 shell: relink P/bin/box", "probe", shell("ln -sf HOME/evil P/bin/box")),
        ("H5 shell: move P/bin to P/bin.old", "probe", shell("mv P/bin P/bin.old")),
        ("H6 shell: new P/bin/newtool", "probe", shell("echo x > P/bin/newtool")),
        ("H7 shell: write the real box", "probe", shell("echo evil > REAL")),
        ("H8 monty: write P/bin/box", "probe", monty("open('P/bin/box', 'w').write('evil')")),
        ("H9 monty: move P/bin to P/bin.old", "probe", monty("import os; os.rename('P/bin', 'P/bin.old')")),
        ("H10 agent: write P/bin/box", "probe", agent("echo evil > P/bin/box")),
        ("H11 agent: move P/bin to P/bin.old", "probe", agent("/bin/mv P/bin P/bin.old")),
        ("H12 profile write grant on P/bin", "grant-bin", agent("echo started")),
        ("H13 profile write grant on P", "grant-prefix", agent("echo started")),
    ];
    for (label, profile, script) in cases {
        let scene = Scene::new(&brew);
        let home = scene.home();
        let before = brew.state(&home);
        let script = script
            .replace("P/", &format!("{}/", brew.prefix.display()))
            .replace("HOME", &home.display().to_string())
            .replace("REAL", &brew.real.display().to_string());
        let output = scene.run_as(&brew, profile, &script);
        let shown = |text: &[u8]| String::from_utf8_lossy(text).replace(&home.display().to_string(), "~");
        println!("=== {label}");
        println!("  box exit: {}", output.status);
        for line in shown(&output.stdout).lines() {
            println!("  out: {line}");
        }
        for line in shown(&output.stderr).lines().filter(|line| {
            line.contains("error") || line.contains("refus") || line.contains("denied") || line.contains("PATH")
        }) {
            println!("  err: {line}");
        }
        let after = brew.state(&home);
        println!("  before: {before}");
        println!("  after:  {after}");
        println!("  verdict: {}", if after == before { "same" } else { "CHANGED" });
        brew.restore();
    }
}
