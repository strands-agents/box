//! Probe, not a regression test: under an operator permit on every filesystem action, which `PATH`
//! folders and `box` links can the agent, the Shell, and Monty change? Prints one block per case.
//! Run with `cargo test -p strands-box-cli --all-features --test launch_probe -- --nocapture`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const PROBE: &str = include_str!("../../../../test-corpus/profiles/probe/profile.toml");

const POLICY: &str = r#"@id("probe_shell") permit (principal, action == Box::Action::"shell:exec", resource);
@id("read_everything") permit (principal, action == Box::Action::"fs:read", resource);
@id("write_everything") permit (principal, action == Box::Action::"fs:write", resource);
@id("delete_everything") permit (principal, action == Box::Action::"fs:delete", resource);
@id("move_everything") permit (principal, action == Box::Action::"fs:move", resource);
"#;

struct Scene {
    _root: tempfile::TempDir,
    _outside: tempfile::TempDir,
    root: PathBuf,
    outside: PathBuf,
}

impl Scene {
    fn new() -> Self {
        let parent = PathBuf::from(std::env::var_os("HOME").expect("HOME")).join(".cache");
        std::fs::create_dir_all(&parent).unwrap();
        let directory = tempfile::Builder::new().prefix("bx").tempdir_in(parent).unwrap();
        let outside = tempfile::Builder::new().prefix("bx").tempdir_in("/tmp").unwrap();
        let scene = Self {
            root: directory.path().canonicalize().unwrap(),
            outside: outside.path().canonicalize().unwrap(),
            _root: directory,
            _outside: outside,
        };
        std::fs::create_dir_all(scene.workspace()).unwrap();
        let folder = scene.home().join(".strands/box/profiles/probe");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("profile.toml"), format!("policies = [\"policy.dw\"]\n{PROBE}")).unwrap();
        std::fs::write(folder.join("policy.dw"), POLICY).unwrap();
        // The agent itself may write `~/.cargo`, but not its `bin`, as a profile must say.
        let native = scene.home().join(".strands/box/profiles/native");
        std::fs::create_dir_all(&native).unwrap();
        std::fs::write(
            native.join("profile.toml"),
            format!(
                "policies = [\"policy.dw\"]\n{PROBE}\n[agent.filesystem]\nwrite = [\"${{{{ home }}}}/.cargo\"]\n\n\
                 [filesystem]\ndeny_write = [\"${{{{ home }}}}/.cargo/bin\"]\n"
            ),
        )
        .unwrap();
        std::fs::write(native.join("policy.dw"), POLICY).unwrap();
        // The launch layout: `~/bin/box` and `<outside>/brew/bin/box` link to this `box`, and
        // `~/.cargo/bin` comes first on `PATH` with no `box` in it.
        let real = Path::new(env!("CARGO_BIN_EXE_box"));
        for folder in [scene.home().join("bin"), scene.home().join(".cargo/bin"), scene.brew_bin(), scene.home().join("dot/bin")] {
            std::fs::create_dir_all(&folder).unwrap();
        }
        std::os::unix::fs::symlink(real, scene.home().join("bin/box")).unwrap();
        // `~/linked-bin` is a link to `~/dot/bin`, as a dotfiles checkout does.
        std::os::unix::fs::symlink(scene.home().join("dot/bin"), scene.home().join("linked-bin")).unwrap();
        std::os::unix::fs::symlink(real, scene.home().join("dot/bin/box")).unwrap();
        std::fs::write(scene.home().join("evil"), "evil").unwrap();
        std::os::unix::fs::symlink(real, scene.brew_bin().join("box")).unwrap();
        std::fs::write(scene.home().join("bin/tool"), "tool").unwrap();
        std::fs::write(scene.brew_bin().join("tool"), "tool").unwrap();
        scene
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn workspace(&self) -> PathBuf {
        self.home().join("project")
    }

    fn brew_bin(&self) -> PathBuf {
        self.outside.join("brew/bin")
    }

    fn search_path(&self) -> String {
        format!(
            "{}:{}:{}:{}:/usr/bin:/bin",
            self.home().join(".cargo/bin").display(),
            self.home().join("bin").display(),
            self.home().join("linked-bin").display(),
            self.brew_bin().display()
        )
    }

    fn run(&self, script: &str) -> Output {
        self.run_as("probe", script)
    }

    fn run_as(&self, profile: &str, script: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_box"))
            .env_clear()
            .env("HOME", self.home())
            .env("PATH", self.search_path())
            .stdin(Stdio::null())
            .arg("run")
            .arg(profile)
            .arg("--")
            .arg("-c")
            .arg(script)
            .current_dir(self.workspace())
            .output()
            .expect("box runs")
    }

    fn policy(&self) -> String {
        let mut runs: Vec<PathBuf> = std::fs::read_dir(self.home().join(".strands/box/r"))
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default();
        runs.sort();
        runs.last()
            .map(|run| std::fs::read_to_string(run.join("policy.dw")).unwrap_or_default())
            .unwrap_or_default()
    }

    fn records(&self) -> String {
        let mut runs: Vec<PathBuf> = std::fs::read_dir(self.home().join(".strands/box/r"))
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default();
        runs.sort();
        runs.last()
            .map(|run| std::fs::read_to_string(run.join("records.jsonl")).unwrap_or_default())
            .unwrap_or_default()
    }

    /// What each probed path is now.
    fn state(&self) -> String {
        let real = Path::new(env!("CARGO_BIN_EXE_box"));
        let mut lines = Vec::new();
        for path in [
            self.home().join("bin"),
            self.home().join("bin/box"),
            self.home().join("bin/tool"),
            self.home().join("bin/new"),
            self.home().join("bin.old"),
            self.home().join(".cargo/bin"),
            self.home().join(".cargo/bin/box"),
            self.home().join(".cargo/bin/new"),
            self.home().join(".cargo/bin.old"),
            self.home().join(".cargo/new"),
            self.home().join("linked-bin"),
            self.home().join("dot/bin/box"),
            self.home().join("dot.old"),
            self.home().join("linked-bin.old"),
            self.brew_bin(),
            self.brew_bin().join("box"),
            self.brew_bin().join("tool"),
            self.brew_bin().join("new"),
            self.outside.join("brew/bin.old"),
        ] {
            let shown = path.display().to_string().replace(&self.home().display().to_string(), "~").replace(&self.outside.display().to_string(), "<outside>");
            let what = match std::fs::symlink_metadata(&path) {
                Err(_) => "absent".to_string(),
                Ok(meta) if meta.file_type().is_symlink() => {
                    let target = std::fs::read_link(&path).unwrap();
                    if target == real { "link to box".to_string() } else { format!("link to {}", target.display()) }
                }
                Ok(meta) if meta.is_dir() => "folder".to_string(),
                Ok(_) => format!("file {:?}", std::fs::read_to_string(&path).unwrap_or_default()),
            };
            lines.push(format!("    {shown}: {what}"));
        }
        lines.join("\n")
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
fn launch_folders() {
    let probe = Scene::new();
    let home = probe.home().display().to_string();
    let brew = probe.brew_bin().display().to_string();
    let cases: Vec<(String, String)> = vec![
        ("native: write ~/.cargo/new".into(), format!("native:{}", agent(&format!("echo ok > {home}/.cargo/new")))),
        ("native: new ~/.cargo/bin/box".into(), format!("native:{}", agent(&format!("echo evil > {home}/.cargo/bin/box")))),
        ("shell: move a file to ~/.cargo/bin/box".into(), shell(&format!("mv {home}/evil {home}/.cargo/bin/box"))),
        ("shell: copy a file to ~/.cargo/bin/box".into(), shell(&format!("cp {home}/evil {home}/.cargo/bin/box"))),
        ("shell: link ~/.cargo/bin/box".into(), shell(&format!("ln -s {home}/evil {home}/.cargo/bin/box"))),
        ("shell: delete ~/dot/bin/box".into(), shell(&format!("rm {home}/dot/bin/box"))),
        ("shell: delete ~/linked-bin/box".into(), shell(&format!("rm {home}/linked-bin/box"))),
        ("shell: move ~/dot aside".into(), shell(&format!("mv {home}/dot {home}/dot.old"))),
        ("shell: move ~/linked-bin aside".into(), shell(&format!("mv {home}/linked-bin {home}/linked-bin.old"))),
        ("agent: write through ~/bin/box".into(), agent(&format!("echo evil > {home}/bin/box"))),
        ("agent: new ~/.cargo/bin/box".into(), agent(&format!("echo evil > {home}/.cargo/bin/box"))),
        ("shell: write through ~/bin/box".into(), shell(&format!("echo evil > {home}/bin/box"))),
        ("shell: delete ~/bin/box".into(), shell(&format!("rm {home}/bin/box"))),
        ("shell: delete ~/bin/box, then new ~/bin/box".into(), shell(&format!("rm {home}/bin/box && echo evil > {home}/bin/box"))),
        ("shell: move ~/bin/box aside".into(), shell(&format!("mv {home}/bin/box {home}/bin/box.old"))),
        ("shell: move ~/bin aside".into(), shell(&format!("mv {home}/bin {home}/bin.old"))),
        ("shell: write ~/bin/tool".into(), shell(&format!("echo changed > {home}/bin/tool"))),
        ("shell: new ~/bin/new".into(), shell(&format!("echo new > {home}/bin/new"))),
        ("shell: new ~/.cargo/bin/box".into(), shell(&format!("echo evil > {home}/.cargo/bin/box"))),
        ("shell: new ~/.cargo/bin/new".into(), shell(&format!("echo new > {home}/.cargo/bin/new"))),
        ("shell: move ~/.cargo/bin aside".into(), shell(&format!("mv {home}/.cargo/bin {home}/.cargo/bin.old"))),
        ("shell: write through <outside>/brew/bin/box".into(), shell(&format!("echo evil > {brew}/box"))),
        ("shell: delete <outside>/brew/bin/box".into(), shell(&format!("rm {brew}/box"))),
        ("shell: new <outside>/brew/bin/new".into(), shell(&format!("echo new > {brew}/new"))),
        ("shell: move <outside>/brew/bin aside".into(), shell(&format!("mv {brew} {brew}.old"))),
        ("monty: write through ~/bin/box".into(), monty(&format!("open('{home}/bin/box', 'w').write('evil')"))),
        ("monty: new ~/.cargo/bin/box".into(), monty(&format!("open('{home}/.cargo/bin/box', 'w').write('evil')"))),
        ("monty: new <outside>/brew/bin/new".into(), monty(&format!("open('{brew}/new', 'w').write('new')"))),
    ];
    drop(probe);
    for (label, script) in cases {
        let scene = Scene::new();
        // Each case runs in its own scene, so the home differs: rewrite the probe's paths.
        let script = script
            .replace(&home, &scene.home().display().to_string())
            .replace(&brew, &scene.brew_bin().display().to_string());
        let output = match script.strip_prefix("native:") {
            Some(script) => scene.run_as("native", script),
            None => scene.run(&script),
        };
        let shown = |text: &str| {
            text.replace(&scene.home().display().to_string(), "~")
                .replace(&scene.outside.display().to_string(), "<outside>")
        };
        println!("=== {label}");
        println!("  box exit: {}", output.status);
        for line in shown(&String::from_utf8_lossy(&output.stdout)).lines() {
            println!("  out: {line}");
        }
        for line in shown(&String::from_utf8_lossy(&output.stderr)).lines() {
            println!("  err: {line}");
        }
        let records = scene.records();
        let mut found = Vec::new();
        for line in records.lines() {
            let value: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
            collect(&value, &mut found);
        }
        for (action, path, rule, decision) in found {
            if path.contains("bin") {
                println!("  decision: {action} {} -> {decision} {rule}", shown(&path));
            }
        }
        println!("  state after:\n{}", shown(&scene.state()));
        let policy = scene.policy();
        let ids: Vec<&str> = policy
            .lines()
            .filter(|line| line.starts_with("@id(\"protected_") || line.starts_with("@id(\"launch"))
            .filter_map(|line| line.split('"').nth(1))
            .collect();
        println!("  protected rules: {ids:?}");
    }
    let scene = Scene::new();
    let _ = scene.run("true");
    println!("=== compiled policy for the layout\n{}", scene.policy().replace(&scene.home().display().to_string(), "~").replace(&scene.outside.display().to_string(), "<outside>"));
}

fn collect(value: &serde_json::Value, found: &mut Vec<(String, String, String, String)>) {
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
                        .find(|item| item["key"].as_str().is_some_and(|key| key.ends_with(suffix)))
                        .and_then(|item| item["value"]["stringValue"].as_str())
                        .unwrap_or_default()
                        .to_string()
                };
                found.push((action.to_string(), attribute(".path"), attribute(".rule"), attribute(".decision")));
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
