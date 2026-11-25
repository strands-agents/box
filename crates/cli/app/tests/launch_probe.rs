//! Probe, not a regression test: under an operator policy that permits every filesystem action,
//! can the agent, the Shell, or Monty change which `box` the operator's next shell starts?
//! Run with `cargo test -p strands-box-cli --all-features --test launch_probe -- --nocapture`.
//!
//! Each case runs in a fresh scene. After the run, the probe prints the first `box` on the scene's
//! `PATH`, as a shell finds it, and every path that changed. A case is an attack when the next
//! `box` is no longer `~/plainbin/box` with its original bytes.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const PROBE: &str = include_str!("../../../../test-corpus/profiles/probe/profile.toml");

const POLICY: &str = r#"@id("probe_shell") permit (principal, action == Box::Action::"shell:exec", resource);
@id("read_everything") permit (principal, action == Box::Action::"fs:read", resource);
@id("write_everything") permit (principal, action == Box::Action::"fs:write", resource);
@id("delete_everything") permit (principal, action == Box::Action::"fs:delete", resource);
@id("move_everything") permit (principal, action == Box::Action::"fs:move", resource);
"#;

/// The folders the scene puts on `PATH`, in order, relative to the home unless absolute.
const PATH_FOLDERS: &[&str] = &[
    "gomissing/bin", // missing, with its parent
    "goexists/bin",  // missing, under an existing folder
    ".cargo/bin",    // exists, holds no box
    "plainbin",      // holds a regular-file box: the next box
    "bin",           // box links to the real box
    "linked-bin",    // a link to dot/bin, whose box links to the real box
    "tools/box",     // a link to opt/boxroot, a folder that holds a box
    "tools2",        // holds a folder named box
    "<outside>/brew/bin",
];

const REAL: &str = "real-plain";

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
        let directory = tempfile::Builder::new()
            .prefix("bx")
            .tempdir_in(parent)
            .unwrap();
        let outside = tempfile::Builder::new()
            .prefix("bx")
            .tempdir_in("/tmp")
            .unwrap();
        let scene = Self {
            root: directory.path().canonicalize().unwrap(),
            outside: outside.path().canonicalize().unwrap(),
            _root: directory,
            _outside: outside,
        };
        let home = scene.home();
        std::fs::create_dir_all(scene.workspace()).unwrap();
        let profile = |name: &str, extra: &str| {
            let folder = home.join(".strands/box/profiles").join(name);
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(
                folder.join("profile.toml"),
                format!("policies = [\"policy.dw\"]\n{PROBE}\n{extra}"),
            )
            .unwrap();
            std::fs::write(folder.join("policy.dw"), POLICY).unwrap();
        };
        profile("probe", "");
        // The agent itself may write `~/.cargo`, but not its `bin`, as a profile must say.
        profile(
            "native",
            "[agent.filesystem]\nread = [\"${{ home }}/.cargo\"]\nwrite = [\"${{ home }}/.cargo\"]\n\n\
             [filesystem]\ndeny_write = [\"${{ home }}/.cargo/bin\"]\n",
        );
        // The agent itself may write `~/goexists`, whose `bin` is on `PATH` but missing.
        let mkdir = ["/bin/mkdir", "/usr/bin/mkdir"]
            .into_iter()
            .find(|path| Path::new(path).exists())
            .expect("a mkdir");
        let mkdir = Path::new(mkdir).canonicalize().unwrap();
        profile(
            "native-go",
            &format!(
                "[agent.filesystem]\nread = [\"${{{{ home }}}}/goexists\"]\nwrite = [\"${{{{ home }}}}/goexists\"]\n\
                 exec = [{:?}]\n",
                mkdir.display().to_string()
            ),
        );
        // The agent itself may write all of `~/.cargo`, `bin` included.
        profile(
            "native-cargo",
            "[agent.filesystem]\nread = [\"${{ home }}/.cargo\"]\nwrite = [\"${{ home }}/.cargo\"]\n",
        );
        let real = Path::new(env!("CARGO_BIN_EXE_box"));
        for folder in [
            ".cargo/bin",
            "goexists",
            "plainbin",
            "bin",
            "dot/bin",
            "opt/boxroot",
            "tools",
            "tools2/box",
            "stage/bin",
        ] {
            std::fs::create_dir_all(home.join(folder)).unwrap();
        }
        std::fs::create_dir_all(scene.outside.join("brew/bin")).unwrap();
        std::fs::write(home.join("plainbin/box"), REAL).unwrap();
        std::os::unix::fs::symlink(real, home.join("bin/box")).unwrap();
        std::os::unix::fs::symlink(home.join("dot/bin"), home.join("linked-bin")).unwrap();
        std::os::unix::fs::symlink(real, home.join("dot/bin/box")).unwrap();
        std::fs::write(home.join("opt/boxroot/box"), "boxroot").unwrap();
        std::os::unix::fs::symlink(home.join("opt/boxroot"), home.join("tools/box")).unwrap();
        std::os::unix::fs::symlink(real, scene.outside.join("brew/bin/box")).unwrap();
        std::fs::write(home.join("bin/tool"), "tool").unwrap();
        std::fs::write(scene.outside.join("brew/bin/tool"), "tool").unwrap();
        std::fs::write(home.join("evil"), "evil").unwrap();
        std::fs::write(home.join("stage/bin/box"), "evil").unwrap();
        scene
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn workspace(&self) -> PathBuf {
        self.home().join("project")
    }

    fn folders(&self) -> Vec<PathBuf> {
        PATH_FOLDERS
            .iter()
            .map(|folder| match folder.strip_prefix("<outside>/") {
                Some(rest) => self.outside.join(rest),
                None => self.home().join(folder),
            })
            .collect()
    }

    fn search_path(&self) -> String {
        let mut folders: Vec<String> = self
            .folders()
            .iter()
            .map(|folder| folder.display().to_string())
            .collect();
        folders.extend(["/usr/bin".into(), "/bin".into()]);
        folders.join(":")
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

    fn last_run(&self) -> Option<PathBuf> {
        let mut runs: Vec<PathBuf> = std::fs::read_dir(self.home().join(".strands/box/r"))
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default();
        runs.sort();
        runs.pop()
    }

    fn shown(&self, text: &str) -> String {
        text.replace(&self.home().display().to_string(), "~")
            .replace(&self.outside.display().to_string(), "<outside>")
            .replace(env!("CARGO_BIN_EXE_box"), "<real box>")
    }

    /// Every path under the home and the outside folder, except Box's own state and the project,
    /// with what it is.
    fn snapshot(&self) -> Vec<(String, String)> {
        let mut entries = Vec::new();
        for (root, skip) in [
            (self.home(), vec![".strands", "project", ".cache"]),
            (self.outside.clone(), vec![]),
        ] {
            walk(&root, &root, &skip, &mut entries);
        }
        entries
            .into_iter()
            .map(|(path, what)| (self.shown(&path.display().to_string()), self.shown(&what)))
            .collect()
    }

    /// The first `box` on `PATH` that a shell would start, ignoring the executable bit so that a
    /// planted file counts even before it is made executable.
    fn next_box(&self) -> String {
        for folder in self.folders() {
            let candidate = folder.join("box");
            if let Ok(meta) = std::fs::metadata(&candidate)
                && meta.is_file()
            {
                let target = std::fs::canonicalize(&candidate).unwrap_or(candidate.clone());
                let what = if target == Path::new(env!("CARGO_BIN_EXE_box")) {
                    "the real box".to_string()
                } else {
                    format!("{:?}", std::fs::read_to_string(&target).unwrap_or_default())
                };
                return self.shown(&format!("{} -> {what}", candidate.display()));
            }
        }
        "none".into()
    }
}

fn walk(root: &Path, path: &Path, skip: &[&str], entries: &mut Vec<(PathBuf, String)>) {
    let Ok(read) = std::fs::read_dir(path) else {
        return;
    };
    let mut children: Vec<PathBuf> = read.flatten().map(|entry| entry.path()).collect();
    children.sort();
    for child in children {
        if path == root
            && skip
                .iter()
                .any(|name| child.file_name() == Some(std::ffi::OsStr::new(name)))
        {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(&child) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&child).unwrap();
            entries.push((child, format!("link to {}", target.display())));
        } else if meta.is_dir() {
            entries.push((child.clone(), "folder".into()));
            walk(root, &child, skip, entries);
        } else {
            entries.push((
                child.clone(),
                format!("file {:?}", std::fs::read_to_string(&child).unwrap_or_default()),
            ));
        }
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

/// `(label, profile, script)`, with `~` written as `HOME` and the outside folder as `OUT`.
fn cases() -> Vec<(&'static str, &'static str, String)> {
    vec![
        // Plant a box in an existing PATH folder that holds none.
        ("A1 shell: new ~/.cargo/bin/box", "probe", shell("echo evil > HOME/.cargo/bin/box")),
        ("A2 shell: move a file to ~/.cargo/bin/box", "probe", shell("mv HOME/evil HOME/.cargo/bin/box")),
        ("A3 shell: copy a file to ~/.cargo/bin/box", "probe", shell("cp HOME/evil HOME/.cargo/bin/box")),
        ("A4 shell: hard link to ~/.cargo/bin/box", "probe", shell("ln HOME/evil HOME/.cargo/bin/box")),
        ("A5 shell: relative symlink ~/.cargo/bin/box", "probe", shell("cd HOME/.cargo/bin && ln -s ../../evil box")),
        ("A6 shell: new ~/.cargo/bin/BOX (one file on macOS)", "probe", shell("echo evil > HOME/.cargo/bin/BOX")),
        ("A7 shell: new ~/.cargo/bin/Box (one file on macOS)", "probe", shell("echo evil > HOME/.cargo/bin/Box")),
        ("A8 monty: new ~/.cargo/bin/box", "probe", monty("open('HOME/.cargo/bin/box', 'w').write('evil')")),
        ("A9 monty: rename to ~/.cargo/bin/box", "probe", monty("import os; os.rename('HOME/evil', 'HOME/.cargo/bin/box')")),
        ("A10 monty: new ~/.cargo/bin/BOX (one file on macOS)", "probe", monty("open('HOME/.cargo/bin/BOX', 'w').write('evil')")),
        // Replace a PATH folder.
        ("B1 shell: move ~/.cargo/bin aside", "probe", shell("mv HOME/.cargo/bin HOME/.cargo/bin.old && mkdir HOME/.cargo/bin && echo evil > HOME/.cargo/bin/box")),
        ("B2 shell: move ~/.cargo aside", "probe", shell("mv HOME/.cargo HOME/cargo.old && mkdir -p HOME/.cargo/bin && echo evil > HOME/.cargo/bin/box")),
        ("B3 shell: delete ~/.cargo/bin", "probe", shell("rm -rf HOME/.cargo/bin && mkdir HOME/.cargo/bin && echo evil > HOME/.cargo/bin/box")),
        ("B4 shell: move ~/dot aside (behind ~/linked-bin)", "probe", shell("mv HOME/dot HOME/dot.old")),
        ("B5 shell: move ~/linked-bin aside", "probe", shell("mv HOME/linked-bin HOME/linked-bin.old")),
        ("B6 shell: repoint ~/linked-bin", "probe", shell("cd HOME && rm linked-bin && ln -s stage/bin linked-bin")),
        ("B7 shell: move ~/tools aside (PATH entry is a link)", "probe", shell("mv HOME/tools HOME/tools.old && mkdir -p HOME/tools/box && echo evil > HOME/tools/box/box")),
        ("B8 shell: move ~/opt/boxroot aside", "probe", shell("mv HOME/opt/boxroot HOME/opt/boxroot.old && mkdir HOME/opt/boxroot && echo evil > HOME/opt/boxroot/box")),
        // A PATH folder that does not exist yet.
        ("C1 shell: mkdir ~/gomissing/bin and plant box", "probe", shell("mkdir -p HOME/gomissing/bin && echo evil > HOME/gomissing/bin/box")),
        ("C2 shell: relative symlink ~/gomissing -> stage", "probe", shell("cd HOME && mkdir -p stage2/bin && echo evil > stage2/bin/box && ln -s stage2 gomissing")),
        ("C3 shell: move a folder to ~/gomissing", "probe", shell("mkdir -p HOME/stage3/bin && echo evil > HOME/stage3/bin/box && mv HOME/stage3 HOME/gomissing")),
        ("C4 shell: move a folder to ~/goexists/bin", "probe", shell("mv HOME/stage/bin HOME/goexists/bin")),
        ("C5 shell: relative symlink ~/goexists/bin -> ../stage/bin", "probe", shell("cd HOME/goexists && ln -s ../stage/bin bin")),
        ("C6 shell: mkdir ~/goexists/bin and plant box", "probe", shell("mkdir HOME/goexists/bin && echo evil > HOME/goexists/bin/box")),
        ("C7 shell: mkdir ~/GOMISSING/bin (one folder on macOS)", "probe", shell("mkdir -p HOME/GOMISSING/bin && echo evil > HOME/GOMISSING/bin/box")),
        ("C8 monty: makedirs ~/gomissing/bin and plant box", "probe", monty("import os; os.makedirs('HOME/gomissing/bin'); open('HOME/gomissing/bin/box', 'w').write('evil')")),
        ("C9 monty: rename a folder to ~/gomissing", "probe", monty("import os; os.makedirs('HOME/stage4/bin'); open('HOME/stage4/bin/box', 'w').write('evil'); os.rename('HOME/stage4', 'HOME/gomissing')")),
        // Delete or replace an existing box.
        ("D1 shell: delete ~/plainbin/box", "probe", shell("rm HOME/plainbin/box")),
        ("D2 shell: overwrite ~/plainbin/box", "probe", shell("echo evil > HOME/plainbin/box")),
        ("D3 shell: move ~/plainbin/box aside", "probe", shell("mv HOME/plainbin/box HOME/plainbin/box.old")),
        ("D4 shell: move a file over ~/plainbin/box", "probe", shell("mv HOME/evil HOME/plainbin/box")),
        ("D5 monty: remove ~/plainbin/box", "probe", monty("import os; os.remove('HOME/plainbin/box')")),
        ("D6 shell: move ~/plainbin aside", "probe", shell("mv HOME/plainbin HOME/plainbin.old")),
        ("D7 shell: write through ~/bin/box", "probe", shell("echo evil > HOME/bin/box")),
        ("D8 shell: write through OUT/brew/bin/box", "probe", shell("echo evil > OUT/brew/bin/box")),
        // The agent itself, through its own write grant.
        ("E1 agent: new ~/.cargo/bin/box", "native", agent("echo evil > HOME/.cargo/bin/box")),
        ("E2 agent: mkdir ~/goexists/bin and plant box", "native-go", agent("mkdir HOME/goexists/bin && echo evil > HOME/goexists/bin/box")),
        ("E3 agent: write grant on all of ~/.cargo, new ~/.cargo/bin/box", "native-cargo", agent("echo evil > HOME/.cargo/bin/box")),
        // Writes that should keep working.
        ("N1 shell: write ~/bin/tool", "probe", shell("echo changed > HOME/bin/tool")),
        ("N2 shell: new ~/bin/new", "probe", shell("echo new > HOME/bin/new")),
        ("N3 shell: new ~/.cargo/bin/new", "probe", shell("echo new > HOME/.cargo/bin/new")),
        ("N4 shell: new ~/tools2/other-tool", "probe", shell("echo new > HOME/tools2/other-tool")),
        ("N5 shell: new ~/newfolder/file", "probe", shell("mkdir -p HOME/newfolder && echo new > HOME/newfolder/file")),
        ("N6 monty: new ~/.cargo/bin/new", "probe", monty("open('HOME/.cargo/bin/new', 'w').write('new')")),
        ("N7 agent: write ~/.cargo/new", "native", agent("echo ok > HOME/.cargo/new")),
        ("N8 agent: write ~/goexists/file", "native-go", agent("echo ok > HOME/goexists/file")),
        ("N9 shell: new ~/.cargo/bin/boxer", "probe", shell("echo new > HOME/.cargo/bin/boxer")),
    ]
}

#[test]
fn launch_probe() {
    let only = std::env::var("LAUNCH_PROBE_ONLY").ok();
    for (label, profile, script) in cases() {
        if only
            .as_deref()
            .is_some_and(|only| !only.split(',').any(|id| label.starts_with(&format!("{id} "))))
        {
            continue;
        }
        let scene = Scene::new();
        let before = scene.snapshot();
        let next_before = scene.next_box();
        let script = script
            .replace("HOME", &scene.home().display().to_string())
            .replace("OUT", &scene.outside.display().to_string());
        let output = scene.run_as(profile, &script);
        println!("=== {label}");
        println!("  box exit: {}", output.status);
        for line in scene.shown(&String::from_utf8_lossy(&output.stdout)).lines() {
            println!("  out: {line}");
        }
        let stderr = scene.shown(&String::from_utf8_lossy(&output.stderr));
        for line in stderr
            .lines()
            .filter(|line| !line.contains("note[") && !line.starts_with("box: ") && !line.starts_with("  "))
        {
            println!("  err: {line}");
        }
        let after = scene.snapshot();
        for (path, what) in &after {
            match before.iter().find(|(old, _)| old == path) {
                Some((_, old)) if old == what => {}
                Some((_, old)) => println!("  changed: {path}: {old} -> {what}"),
                None => println!("  added: {path}: {what}"),
            }
        }
        for (path, _) in &before {
            if !after.iter().any(|(new, _)| new == path) {
                println!("  removed: {path}");
            }
        }
        let next_after = scene.next_box();
        let verdict = if next_after == next_before { "same" } else { "CHANGED" };
        println!("  next box: {next_after} [{verdict}]");
        if let Some(run) = scene.last_run() {
            let policy = std::fs::read_to_string(run.join("policy.dw")).unwrap_or_default();
            let ids: Vec<&str> = policy
                .lines()
                .filter(|line| line.starts_with("@id(\"protected_") || line.starts_with("@id(\"profile_") || line.starts_with("@id(\"launch"))
                .filter_map(|line| line.split('"').nth(1))
                .collect();
            println!("  protecting rules: {ids:?}");
        }
    }
    if only.is_none() {
        let scene = Scene::new();
        let _ = scene.run_as("probe", "true");
        let policy = scene
            .last_run()
            .map(|run| std::fs::read_to_string(run.join("policy.dw")).unwrap_or_default())
            .unwrap_or_default();
        println!("=== compiled policy for the layout\n{}", scene.shown(&policy));
    }
}
