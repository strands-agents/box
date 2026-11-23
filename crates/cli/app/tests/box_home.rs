use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const GUIDE: &str = "editing-box-profile.md";
const STALE: &str =
    "---\n# box-managed-profile-editing-guide\nname: editing-box-profile\n---\nold guidance\n";

struct Scene {
    _root: tempfile::TempDir,
    root: PathBuf,
}

impl Scene {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().canonicalize().unwrap();
        std::fs::create_dir_all(path.join("home/project")).unwrap();
        Self {
            _root: root,
            root: path,
        }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn box_home(&self) -> PathBuf {
        self.root.join("try/home")
    }

    fn profile(&self, box_home: &Path, name: &str) -> PathBuf {
        let folder = box_home.join("profiles").join(name);
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("profile.toml"), "[not valid TOML\n").unwrap();
        std::fs::write(folder.join(GUIDE), STALE).unwrap();
        folder
    }

    fn command(&self, box_home: &str, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_box"))
            .args(arguments)
            .env_clear()
            .env("HOME", self.home())
            .env("PATH", "/usr/bin:/bin")
            .env("BOX_HOME", box_home)
            .current_dir(self.home().join("project"))
            .output()
            .unwrap()
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn profile_list_reads_box_home_and_leaves_the_default_alone() {
    let scene = Scene::new();
    let box_home = scene.box_home();
    let output = scene.command(box_home.to_str().unwrap(), &["profile", "list"]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(
        text(&output.stdout).contains(&format!(
            "No profiles in {}. ",
            box_home.join("profiles").display()
        )),
        "{}",
        text(&output.stdout)
    );
    scene.profile(&scene.home().join(".strands/box"), "installed");
    scene.profile(&box_home, "tried");
    let output = scene.command(box_home.to_str().unwrap(), &["profile", "list"]);
    let listed = text(&output.stdout);
    assert!(listed.contains("tried"), "{listed}");
    assert!(!listed.contains("installed"), "{listed}");
}

#[test]
fn profile_show_reads_box_home_and_leaves_each_old_guide_copy_alone() {
    let scene = Scene::new();
    let box_home = scene.box_home();
    let tried = scene.profile(&box_home, "work");
    let installed = scene.profile(&scene.home().join(".strands/box"), "work");
    let output = scene.command(box_home.to_str().unwrap(), &["profile", "show", "work"]);
    assert!(!output.status.success());
    let error = text(&output.stderr);
    assert!(
        error
            .split_whitespace()
            .collect::<String>()
            .contains(&tried.join("profile.toml").display().to_string()),
        "{error}"
    );
    for folder in [tried, installed] {
        assert_eq!(std::fs::read_to_string(folder.join(GUIDE)).unwrap(), STALE);
    }
}

#[test]
fn help_agent_names_box_home_and_writes_in_neither_home() {
    let scene = Scene::new();
    let box_home = scene.box_home();
    let folder = scene.profile(&box_home, "tried");
    let output = scene.command(box_home.to_str().unwrap(), &["help", "agent"]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let printed = text(&output.stdout);
    for line in [
        format!("\nbox home    {}\n", box_home.display()),
        format!(
            "\nprofiles    {}   (tried)\n",
            box_home.join("profiles").display()
        ),
    ] {
        assert!(printed.contains(&line), "{printed}");
    }
    assert!(!box_home.join(GUIDE).exists());
    assert_eq!(std::fs::read_to_string(folder.join(GUIDE)).unwrap(), STALE);
    assert!(!scene.home().join(".strands/box").exists());
}

#[test]
fn an_empty_box_home_is_the_default() {
    let scene = Scene::new();
    let output = scene.command("", &["profile", "list"]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(
        text(&output.stdout).contains(
            &scene
                .home()
                .join(".strands/box/profiles")
                .display()
                .to_string()
        ),
        "{}",
        text(&output.stdout)
    );
}

#[test]
fn a_relative_box_home_stops_every_command() {
    let scene = Scene::new();
    for arguments in [
        &["profile", "list"][..],
        &["help", "agent"],
        &["run", "work"],
    ] {
        let output = scene.command("try/home", arguments);
        assert!(!output.status.success(), "{arguments:?}");
        assert!(
            text(&output.stderr).contains("BOX_HOME must be a full path, not try/home"),
            "{arguments:?}: {}",
            text(&output.stderr)
        );
    }
    assert!(!scene.home().join("project/try").exists());
}
