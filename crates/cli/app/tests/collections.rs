//! A collection in `~/.strands/box/external/` gives `box profile create` its starters and
//! policies, gives a profile its packs, and is protected with the box home.

use std::path::PathBuf;
use std::process::{Command, Output};

struct Scene {
    _root: tempfile::TempDir,
    home: PathBuf,
    project: PathBuf,
}

impl Scene {
    /// A home with the collection `@acme` in `~/.strands/box/external/acme`: an agent pack, its
    /// starter, and a policy starter that the collection makes the default.
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap().join("home");
        let project = home.join("project");
        let collection = home.join(".strands/box/external/acme");
        for (path, text) in [
            (
                "collection.toml",
                "[starters]\nadd = [\"@acme/helper\"]\n\
                 [policy-starters]\nadd = [\"@acme/team\"]\ndefault = \"@acme/team\"\n",
            ),
            (
                "packs/helper/pack.toml",
                "[pack]\nname = \"@acme/helper\"\nversion = 1\nkind = \"agent\"\n\
                 [run]\ncommand = [\"/usr/bin/true\"]\n",
            ),
            (
                "starters/helper/starter.toml",
                "[starter]\nname = \"@acme/helper\"\nlabel = \"Acme helper\"\n\
                 packs = [\"@acme/helper\"]\n",
            ),
            (
                "policies/team/policy.toml",
                "[policy]\nname = \"@acme/team\"\nlabel = \"Team\"\n\
                 description = \"The team's rules.\"\n",
            ),
            ("policies/team/policy.dw", "// The team's rules.\n"),
        ] {
            let path = collection.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        std::fs::create_dir_all(&project).unwrap();
        Self {
            _root: root,
            home,
            project,
        }
    }

    fn command(&self, directory: &PathBuf, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_box"))
            .args(arguments)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", "/usr/bin:/bin")
            .env("NO_COLOR", "1")
            .current_dir(directory)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap()
    }

    fn create(&self) {
        let output = self.command(
            &self.project,
            &[
                "profile",
                "create",
                "mine",
                "--with",
                "@acme/helper",
                "--policy",
                "@acme/team",
                "--tools",
                "git",
            ],
        );
        assert!(output.status.success(), "{}", text(&output.stderr));
    }

    fn profile(&self) -> PathBuf {
        self.home.join(".strands/box/profiles/mine")
    }

    fn show(&self, directory: &PathBuf) -> Output {
        self.command(directory, &["profile", "show", "mine", "--full"])
    }
}

/// `arguments`, then `box run mine` on macOS and Linux: on other systems `box run` stops first
/// with the platform error.
fn commands<'a>(arguments: &'a [&'a str]) -> Vec<&'a [&'a str]> {
    let mut commands = vec![arguments];
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        commands.push(&["run", "mine"]);
    }
    commands
}

/// `text` with no whitespace, so a path that `box` wraps at the terminal width still matches.
fn unwrapped(text: &str) -> String {
    text.split_whitespace().collect()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .replace('\n', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn profile_create_offers_and_copies_what_a_collection_adds() {
    let scene = Scene::new();
    let output = scene.command(&scene.project, &["profile", "show", "mine"]);
    let menu = text(&output.stderr);
    assert!(
        menu.contains("box profile create mine --with @acme/helper Acme helper"),
        "{menu}"
    );
    scene.create();
    let profile = std::fs::read_to_string(scene.profile().join("profile.toml")).unwrap();
    assert!(
        profile.contains("packs = [\"@acme/helper\", \"@box/git\"]"),
        "{profile}"
    );
    let policy = std::fs::read_to_string(scene.profile().join("policy.dw")).unwrap();
    assert!(
        policy.starts_with("// Copied from @acme/team (Team)"),
        "{policy}"
    );
    assert!(policy.contains("// The team's rules."), "{policy}");
}

#[test]
fn the_box_home_forbids_cover_a_collection_and_a_write_grant_over_it_is_refused() {
    let scene = Scene::new();
    scene.create();
    let output = scene.show(&scene.project);
    let shown = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(shown.contains("@acme/helper 1"), "{shown}");
    for verb in ["write", "delete", "move"] {
        assert!(
            shown
                .lines()
                .any(|line| line.contains(&format!("@id(\"box_home_{verb}\")"))
                    && line.contains("context.input.path like \"~/.strands/box/*\"")),
            "no box home {verb} forbid in {shown}"
        );
    }
    let file = scene.profile().join("profile.toml");
    let profile = std::fs::read_to_string(&file).unwrap();
    std::fs::write(
        &file,
        format!("{profile}\n[agent.filesystem]\nwrite = [\"~/.strands/box/external/acme\"]\n"),
    )
    .unwrap();
    let error = text(&scene.show(&scene.project).stderr);
    assert!(
        error.contains("the agent could change files that box trusts"),
        "{error}"
    );
}

#[test]
fn an_unknown_scope_names_the_folder_to_clone_into() {
    let scene = Scene::new();
    scene.create();
    let file = scene.profile().join("profile.toml");
    let profile = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&file, profile.replace("@acme/helper", "@other/helper")).unwrap();
    let output = scene.show(&scene.project);
    let error = unwrapped(&text(&output.stderr));
    assert!(
        error.contains("namesthecollection@other")
            && error.contains(&unwrapped(&format!(
                "{} does not exist",
                scene.home.join(".strands/box/external/other").display()
            ))),
        "{error}"
    );
}

#[test]
fn a_linked_or_broken_collection_stops_create_show_and_run() {
    let scene = Scene::new();
    scene.create();
    let external = scene.home.join(".strands/box/external");
    std::fs::rename(external.join("acme"), scene.home.join("acme-box")).unwrap();
    std::os::unix::fs::symlink(scene.home.join("acme-box"), external.join("acme")).unwrap();
    // A link stops every command that finds packs; a bad `collection.toml` stops the ones that
    // read the menus, which `box profile show` does not.
    let commands_for = |error: &str, show: bool| {
        let create = ["profile", "create", "other", "--with", "@acme/helper"];
        let show_mine = ["profile", "show", "mine"];
        let mut all = commands(&create);
        if show {
            all.push(&show_mine);
        }
        for arguments in all {
            let output = scene.command(&scene.project, arguments);
            let found = text(&output.stderr);
            assert!(!output.status.success(), "{arguments:?}");
            assert!(found.contains(error), "{arguments:?}: {found}");
        }
    };
    commands_for(
        "a collection is a symbolic link; clone the repository into external/",
        true,
    );
    std::fs::remove_file(external.join("acme")).unwrap();
    std::fs::rename(scene.home.join("acme-box"), external.join("acme")).unwrap();
    std::fs::write(external.join("acme/collection.toml"), "name = \"@acme\"\n").unwrap();
    commands_for("the unknown key `name`", false);
}
