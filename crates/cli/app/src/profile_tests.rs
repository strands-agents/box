#[path = "native_filesystem_policy_tests.rs"]
mod native_filesystem_policy_tests;

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use crate::Profiles;
use crate::compile::{Compiled, Instance, Run, compile};
use crate::error::{Error, PolicyFinding};
use crate::host::resolved;
use crate::lang::{Inputs, Lookup, storage_root};
use crate::profile::{Profile, Resolved, validate_name};
use crate::reference::Sources;
use crate::run::{Cleaned, Launcher, confirm, existing, mint, mint_claimed};
use crate::test_support::script;

/// A home, a workspace below it, an instance beside neither, and a folder of packs.
struct Scene {
    _root: tempfile::TempDir,
    root: PathBuf,
    workspace: String,
    /// Whether the run has effective user ID 0.
    as_root: bool,
}

/// What one resolve reads besides the profile.
struct Context {
    workspace: PathBuf,
    os: &'static str,
}

impl Scene {
    fn new() -> Self {
        Self::with_workspace("project")
    }

    fn with_workspace(name: &str) -> Self {
        let directory = tempfile::tempdir().expect("a temporary root");
        let root = directory.path().canonicalize().expect("a canonical root");
        let scene = Self {
            _root: directory,
            root,
            workspace: name.to_string(),
            as_root: false,
        };
        std::fs::create_dir_all(scene.workspace()).expect("a workspace");
        scene
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn workspace(&self) -> PathBuf {
        self.home().join("work").join(&self.workspace)
    }

    fn instance(&self) -> Instance {
        let directory = self.home().join(".strands/box/r/test-0000abcd");
        Instance {
            name: "test-0000abcd".to_string(),
            box_directory: directory.join("box"),
            directory,
        }
    }

    fn protected(&self) -> Vec<PathBuf> {
        vec![self.home().join(".strands/box")]
    }

    fn storage(&self) -> PathBuf {
        storage_root(&self.home().join(".strands/box"), "test")
    }

    /// Write the pack `@box/<name>`: a `[pack]` header, then `text`.
    fn share(&self, name: &str, text: &str) {
        self.share_raw(
            name,
            &format!(
                "[pack]\nname = \"@box/{name}\"\nversion = 1\n{}{text}",
                crate::lang::test_kind_line(text)
            ),
        );
    }

    /// Write the pack `@box/<name>`: `top` at the top of the file, then a `[pack]` header, then
    /// `text`.
    fn share_top(&self, name: &str, top: &str, text: &str) {
        self.share_raw(
            name,
            &format!(
                "{top}\n[pack]\nname = \"@box/{name}\"\nversion = 1\n{}{text}",
                crate::lang::test_kind_line(text)
            ),
        );
    }

    /// Write the pack `@box/<name>` as `text` alone.
    fn share_raw(&self, name: &str, text: &str) {
        let folder = self.root.join("packs").join(name);
        std::fs::create_dir_all(&folder).expect("a pack folder");
        std::fs::write(folder.join("pack.toml"), text).expect("a pack");
    }

    fn lookup(&self) -> Lookup {
        Lookup {
            vendored: Some(self.root.join("packs")),
            operator: self.home().join(".strands/box/packs"),
            collections: Vec::new(),
            version: crate::VERSION,
        }
    }

    fn context(&self) -> Context {
        Context {
            workspace: self.workspace(),
            os: "macos",
        }
    }

    fn resolve(&self, profile: &Profile) -> Result<Resolved, Error> {
        self.resolve_with(profile, &self.context())
    }

    fn resolve_with(&self, profile: &Profile, context: &Context) -> Result<Resolved, Error> {
        self.resolve_using(profile, context, &mut Fixed)
    }

    fn resolve_using(
        &self,
        profile: &Profile,
        context: &Context,
        sources: &mut impl Sources,
    ) -> Result<Resolved, Error> {
        self.resolve_shipped(profile, context, sources, &self.root.join("packs"))
    }

    /// Resolve `profile` with box's own packs in `packs`.
    fn resolve_shipped(
        &self,
        profile: &Profile,
        context: &Context,
        sources: &mut impl Sources,
        packs: &Path,
    ) -> Result<Resolved, Error> {
        let home = self.home();
        let folder = self.root.join("profile");
        let storage = storage_root(&home.join(".strands/box"), "test");
        let instance = self.instance();
        profile.resolve(
            None,
            &self.lookup(),
            sources,
            &Inputs {
                tool_cache: None,
                home: &home,
                box_home: &home.join(".strands/box"),
                workspace: &context.workspace,
                profile: &folder,
                profile_file: &folder.join("profile.toml"),
                box_dir: &instance.box_directory,
                storage: &storage,
                os: context.os,
                packs: Some(packs),
            },
        )
    }

    /// Why resolving `text` is refused.
    fn resolve_refusal(&self, text: &str) -> String {
        match self.resolve(&profile(text)) {
            Err(Error::Profile { reason, .. }) => reason,
            other => panic!("a refusal, not {other:?}"),
        }
    }

    fn compile(&self, profile: &Profile, policy: Option<&str>) -> Result<Compiled, Error> {
        self.compile_in(&self.workspace(), profile, policy, "/usr/bin:/bin")
    }

    fn compile_in(
        &self,
        workspace: &Path,
        profile: &Profile,
        policy: Option<&str>,
        search_path: &str,
    ) -> Result<Compiled, Error> {
        let resolved_profile = self.resolve_with(
            profile,
            &Context {
                workspace: workspace.to_path_buf(),
                ..self.context()
            },
        )?;
        let joined = [policy.unwrap_or_default(), resolved_profile.policy.as_str()]
            .into_iter()
            .filter(|part| !part.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n\n");
        compile(&Run {
            profile: &resolved_profile,
            policy: Some(&joined),
            tool_rules: &crate::render::Rules::default(),
            workspace,
            instance: &self.instance(),
            home: &self.home(),
            box_homes: &[self.home().join(".strands/box")],
            trusted: &[],
            protected: &self.protected(),
            resources: None,
            search_path: search_path.as_ref(),
            resolve: &resolved,
            root: self.as_root,
        })
    }

    /// Resolve and compile `profile` against `sources`, with `search_path` as the operator's.
    fn compile_using(
        &self,
        profile: &Profile,
        sources: &mut impl Sources,
        search_path: &str,
    ) -> Result<(Resolved, Compiled), Error> {
        self.compile_using_in(profile, &self.context(), sources, search_path)
    }

    /// Resolve and compile `profile` in `context` against `sources`.
    fn compile_using_in(
        &self,
        profile: &Profile,
        context: &Context,
        sources: &mut impl Sources,
        search_path: &str,
    ) -> Result<(Resolved, Compiled), Error> {
        let resolved_profile = self.resolve_using(profile, context, sources)?;
        let compiled = compile(&Run {
            profile: &resolved_profile,
            policy: Some(&resolved_profile.policy),
            workspace: &self.workspace(),
            instance: &self.instance(),
            home: &self.home(),
            box_homes: &[self.home().join(".strands/box")],
            trusted: &[],
            protected: &self.protected(),
            resources: None,
            search_path: search_path.as_ref(),
            resolve: &resolved,
            tool_rules: &crate::render::Rules::default(),
            root: self.as_root,
        })?;
        Ok((resolved_profile, compiled))
    }

    /// Why resolving and compiling `text` is refused.
    fn refusal(&self, text: &str) -> String {
        self.located(text).2
    }

    /// The file, the line, and the reason of the refusal of `text`.
    fn located(&self, text: &str) -> (PathBuf, Option<usize>, String) {
        match self.compile(&profile(text), None) {
            Err(Error::Profile { path, line, reason }) => (path, line, reason),
            other => panic!("a refusal, not {other:?}"),
        }
    }
}

/// Sources with one set variable, one empty variable, and one `key=value` list, and no toolchain
/// or program.
struct Fixed;

impl Sources for Fixed {
    fn env(&self, name: &str) -> Option<String> {
        match name {
            "SET" => Some("set-value".to_string()),
            "EMPTY" => Some(String::new()),
            "LIST" => Some(
                "group=/aws/runtimes/rt-DEFAULT, stream=otel%2Drt ,twice=a,twice=b".to_string(),
            ),
            _ => None,
        }
    }

    fn env_with_prefix(&self, prefix: &str) -> Vec<(String, String)> {
        ["EMPTY", "SET"]
            .into_iter()
            .filter(|name| name.starts_with(prefix))
            .filter_map(|name| Some((name.to_string(), self.env(name)?)))
            .collect()
    }

    fn program(&mut self, _: &str) -> Option<PathBuf> {
        None
    }

    fn search(&self, _: &str) -> Option<PathBuf> {
        None
    }

    fn developer_dir(&mut self) -> Result<String, String> {
        Err("ran xcode-select, which this host never runs".to_string())
    }
}

/// Sources like `Fixed`, where `PATH` finds every program at `/usr/bin/true`.
struct Detecting;

impl Sources for Detecting {
    fn env(&self, name: &str) -> Option<String> {
        Fixed.env(name)
    }

    fn env_with_prefix(&self, prefix: &str) -> Vec<(String, String)> {
        Fixed.env_with_prefix(prefix)
    }

    fn program(&mut self, _: &str) -> Option<PathBuf> {
        None
    }

    fn search(&self, _: &str) -> Option<PathBuf> {
        Some(PathBuf::from("/usr/bin/true"))
    }

    fn developer_dir(&mut self) -> Result<String, String> {
        Fixed.developer_dir()
    }
}

/// The profile `text`, with the `[project] access = "write"` that `box profile create` writes
/// when `text` holds no `[project]`.
fn profile(text: &str) -> Profile {
    let text = if text.contains("[project]") {
        text.to_string()
    } else {
        format!("{text}\n\n[project]\naccess = \"write\"\n")
    };
    bare_profile(&text)
}

/// The profile `text` as it is.
fn bare_profile(text: &str) -> Profile {
    Profile::parse(text, Path::new("test.toml")).expect("a profile")
}

fn refusal(text: &str) -> String {
    match Profile::parse(text, Path::new("test.toml")) {
        Err(Error::Profile { reason, .. }) => reason,
        other => panic!("a refusal, not {other:?}"),
    }
}

const MINIMAL: &str = r#"
[agent]
command = ["/usr/bin/true"]
"#;

const WITH_TOOL_AND_SERVER: &str = r#"
[agent]
command = ["/usr/bin/true"]
env.TMPDIR = "${{ workspace }}/.tmp"

[tool.git]
command = ["/usr/bin/git"]
filesystem.read = ["${{ workspace }}"]
filesystem.write = ["${{ workspace }}"]

[mcp.local]
type = "stdio"
command = ["true"]
env.CACHE = "${{ workspace }}/.cache"
"#;

fn table(compiled: &Compiled) -> toml::Value {
    toml::from_str(&compiled.box_toml).expect("TOML")
}

fn strings(value: &toml::Value) -> Vec<String> {
    value
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|item| item.as_str().map(str::to_string))
        .collect()
}

#[test]
fn a_profile_refuses_every_key_of_one_run() {
    for (text, key) in [
        ("name = \"x\"\n[agent]\ncommand = [\"/bin/x\"]", "`name`"),
        (
            "box_dir = \"/x\"\n[agent]\ncommand = [\"/bin/x\"]",
            "`box_dir`",
        ),
        (
            "workspace = \"/x\"\n[agent]\ncommand = [\"/bin/x\"]",
            "`workspace`",
        ),
        (
            "[agent]\ncommand = [\"/bin/x\"]\nworkspace = \"/x\"",
            "`[agent] workspace`",
        ),
        (
            "[agent]\ncommand = [\"/bin/x\"]\n[tool.git]\ncommand = [\"/bin/git\"]\nworkspace = \"/x\"",
            "`[tool.git] workspace`",
        ),
    ] {
        let reason = refusal(text);
        assert!(reason.contains(key), "{key}: {reason}");
        assert!(reason.contains("for each run"), "{reason}");
    }
}

#[test]
fn a_profile_refuses_an_unknown_key() {
    for (text, why) in [
        (
            "[agent]\ncommand = [\"/bin/x\"]\n[paths.read]\ndir = [\"..\"]",
            "a profile holds the unknown key `paths`; a profile holds `packs`, `options`",
        ),
        (
            "[agent]\ncommand = [\"/bin/x\"]\nfilesystem.reed = [\"/x\"]",
            "`[agent.filesystem]` holds the unknown key `reed`",
        ),
        (
            "[agent]\ncommand = [\"/bin/x\"]\n[launch]\nfiles = {}",
            "a profile holds the unknown key `launch`",
        ),
        (
            "[agent]\ncommand = [\"/bin/x\"]\n[tool.git]\ncommand = [\"/bin/git\"]\npacks = []",
            "`[tool.git]` holds the unknown key `packs`",
        ),
    ] {
        let reason = Scene::new().refusal(text);
        assert!(reason.contains(why), "{text}: {reason}");
    }
}

#[test]
fn a_misspelled_key_names_its_line_and_the_key_it_is_close_to() {
    for (text, line, why) in [
        (
            "[agent]\ncommand = [\"/bin/x\"]\n\n[agnt]\nx = \"1\"",
            4,
            "a profile holds the unknown key `agnt`; did you mean `agent`?",
        ),
        (
            "[agent]\ncommand = [\"/bin/x\"]\n[agent.filesytem]\nread = [\"/x\"]",
            3,
            "`[agent]` holds the unknown key `filesytem`; did you mean `filesystem`?",
        ),
        (
            "[agent]\ncommand = [\"/bin/x\"]\n[agent.filesystem]\nraed = [\"/x\"]",
            4,
            "`[agent.filesystem]` holds the unknown key `raed`; did you mean `read`?",
        ),
        (
            "[agent]\ncommand = [\"/bin/x\"]\nfilesystem = { exce = [\"/x\"] }",
            3,
            "`[agent.filesystem]` holds the unknown key `exce`; did you mean `exec`?",
        ),
        (
            "[agent]\ncommand = [\"/bin/x\"]\n[tool.git]\ncomand = [\"/bin/git\"]",
            4,
            "`[tool.git]` holds the unknown key `comand`; did you mean `command`?",
        ),
        (
            "[storage]\ndirectores = [\"a\"]\n[agent]\ncommand = [\"/bin/x\"]",
            2,
            "`[storage]` holds the unknown key `directores`; did you mean `directories`?",
        ),
    ] {
        let (path, at, reason) = Scene::new().located(text);
        assert_eq!(path, Path::new("test.toml"), "{text}");
        assert_eq!(at, Some(line), "{text}: {reason}");
        assert!(reason.contains(why), "{text}: {reason}");
    }
}

#[test]
fn a_refusal_prints_its_file_and_line() {
    let error = Scene::new()
        .compile(
            &profile("[agent]\ncommand = [\"/bin/x\"]\n\n[agnt]\nx = \"1\""),
            None,
        )
        .expect_err("a refusal");
    assert_eq!(
        error.to_string(),
        "test.toml:4: a profile holds the unknown key `agnt`; did you mean `agent`?"
    );
}

#[test]
fn an_unknown_key_close_to_no_known_key_lists_the_known_keys() {
    let (_, line, reason) = Scene::new().located("[agent]\ncommand = [\"/bin/x\"]\nzzzzzz = 1");
    assert_eq!(line, Some(3), "{reason}");
    assert_eq!(
        reason,
        "`[agent]` holds the unknown key `zzzzzz`; `[agent]` holds `command`, `dependency`, \
         `env`, `file-watching`, `filesystem`, `ingress`, `native-filesystem-policy`, `when`"
    );
}

#[test]
fn a_misspelled_key_in_a_pack_names_the_pack_file_and_its_line() {
    let scene = Scene::new();
    scene.share("p", "[agent.filesystem]\nexce = [\"/x\"]");
    let (path, line, reason) =
        scene.located("packs = [\"@box/p\"]\n[agent]\ncommand = [\"/bin/x\"]");
    assert_eq!(path, scene.root.join("packs/p/pack.toml"));
    assert_eq!(line, Some(6), "{reason}");
    assert!(
        reason.contains("`[agent.filesystem]` holds the unknown key `exce`; did you mean `exec`?"),
        "{reason}"
    );
}

#[test]
fn a_misspelled_key_in_an_agent_pack_names_its_line() {
    let scene = Scene::new();
    scene.share(
        "p",
        "[run]\ncommand = [\"/bin/x\"]\n[env]\nA = \"1\"\n[filesystem]\nexce = [\"/x\"]",
    );
    let (path, line, reason) = scene.located("packs = [\"@box/p\"]");
    assert_eq!(path, scene.root.join("packs/p/pack.toml"));
    assert_eq!(line, Some(10), "{reason}");
    assert!(
        reason.contains("`[agent.filesystem]` holds the unknown key `exce`; did you mean `exec`?"),
        "{reason}"
    );
}

#[test]
fn a_refusal_of_extends_and_of_a_key_of_run_names_its_line() {
    let scene = Scene::new();
    scene.share("claude", "[run]\ncommand = [\"/bin/claude\"]");
    scene.share_raw(
        "t",
        "[pack]\nname = \"@box/t\"\nversion = 1\nkind = \"tool\"\nextend = [\"@box/claude\"]\n\
         [inputs.t.path]\ntype = \"program\"\nprogram = \"t\"\nsearch = [{ env = \"PATH\" }]\n\
         [run]\ncommand = [\"${{ inputs.t.path }}\"]",
    );
    let (_, line, reason) = scene.located("packs = [\"@box/t\"]");
    assert_eq!(line, Some(5), "{reason}");
    assert!(
        reason.contains("a tool pack cannot extend the agent pack @box/claude"),
        "{reason}"
    );
    scene.share_raw(
        "a",
        "[pack]\nname = \"@box/a\"\nversion = 1\nkind = \"agent\"\n\n[run]\nprogram = \"a\"",
    );
    let (_, line, reason) = scene.located("packs = [\"@box/a\"]");
    assert_eq!(line, Some(7), "{reason}");
    assert!(
        reason.contains("the `[run]` of an agent pack holds the unknown key `program`"),
        "{reason}"
    );
}

#[test]
fn a_misspelled_header_key_names_its_line() {
    let scene = Scene::new();
    scene.share_raw(
        "p",
        "[pack]\nname = \"@box/p\"\nkind = \"support\"\nversoin = 1",
    );
    let (_, line, reason) = scene.located("packs = [\"@box/p\"]\n[agent]\ncommand = [\"/bin/x\"]");
    assert_eq!(line, Some(4), "{reason}");
    assert!(
        reason.contains("`[pack]` holds the unknown key `versoin`; did you mean `version`?"),
        "{reason}"
    );
}

#[test]
fn a_key_of_one_run_names_its_line() {
    for (text, line) in [
        ("\nname = \"x\"\n[agent]\ncommand = [\"/bin/x\"]", 2),
        ("[agent]\ncommand = [\"/bin/x\"]\nworkspace = \"/x\"", 3),
        ("\n\npolicy = \"p\"\n[agent]\ncommand = [\"/bin/x\"]", 3),
    ] {
        match Profile::parse(text, Path::new("test.toml")) {
            Err(Error::Profile { line: at, .. }) => assert_eq!(at, Some(line), "{text}"),
            other => panic!("a refusal, not {other:?}"),
        }
    }
}

#[test]
fn a_key_of_the_other_kind_of_file_names_its_line() {
    let scene = Scene::new();
    for (text, line) in [
        (
            "[agent]\ncommand = [\"/bin/x\"]\n[inputs.a]\ntype = \"string\"",
            3,
        ),
        (
            "\nextend = [\"@box/p\"]\n[agent]\ncommand = [\"/bin/x\"]",
            2,
        ),
    ] {
        let (_, at, reason) = scene.located(text);
        assert_eq!(at, Some(line), "{text}: {reason}");
        assert!(reason.contains("belongs in a pack"), "{reason}");
    }
    scene.share("p", "\n[options]\na = \"1\"");
    let (_, line, reason) = scene.located("packs = [\"@box/p\"]\n[agent]\ncommand = [\"/bin/x\"]");
    assert_eq!(line, Some(6), "{reason}");
    assert!(reason.contains("belongs in a profile"), "{reason}");
    scene.share_top("q", "workspace = \"/x\"", "[run]\ncommand = [\"/bin/x\"]");
    let (_, line, reason) = scene.located("packs = [\"@box/q\"]\n[agent]\ncommand = [\"/bin/x\"]");
    assert_eq!(line, Some(1), "{reason}");
    assert!(reason.contains("for each run"), "{reason}");
}

#[test]
fn an_option_written_as_one_quoted_key_names_its_line() {
    let scene = Scene::new();
    scene.share(
        "p",
        "[inputs.bedrock.region]\ndescription = \"The region.\"",
    );
    let (_, line, reason) = scene.located(
        "packs = [\"@box/p\"]\n[agent]\ncommand = [\"/bin/x\"]\n[options]\n\n\"bedrock.regon\" = \"x\"",
    );
    assert_eq!(line, Some(6), "{reason}");
    assert!(
        reason.contains("did you mean `bedrock.region`?"),
        "{reason}"
    );
}

#[test]
fn an_option_that_no_pack_declares_names_its_line_and_the_input_it_is_close_to() {
    let scene = Scene::new();
    scene.share(
        "p",
        "[inputs.bedrock.region]\ndescription = \"The region.\"",
    );
    let (path, line, reason) = scene.located(
        "packs = [\"@box/p\"]\n[agent]\ncommand = [\"/bin/x\"]\n[options]\nbedrock.regon = \"x\"",
    );
    assert_eq!(path, Path::new("test.toml"));
    assert_eq!(line, Some(5), "{reason}");
    assert!(
        reason.contains(
            "`[options] bedrock.regon` sets an input that no pack declares; did you mean \
             `bedrock.region`?"
        ),
        "{reason}"
    );
}

#[test]
fn a_profile_names_a_program() {
    let reason = Scene::new().refusal("[agent]\ncommand = []");
    assert!(reason.contains("names no program"), "{reason}");
}

#[test]
fn the_name_box_is_reserved() {
    let error = validate_name("box").expect_err("a reserved name");
    assert!(error.to_string().contains("`box` is reserved"), "{error}");
    validate_name("boxes").expect("a longer name is not reserved");
}

#[test]
fn the_name_base_is_reserved() {
    let error = validate_name("base").expect_err("a reserved name");
    assert!(error.to_string().contains("`base` is reserved"), "{error}");
    let profiles = Profiles::at("/nonexistent");
    assert!(matches!(
        profiles.load("base"),
        Err(Error::ProfileName { .. })
    ));
    for name in [
        "",
        ".hidden",
        "-flag",
        "a/b",
        "a b",
        "~box",
        &"x".repeat(65),
    ] {
        assert!(validate_name(name).is_err(), "{name:?}");
    }
    for name in ["claude", "claude-dev", "codex.2", "a_b", "base2"] {
        validate_name(name).expect(name);
    }
}

#[test]
fn a_profile_uses_policies_instead_of_the_engine_policy_key() {
    let reason = refusal("policy = \"claude.dw\"\n[agent]\ncommand = [\"/bin/x\"]");
    assert!(reason.contains("a profile holds no `policy`"), "{reason}");
    assert!(reason.contains("`policies`"), "{reason}");
}

#[test]
fn policy_references_are_nonempty_literal_paths() {
    for (text, field) in [
        ("policies = \"policy.dw\"", "`policies`"),
        ("policies = [1]", "`policies[0]`"),
        ("policies = [\"ok.dw\", false]", "`policies[1]`"),
        ("policies = [\"\"]", "`policies[0]`"),
        ("policies = [\"${{ profile }}/policy.dw\"]", "`policies[0]`"),
    ] {
        let path = Path::new("profiles/test/profile.toml");
        match Profile::parse(text, path) {
            Err(Error::Profile {
                path: found,
                line,
                reason,
            }) => {
                assert_eq!(found, path);
                assert_eq!(line, Some(1), "{text}");
                assert!(reason.contains(field), "{text}: {reason}");
            }
            other => panic!("an invalid policy reference refusal, not {other:?}"),
        }
    }
}

#[test]
fn policy_references_load_relative_absolute_and_linked_files() {
    let scene = Scene::new();
    let profiles = Profiles::at(scene.root.join("profiles"));
    let folder = profiles.folder("test");
    std::fs::create_dir_all(folder.join("policies")).expect("policy folder");
    let first = "  // service policy\r\n@id(\"service\") permit (principal, action, resource);  ";
    let second = "\t// workspace policy, with no final newline";
    let local = folder.join("workspace.dw");
    std::fs::write(folder.join("policies/service.dw"), format!("\n{first}\n"))
        .expect("first policy");
    std::fs::write(&local, second).expect("second policy");
    std::os::unix::fs::symlink("policies/service.dw", folder.join("service-link.dw"))
        .expect("policy link");
    std::os::unix::fs::symlink("policies", folder.join("policy-link"))
        .expect("policy directory link");
    std::os::unix::fs::symlink(
        folder.join("policies/service.dw"),
        folder.join("absolute-link.dw"),
    )
    .expect("absolute policy link");
    let expected = format!("{first}\n\n{second}");
    for reference in [
        "policies/service.dw",
        "service-link.dw",
        "policy-link/service.dw",
        "absolute-link.dw",
    ] {
        std::fs::write(
            profiles.path("test"),
            format!(
                "policies = [{reference:?}, {:?}]\n{MINIMAL}",
                local.to_str().unwrap()
            ),
        )
        .expect("profile");
        let (_, policy) = profiles.load("test").expect("load").expect("profile");
        assert_eq!(policy.as_deref(), Some(expected.as_str()), "{reference}");
    }
}

#[test]
fn policy_references_refuse_paths_outside_the_profile() {
    let scene = Scene::new();
    let profiles = Profiles::at(scene.root.join("profiles"));
    let folder = profiles.folder("test");
    let sibling = profiles.folder("test-other");
    std::fs::create_dir_all(&folder).expect("profile folder");
    std::fs::create_dir_all(&sibling).expect("sibling folder");
    std::fs::write(folder.join("ok.dw"), "// local").expect("local policy");
    std::fs::write(folder.join("returned.dw"), "// returned").expect("second local policy");
    let outside = sibling.join("outside.dw");
    std::fs::write(&outside, "// outside").expect("outside policy");
    std::os::unix::fs::symlink(&outside, folder.join("file-link.dw")).expect("outside file link");
    std::os::unix::fs::symlink(&sibling, folder.join("directory-link"))
        .expect("outside directory link");
    std::os::unix::fs::symlink(folder.join("returned.dw"), sibling.join("return-link.dw"))
        .expect("outside link back into the profile");
    std::os::unix::fs::symlink(
        sibling.join("return-link.dw"),
        folder.join("out-and-back.dw"),
    )
    .expect("policy link through an outside directory");
    for reference in [
        outside.to_str().unwrap(),
        "../test-other/outside.dw",
        "file-link.dw",
        "directory-link/outside.dw",
        "out-and-back.dw",
        "../test/returned.dw",
    ] {
        std::fs::write(
            profiles.path("test"),
            format!("\npolicies = [\"ok.dw\", {reference:?}]\n{MINIMAL}"),
        )
        .expect("profile");
        match profiles.load("test") {
            Err(Error::Profile { path, line, reason }) => {
                assert_eq!(path, profiles.path("test"), "{reference}");
                assert_eq!(line, Some(2), "{reference}");
                for detail in ["`policies[1]`", reference, "profile folder"] {
                    assert!(reason.contains(detail), "{reference}: {reason}");
                }
            }
            other => panic!("{reference}: an outside policy refusal, not {other:?}"),
        }
    }
}

#[test]
fn policy_references_refuse_hard_linked_files() {
    let scene = Scene::new();
    let profiles = Profiles::at(scene.root.join("profiles"));
    let folder = profiles.folder("test");
    std::fs::create_dir_all(&folder).expect("profile folder");
    std::fs::write(folder.join("ok.dw"), "// local").expect("local policy");
    let file = folder.join("rules.dw");
    std::fs::write(&file, "// shared").expect("policy");
    std::os::unix::fs::symlink("rules.dw", folder.join("link.dw")).expect("policy link");
    for alias in [scene.workspace().join("rules.dw"), folder.join("alias.dw")] {
        std::fs::hard_link(&file, &alias).expect("hard link");
        for reference in ["rules.dw", "link.dw"] {
            std::fs::write(
                profiles.path("test"),
                format!("\npolicies = [\"ok.dw\", {reference:?}]\n{MINIMAL}"),
            )
            .expect("profile");
            match profiles.load("test") {
                Err(Error::Profile { path, line, reason }) => {
                    assert_eq!(path, profiles.path("test"), "{reference}");
                    assert_eq!(line, Some(2), "{reference}");
                    for detail in ["`policies[1]`", reference, "hard link", "copy"] {
                        assert!(reason.contains(detail), "{reference}: {reason}");
                    }
                }
                other => panic!("{reference}: a hard-linked policy refusal, not {other:?}"),
            }
        }
        std::fs::remove_file(&file).expect("remove hard-linked policy");
        std::fs::copy(&alias, &file).expect("separate policy copy");
        let (_, policy) = profiles.load("test").expect("load").expect("profile");
        assert_eq!(policy.as_deref(), Some("// local\n\n// shared"));
        std::fs::remove_file(&alias).expect("remove alias");
    }
}

#[test]
fn policy_references_refuse_redirected_profile_directories() {
    for redirect_root in [false, true] {
        let scene = Scene::new();
        let profiles = Profiles::at(scene.root.join("profiles"));
        let folder = profiles.folder("test");
        std::fs::create_dir_all(&folder).expect("profile folder");
        std::fs::write(
            profiles.path("test"),
            format!("\npolicies = [\"policy.dw\"]\n{MINIMAL}"),
        )
        .expect("profile");
        std::fs::write(folder.join("policy.dw"), "// policy").expect("policy");
        let redirected = if redirect_root {
            profiles.root()
        } else {
            folder.as_path()
        };
        let outside = scene.workspace().join("redirected");
        std::fs::rename(redirected, &outside).expect("move the directory");
        std::os::unix::fs::symlink(&outside, redirected).expect("redirect the directory");
        match profiles.load("test") {
            Err(Error::Profile { path, line, reason }) => {
                assert_eq!(path, profiles.path("test"), "{}", redirected.display());
                assert_eq!(line, Some(2), "{}", redirected.display());
                for detail in ["policies", "profile folder", "symbolic link"] {
                    assert!(reason.contains(detail), "{reason}");
                }
            }
            other => panic!(
                "{}: a redirected directory refusal, not {other:?}",
                redirected.display()
            ),
        }
    }
}

#[test]
fn policy_references_allow_aliases_above_the_profiles_root() {
    let scene = Scene::new();
    let alias = scene.root.join("home-link");
    std::os::unix::fs::symlink(scene.home(), &alias).expect("home alias");
    let profiles = Profiles::at(alias.join(".strands/box/profiles"));
    let folder = profiles.folder("test");
    std::fs::create_dir_all(&folder).expect("profile folder");
    let file = folder.join("policy.dw");
    std::fs::write(&file, "// policy").expect("policy");
    let real_file = file.canonicalize().expect("real policy path");
    for reference in [
        "policy.dw",
        file.to_str().unwrap(),
        real_file.to_str().unwrap(),
    ] {
        std::fs::write(
            profiles.path("test"),
            format!("policies = [{reference:?}]\n{MINIMAL}"),
        )
        .expect("profile");
        let (_, policy) = profiles.load("test").expect("load").expect("profile");
        assert_eq!(policy.as_deref(), Some("// policy"), "{reference}");
    }
}

#[test]
fn policy_references_ignore_unlisted_adjacent_files() {
    let scene = Scene::new();
    let profiles = Profiles::at(scene.root.join("profiles"));
    std::fs::create_dir_all(profiles.folder("test").join("policy.dw"))
        .expect("an unreadable adjacent policy directory");
    std::fs::write(profiles.folder("test").join("listed.dw"), "// listed").expect("policy");
    for (header, expected) in [
        ("", None),
        ("policies = []\n", None),
        ("policies = [\"listed.dw\"]\n", Some("// listed")),
    ] {
        std::fs::write(profiles.path("test"), format!("{header}{MINIMAL}")).expect("profile");
        let (_, policy) = profiles.load("test").expect("load").expect("profile");
        assert_eq!(policy.as_deref(), expected, "{header:?}");
    }
}

#[test]
fn policy_references_report_the_unreadable_entry() {
    let scene = Scene::new();
    let profiles = Profiles::at(scene.root.join("profiles"));
    let folder = profiles.folder("test");
    std::fs::create_dir_all(folder.join("directory.dw")).expect("folder");
    std::fs::write(folder.join("ok.dw"), "// a valid file").expect("policy");
    std::fs::write(folder.join("invalid.dw"), [0xff]).expect("non-UTF-8 policy");
    for reference in ["missing.dw", "directory.dw", "invalid.dw"] {
        std::fs::write(
            profiles.path("test"),
            format!("policies = [\"ok.dw\", {reference:?}]\n{MINIMAL}"),
        )
        .expect("profile");
        match profiles.load("test") {
            Err(Error::Profile { path, line, reason }) => {
                assert_eq!(path, profiles.path("test"), "{reference}");
                assert_eq!(line, Some(1), "{reference}");
                assert!(reason.contains("`policies[1]`"), "{reference}: {reason}");
                assert!(reason.contains(reference), "{reference}: {reason}");
                assert!(reason.contains("cannot read"), "{reference}: {reason}");
            }
            other => panic!("{reference}: an unreadable policy refusal, not {other:?}"),
        }
    }
}

#[test]
fn policy_references_refuse_repeated_files_and_symlink_aliases() {
    let scene = Scene::new();
    let profiles = Profiles::at(scene.root.join("profiles"));
    let folder = profiles.folder("test");
    std::fs::create_dir_all(folder.join("policies")).expect("folder");
    std::os::unix::fs::symlink("policy.dw", folder.join("alias.dw")).expect("policy link");
    for text in ["// policy", "", " \r\n\t\n  "] {
        std::fs::write(folder.join("policy.dw"), text).expect("policy");
        for reference in [
            "policy.dw",
            "./policy.dw",
            "policies/../policy.dw",
            "alias.dw",
        ] {
            std::fs::write(
                profiles.path("test"),
                format!("policies = [\"policy.dw\", {reference:?}]\n{MINIMAL}"),
            )
            .expect("profile");
            match profiles.load("test") {
                Err(Error::Profile { path, line, reason }) => {
                    assert_eq!(path, profiles.path("test"), "{reference}, {text:?}");
                    assert_eq!(line, Some(1), "{reference}");
                    for detail in ["`policies[1]`", reference, "`policies[0]`"] {
                        assert!(reason.contains(detail), "{reference}, {text:?}: {reason}");
                    }
                }
                other => panic!("{reference}, {text:?}: a repeated policy refusal, not {other:?}"),
            }
        }
    }
}

#[test]
fn policy_references_are_refused_in_packs_and_tool_packs() {
    let scene = Scene::new();
    for program in [
        "",
        "[inputs.git.path]\ntype = \"program\"\nprogram = \"git\"\n\
                         search = [{ env = \"PATH\" }]\n[run]\n\
                         command = [\"${{ inputs.git.path }}\"]\n",
    ] {
        for policies in ["[]", "[\"service.dw\"]"] {
            scene.share_top("p", &format!("policies = {policies}"), program);
            let reason = scene.resolve_refusal("packs = [\"@box/p\"]");
            assert!(
                reason.contains("a pack holds no `policies`"),
                "{program:?}, {policies}: {reason}"
            );
        }
    }
}

#[test]
fn base_policy_is_not_a_key() {
    let scene = Scene::new();
    let reason = scene.resolve_refusal(&format!("base-policy = \"@box/open\"\n{MINIMAL}"));
    assert!(reason.contains("the unknown key `base-policy`"), "{reason}");
    scene.share("p", "base-policy = \"@box/open\"");
    let reason = scene.resolve_refusal("packs = [\"@box/p\"]");
    assert!(reason.contains("unknown key `base-policy`"), "{reason}");
}

#[test]
fn a_placeholder_resolves_to_its_value() {
    let scene = Scene::new();
    scene.share(
        "p",
        r#"
[inputs.region]
default = "eu-west-1"
pattern = "[a-z]{2}-[a-z]+-[0-9]"

[inputs.set]
from = "env:SET"

[inputs.unset]
from = "env:UNSET"
default = "fallback"

[inputs.empty]
from = "env:EMPTY"
default = "fallback"

[inputs.agent]
type = "program"
default = "/usr/bin/true"
"#,
    );
    let workspace = scene.workspace().display().to_string();
    let compiled = scene
        .compile(
            &profile(
                r#"
packs = ["@box/p"]

[agent]
command = ["${{ inputs.agent }}", "--region=${{ inputs.region }}", "$${{ kept }}"]
env.SET = "${{ inputs.set }}"
env.UNSET = "${{ inputs.unset }}"
env.EMPTY = "${{ inputs.empty }}"
env.TMPDIR = "${{ workspace }}/.tmp"
env.HOST = "bedrock-runtime.${{ inputs.region }}.amazonaws.com"
env.OTEL = "${OTEL_EXPORTER_OTLP_TRACES_ENDPOINT}"
"#,
            ),
            None,
        )
        .expect("a compile");
    let file = table(&compiled);
    assert_eq!(file["agent"]["env"]["EMPTY"].as_str(), Some("fallback"));
    assert_eq!(
        strings(&file["agent"]["command"]),
        ["/usr/bin/true", "--region=eu-west-1", "${{ kept }}"]
    );
    let env = &file["agent"]["env"];
    assert_eq!(env["SET"].as_str(), Some("set-value"));
    assert_eq!(env["UNSET"].as_str(), Some("fallback"));
    assert_eq!(
        env["TMPDIR"].as_str(),
        Some(format!("{workspace}/.tmp").as_str())
    );
    assert_eq!(
        env["HOST"].as_str(),
        Some("bedrock-runtime.eu-west-1.amazonaws.com")
    );
    assert_eq!(
        env["OTEL"].as_str(),
        Some("${OTEL_EXPORTER_OTLP_TRACES_ENDPOINT}")
    );
    for key in [
        "options", "inputs", "packs", "pack", "storage", "extend", "include",
    ] {
        assert!(file.get(key).is_none(), "{key}");
    }
}

#[test]
fn a_malformed_placeholder_is_refused() {
    for (value, why) in [
        (r#""${{ home""#, "no closing"),
        (r#""${{ a b }}""#, "is not a name"),
        (r#""${{ }}""#, "is not a name"),
    ] {
        let reason = refusal(&format!(
            "[agent]\ncommand = [\"/bin/x\"]\nenv.VALUE = {value}"
        ));
        assert!(reason.contains(why), "{value}: {reason}");
    }
    let scene = Scene::new();
    for (value, why) in [
        (r#""${{ bogus }}""#, "is not a name"),
        (r#""${{ pack.x }}""#, "is not a name"),
        (r#""${{ storage.none }}""#, "not in `[storage] directories`"),
        (r#""${{ option.x }}""#, "is not a name"),
        (r#""${{ env.SET }}""#, "is not a name"),
        (r#""${{ file.x }}""#, "is not a name"),
    ] {
        let reason = scene.refusal(&format!(
            "[agent]\ncommand = [\"/bin/x\"]\nenv.VALUE = {value}"
        ));
        assert!(reason.contains(why), "{value}: {reason}");
    }
    scene.share("unset", "[inputs.unset]\nfrom = \"env:UNSET\"");
    let reason = scene.refusal(
        "packs = [\"@box/unset\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
         env.VALUE = \"${{ inputs.unset }}\"",
    );
    assert!(
        reason.contains("`inputs.unset` has no value; set `unset` in your profile's `[options]`"),
        "{reason}"
    );
}

#[test]
fn a_host_variable_input_cannot_read_a_credential_variable() {
    let scene = Scene::new();
    scene.share(
        "key",
        "[inputs.key]\nfrom = \"env:MY_KEY\"\ndefault = \"x\"",
    );
    for credential in [
        "[egress.model]\ndestinations = [\"example.com\"]\nsecret.ref = \"env://MY_KEY\"",
        "[telemetry.otlp]\nkind = \"otlp\"\ndestination = \"http://localhost:4318\"\n\
         secret.ref = \" env://MY_KEY \"\nsecret.header = \"x-api-key\"",
        "[telemetry.otlp]\nkind = \"otlp\"\ndestination = \"http://localhost:4318\"\n\
         secret.ref = \"secret://MY_KEY\"\nsecret.header = \"x-api-key\"",
    ] {
        let reason = scene.refusal(&format!(
            "packs = [\"@box/key\"]\n\n[agent]\ncommand = [\"/bin/x\"]\n\
             env.KEY = \"${{{{ inputs.key }}}}\"\n\n{credential}"
        ));
        assert!(
            reason.contains("would give the workload the host's `MY_KEY`, which a route or a server names as its credential"),
            "{credential}: {reason}"
        );
    }
}

#[test]
fn an_optional_entry_through_a_broken_link_is_dropped() {
    let scene = Scene::new();
    let dir = tempfile::tempdir().expect("a folder");
    let link = dir.path().join("managed-settings.json");
    std::os::unix::fs::symlink(dir.path().join("gone"), &link).expect("a link");
    let real = dir.path().join("present.json");
    std::fs::write(&real, "{}").expect("a file");
    let resolved = scene
        .resolve(&profile(&format!(
            "[agent]\ncommand = [\"/bin/x\"]\n[agent.filesystem]\nread_file = [\n\
             {{ path = {link:?}, optional = true }},\n{{ path = {real:?}, optional = true }},\n]",
            link = link.display().to_string(),
            real = real.display().to_string(),
        )))
        .expect("a resolve");
    let files = &resolved.agent.filesystem.read_file;
    assert_eq!(files.len(), 1, "{files:?}");
    assert!(files[0].ends_with("present.json"), "{files:?}");
}

#[test]
fn an_env_variable_from_the_host_comes_in_only_when_the_host_sets_it() {
    let scene = Scene::new();
    let env = scene
        .resolve(&profile(
            "[agent]\ncommand = [\"/bin/x\"]\n[agent.env]\n\
             KEPT = { from = \"env:SET\" }\nUNSET = { from = \"env:UNSET\" }",
        ))
        .expect("a resolve")
        .agent
        .env;
    assert_eq!(env.get("KEPT").map(String::as_str), Some("set-value"));
    assert_eq!(env.get("UNSET"), None);
    scene.share(
        "p",
        "[run]\ncommand = [\"/bin/x\"]\n[inputs.pass]\ntype = \"bool\"\ndefault = true\n[env]\n\
         A = { from = \"env:SET\", when = \"${{ inputs.pass }}\" }\nB = { from = \"env:SET\" }",
    );
    let resolve = |text: &str| scene.resolve(&profile(text)).expect("a resolve").agent.env;
    let on = resolve("packs = [\"@box/p\"]");
    assert_eq!(on.get("A").map(String::as_str), Some("set-value"));
    let off = resolve("packs = [\"@box/p\"]\n[options]\npass = false");
    assert_eq!(off.get("A"), None);
    let over = resolve(
        "packs = [\"@box/p\"]\n[agent.env]\nA = { value = \"mine\", when = \"${{ inputs.pass }}\" }\nB = \"plain\"",
    );
    assert_eq!(over.get("A").map(String::as_str), Some("mine"));
    assert_eq!(over.get("B").map(String::as_str), Some("plain"));
    for (text, why) in [
        (
            "[agent]\ncommand = [\"/bin/x\"]\n[egress.model]\ndestinations = [\"example.com\"]\n\
             secret = { from = \"env:SET\" }",
            "only an `env` variable of `[agent]`",
        ),
        (
            "[agent]\ncommand = [\"/bin/x\"]\n[agent.env]\nA = { from = \"SET\" }",
            "is not \"env:<NAME>\"",
        ),
        (
            "[agent]\ncommand = [\"/bin/x\"]\n[agent.env]\nA = { from = \"env:A=B\" }",
            "is not \"env:<NAME>\"",
        ),
        (
            "[agent]\ncommand = [\"/bin/x\"]\n[egress.model]\ndestinations = [\"example.com\"]\n\
             [egress.model.env]\nA = { from = \"env:SET\" }",
            "only an `env` variable of `[agent]`",
        ),
        (
            "[agent]\ncommand = [\"/bin/x\"]\n[agent.env]\nA = { from = \"env:MY_KEY\" }\n\
             [egress.model]\ndestinations = [\"example.com\"]\nsecret.ref = \"env://MY_KEY\"",
            "would give the workload the host's `MY_KEY`, which a route or a server names as its credential",
        ),
    ] {
        let reason = scene.refusal(text);
        assert!(reason.contains(why), "{reason}");
    }
}

#[test]
fn a_tool_table_names_one_program_and_box_writes_its_command() {
    for (table, why) in [
        ("detect = \"git\"", "`[tool.git] detect` is not a key"),
        ("program = \"bin/git\"", "is not a program name"),
        ("program = 1", "is not a program name"),
        (
            "program = \"git\"\ncommand = [\"/usr/bin/git\"]",
            "holds `program` and `command`",
        ),
        ("helpers = [\"cc\"]", "`[tool.git] helpers` needs `program`"),
        (
            "program = \"git\"\nhelpers = [\"/usr/bin/cc\"]",
            "not a name",
        ),
        ("program = \"git\"\nhosts = [\"https://x\"]", "not a name"),
    ] {
        let reason = Scene::new().refusal(&format!(
            "[agent]\ncommand = [\"/bin/x\"]\n[tool.git]\n{table}"
        ));
        assert!(reason.contains(why), "{table}: {reason}");
    }
}

#[test]
fn a_toolchain_the_host_lacks_leaves_the_run_and_its_dependencies() {
    let scene = Scene::new();
    let text = "[agent]\ncommand = [\"/bin/x\"]\ndependency = [\"tool.git\", \"egress.model\"]\n\
                [tool.git]\nprogram = \"git\"";
    let resolved = scene.resolve(&profile(text)).expect("a resolve");
    assert!(resolved.tool.is_empty());
    assert_eq!(
        resolved.tools.skipped,
        [("git".to_string(), "git is not on PATH".to_string())]
    );
    assert_eq!(resolved.agent.dependency, ["egress.model"]);
    let compiled = scene.compile(&profile(text), None).expect("a compile");
    let file = table(&compiled);
    assert!(file.get("tool").is_none(), "{}", compiled.box_toml);
    assert!(
        file["agent"].get("dependency").is_none(),
        "Box Core refuses `dependency`: {}",
        compiled.box_toml
    );
}

#[test]
fn the_agent_enters_reads_and_writes_the_workspace() {
    let scene = Scene::new();
    let compiled = scene
        .compile(
            &profile(
                "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.read = [\"/usr/bin/true\"]",
            ),
            None,
        )
        .expect("a compile");
    let file = table(&compiled);
    let workspace = scene.workspace().display().to_string();
    assert_eq!(
        file["agent"]["workspace"].as_str(),
        Some(workspace.as_str())
    );
    assert_eq!(
        strings(&file["agent"]["filesystem"]["read"]),
        [workspace.clone(), real("/usr/bin/true")]
    );
    assert_eq!(strings(&file["agent"]["filesystem"]["write"]), [workspace]);
    assert_eq!(file["name"].as_str(), Some("test-0000abcd"));
    assert_eq!(
        file["box_dir"].as_str(),
        scene.instance().box_directory.to_str()
    );
    assert_eq!(file["policy"].as_str(), Some("policy.dw"));
}

#[test]
fn a_minimal_profile_compiles_to_exactly_this_box_toml() {
    let scene = Scene::new();
    let compiled = scene
        .compile(
            &profile(
                "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.read = [\"/usr/bin/true\"]",
            ),
            None,
        )
        .expect("a compile");
    let workspace = scene.workspace().display().to_string();
    let instance = scene.instance();
    let expected: toml::Value = toml::from_str(&format!(
        r#"
name = "test-0000abcd"
box_dir = "{box_dir}"
policy = "policy.dw"
file-attributes = true

[limits.shell]
timeout = false

[agent]
command = ["/usr/bin/true"]
workspace = "{workspace}"

[agent.filesystem]
read = ["{workspace}", "{program}"]
write = ["{workspace}"]
deny = ["{workspace}/.box"]

[telemetry.records]
kind = "file"
destination = "{records}"
include = ["deny", "permit", "trace", "logs"]
"#,
        program = real("/usr/bin/true"),
        box_dir = instance.box_directory.display(),
        records = instance.directory.join("records.jsonl").display(),
    ))
    .expect("TOML");
    assert_eq!(table(&compiled), expected);
}

/// Profiles and packs are read as TOML 1.1, as Box Core reads `box.toml`, so an inline table may
/// span lines and end in a comma. TOML 1.0 refuses this form. It compiles like the dotted form.
#[test]
fn a_profile_may_use_toml_1_1_syntax() {
    let scene = Scene::new();
    let dotted = scene
        .compile(
            &profile(
                "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.read = [\"/usr/bin/true\"]",
            ),
            None,
        )
        .expect("a compile");
    let multi_line = scene
        .compile(
            &profile(
                "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem = {\n  read = [\"/usr/bin/true\"],\n}",
            ),
            None,
        )
        .expect("a compile");
    assert_eq!(table(&multi_line), table(&dotted));
}

/// The text of `box.toml`, byte for byte, so a change in how `toml` writes it shows: the order of
/// keys and tables, the quoting and escaping of strings, nested tables, and arrays of tables. The
/// expected text is what `toml` 0.8 wrote before the bump to `toml` 1.
#[test]
fn a_profile_compiles_to_exactly_this_box_toml_text() {
    let scene = Scene::new();
    let compiled = scene
        .compile(
            &profile(
                r#"
file-attributes = false

[agent]
command = ["/usr/bin/true", "say \"hi\"", 'C:\back\slash', "café ☕", "two\nlines", "tab\tend"]
filesystem.read = ["/usr/bin/true"]
file-watching = true
env.GREETING = "a \"quoted\" \\ value é"
env.PLAIN = "plain"

[limits.shell]
timeout = 600
max_stdin = 1048576

[egress.model]
destinations = ["model.example.com", "other.example.com"]
secret.ref = "aws://"

[[egress.model.backends]]
url = "https://gw.example.com/a"
auth = { ref = "aws://", aws = { service = "bedrock", region = "us-east-1" } }

[[egress.model.backends]]
url = "https://gw.example.com/b"
auth = { ref = "aws://", aws = { service = "bedrock", region = "us-west-2" } }

[mcp.docs]
type = "http"
destinations = ["docs.example.com"]
secret.ref = "aws://"
"#,
            ),
            None,
        )
        .expect("a compile");
    let workspace = scene.workspace().display().to_string();
    let instance = scene.instance();
    let expected = format!(
        r##"name = "test-0000abcd"
box_dir = "{box_dir}"
policy = "policy.dw"
file-attributes = false

[limits.shell]
max_stdin = 1048576
timeout = 600

[agent]
command = ["/usr/bin/true", 'say "hi"', 'C:\back\slash', "café ☕", """
two
lines""", "tab\tend"]
workspace = "{workspace}"
file-watching = true

[agent.env]
GREETING = 'a "quoted" \ value é'
PLAIN = "plain"

[agent.filesystem]
read = ["{workspace}", "{program}"]
write = ["{workspace}"]
deny = ["{workspace}/.box"]

[egress.model]
destinations = ["model.example.com", "other.example.com"]

[[egress.model.backends]]
url = "https://gw.example.com/a"

[egress.model.backends.auth]
ref = "aws://"

[egress.model.backends.auth.aws]
region = "us-east-1"
service = "bedrock"

[[egress.model.backends]]
url = "https://gw.example.com/b"

[egress.model.backends.auth]
ref = "aws://"

[egress.model.backends.auth.aws]
region = "us-west-2"
service = "bedrock"

[egress.model.secret]
ref = "aws://"

[mcp.docs]
destinations = ["docs.example.com"]
type = "http"

[mcp.docs.secret]
ref = "aws://"

[telemetry.records]
destination = "{records}"
include = ["deny", "permit", "trace", "logs"]
kind = "file"
"##,
        program = real("/usr/bin/true"),
        box_dir = instance.box_directory.display(),
        records = instance.directory.join("records.jsonl").display(),
    );
    assert_eq!(compiled.box_toml, expected);
}

#[test]
fn file_attributes_follow_the_user_id_unless_the_profile_sets_them() {
    let agent = "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.read = [\"/usr/bin/true\"]";
    for (as_root, key, expected) in [
        (false, "", true),
        (true, "", false),
        (true, "file-attributes = true\n", true),
        (false, "file-attributes = false\n", false),
    ] {
        let mut scene = Scene::new();
        scene.as_root = as_root;
        let compiled = scene
            .compile(&profile(&format!("{key}{agent}")), None)
            .expect("a compile");
        assert_eq!(
            table(&compiled)["file-attributes"].as_bool(),
            Some(expected),
            "root {as_root}, profile {key:?}"
        );
    }
}

#[test]
fn file_attributes_are_a_boolean_in_the_profile_and_no_key_of_a_pack() {
    let scene = Scene::new();
    let refusal =
        scene.resolve_refusal("file-attributes = \"yes\"\n[agent]\ncommand = [\"/usr/bin/true\"]");
    assert!(
        refusal.contains("`file-attributes` is `true` or `false`"),
        "{refusal}"
    );
    scene.share_top(
        "kiro",
        "file-attributes = true",
        "[run]\ncommand = [\"/usr/bin/true\"]",
    );
    let refusal = scene.resolve_refusal("packs = [\"@box/kiro\"]");
    assert!(
        refusal
            .contains("a pack holds no `file-attributes`; `file-attributes` belongs in a profile"),
        "{refusal}"
    );
}

#[test]
fn file_watching_reaches_box_toml_only_from_the_tables_that_set_it() {
    let text = WITH_TOOL_AND_SERVER
        .replace("[agent]\n", "[agent]\nfile-watching = true\n")
        .replace("[mcp.local]\n", "[mcp.local]\nfile-watching = true\n");
    let compiled = Scene::new()
        .compile(&profile(&text), None)
        .expect("a compile");
    let compiled = table(&compiled);
    let watching = [
        &compiled["agent"],
        &compiled["tool"]["git"],
        &compiled["mcp"]["local"],
    ]
    .map(|process| process.get("file-watching").and_then(toml::Value::as_bool));
    assert_eq!(watching, [Some(true), None, Some(true)]);
}

#[test]
fn a_pack_sets_file_watching_in_run_and_the_profile_can_turn_it_off() {
    let scene = Scene::new();
    scene.share("a", "[run]\ncommand = [\"/bin/x\"]\nfile-watching = true");
    scene.share(
        "rt",
        &crate::lang::test_tool_pack("rt", "file-watching = true"),
    );
    let (_, compiled) = scene
        .compile_using(
            &profile("packs = [\"@box/a\", \"@box/rt\"]\n[tool.rt]\nfile-watching = false"),
            &mut Detecting,
            "/usr/bin:/bin",
        )
        .expect("a compile");
    let compiled = table(&compiled);
    assert_eq!(compiled["agent"]["file-watching"].as_bool(), Some(true));
    assert_eq!(
        compiled["tool"]["rt"]["file-watching"].as_bool(),
        Some(false)
    );
}

#[test]
fn contain_egress_reaches_box_toml_only_from_the_profile_tool_tables_that_set_it() {
    let scene = Scene::new();
    for tool in ["rt", "cc", "ls", "wh"] {
        scene.share(tool, &crate::lang::test_tool_pack(tool, ""));
    }
    scene.share("a", "[run]\ncommand = [\"/bin/x\"]");
    let (_, compiled) = scene
        .compile_using(
            &profile(
                "packs = [\"@box/a\", \"@box/rt\", \"@box/cc\", \"@box/ls\", \"@box/wh\"]\n\
                 [tool.rt.network]\ncontain_egress = false\n\
                 [tool.cc.network]\ncontain_egress = true\n\
                 [tool.wh.network]\n",
            ),
            &mut Detecting,
            "/usr/bin:/bin",
        )
        .expect("a compile");
    let compiled = table(&compiled);
    let contained = ["rt", "cc", "ls", "wh"].map(|tool| {
        compiled["tool"][tool]
            .get("network")
            .map(|network| network["contain_egress"].as_bool())
    });
    assert_eq!(contained, [Some(Some(false)), Some(Some(true)), None, None]);
    assert!(compiled["agent"].get("network").is_none());
}

#[test]
fn a_tool_network_table_holds_only_a_boolean_contain_egress() {
    let tool = "[agent]\ncommand = [\"/usr/bin/true\"]\n[tool.git]\ncommand = [\"/usr/bin/git\"]\n";
    let (_, _, reason) =
        Scene::new().located(&format!("{tool}[tool.git.network]\ncontain = false"));
    assert!(
        reason.contains("`[tool.git.network]` holds the unknown key `contain`")
            && reason.contains("`contain_egress`"),
        "{reason}"
    );
    let refusal = Scene::new().resolve_refusal(&format!(
        "{tool}[tool.git.network]\ncontain_egress = \"no\""
    ));
    assert!(
        refusal.contains("invalid type: string \"no\", expected a boolean"),
        "{refusal}"
    );
    let refusal = Scene::new().resolve_refusal(&format!(
        "{tool}[tool.git.network]\nwhen = \"macos\"\ncontain_egress = false"
    ));
    assert!(
        refusal.contains("`[tool.git.network]` takes no `when`; put it on the value"),
        "{refusal}"
    );
    let refusal = Scene::new().resolve_refusal(
        "[agent]\ncommand = [\"/usr/bin/true\"]\n[agent.network]\ncontain_egress = false",
    );
    assert!(
        refusal.contains("`[agent]` holds the unknown key `network`"),
        "{refusal}"
    );
}

#[test]
fn no_pack_turns_off_a_tool_network_containment() {
    let agent = "[agent]\ncommand = [\"/usr/bin/true\"]";
    for (pack, text, expected) in [
        (
            "rt",
            crate::lang::test_tool_pack("rt", "[network]\ncontain_egress = false"),
            "a pack holds no `[network]`; a tool's network containment is the operator's choice",
        ),
        (
            "s",
            "[network]\ncontain_egress = false".to_string(),
            "a pack holds no `[network]`; a tool's network containment is the operator's choice",
        ),
        (
            "s",
            "[tool.git.network]\ncontain_egress = false".to_string(),
            "a pack holds no `[tool.git.network]`; a tool's network containment is the operator's \
             choice, so only a profile turns it off",
        ),
        (
            "a",
            "[run]\ncommand = [\"/bin/x\"]\n[tool.git.network]\ncontain_egress = true".to_string(),
            "a pack holds no `[tool.git.network]`",
        ),
    ] {
        let scene = Scene::new();
        scene.share(pack, &text);
        let refusal = scene.resolve_refusal(&format!("packs = [\"@box/{pack}\"]\n{agent}"));
        assert!(refusal.contains(expected), "{pack}: {refusal}");
    }
}

#[test]
fn the_shell_limits_reach_box_toml_and_a_profile_value_beats_the_default_timeout() {
    let agent = "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.read = [\"/usr/bin/true\"]\n";
    for (limits, expected) in [
        ("", Some("[shell]\ntimeout = false")),
        (
            "[limits]\nshell.timeout = 30\n",
            Some("[shell]\ntimeout = 30"),
        ),
        (
            "[limits]\nshell.timeout = 600\n",
            Some("[shell]\ntimeout = 600"),
        ),
        (
            "[limits]\nshell.timeout = 31536000\n",
            Some("[shell]\ntimeout = 31536000"),
        ),
        (
            "[limits.shell]\ntimeout = false\n",
            Some("[shell]\ntimeout = false"),
        ),
        (
            "[limits]\nshell.max_stdin = 1048576\n",
            Some("[shell]\nmax_stdin = 1048576\ntimeout = false"),
        ),
        (
            "[limits.shell]\nmax_stdin = 1\ntimeout = 600\n",
            Some("[shell]\nmax_stdin = 1\ntimeout = 600"),
        ),
        (
            "[limits]\nshell.max_output = 1048576\nshell.max_stdin = 1048576\n",
            Some("[shell]\nmax_output = 1048576\nmax_stdin = 1048576\ntimeout = false"),
        ),
        (
            "[limits]\nshell.max_output = 0\n",
            Some("[shell]\nmax_output = 0\ntimeout = false"),
        ),
        (
            "[limits]\nshell.max_input = 1048576\n",
            Some("[shell]\nmax_input = 1048576\ntimeout = false"),
        ),
        (
            "[limits]\nshell.max_input = 0\nshell.max_output = 0\n",
            Some("[shell]\nmax_input = 0\nmax_output = 0\ntimeout = false"),
        ),
    ] {
        let compiled = Scene::new()
            .compile(&profile(&format!("{agent}{limits}")), None)
            .expect("a compile");
        let expected = expected.map(|text| toml::Value::Table(text.parse().expect("TOML")));
        assert_eq!(
            table(&compiled).get("limits"),
            expected.as_ref(),
            "profile {limits:?}"
        );
    }
}

#[test]
fn the_shell_limits_are_checked_and_no_key_of_a_pack() {
    let scene = Scene::new();
    let agent = "[agent]\ncommand = [\"/usr/bin/true\"]\n";
    for value in [
        "0",
        "-5",
        "1.5",
        "true",
        "\"600\"",
        "31536001",
        "9223372036854775807",
    ] {
        let refusal = scene.resolve_refusal(&format!("{agent}[limits]\nshell.timeout = {value}\n"));
        assert!(
            refusal
                .contains("`limits.shell.timeout` is a whole number of seconds from 1 to 31536000"),
            "{value}: {refusal}"
        );
    }
    for value in ["0", "-1", "1.5", "true", "false", "\"65536\""] {
        let refusal =
            scene.resolve_refusal(&format!("{agent}[limits]\nshell.max_stdin = {value}\n"));
        assert!(
            refusal.contains(
                "`limits.shell.max_stdin` is a whole number of bytes from 1, such as 1048576; \
                 it cannot be turned off"
            ),
            "{value}: {refusal}"
        );
    }
    for key in ["max_input", "max_output"] {
        for value in ["-1", "1.5", "true", "false", "\"65536\""] {
            let refusal =
                scene.resolve_refusal(&format!("{agent}[limits]\nshell.{key} = {value}\n"));
            assert!(
                refusal.contains(&format!(
                    "`limits.shell.{key}` is a whole number of bytes, such as 1048576, or `0` \
                     for no limit"
                )),
                "{key} = {value}: {refusal}"
            );
        }
    }
    for (extra, reason) in [
        ("[limits]\npython.timeout = 60\n", "python"),
        ("[limits]\nshell.memory = 60\n", "memory"),
        (
            "[limits]\nshell = 60\n",
            "`[limits]` holds only `shell.timeout`, `shell.max_input`, `shell.max_stdin`, \
             and `shell.max_output`",
        ),
        (
            "limits = 600\n",
            "`[limits]` holds only `shell.timeout`, `shell.max_input`, `shell.max_stdin`, \
             and `shell.max_output`",
        ),
    ] {
        let text = if extra.starts_with('[') {
            format!("{agent}{extra}")
        } else {
            format!("{extra}{agent}")
        };
        let refusal = scene.resolve_refusal(&text);
        assert!(refusal.contains(reason), "{extra:?}: {refusal}");
    }
    scene.share(
        "kiro",
        "[run]\ncommand = [\"/usr/bin/true\"]\n[limits]\nshell.timeout = 600\n",
    );
    let refusal = scene.resolve_refusal("packs = [\"@box/kiro\"]");
    assert!(
        refusal.contains("a pack holds no `limits`; `limits` belongs in a profile"),
        "{refusal}"
    );
}

#[test]
fn project_access_decides_the_agents_reach_and_the_project_permits() {
    let scene = Scene::new();
    let workspace = scene.workspace().display().to_string();
    let program = real("/usr/bin/true");
    let agent = "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.read = [\"/usr/bin/true\"]\n";
    for (project, read, write, permits) in [
        (
            "[project]\naccess = \"write\"\n",
            vec![workspace.clone(), program.clone()],
            vec![workspace.clone()],
            &[
                "project_read",
                "project_write",
                "project_delete",
                "project_move",
            ][..],
        ),
        (
            "[project]\naccess = \"read\"\n",
            vec![workspace.clone(), program.clone()],
            vec![],
            &["project_read"][..],
        ),
        (
            "[project]\naccess = \"none\"\n",
            vec![program.clone()],
            vec![],
            &[][..],
        ),
        ("", vec![program.clone()], vec![], &[][..]),
        (
            "filesystem.write = [\"${{ workspace }}\"]\n[project]\naccess = \"none\"\n",
            vec![program.clone()],
            vec![workspace.clone()],
            &[][..],
        ),
    ] {
        let compiled = scene
            .compile(&bare_profile(&format!("{agent}{project}")), None)
            .expect("a compile");
        let file = table(&compiled);
        let filesystem = &file["agent"]["filesystem"];
        assert_eq!(
            file["agent"]["workspace"].as_str(),
            Some(workspace.as_str()),
            "{project}"
        );
        assert_eq!(strings(&filesystem["read"]), read, "{project}");
        assert_eq!(
            filesystem.get("write").map(strings).unwrap_or_default(),
            write,
            "{project}"
        );
        assert_eq!(
            strings(&filesystem["deny"]),
            [format!("{workspace}/.box")],
            "{project}"
        );
        let ids: Vec<&str> = compiled
            .generated_ids
            .iter()
            .map(String::as_str)
            .filter(|id| id.starts_with("project_") && !id.starts_with("project_configuration"))
            .collect();
        assert_eq!(ids, permits, "{project}");
        for id in [
            "project_configuration_write",
            "project_configuration_delete",
            "project_configuration_move",
            "box_home_write",
        ] {
            assert!(
                compiled
                    .generated_ids
                    .iter()
                    .any(|generated| generated == id),
                "{project}: {id} in {:?}",
                compiled.generated_ids
            );
        }
    }
}

#[test]
fn a_profile_refuses_a_project_table_it_cannot_read() {
    let scene = Scene::new();
    for (project, reason, at) in [
        (
            "[project]\naccess = \"rw\"\n",
            "`project.access` is one of \"none\", \"read\", \"write\"",
            "access",
        ),
        (
            "[project]\naccess = [\"read\", \"write\"]\n",
            "`project.access` is one of \"none\", \"read\", \"write\"",
            "access",
        ),
        (
            "[project]\naccess = \"read\"\nlocation = \"project\"\n",
            "`[project]` holds the unknown key `location`",
            "location",
        ),
        (
            "[project]\n",
            "`[project]` needs `access`, one of \"none\", \"read\", \"write\"",
            "[project]",
        ),
        (
            "project = \"write\"\n",
            "`[project]` is a table with `access`, one of \"none\", \"read\", \"write\"",
            "project =",
        ),
    ] {
        let text = if project.starts_with('[') {
            format!("{MINIMAL}\n{project}")
        } else {
            format!("{project}{MINIMAL}")
        };
        let line = text
            .lines()
            .position(|line| line.starts_with(at))
            .map(|index| index + 1);
        match scene.resolve(&bare_profile(&text)) {
            Err(Error::Profile {
                reason: found,
                line: found_line,
                ..
            }) => {
                assert!(found.contains(reason), "{project}: {found}");
                assert_eq!(found_line, line, "{project}: {found}");
            }
            other => panic!("{project}: a refusal, not {other:?}"),
        }
    }
    for pack in [
        "[run]\ncommand = [\"/usr/bin/true\"]\n[project]\naccess = \"write\"\n",
        "[project]\naccess = \"write\"\n",
        "kind = \"tool\"\n[inputs.wide.path]\ntype = \"program\"\nprogram = \"wide\"\n\
         search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.wide.path }}\"]\n\
         [project]\naccess = \"write\"\n",
    ] {
        scene.share("wide", pack);
        let refusal = scene.resolve_refusal("packs = [\"@box/wide\"]");
        assert!(
            refusal.contains("a pack holds no `project`; `project` belongs in a profile"),
            "{pack}: {refusal}"
        );
    }
}

#[test]
fn a_profile_reads_its_banner_setting_and_keeps_it_out_of_box_toml() {
    let scene = Scene::new();
    for (text, expected) in [
        (
            format!("{MINIMAL}\n[banner]\nenabled = false\n"),
            Some(false),
        ),
        (format!("{MINIMAL}\n[banner]\nenabled = true\n"), Some(true)),
        (format!("{MINIMAL}\n[banner]\n"), None),
        (MINIMAL.to_string(), None),
    ] {
        let profile = bare_profile(&text);
        assert_eq!(profile.banner(), expected, "{text}");
        let compiled = scene.compile(&profile, None).expect("a compile");
        assert!(table(&compiled).get("banner").is_none(), "{text}");
    }
}

#[test]
fn a_profile_refuses_a_banner_table_it_cannot_read() {
    let scene = Scene::new();
    for (banner, reason, at) in [
        (
            "[banner]\nenabled = \"off\"\n",
            "`banner.enabled` is `true` or `false`",
            "enabled",
        ),
        (
            "[banner]\nenabled = false\nexpanded = true\n",
            "`[banner]` holds the unknown key `expanded`",
            "expanded",
        ),
        (
            "banner = false\n",
            "`[banner]` is a table with `enabled`, `true` or `false`",
            "banner =",
        ),
    ] {
        let text = if banner.starts_with('[') {
            format!("{MINIMAL}\n{banner}")
        } else {
            format!("{banner}{MINIMAL}")
        };
        let line = text
            .lines()
            .position(|line| line.starts_with(at))
            .map(|index| index + 1);
        match Profile::parse(&text, Path::new("test.toml")) {
            Err(Error::Profile {
                reason: found,
                line: found_line,
                ..
            }) => {
                assert!(found.contains(reason), "{banner}: {found}");
                assert_eq!(found_line, line, "{banner}: {found}");
            }
            other => panic!("{banner}: a refusal, not {other:?}"),
        }
    }
    for pack in [
        "[run]\ncommand = [\"/usr/bin/true\"]\n[banner]\nenabled = false\n",
        "[banner]\nenabled = false\n",
        "kind = \"tool\"\n[inputs.wide.path]\ntype = \"program\"\nprogram = \"wide\"\n\
         search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.wide.path }}\"]\n\
         [banner]\nenabled = false\n",
    ] {
        scene.share("wide", pack);
        let refusal = scene.resolve_refusal("packs = [\"@box/wide\"]");
        assert!(
            refusal.contains("a pack holds no `banner`; `banner` belongs in a profile"),
            "{pack}: {refusal}"
        );
    }
}

#[test]
fn every_contained_process_denies_the_project_configuration() {
    let scene = Scene::new();
    let compiled = scene
        .compile(&profile(WITH_TOOL_AND_SERVER), None)
        .expect("a compile");
    let file = table(&compiled);
    let deny = scene.workspace().join(".box").display().to_string();
    for process in [&file["agent"], &file["tool"]["git"], &file["mcp"]["local"]] {
        assert_eq!(
            strings(&process["filesystem"]["deny"]),
            std::slice::from_ref(&deny)
        );
    }
}

#[test]
fn the_policy_forbids_writing_the_project_configuration() {
    let scene = Scene::new();
    let compiled = scene
        .compile(
            &profile(MINIMAL),
            Some("@id(\"mine\") permit (principal, action, resource);\n"),
        )
        .expect("a compile");
    let lines: Vec<&str> = compiled.policy.lines().collect();
    assert_eq!(
        lines[0],
        "@id(\"mine\") permit (principal, action, resource);"
    );
    let configuration = "~/work/project/.box";
    for (action, verb) in [
        ("fs:write", "write"),
        ("fs:delete", "delete"),
        ("fs:move", "move"),
    ] {
        let forbid = lines
            .iter()
            .find(|line| line.starts_with(&format!("@id(\"project_configuration_{verb}\") forbid")))
            .unwrap_or_else(|| panic!("a forbid of {action} in {}", compiled.policy));
        assert!(forbid.contains(&format!("\"{action}\"")), "{forbid}");
        assert!(
            forbid.contains(&format!(
                "context.input.path == \"{configuration}\" || context.input.path like \
                 \"{configuration}/*\""
            )),
            "{forbid}"
        );
    }
    for action in ["fs:read", "fs:write", "fs:delete", "fs:move"] {
        assert!(
            lines.iter().any(|line| line.contains("permit")
                && line.contains(&format!("\"{action}\""))
                && line.contains("\"~/work/project/*\"")),
            "{action}: {}",
            compiled.policy
        );
    }
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("forbid") && line.contains("\"fs:read\"")),
        "reading .box stays the workspace permit's"
    );
}

#[test]
fn the_workspace_placeholder_is_filled_in_in_every_string() {
    let scene = Scene::new();
    let compiled = scene
        .compile(&profile(WITH_TOOL_AND_SERVER), None)
        .expect("a compile");
    assert!(!compiled.box_toml.contains("${{"), "{}", compiled.box_toml);
    let file = table(&compiled);
    let workspace = scene.workspace().display().to_string();
    assert_eq!(
        file["agent"]["env"]["TMPDIR"].as_str(),
        Some(format!("{workspace}/.tmp").as_str())
    );
    assert_eq!(
        strings(&file["tool"]["git"]["filesystem"]["write"]),
        std::slice::from_ref(&workspace)
    );
    assert_eq!(
        file["mcp"]["local"]["env"]["CACHE"].as_str(),
        Some(format!("{workspace}/.cache").as_str())
    );
}

/// The rule that `box` writes with the `@id` `id`, from the `@id` to its `;`.
fn generated_rule<'a>(policy: &'a str, id: &str) -> Option<&'a str> {
    let start = policy.find(&format!("@id({id:?})"))?;
    let end = policy[start..].find(';')? + start;
    Some(&policy[start..=end])
}

/// **A `deny_write` folder in the workspace may hold the agent's programs**, with no switch, when
/// every process that can write the folder protects it. A tool that can write it without its own
/// `deny_write` refuses the run.
#[test]
fn a_program_under_the_agents_deny_write_is_not_under_its_write_grant() {
    let scene = Scene::new();
    let workspace = scene.workspace().display().to_string();
    std::fs::create_dir_all(scene.workspace().join(".venv/bin")).expect("a venv");
    let exec = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.exec = [\"{workspace}/.venv\"]"
    );
    let venv = std::fs::canonicalize(scene.workspace().join(".venv")).expect("a real path");
    let error = scene.compile(&profile(&exec), None).expect_err("a refusal");
    assert!(
        matches!(&error, Error::ProgramUnderWrite { writer, folder, .. }
            if writer == "agent" && *folder == venv),
        "the hint names the exec folder itself, not the folder above it: {error}"
    );

    let protected = format!("{exec}\nfilesystem.deny_write = [\"{workspace}/.venv\"]");
    let compiled = scene
        .compile(&profile(&protected), None)
        .expect("the protected folder runs");
    let config: toml::Table = toml::from_str(&compiled.box_toml).expect("box.toml");
    assert!(
        config.get("experimental-features").is_none(),
        "deny_write needs no switch: {}",
        compiled.box_toml
    );
    assert_eq!(
        config["agent"]["filesystem"]["deny_write"],
        toml::Value::Array(vec![
            std::fs::canonicalize(scene.workspace().join(".venv"))
                .expect("a real path")
                .display()
                .to_string()
                .into()
        ])
    );

    let tool = format!(
        "{protected}\n[tool.x]\ncommand = [\"/usr/bin/true\"]\nfilesystem.read = [\"{workspace}\"]\n\
         filesystem.write = [\"{workspace}\"]"
    );
    let error = scene
        .compile(&profile(&tool), None)
        .expect_err("the tool can write the folder");
    assert!(
        matches!(&error, Error::ProgramUnderWrite { writer, .. } if writer == "tool.x"),
        "{error}"
    );
    assert!(
        error.to_string().contains(&format!(
            "list {} in your profile's `[filesystem] deny_write`",
            venv.display()
        )),
        "{error}"
    );

    let protected_tool = format!(
        "{tool}
filesystem.deny_write = [\"{workspace}/.venv\"]"
    );
    let compiled = scene
        .compile(&profile(&protected_tool), None)
        .expect("every writer protects the folder");
    let config: toml::Table = toml::from_str(&compiled.box_toml).expect("box.toml");
    assert_eq!(
        config["tool"]["x"]["filesystem"]["deny_write"],
        config["agent"]["filesystem"]["deny_write"],
        "{}",
        compiled.box_toml
    );
}

/// **A stdio MCP server that can write the agent's program folder protects it too**: without its
/// own `deny_write` the run is refused and names the server's table, and with it the profile
/// compiles and keeps the entry.
#[test]
fn a_stdio_mcp_server_that_can_write_a_program_folder_needs_its_own_deny_write() {
    let scene = Scene::new();
    let workspace = scene.workspace().display().to_string();
    std::fs::create_dir_all(scene.workspace().join(".venv/bin")).expect("a venv");
    let venv = std::fs::canonicalize(scene.workspace().join(".venv")).expect("a real path");
    let server = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.exec = [\"{workspace}/.venv\"]\n\
         filesystem.deny_write = [\"{workspace}/.venv\"]\n\
         [mcp.local]\ntype = \"stdio\"\ncommand = [\"/usr/bin/true\"]\n\
         filesystem.read = [\"{workspace}\"]\nfilesystem.write = [\"{workspace}\"]"
    );
    let error = scene
        .compile(&profile(&server), None)
        .expect_err("the server can write the folder");
    assert!(
        matches!(&error, Error::ProgramUnderWrite { writer, folder, .. }
            if writer == "mcp.local" && *folder == venv),
        "{error}"
    );
    assert!(
        error.to_string().contains(&format!(
            "list {} in your profile's `[filesystem] deny_write`",
            venv.display()
        )),
        "{error}"
    );

    let protected = format!("{server}\nfilesystem.deny_write = [\"{workspace}/.venv\"]");
    let compiled = scene
        .compile(&profile(&protected), None)
        .expect("every writer protects the folder");
    let config: toml::Table = toml::from_str(&compiled.box_toml).expect("box.toml");
    assert_eq!(
        config["mcp"]["local"]["filesystem"]["deny_write"],
        toml::Value::Array(vec![venv.display().to_string().into()]),
        "{}",
        compiled.box_toml
    );
}

/// **A `deny_write` that covers only part of an `exec` folder leaves it writable**, so the run is
/// refused.
#[test]
fn a_deny_write_on_part_of_an_exec_folder_is_refused() {
    let scene = Scene::new();
    let workspace = scene.workspace().display().to_string();
    std::fs::create_dir_all(scene.workspace().join(".venv/bin")).expect("a venv");
    let text = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.exec = [\"{workspace}/.venv\"]\n\
         filesystem.deny_write = [\"{workspace}/.venv/bin\"]"
    );
    let error = scene
        .compile(&profile(&text), None)
        .expect_err("the rest of the exec folder is writable");
    assert!(
        matches!(&error, Error::ProgramUnderWrite { writer, .. } if writer == "agent"),
        "{error}"
    );
}

/// **Each `deny_write` folder is forbidden to the Shell and Monty**: `box` writes a `forbid` on
/// `fs:write`, `fs:delete`, and `fs:move` below it, because they run outside the cage.
#[test]
fn a_deny_write_folder_is_forbidden_to_the_shell_and_monty() {
    let scene = Scene::new();
    let workspace = scene.workspace().display().to_string();
    std::fs::create_dir_all(scene.workspace().join(".venv/bin")).expect("a venv");
    let text = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.exec = [\"{workspace}/.venv\"]\n\
         filesystem.deny_write = [\"{workspace}/.venv\"]"
    );
    let compiled = scene.compile(&profile(&text), None).expect("the venv runs");
    for (id, action) in [
        ("deny_write_write_0", "fs:write"),
        ("deny_write_delete_0", "fs:delete"),
        ("deny_write_move_0", "fs:move"),
    ] {
        let rule = generated_rule(&compiled.policy, id)
            .unwrap_or_else(|| panic!("{id}: {}", compiled.policy));
        assert!(
            rule.contains(&format!(
                "forbid (principal, action == Box::Action::{action:?}"
            )) && rule.contains("/.venv\"")
                && rule.contains("/.venv/*\"")
                && rule.contains(
                    "@description(\"A deny_write entry in the profile or a pack keeps this folder \
                     read-only.\")"
                ),
            "{rule}"
        );
        assert!(
            compiled.generated_ids.iter().any(|known| known == id),
            "{id}"
        );
        assert!(
            !compiled.box_forbids.contains(&format!("@id({id:?})")),
            "policy off lifts a profile's deny_write: {}",
            compiled.box_forbids
        );
    }
    assert!(
        compiled.box_forbids.contains("@id(\"box_home_write\")"),
        "{}",
        compiled.box_forbids
    );
    assert!(
        !compiled.policy.contains("deny_write_parent"),
        "the workspace is the only folder above .venv: {}",
        compiled.policy
    );
}

/// **A nested `deny_write` folder's parents cannot be moved or deleted** through the Shell or
/// Monty, up to its write grant, so its path cannot change.
#[test]
fn the_folders_above_a_nested_deny_write_folder_cannot_be_moved() {
    let scene = Scene::new();
    let workspace = scene.workspace().display().to_string();
    std::fs::create_dir_all(scene.workspace().join("services/api/.venv")).expect("a nested venv");
    let text = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\n\
         filesystem.deny_write = [\"{workspace}/services/api/.venv\"]"
    );
    let compiled = scene
        .compile(&profile(&text), None)
        .expect("the nested venv runs");
    for (id, action) in [
        ("deny_write_parent_move_0", "fs:move"),
        ("deny_write_parent_delete_0", "fs:delete"),
    ] {
        let rule = generated_rule(&compiled.policy, id)
            .unwrap_or_else(|| panic!("{id}: {}", compiled.policy));
        assert!(
            rule.contains(&format!(
                "forbid (principal, action == Box::Action::{action:?}"
            )) && rule.contains("/services/api\"")
                && rule.contains("/services\"")
                && !rule.contains(" like "),
            "{rule}"
        );
        assert!(
            compiled.generated_ids.iter().any(|known| known == id),
            "{id}"
        );
    }
}

/// **A tool's or MCP server's `deny_write` folder that its own write grants do not reach is dropped**,
/// so a profile can list the folder on every tool, including one that cannot write the project.
#[test]
fn a_tool_deny_write_outside_its_write_grants_is_dropped() {
    let scene = Scene::new();
    let workspace = scene.workspace().display().to_string();
    std::fs::create_dir_all(scene.workspace().join(".venv")).expect("a folder");
    let text = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\n\
         [tool.reader]\ncommand = [\"/usr/bin/true\"]\nfilesystem.read = [\"{workspace}\"]\n\
         filesystem.deny_write = [\"{workspace}/.venv\"]\n\
         [mcp.local]\ntype = \"stdio\"\ncommand = [\"/usr/bin/true\"]\n\
         filesystem.read = [\"{workspace}\"]\nfilesystem.deny_write = [\"{workspace}/.venv\"]"
    );
    let compiled = scene
        .compile(&profile(&text), None)
        .expect("the profile compiles");
    let config: toml::Table = toml::from_str(&compiled.box_toml).expect("box.toml");
    assert!(
        config["tool"]["reader"]["filesystem"]
            .get("deny_write")
            .is_none(),
        "{}",
        compiled.box_toml
    );
    assert!(
        config["mcp"]["local"]["filesystem"]
            .get("deny_write")
            .is_none(),
        "{}",
        compiled.box_toml
    );
}

/// **A `deny_write` folder that no agent write grant reaches is dropped**, with its rules,
/// because it protects nothing there and Box Core refuses it.
#[test]
fn a_deny_write_folder_outside_every_write_grant_is_dropped() {
    let scene = Scene::new();
    let outside = scene.root.join("envs/proj");
    std::fs::create_dir_all(outside.join("bin")).expect("a venv outside the project");
    let outside = outside.display().to_string();
    let text = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.exec = [\"{outside}\"]\n\
         filesystem.deny_write = [\"{outside}\"]"
    );
    let compiled = scene.compile(&profile(&text), None).expect("the venv runs");
    let config: toml::Table = toml::from_str(&compiled.box_toml).expect("box.toml");
    assert!(
        config["agent"]["filesystem"].get("deny_write").is_none(),
        "{}",
        compiled.box_toml
    );
    assert!(
        config.get("experimental-features").is_none(),
        "{}",
        compiled.box_toml
    );
    assert!(
        !compiled.policy.contains("deny_write"),
        "{}",
        compiled.policy
    );
}

/// **A `deny_write` on a tool alone reaches `box.toml` with no switch**, and a `deny_write` entry that
/// names a file is refused before Box Core sees it.
#[test]
fn a_tool_deny_write_reaches_box_toml_and_a_file_entry_is_refused() {
    let scene = Scene::new();
    let workspace = scene.workspace().display().to_string();
    std::fs::create_dir_all(scene.workspace().join("vendor")).expect("a folder");
    std::fs::write(scene.workspace().join("vendor/lib.py"), "").expect("a file");
    let tool = |entry: &str| {
        format!(
            "[agent]\ncommand = [\"/usr/bin/true\"]\n[tool.x]\ncommand = [\"/usr/bin/true\"]\n\
             filesystem.read = [\"{workspace}\"]\nfilesystem.write = [\"{workspace}\"]\n\
             filesystem.deny_write = [\"{workspace}/{entry}\"]"
        )
    };
    let compiled = scene
        .compile(&profile(&tool("vendor")), None)
        .expect("a tool protects a folder");
    let config: toml::Table = toml::from_str(&compiled.box_toml).expect("box.toml");
    assert_eq!(
        config["tool"]["x"]["filesystem"]["deny_write"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "{}",
        compiled.box_toml
    );
    assert!(
        config.get("experimental-features").is_none(),
        "deny_write needs no switch: {}",
        compiled.box_toml
    );
    let error = scene
        .compile(&profile(&tool("vendor/lib.py")), None)
        .expect_err("a file entry");
    assert!(error.to_string().contains("is not a folder"), "{error}");
    let error = scene
        .compile(
            &profile(&format!(
                "[agent]\ncommand = [\"/usr/bin/true\"]\n\
                 filesystem.deny_write = [\"{workspace}/vendor/lib.py\"]"
            )),
            None,
        )
        .expect_err("an agent file entry");
    assert!(error.to_string().contains("is not a folder"), "{error}");
    let error = scene
        .compile(
            &profile(&format!(
                "[agent]\ncommand = [\"/usr/bin/true\"]\n[mcp.local]\ntype = \"stdio\"\n\
                 command = [\"/usr/bin/true\"]\nfilesystem.read = [\"{workspace}\"]\n\
                 filesystem.write = [\"{workspace}\"]\n\
                 filesystem.deny_write = [\"{workspace}/vendor/lib.py\"]"
            )),
            None,
        )
        .expect_err("an MCP server file entry");
    assert!(
        error.to_string().contains("[mcp.local.filesystem]"),
        "{error}"
    );
}

/// **A profile's `[filesystem] deny_write` reaches every process that can write the folder**: the
/// agent, a tool and a detected MCP server that `[project] access = "write"` lets write the
/// workspace, and not a tool that cannot write it. So one list lets a program in the folder run.
#[test]
fn a_profile_deny_write_reaches_every_process_that_can_write_it() {
    let (scene, bin) = servers_scene();
    std::fs::copy("/usr/bin/true", bin.join("git")).expect("a program");
    std::fs::create_dir_all(scene.workspace().join(".venv/bin")).expect("a venv");
    std::fs::write(
        scene.home().join(".agent.json"),
        serde_json::json!({"mcpServers": {"fetch": {"command": "fetcher"}}}).to_string(),
    )
    .expect("a host file");
    let processes = "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
                     filesystem.exec = [\"${{ workspace }}/.venv\"]\n";
    let tools = "[tool.git]\nprogram = \"git\"\n\
                 [tool.reader]\ncommand = [\"/usr/bin/true\"]\n\
                 filesystem.read = [\"${{ workspace }}\"]\n";
    let agent_only =
        format!("{processes}filesystem.deny_write = [\"${{{{ workspace }}}}/.venv\"]\n{tools}");
    let error = scene
        .compile_using(
            &profile(&agent_only),
            &mut OnPath(bin.clone()),
            "/usr/bin:/bin",
        )
        .expect_err("the tool and the MCP server can write the folder");
    assert!(
        matches!(&error, Error::ProgramUnderWrite { writer, .. } if writer != "agent"),
        "{error}"
    );

    let everywhere =
        format!("{processes}{tools}[filesystem]\ndeny_write = [\"${{{{ workspace }}}}/.venv\"]\n");
    let (_, compiled) = scene
        .compile_using(&profile(&everywhere), &mut OnPath(bin), "/usr/bin:/bin")
        .expect("one list protects the folder in every process");
    let config = table(&compiled);
    let venv = toml::Value::Array(vec![
        std::fs::canonicalize(scene.workspace().join(".venv"))
            .expect("a real path")
            .display()
            .to_string()
            .into(),
    ]);
    assert_eq!(config["agent"]["filesystem"]["deny_write"], venv);
    assert_eq!(config["tool"]["git"]["filesystem"]["deny_write"], venv);
    assert_eq!(config["mcp"]["fetch"]["filesystem"]["deny_write"], venv);
    assert!(
        config["tool"]["reader"]["filesystem"]
            .get("deny_write")
            .is_none(),
        "a tool that cannot write the folder gets no entry: {}",
        compiled.box_toml
    );
    assert!(
        config.get("filesystem").is_none(),
        "the profile-wide list is not a Box Core table: {}",
        compiled.box_toml
    );
    for id in [
        "deny_write_write_0",
        "deny_write_delete_0",
        "deny_write_move_0",
    ] {
        assert!(
            generated_rule(&compiled.policy, id).is_some_and(|rule| rule.contains("/.venv\"")),
            "{id}: {}",
            compiled.policy
        );
    }
}

/// **A profile-wide `deny_write` keeps each process's own entries, reaches an authored stdio MCP
/// server, and follows `when`** on its table and on each entry.
#[test]
fn a_profile_deny_write_joins_each_process_list_and_follows_when() {
    let scene = Scene::new();
    let workspace = scene.workspace().display().to_string();
    for folder in [".venv", "vendor", "linux-only"] {
        std::fs::create_dir_all(scene.workspace().join(folder)).expect("a folder");
    }
    let real = |folder: &str| {
        std::fs::canonicalize(scene.workspace().join(folder))
            .expect("a real path")
            .display()
            .to_string()
    };
    let processes = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.deny_write = [\"{workspace}/vendor\"]\n\
         [mcp.local]\ntype = \"stdio\"\ncommand = [\"/usr/bin/true\"]\n\
         filesystem.read = [\"{workspace}\"]\nfilesystem.write = [\"{workspace}\"]\n"
    );
    let text = format!(
        "{processes}[filesystem]\ndeny_write = [\"{workspace}/.venv\", \
         {{ path = \"{workspace}/linux-only\", when = \"linux\" }}]\n"
    );
    let compiled = scene.compile(&profile(&text), None).expect("a compile");
    let config = table(&compiled);
    assert_eq!(
        strings(&config["agent"]["filesystem"]["deny_write"]),
        [real("vendor"), real(".venv")],
        "{}",
        compiled.box_toml
    );
    assert_eq!(
        strings(&config["mcp"]["local"]["filesystem"]["deny_write"]),
        [real(".venv")],
        "{}",
        compiled.box_toml
    );

    let listed = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.deny_write = [\"{workspace}/.venv\"]\n\
         [mcp.local]\ntype = \"stdio\"\ncommand = [\"/usr/bin/true\"]\n\
         filesystem.read = [\"{workspace}\"]\nfilesystem.write = [\"{workspace}\"]\n\
         filesystem.deny_write = [\"{workspace}/.venv\"]\n\
         [tool.x]\ncommand = [\"/usr/bin/true\"]\n\
         filesystem.read = [\"{workspace}\"]\nfilesystem.write = [\"{workspace}\"]\n\
         filesystem.deny_write = [\"{workspace}/.venv\"]\n\
         [filesystem]\ndeny_write = [\"{workspace}/.venv\"]\n"
    );
    let compiled = scene.compile(&profile(&listed), None).expect("a compile");
    let config = table(&compiled);
    for process in [
        &config["agent"],
        &config["tool"]["x"],
        &config["mcp"]["local"],
    ] {
        assert_eq!(
            strings(&process["filesystem"]["deny_write"]),
            [real(".venv")],
            "a folder a process lists itself is not listed twice: {}",
            compiled.box_toml
        );
    }

    let off = format!(
        "{processes}[filesystem]\nwhen = \"linux\"\ndeny_write = [\"{workspace}/.venv\"]\n"
    );
    let compiled = scene.compile(&profile(&off), None).expect("a compile");
    let config = table(&compiled);
    assert_eq!(
        strings(&config["agent"]["filesystem"]["deny_write"]),
        [real("vendor")],
        "{}",
        compiled.box_toml
    );
    assert!(
        config["mcp"]["local"]["filesystem"]
            .get("deny_write")
            .is_none(),
        "{}",
        compiled.box_toml
    );
}

/// The `@description` on each rule that a profile's `[filesystem] deny` writes.
const DENY_DESCRIPTION: &str =
    "@description(\"The profile's [filesystem] deny keeps this path out of the box.\")";

/// **A profile's `[filesystem] deny` reaches every process**: the agent, each tool, and each stdio
/// MCP server, detected ones included. `box` also forbids the Shell and Monty every read and change
/// of the path, and a move or delete of each folder between it and the agent's write grant.
#[test]
fn a_profile_deny_reaches_every_process_and_the_shell() {
    let (scene, bin) = servers_scene();
    std::fs::create_dir_all(scene.workspace().join("secrets/keys")).expect("a folder");
    std::fs::write(
        scene.home().join(".agent.json"),
        serde_json::json!({"mcpServers": {"fetch": {"command": "fetcher"}}}).to_string(),
    )
    .expect("a host file");
    let text = "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
                [tool.reader]\ncommand = [\"/usr/bin/true\"]\n\
                [mcp.local]\ntype = \"stdio\"\ncommand = [\"/usr/bin/true\"]\n\
                [filesystem]\ndeny = [\"${{ workspace }}/secrets/keys\"]\n";
    let (_, compiled) = scene
        .compile_using(&profile(text), &mut OnPath(bin), "/usr/bin:/bin")
        .expect("a compile");
    let config = table(&compiled);
    let keys = std::fs::canonicalize(scene.workspace().join("secrets/keys"))
        .expect("a real path")
        .display()
        .to_string();
    for (name, process) in [
        ("agent", &config["agent"]),
        ("tool.reader", &config["tool"]["reader"]),
        ("mcp.local", &config["mcp"]["local"]),
        ("mcp.fetch", &config["mcp"]["fetch"]),
    ] {
        assert!(
            strings(&process["filesystem"]["deny"]).contains(&keys),
            "{name}: {}",
            compiled.box_toml
        );
    }
    assert!(config.get("filesystem").is_none(), "{}", compiled.box_toml);
    for (id, action) in [
        ("filesystem_deny_read_0", "fs:read"),
        ("filesystem_deny_write_0", "fs:write"),
        ("filesystem_deny_delete_0", "fs:delete"),
        ("filesystem_deny_move_0", "fs:move"),
    ] {
        let rule = generated_rule(&compiled.policy, id)
            .unwrap_or_else(|| panic!("{id}: {}", compiled.policy));
        assert!(
            rule.contains(&format!(
                "forbid (principal, action == Box::Action::{action:?}"
            )) && rule.contains("/secrets/keys\"")
                && rule.contains("/secrets/keys/*\"")
                && rule.contains(DENY_DESCRIPTION),
            "{rule}"
        );
        assert!(
            compiled.generated_ids.iter().any(|known| known == id),
            "{id}"
        );
        assert!(
            !compiled.box_forbids.contains(&format!("@id({id:?})")),
            "policy off lifts a profile's deny: {}",
            compiled.box_forbids
        );
    }
    assert!(
        compiled
            .box_forbids
            .contains("@id(\"project_configuration_write\")"),
        "{}",
        compiled.box_forbids
    );
    for id in [
        "filesystem_deny_parent_move_0",
        "filesystem_deny_parent_delete_0",
    ] {
        let rule = generated_rule(&compiled.policy, id)
            .unwrap_or_else(|| panic!("{id}: {}", compiled.policy));
        assert!(
            rule.contains("/secrets\"")
                && !rule.contains(" like ")
                && rule.contains(DENY_DESCRIPTION),
            "{rule}"
        );
    }
}

/// **An `optional` profile-wide `deny` or `deny_write` entry is dropped in a project without the folder**, so
/// one profile runs in every project, and it reaches each process in a project that has it.
#[test]
fn an_optional_profile_deny_and_deny_write_entry_follows_the_folder() {
    let scene = Scene::new();
    let workspace = scene.workspace().display().to_string();
    let text = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\n\
         [filesystem]\ndeny_write = [{{ path = \"{workspace}/.venv\", optional = true }}]\n\
         deny = [{{ path = \"{workspace}/keys\", optional = true }}]\n"
    );
    let compiled = scene
        .compile(&profile(&text), None)
        .expect("a project without the folder runs");
    assert!(
        table(&compiled)["agent"]["filesystem"]
            .get("deny_write")
            .is_none(),
        "{}",
        compiled.box_toml
    );
    assert!(
        !compiled.policy.contains("deny_write"),
        "{}",
        compiled.policy
    );

    assert!(
        !strings(&table(&compiled)["agent"]["filesystem"]["deny"])
            .iter()
            .any(|entry| entry.ends_with("/keys")),
        "{}",
        compiled.box_toml
    );
    std::fs::create_dir_all(scene.workspace().join(".venv")).expect("a venv");
    std::fs::create_dir_all(scene.workspace().join("keys")).expect("a folder");
    let compiled = scene
        .compile(&profile(&text), None)
        .expect("a project with the folder runs");
    assert_eq!(
        strings(&table(&compiled)["agent"]["filesystem"]["deny_write"]),
        [std::fs::canonicalize(scene.workspace().join(".venv"))
            .expect("a real path")
            .display()
            .to_string()],
        "{}",
        compiled.box_toml
    );
    let keys = std::fs::canonicalize(scene.workspace().join("keys"))
        .expect("a real path")
        .display()
        .to_string();
    assert!(
        strings(&table(&compiled)["agent"]["filesystem"]["deny"]).contains(&keys),
        "{}",
        compiled.box_toml
    );
    assert!(
        compiled.policy.contains("@id(\"filesystem_deny_read_0\")"),
        "{}",
        compiled.policy
    );
}

/// **A profile-wide `deny_write` entry that names a file is refused**, and the refusal names
/// `[filesystem] deny_write`, where the operator wrote it.
#[test]
fn a_profile_deny_write_file_entry_is_refused_where_it_is_written() {
    let scene = Scene::new();
    let workspace = scene.workspace().display().to_string();
    std::fs::write(scene.workspace().join("lib.py"), "").expect("a file");
    let error = scene
        .compile(
            &profile(&format!(
                "[agent]\ncommand = [\"/usr/bin/true\"]\n\
                 [filesystem]\ndeny_write = [\"{workspace}/lib.py\"]"
            )),
            None,
        )
        .expect_err("a file entry");
    assert!(
        matches!(&error, Error::Profile { path, .. } if path == Path::new("[filesystem] deny_write")),
        "{error}"
    );
    assert!(error.to_string().contains("is not a folder"), "{error}");
    let error = scene
        .compile(
            &profile(&format!(
                "[agent]\ncommand = [\"/usr/bin/true\"]\n\
                 [mcp.local]\ntype = \"stdio\"\ncommand = [\"/usr/bin/true\"]\n\
                 filesystem.deny_write = \"x\"\n\
                 [filesystem]\ndeny_write = [\"{workspace}\"]"
            )),
            None,
        )
        .expect_err("an MCP server's deny_write that is not a list");
    assert!(
        matches!(&error, Error::Profile { path, reason, .. }
            if path == Path::new("[mcp.local]") && reason == "`filesystem.deny_write` is not a list"),
        "{error}"
    );
}

/// **A profile's `[filesystem]` holds only `deny` and `deny_write`**: a grant there would reach no process,
/// so `box` names where it goes.
#[test]
fn a_profile_filesystem_holds_only_deny_and_deny_write() {
    let scene = Scene::new();
    let refused = |table: &str| {
        scene.resolve_refusal(&format!(
            "[agent]\ncommand = [\"/bin/x\"]\n[filesystem]\n{table}"
        ))
    };
    for (key, tables) in [
        (
            "read",
            "`[agent.filesystem]` or a `[tool.<name>.filesystem]` table",
        ),
        (
            "write",
            "`[agent.filesystem]` or a `[tool.<name>.filesystem]` table",
        ),
        (
            "read_file",
            "`[agent.filesystem]` or a `[tool.<name>.filesystem]` table",
        ),
        ("exec", "`[agent.filesystem]`"),
        ("metadata", "`[agent.filesystem]`"),
    ] {
        let reason = refused(&format!("{key} = [\"/x\"]"));
        assert!(
            reason.ends_with(&format!(
                "a profile's `[filesystem]` holds only `deny` and `deny_write`, for every \
                 process; write `{key}` in {tables}"
            )),
            "{key}: {reason}"
        );
    }
    let reason = refused("deny-write = [\"/x\"]");
    assert!(
        reason.contains("`[filesystem]` holds the unknown key `deny-write`")
            && reason.contains("did you mean `deny_write`?"),
        "{reason}"
    );
    let reason = scene.resolve_refusal("filesystem = \"x\"\n[agent]\ncommand = [\"/bin/x\"]");
    assert!(
        reason.contains("`[filesystem]` is a table with `deny` and `deny_write`, lists of paths"),
        "{reason}"
    );
    scene
        .resolve(&profile(
            "[agent]\ncommand = [\"/bin/x\"]\n[filesystem]\ndeny_write = [\"/x\"]\ndeny = [\"/y\"]",
        ))
        .expect("deny and deny_write are a profile's keys");
}

#[test]
fn a_program_under_a_write_grant_is_refused() {
    let scene = Scene::new();
    let workspace = scene.workspace().display().to_string();
    let tools = scene.root.join("tools");
    std::fs::create_dir_all(&tools).expect("a directory");
    let tools = tools.display().to_string();
    std::fs::write(scene.workspace().join("agent.js"), "").expect("a script");
    for text in [
        format!("[agent]\ncommand = [\"{workspace}/bin/agent\"]"),
        "[agent]\ncommand = [\"${{ workspace }}/bin/agent\"]".to_string(),
        format!(
            "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.exec = [\"{workspace}/run.sh\"]"
        ),
        format!("[agent]\ncommand = [\"true\"]\nenv.PATH = \"{workspace}/bin:/usr/bin\""),
        format!(
            "[agent]\ncommand = [\"/usr/bin/true\"]\n[tool.x]\ncommand = [\"{tools}/x\"]\n\
             filesystem.write = [\"{tools}\"]"
        ),
        format!("[agent]\ncommand = [\"/usr/bin/true\", \"{workspace}/agent.js\"]"),
        format!(
            "[agent]\ncommand = [\"/usr/bin/true\"]\n[tool.x]\n\
             command = [\"/usr/bin/true\", \"~/work/{name}/agent.js\"]",
            name = scene.workspace
        ),
    ] {
        let error = scene.compile(&profile(&text), None).expect_err("a refusal");
        assert!(
            matches!(error, Error::ProgramUnderWrite { .. }),
            "{text}: {error}"
        );
    }
    let error = scene
        .compile_in(
            &scene.workspace(),
            &profile("[agent]\ncommand = [\"agent\"]"),
            None,
            &format!("{workspace}/node_modules/.bin:/usr/bin"),
        )
        .expect_err("the operator's PATH is searched when env.PATH is absent");
    assert!(matches!(error, Error::ProgramUnderWrite { .. }), "{error}");
    let link = scene.root.join("link-to-workspace");
    std::os::unix::fs::symlink(scene.workspace(), &link).expect("a link");
    let error = scene
        .compile(
            &profile(&format!(
                "[agent]\ncommand = [\"{}/agent\"]",
                link.display()
            )),
            None,
        )
        .expect_err("a link into the workspace resolves");
    assert!(matches!(error, Error::ProgramUnderWrite { .. }), "{error}");
}

#[test]
fn an_exec_folder_that_holds_a_write_grant_is_refused() {
    let scene = Scene::new();
    let workspace = scene.workspace();
    let parent = workspace.parent().expect("a parent").display().to_string();
    let text = format!("[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.exec = [\"{parent}\"]");
    match scene.compile(&profile(&text), None).expect_err("a refusal") {
        Error::WriteUnderExec { exec, grant } => {
            assert!(grant.starts_with(&exec), "{exec:?} {grant:?}");
            assert!(grant.ends_with(&scene.workspace), "{grant:?}");
        }
        other => panic!("{other}"),
    }
}

#[test]
fn a_write_grant_over_box_state_is_refused() {
    let scene = Scene::new();
    let home = scene.home().display().to_string();
    for grant in [
        format!("{home}/.strands/box/profiles"),
        format!("{home}/.strands/box/r/x"),
        "~/.strands/box".to_string(),
        "~/.strands".to_string(),
        home.clone(),
    ] {
        let text = format!(
            "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.write_file = [\"{grant}\"]"
        );
        let error = scene.compile(&profile(&text), None).expect_err("a refusal");
        assert!(
            matches!(error, Error::WriteOverProtected { .. }),
            "{grant}: {error}"
        );
    }
    let parent = scene.home().join("work");
    let inside = scene.home().join(".strands/box/profiles");
    std::fs::create_dir_all(&inside).expect("a directory");
    let error = scene
        .compile_in(&inside, &profile(MINIMAL), None, "/usr/bin:/bin")
        .expect_err("a workspace in the box home");
    assert!(matches!(error, Error::WriteOverProtected { .. }), "{error}");
    scene
        .compile_in(&parent, &profile(MINIMAL), None, "/usr/bin:/bin")
        .expect("a workspace beside the box home");
    scene
        .compile(
            &profile(
                "[agent]\ncommand = [\"/usr/bin/true\"]\n\
                 filesystem.write = [\"~/.strands/another-tool\"]",
            ),
            None,
        )
        .expect("a write grant for another Strands tool's own directory");
}

#[test]
fn a_mistyped_server_filesystem_is_refused() {
    let scene = Scene::new();
    for filesystem in ["filesystem = \"x\"", "filesystem.deny = \"x\""] {
        let text = format!(
            "[agent]\ncommand = [\"/usr/bin/true\"]\n[mcp.m]\ntype = \"stdio\"\n\
             command = [\"true\"]\n{filesystem}"
        );
        let error = scene.compile(&profile(&text), None).expect_err("a refusal");
        assert!(
            matches!(error, Error::Profile { .. }),
            "{filesystem}: {error}"
        );
    }
}

#[test]
fn a_server_program_is_checked_against_the_operators_path() {
    let scene = Scene::new();
    let workspace = scene.workspace().display().to_string();
    let error = scene
        .compile_in(
            &scene.workspace(),
            &profile(
                "[agent]\ncommand = [\"/usr/bin/true\"]\nenv.PATH = \"/usr/bin\"\n\
                 [mcp.m]\ntype = \"stdio\"\ncommand = [\"server\"]\nenv.PATH = \"/usr/bin\"",
            ),
            None,
            &format!("{workspace}/bin:/usr/bin"),
        )
        .expect_err("the engine resolves a server on the operator's PATH");
    assert!(matches!(error, Error::ProgramUnderWrite { .. }), "{error}");
}

#[test]
fn a_workspace_that_holds_the_home_is_refused() {
    let scene = Scene::new();
    for workspace in [scene.home(), scene.root.clone()] {
        let error = scene
            .compile_in(&workspace, &profile(MINIMAL), None, "/usr/bin:/bin")
            .expect_err("a refusal");
        assert!(matches!(error, Error::ProjectHoldsHome { .. }), "{error}");
    }
}

#[test]
fn a_workspace_that_holds_the_run_is_refused() {
    let scene = Scene::new();
    let workspace = scene.home().join(".strands/box");
    std::fs::create_dir_all(&workspace).expect("a directory");
    let error = scene
        .compile_in(&workspace, &profile(MINIMAL), None, "/usr/bin:/bin")
        .expect_err("a refusal");
    assert!(matches!(error, Error::ProjectHoldsBox { .. }), "{error}");
}

#[test]
fn a_quote_or_a_star_in_the_workspace_permits_nothing_else() {
    let scene = Scene::with_workspace("a\"b*c");
    let compiled = scene.compile(&profile(MINIMAL), None).expect("a compile");
    let file = table(&compiled);
    assert_eq!(
        file["agent"]["workspace"].as_str(),
        scene.workspace().to_str()
    );
    assert!(
        compiled
            .policy
            .contains(r#"context.input.path like "~/work/a\"b\*c/*""#),
        "{}",
        compiled.policy
    );
    assert!(
        compiled
            .policy
            .contains(r#"context.input.path like "~/work/a\"b\*c/.box/*""#),
        "{}",
        compiled.policy
    );
}

#[test]
fn the_records_go_to_the_runs_own_file() {
    let scene = Scene::new();
    let compiled = scene
        .compile(
            &profile(
                "[agent]\ncommand = [\"/usr/bin/true\"]\n\
                 [telemetry.otlp]\nkind = \"otlp\"\ndestination = \"http://localhost:4318\"",
            ),
            None,
        )
        .expect("a compile");
    let file = table(&compiled);
    let journal = scene.instance().directory.join("records.jsonl");
    assert_eq!(compiled.journal, journal);
    let records = &file["telemetry"]["records"];
    assert_eq!(records["kind"].as_str(), Some("file"));
    assert_eq!(records["destination"].as_str(), journal.to_str());
    assert_eq!(
        strings(&records["include"]),
        ["deny", "permit", "trace", "logs"]
    );
    assert_eq!(file["telemetry"]["otlp"]["kind"].as_str(), Some("otlp"));
    let reason = scene.refusal(
        "[agent]\ncommand = [\"/bin/x\"]\n[telemetry.records]\nkind = \"file\"\n\
         destination = \"/tmp/x\"",
    );
    assert!(reason.contains("telemetry.records"), "{reason}");
}

#[test]
fn a_clean_of_every_box_keeps_a_box_that_is_starting() {
    let scene = Scene::new();
    let launcher = Launcher::from_host().home(scene.home());
    let (instance, _claim) =
        mint_claimed(&launcher.runs_root(), "claude", &scene.home()).expect("an instance");

    assert_eq!(
        cleaned(&launcher),
        Cleaned {
            removed: 0,
            running: vec![instance.name.clone()]
        }
    );
    assert!(instance.box_directory.is_dir(), "the starting box stays");
}

#[test]
fn each_run_gets_its_own_name_directory_and_box_dir() {
    let scene = Scene::new();
    let runs = scene.home().join(".strands/box/r");
    let instances: Vec<Instance> = (0..3)
        .map(|_| mint(&runs, "claude", &scene.home()).expect("an instance"))
        .collect();
    for (index, instance) in instances.iter().enumerate() {
        assert_eq!(instance.name.len(), 18, "{}", instance.name);
        assert!(
            instance
                .name
                .strip_prefix("b-")
                .expect("the box ID prefix")
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "{}",
            instance.name
        );
        assert_eq!(instance.directory, runs.join(&instance.name));
        assert_eq!(instance.box_directory, instance.directory.join("box"));
        for directory in [&instance.directory, &instance.box_directory] {
            let mode = std::fs::metadata(directory)
                .expect("stat")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "{}", directory.display());
        }
        assert!(
            std::fs::read_dir(&instance.box_directory)
                .expect("list")
                .next()
                .is_none()
        );
        for other in &instances[index + 1..] {
            assert_ne!(instance.name, other.name);
        }
    }
}

#[test]
fn a_long_profile_name_does_not_lengthen_the_box_id() {
    let scene = Scene::new();
    let name = "a-profile-name-far-longer-than-a-box-name-allows";
    let instance =
        mint(&scene.home().join(".strands/box/r"), name, &scene.home()).expect("an instance");
    assert_eq!(instance.name.len(), 18, "{}", instance.name);
    assert!(
        instance
            .name
            .strip_prefix("b-")
            .expect("the box ID prefix")
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(
        std::fs::read_to_string(instance.directory.join("profile-name"))
            .expect("the profile record"),
        format!("{name}\n")
    );
    let mode = std::fs::metadata(instance.directory.join("profile-name"))
        .expect("stat")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn box_core_s_box_identity_is_refused_with_its_own_error() {
    let scene = Scene::new();
    let runs = scene.home().join(".strands/box/r");
    let result = existing(&runs, &scene.home(), "claude", "box-1f2e3d4c5b6a7980");
    assert!(matches!(result, Err(Error::BoxIdCore { .. })), "{result:?}");
    for id in [
        "box-1f2e3d4c",
        "box-1F2E3D4C5B6A7980",
        "box-1f2e3d4c5b6a79801",
    ] {
        let result = existing(&runs, &scene.home(), "box", id);
        assert!(
            matches!(result, Err(Error::BoxIdUnknown { .. })),
            "{id}: {result:?}"
        );
    }
}

#[test]
fn a_box_id_is_reused_only_by_the_profile_that_minted_it() {
    let scene = Scene::new();
    let runs = scene.home().join(".strands/box/r");
    let workspace = scene.home().join("project");
    std::fs::create_dir_all(&workspace).expect("a project");
    let (team_a, team_b) = ("claude-bedrk-opus-team-a", "claude-bedrk-opus-team-b");
    let instance = mint(&runs, team_a, &scene.home()).expect("an instance");
    std::fs::write(
        instance.directory.join("box.toml"),
        format!(
            "[agent]\nworkspace = {:?}\n",
            workspace.display().to_string()
        ),
    )
    .expect("box.toml");
    assert_eq!(instance.name.len(), 18, "{}", instance.name);
    existing(&runs, &scene.home(), team_a, &instance.name).expect("its own profile");
    let record = instance.directory.join("profile-name");
    std::fs::write(&record, format!("{team_a}-x\n")).expect("a longer name");
    assert!(
        matches!(
            existing(&runs, &scene.home(), team_a, &instance.name),
            Err(Error::BoxIdProfile { .. })
        ),
        "the record names the profile exactly"
    );
    std::fs::write(&record, format!("{team_a}\n")).expect("the record");
    assert!(matches!(
        existing(&runs, &scene.home(), team_b, &instance.name),
        Err(Error::BoxIdProfile { .. })
    ));
    let elsewhere = scene.home().join("elsewhere-profile");
    std::fs::rename(&record, &elsewhere).expect("move the record");
    assert!(
        matches!(
            existing(&runs, &scene.home(), team_a, &instance.name),
            Err(Error::BoxIdProfile { .. })
        ),
        "a run without a record is refused"
    );
    std::os::unix::fs::symlink(&elsewhere, &record).expect("a linked record");
    assert_eq!(
        std::fs::read_to_string(&record).expect("the linked record"),
        format!("{team_a}\n")
    );
    assert!(
        matches!(
            existing(&runs, &scene.home(), team_a, &instance.name),
            Err(Error::BoxIdProfile { .. })
        ),
        "a linked record is refused, even when it names the profile"
    );
    std::fs::remove_file(&record).expect("drop the link");
    let refused = |what: &str| {
        let (runs, home, name) = (runs.clone(), scene.home(), instance.name.clone());
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(existing(&runs, &home, team_a, &name));
        });
        let result = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("a {what} record is checked without blocking"));
        assert!(
            matches!(result, Err(Error::BoxIdProfile { .. })),
            "a {what} record is refused: {result:?}"
        );
    };
    std::fs::create_dir(&record).expect("a directory record");
    refused("directory");
    std::fs::remove_dir(&record).expect("drop the directory");
    let made = std::process::Command::new("/usr/bin/mkfifo")
        .arg(&record)
        .status()
        .expect("mkfifo runs");
    assert!(made.success());
    refused("FIFO");
    std::fs::remove_file(&record).expect("drop the FIFO");
    let short = tempfile::Builder::new()
        .prefix("bx")
        .tempdir_in("/tmp")
        .expect("a short directory");
    // A socket path is capped near 100 bytes, so bind through a short symlink to the record's
    // directory. A rename out of `/tmp` would cross filesystems wherever `/tmp` is a tmpfs.
    let short_link = short.path().join("d");
    std::os::unix::fs::symlink(&instance.directory, &short_link).expect("a short link");
    let _socket = std::os::unix::net::UnixListener::bind(short_link.join("profile-name"))
        .expect("a socket record");
    refused("socket");
}

#[test]
fn a_saved_run_with_a_malformed_id_is_refused() {
    let scene = Scene::new();
    let runs = scene.home().join(".strands/box/r");
    let instance = mint(&runs, "claude", &scene.home()).expect("an instance");
    std::fs::write(
        instance.directory.join("box.toml"),
        format!("[agent]\nworkspace = {:?}\n", scene.home()),
    )
    .expect("a configuration");
    for id in [
        "0123456789abcdef",
        "x-0123456789abcdef",
        "box-0123456789abcdef",
        "b-0123456789abcde",
        "b-0123456789abcdef0",
        "b-0123456789abcdeF",
        "b-0123456789abcdeg",
    ] {
        let renamed = runs.join(id);
        std::fs::rename(&instance.directory, &renamed).expect("a malformed ID");
        let result = existing(&runs, &scene.home(), "claude", id);
        assert!(
            matches!(result, Err(Error::BoxIdProfile { .. })),
            "{id}: {result:?}"
        );
        std::fs::rename(&renamed, &instance.directory).expect("restore the ID");
    }
}

#[test]
fn a_profile_is_removed_by_name_and_only_by_a_name_box_accepts() {
    let root = tempfile::tempdir().expect("a temporary root");
    let profiles = Profiles::at(root.path().join("profiles"));
    assert!(!profiles.contains("claude").expect("a look"));
    assert!(!profiles.remove("claude").expect("a removal of nothing"));
    for name in ["claude", "codex"] {
        std::fs::create_dir_all(profiles.folder(name)).expect("a folder");
        std::fs::write(profiles.path(name), "").expect("a profile");
    }
    std::fs::create_dir_all(profiles.folder("stray")).expect("a stray folder");

    assert!(profiles.contains("claude").expect("a look"));
    assert!(profiles.remove("claude").expect("a removal"));
    assert!(!profiles.remove("claude").expect("a second removal"));
    assert!(profiles.folder("codex").is_dir(), "another profile stays");
    assert!(
        profiles.folder("stray").is_dir(),
        "a folder that is no profile stays"
    );

    for name in ["../profiles", "base", "", "a/b"] {
        assert!(
            matches!(profiles.remove(name), Err(Error::ProfileName { .. })),
            "{name:?} is removed"
        );
        assert!(matches!(
            profiles.contains(name),
            Err(Error::ProfileName { .. })
        ));
    }
}

#[test]
fn a_reset_with_no_name_takes_the_whole_profiles_folder() {
    let root = tempfile::tempdir().expect("a temporary root");
    let profiles = Profiles::at(root.path().join("profiles"));
    assert!(!profiles.reset().expect("a reset of nothing"));
    for name in ["claude", "codex"] {
        std::fs::create_dir_all(profiles.folder(name)).expect("a folder");
        std::fs::write(profiles.path(name), "").expect("a profile");
    }
    std::fs::create_dir_all(profiles.folder("stray")).expect("a stray folder");

    assert!(profiles.reset().expect("a reset"));
    assert!(
        std::fs::symlink_metadata(profiles.root()).is_err(),
        "the folder and the stray folder in it go too"
    );
}

#[test]
fn a_removal_takes_a_link_and_not_its_target() {
    let root = tempfile::tempdir().expect("a temporary root");
    let target = root.path().join("elsewhere");
    std::fs::create_dir_all(&target).expect("a target");
    std::fs::write(target.join("keep"), "").expect("a file");
    let profiles = Profiles::at(root.path().join("profiles"));
    std::fs::create_dir_all(profiles.root()).expect("a root");
    std::os::unix::fs::symlink(&target, profiles.folder("linked")).expect("a link");

    assert!(profiles.remove("linked").expect("a removal"));
    assert!(std::fs::symlink_metadata(profiles.folder("linked")).is_err());
    assert!(target.join("keep").exists(), "the target stays");

    std::fs::remove_dir(profiles.root()).expect("an empty folder");
    std::os::unix::fs::symlink(&target, profiles.root()).expect("a linked folder");
    assert!(profiles.reset().expect("a reset"));
    assert!(std::fs::symlink_metadata(profiles.root()).is_err());
    assert!(target.join("keep").exists(), "the target stays");
}

#[test]
fn a_removal_needs_a_yes_on_a_terminal() {
    let mut input: &[u8] = b"y\n";
    let mut output = Vec::new();
    assert!(matches!(
        confirm("Remove?", false, &mut input, &mut output),
        Err(Error::Unconfirmed)
    ));
    assert_eq!(input, b"y\n", "nothing was read");
    assert!(output.is_empty());

    confirm("Remove?", true, &mut input, &mut output).expect("a yes");
    assert_eq!(String::from_utf8(output).expect("UTF-8"), "Remove? [y/N] ");
    for answer in [&b"\n"[..], b"n\n", b"yes please\n", b""] {
        let mut input = answer;
        assert!(matches!(
            confirm("Remove?", true, &mut input, &mut Vec::new()),
            Err(Error::Kept)
        ));
    }
}

#[test]
fn a_clean_removes_each_run_and_keeps_a_linked_target() {
    let root = tempfile::tempdir().expect("a temporary root");
    let launcher = Launcher::from_host().home(root.path().join("home"));
    assert_eq!(launcher.runs().expect("no runs"), Vec::<String>::new());
    assert_eq!(cleaned(&launcher), Cleaned::default());
    let runs = launcher.runs_root();
    for name in ["claude-00000001", "codex-00000002"] {
        std::fs::create_dir_all(runs.join(name).join("box")).expect("a run");
        std::fs::write(runs.join(name).join("records.jsonl"), "").expect("records");
    }
    let target = root.path().join("elsewhere");
    std::fs::create_dir_all(&target).expect("a target");
    std::fs::write(target.join("keep"), "").expect("a file");
    std::os::unix::fs::symlink(&target, runs.join("linked")).expect("a link");
    std::fs::write(runs.join("note"), "").expect("a file beside the runs");

    assert_eq!(
        launcher.runs().expect("the runs"),
        ["claude-00000001", "codex-00000002", "linked"]
    );
    assert_eq!(
        cleaned(&launcher),
        Cleaned {
            removed: 3,
            running: Vec::new()
        }
    );
    assert_eq!(launcher.runs().expect("no runs"), Vec::<String>::new());
    assert!(target.join("keep").exists(), "the target stays");
    assert!(runs.join("note").exists(), "a file is no run");
}

#[test]
fn a_clean_with_a_box_id_removes_only_that_run() {
    let root = tempfile::tempdir().expect("a temporary root");
    let launcher = Launcher::from_host().home(root.path().join("home"));
    let runs = launcher.runs_root();
    for name in ["claude-00000001", "codex-00000002"] {
        std::fs::create_dir_all(runs.join(name).join("box")).expect("a run");
    }
    let target = root.path().join("elsewhere");
    std::fs::create_dir_all(&target).expect("a target");
    std::fs::write(target.join("keep"), "").expect("a file");
    std::os::unix::fs::symlink(&target, runs.join("linked")).expect("a link");

    launcher.remove_run("claude-00000001").expect("one run");
    assert_eq!(
        launcher.runs().expect("the runs"),
        ["codex-00000002", "linked"]
    );
    for refused in [
        "claude-00000001",
        "../home",
        "codex-00000002/box",
        "",
        ".",
        "linked/",
        "linked/.",
        "codex-00000002/",
    ] {
        assert!(
            matches!(launcher.remove_run(refused), Err(Error::BoxUnknown { .. })),
            "{refused:?} names no run"
        );
    }
    assert!(target.join("keep").exists(), "a link's target stays");
    assert!(
        runs.join("codex-00000002").exists(),
        "a run named with a trailing slash stays"
    );
    launcher.remove_run("linked").expect("a link");
    assert!(target.join("keep").exists(), "the target stays");
    assert_eq!(launcher.runs().expect("the runs"), ["codex-00000002"]);
}

/// What `box clean --all` removes and keeps in `launcher`'s runs.
fn cleaned(launcher: &Launcher) -> Cleaned {
    let mut cleaned = Cleaned::default();
    launcher.remove_runs(&mut cleaned).expect("a clean");
    cleaned
}

/// A run folder held as `box run` holds it while its box runs.
struct RunningBox(std::fs::File);

impl Drop for RunningBox {
    /// Unlock the run folder, even while a forked child shares the file.
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

/// Hold the run folder `name` as `box run` does while its box runs.
fn running(runs: &Path, name: &str) -> RunningBox {
    let file = std::fs::File::open(runs.join(name)).expect("a run folder");
    file.try_lock().expect("the run lock");
    RunningBox(file)
}

#[test]
fn a_profile_clean_holds_each_box_until_it_removes_it() {
    let root = tempfile::tempdir().expect("a temporary root");
    let launcher = Launcher::from_host().home(root.path().join("home"));
    let runs = launcher.runs_root();
    for id in ["b-0123456789abcdef", "b-fedcba9876543210"] {
        std::fs::create_dir_all(runs.join(id).join("box")).expect("a run");
        std::fs::write(runs.join(id).join("profile-name"), "claude\n").expect("a record");
    }
    let ids = launcher
        .profile_boxes(Some(&["claude".to_string()]))
        .expect("the boxes of claude");
    assert_eq!(ids.len(), 2);

    let held = launcher.hold_boxes(&ids, "clean").expect("no box runs");
    for id in &ids {
        let probe = std::fs::File::open(runs.join(id)).expect("a run folder");
        assert!(
            matches!(probe.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
            "{id} is held until it is removed"
        );
    }
    let mut removed = 0;
    held.remove(&mut removed).expect("the boxes are removed");
    assert_eq!(removed, 2);
    assert!(launcher.runs().expect("the runs").is_empty());
}

#[test]
fn a_clean_refuses_a_box_that_is_still_running() {
    let root = tempfile::tempdir().expect("a temporary root");
    let launcher = Launcher::from_host().home(root.path().join("home"));
    let runs = launcher.runs_root();
    std::fs::create_dir_all(runs.join("claude-00000001").join("box")).expect("a run");
    let held = running(&runs, "claude-00000001");
    let child = held.0.try_clone().expect("a forked child's copy");

    for result in [
        launcher.find_run("claude-00000001"),
        launcher.remove_run("claude-00000001"),
    ] {
        assert!(
            matches!(&result, Err(Error::BoxRunning { id }) if id == "claude-00000001"),
            "{result:?}"
        );
    }
    assert!(runs.join("claude-00000001").exists(), "a running box stays");

    drop(held);
    launcher
        .remove_run("claude-00000001")
        .expect("a stopped box");
    assert!(launcher.runs().expect("no runs").is_empty());
    drop(child);
}

#[test]
fn a_clean_of_every_box_keeps_each_box_that_is_still_running() {
    let root = tempfile::tempdir().expect("a temporary root");
    let launcher = Launcher::from_host().home(root.path().join("home"));
    let runs = launcher.runs_root();
    for name in [
        "claude-00000001",
        "codex-00000002",
        "kiro-00000003",
        "pi-00000004",
    ] {
        std::fs::create_dir_all(runs.join(name).join("box")).expect("a run");
    }
    let _codex = running(&runs, "codex-00000002");
    let _pi = running(&runs, "pi-00000004");

    assert_eq!(
        cleaned(&launcher),
        Cleaned {
            removed: 2,
            running: vec!["codex-00000002".to_string(), "pi-00000004".to_string()]
        }
    );
    assert_eq!(
        launcher.runs().expect("the runs"),
        ["codex-00000002", "pi-00000004"]
    );
}

#[test]
fn box_resources_overrides_the_directory_beside_the_cli() {
    let scene = Scene::new();
    let cli = scene.root.join("bin/box");
    let beside = scene.root.join("bin/resources");
    std::fs::create_dir_all(beside.join("packs")).expect("a directory");
    assert_eq!(
        crate::resources::root_from(None, Some(&cli)).expect("a root"),
        beside
    );
    let named = scene.root.join("named");
    std::fs::create_dir_all(named.join("packs")).expect("a directory");
    assert_eq!(
        crate::resources::root_from(Some(named.clone().into()), Some(&cli)).expect("a root"),
        named
    );
    let absent = scene.root.join("absent");
    let error = crate::resources::root_from(Some(absent.clone().into()), Some(&cli))
        .expect_err("a named directory is not passed over");
    assert!(
        error.to_string().contains(&absent.display().to_string()),
        "{error}"
    );
}

#[test]
fn a_placeholder_in_a_literal_field_is_refused() {
    let scene = Scene::new();
    scene.share("set", "[inputs.set]\nfrom = \"env:SET\"");
    scene.share(
        "described",
        "[inputs.x]\ndescription = \"${{ home }}\"\ndefault = \"a\"",
    );
    for (text, field) in [
        (
            "packs = [\"@box/set\"]\n[agent]\ncommand = [\"/bin/x\"]\n[egress.model]\n\
             destinations = [\"example.com\"]\nsecret.ref = \"env://${{ inputs.set }}\"",
            "`egress.model.secret.ref` is literal",
        ),
        (
            "[agent]\ncommand = [\"/bin/x\"]\n[telemetry.otlp]\nkind = \"otlp\"\n\
             destination = \"http://localhost:4318\"\nheaders.x-home = \"${{ home }}\"",
            "`telemetry.otlp.headers.x-home` is literal",
        ),
        (
            "packs = [\"@box/described\"]\n[agent]\ncommand = [\"/bin/x\"]",
            "`[inputs.x] description` is literal",
        ),
        (
            "packs = [\"${{ home }}\"]\n[agent]\ncommand = [\"/bin/x\"]",
            "not a pack name",
        ),
    ] {
        let reason = scene.refusal(text);
        assert!(reason.contains(field), "{field}: {reason}");
    }
}

#[test]
fn an_undeclared_name_is_refused() {
    let scene = Scene::new();
    for (name, why) in [
        (
            "inputs.x",
            "`inputs.x` is not an input that a pack declares",
        ),
        ("option.x", "is not a name"),
        ("env.SET", "is not a name"),
        ("file.x", "is not a name"),
    ] {
        let reason = scene.refusal(&format!(
            "[agent]\ncommand = [\"/bin/x\"]\nenv.VALUE = \"${{{{ {name} }}}}\""
        ));
        assert!(reason.contains(why), "{name}: {reason}");
    }
}

#[test]
fn a_path_placeholder_comes_first_and_fills_in_one_component() {
    let scene = Scene::new();
    scene.share("part", "[inputs.part]\ndescription = \"One path part.\"");
    let path = |entry: &str, part: &str| {
        format!(
            "packs = [\"@box/part\"]\n[options]\npart = {part:?}\n[agent]\ncommand = [\"/bin/x\"]\n\
             filesystem.read = [{entry:?}]"
        )
    };
    for (entry, part, why) in [
        (
            "/opt/${{ inputs.part }}",
            "a",
            "in a path, a placeholder comes first",
        ),
        (
            "${{ home }}/${{ inputs.part }}",
            "a/b",
            "is not one path component",
        ),
        (
            "${{ home }}/${{ inputs.part }}",
            "..",
            "is not one path component",
        ),
        ("${{ home }}/../x", "a", "holds `..`"),
        ("${{ inputs.part }}", "relative", "is not an absolute path"),
        ("relative", "a", "is not an absolute path"),
    ] {
        let reason = scene.refusal(&path(entry, part));
        assert!(reason.contains(why), "{entry} with {part:?}: {reason}");
    }
    let resolved = scene
        .resolve(&profile(&path("${{ home }}/${{ inputs.part }}", "a")))
        .expect("one component");
    assert_eq!(
        resolved.agent.filesystem.read,
        [scene.home().join("a").display().to_string()]
    );
}

#[test]
fn an_entry_table_drops_a_missing_optional_path_and_an_entry_for_another_os() {
    let scene = Scene::new();
    let linux = scene.root.join("linux.cnf");
    let macos = scene.root.join("macos.cnf");
    for file in [&linux, &macos] {
        std::fs::write(file, "").expect("a file");
    }
    let missing = scene.root.join("missing.cnf");
    let required = scene.root.join("required.cnf");
    let text = format!(
        "[agent]\ncommand = [\"/bin/x\"]\n[agent.filesystem]\nread_file = [\n\
         {{ path = {missing:?}, optional = true }},\n\
         {{ path = {linux:?}, when = \"linux\" }},\n\
         {{ path = {macos:?}, optional = true, when = \"macos\" }},\n\
         {required:?},\n]",
    );
    let read_file = |os| {
        scene
            .resolve_with(
                &profile(&text),
                &Context {
                    os,
                    ..scene.context()
                },
            )
            .expect("a resolve")
            .agent
            .filesystem
            .read_file
    };
    let shown = |path: &PathBuf| path.display().to_string();
    assert_eq!(read_file("macos"), [shown(&macos), shown(&required)]);
    assert_eq!(read_file("linux"), [shown(&linux), shown(&required)]);
    for (entry, why) in [
        (
            "{ path = \"/x\", when = \"windows\" }",
            "use macos, linux, or a placeholder for a bool input",
        ),
        ("{ path = \"/x\", mode = \"r\" }", "unknown key `mode`"),
        ("{ optional = true }", "needs `path`"),
    ] {
        let reason = scene.refusal(&format!(
            "[agent]\ncommand = [\"/bin/x\"]\nfilesystem.read_file = [{entry}]"
        ));
        assert!(reason.contains(why), "{entry}: {reason}");
    }
}

#[test]
fn a_structured_when_gates_a_single_value_on_an_input() {
    let scene = Scene::new();
    scene.share("prov", "");
    scene.share(
        "p",
        "[run]\ncommand = [\"/bin/x\"]\n[inputs.host]\ntype = \"string\"\n\
         values = [\"bedrock\", \"anthropic\"]\ndefault = \"bedrock\"\n[env]\n\
         FLAG = { value = \"1\", when = { variable = \"inputs.host\", equals = \"bedrock\" } }\n\
         ALWAYS = \"on\"",
    );
    let env = |host: &str| {
        scene
            .resolve(&profile(&format!(
                "packs = [\"@box/p\", \"@box/prov\"]\n[options]\nhost = \"{host}\""
            )))
            .expect("a resolve")
            .agent
            .env
    };
    let on = env("bedrock");
    assert_eq!(on.get("FLAG").map(String::as_str), Some("1"));
    assert_eq!(on.get("ALWAYS").map(String::as_str), Some("on"));
    let off = env("anthropic");
    assert_eq!(off.get("FLAG"), None);
    assert_eq!(off.get("ALWAYS").map(String::as_str), Some("on"));
}

#[test]
fn a_structured_when_on_a_whole_table_drops_the_block() {
    let scene = Scene::new();
    scene.share("prov", "");
    scene.share(
        "p",
        "[run]\ncommand = [\"/bin/x\"]\n[inputs.host]\ntype = \"string\"\n\
         values = [\"bedrock\", \"anthropic\"]\ndefault = \"bedrock\"\n[env]\n\
         when = { variable = \"inputs.host\", equals = \"bedrock\" }\nONLY_ON_BEDROCK = \"1\"",
    );
    let env = |host: &str| {
        scene
            .resolve(&profile(&format!(
                "packs = [\"@box/p\", \"@box/prov\"]\n[options]\nhost = \"{host}\""
            )))
            .expect("a resolve")
            .agent
            .env
    };
    assert_eq!(
        env("bedrock").get("ONLY_ON_BEDROCK").map(String::as_str),
        Some("1")
    );
    assert!(env("anthropic").is_empty());
}

#[test]
fn a_when_table_with_an_unknown_or_missing_key_is_refused() {
    let scene = Scene::new();
    scene.share("prov", "");
    let share = |body: &str| {
        scene.share(
            "p",
            &format!(
                "[run]\ncommand = [\"/bin/x\"]\n[inputs.host]\ntype = \"string\"\n\
                 values = [\"bedrock\"]\ndefault = \"bedrock\"\n[env]\n\
                 FLAG = {{ value = \"1\", when = {{ {body} }} }}"
            ),
        );
        scene.resolve_refusal("packs = [\"@box/p\", \"@box/prov\"]\n[options]\nhost = \"bedrock\"")
    };
    let unknown = share("variable = \"inputs.host\", equals = \"bedrock\", extra = \"x\"");
    assert!(unknown.contains("unknown key `extra`"), "{unknown}");
    let no_variable = share("equals = \"bedrock\"");
    assert!(no_variable.contains("needs `variable`"), "{no_variable}");
    let no_equals = share("variable = \"inputs.host\"");
    assert!(no_equals.contains("needs `equals`"), "{no_equals}");
}

#[test]
fn a_string_when_still_gates_on_an_os_and_a_bool_input() {
    let scene = Scene::new();
    scene.share("prov", "");
    scene.share(
        "p",
        "[run]\ncommand = [\"/bin/x\"]\n[inputs.on]\ntype = \"bool\"\ndefault = \"true\"\n[env]\n\
         MAC = { value = \"1\", when = \"macos\" }\nLIN = { value = \"1\", when = \"linux\" }\n\
         BOOL = { value = \"1\", when = \"${{ inputs.on }}\" }",
    );
    let env = scene
        .resolve(&profile("packs = [\"@box/p\", \"@box/prov\"]"))
        .expect("a resolve")
        .agent
        .env;
    assert_eq!(env.get("MAC").map(String::as_str), Some("1"));
    assert_eq!(env.get("LIN"), None);
    assert_eq!(env.get("BOOL").map(String::as_str), Some("1"));
}

#[test]
fn an_agent_storage_directory_never_reaches_what_box_keeps_in_the_storage_root() {
    let scene = Scene::new();
    let root = scene.storage();
    let tilde = |path: &Path| {
        format!(
            "~/{}",
            path.strip_prefix(scene.home())
                .expect("below the home")
                .display()
        )
    };
    for name in ["mcp-cache", "tool", "copies.json"] {
        let text = format!(
            "[storage]\ndirectories = [\"{name}\"]\n[agent]\ncommand = [\"/usr/bin/true\"]"
        );
        let compiled = scene.compile(&profile(&text), None).expect("a compile");
        let directory = root.join("agent").join(name);
        assert_eq!(
            compiled.storage.directories,
            std::slice::from_ref(&directory),
            "{name}"
        );
        let file = table(&compiled);
        let boxs = root.join(name);
        for list in ["read", "write"] {
            let grants = strings(&file["agent"]["filesystem"][list]);
            assert!(
                grants.contains(&directory.display().to_string()),
                "{name} {list}: {grants:?}"
            );
            assert!(
                grants
                    .iter()
                    .all(|grant| !Path::new(grant).starts_with(&boxs)),
                "{name} {list}: {grants:?}"
            );
        }
        let permit = format!("context.input.path == \"{}\"", tilde(&directory));
        let leak = format!("context.input.path == \"{}\"", tilde(&boxs));
        let rules: Vec<&str> = compiled
            .policy
            .lines()
            .filter(|line| line.starts_with("@id(\"storage_0_"))
            .collect();
        assert_eq!(rules.len(), 4, "{name}: {}", compiled.policy);
        for rule in rules {
            assert!(rule.contains(&permit), "{name}: {rule}");
            assert!(!rule.contains(&leak), "{name}: {rule}");
        }
    }
}

#[test]
fn a_storage_directory_gets_grants_and_permits_and_only_storage_is_writable_in_the_box_home() {
    let scene = Scene::new();
    let text = "[storage]\ndirectories = [\"state\"]\n[agent]\ncommand = [\"/usr/bin/true\"]\n\
                env.STATE = \"${{ storage.state }}\"";
    let compiled = scene.compile(&profile(text), None).expect("a compile");
    let file = table(&compiled);
    let state = scene.storage().join("agent/state");
    let shown = state.display().to_string();
    assert_eq!(file["agent"]["env"]["STATE"].as_str(), Some(shown.as_str()));
    for list in ["read", "write"] {
        assert!(
            strings(&file["agent"]["filesystem"][list]).contains(&shown),
            "{list}: {}",
            compiled.box_toml
        );
    }
    assert_eq!(compiled.storage.directories, std::slice::from_ref(&state));
    let tilde = format!(
        "~/{}",
        state
            .strip_prefix(scene.home())
            .expect("below the home")
            .display()
    );
    for (action, verb) in [
        ("fs:read", "read"),
        ("fs:write", "write"),
        ("fs:delete", "delete"),
        ("fs:move", "move"),
    ] {
        let rule = format!(
            "@id(\"storage_0_{verb}\") permit (principal, action == Box::Action::\"{action}\", \
             resource) when {{ context.input.path == \"{tilde}\" || context.input.path like \
             \"{tilde}/*\" }};"
        );
        assert!(
            compiled.policy.contains(&rule),
            "{rule} in\n{}",
            compiled.policy
        );
    }
    let root = format!(
        "~/{}",
        scene
            .storage()
            .strip_prefix(scene.home())
            .expect("below the home")
            .display()
    );
    let forbid = compiled
        .policy
        .lines()
        .find(|line| line.starts_with("@id(\"box_home_write\") forbid"))
        .expect("a forbid on the box home");
    assert!(
        forbid.contains("\"~/.strands/box\"")
            && forbid.contains(&format!(
                "&& !((context.input.path == \"{root}/agent/state\" || context.input.path like \
                 \"{root}/agent/state/*\"))"
            )),
        "{forbid}"
    );
    assert!(
        !forbid.contains(&format!("context.input.path == \"{root}\" ")),
        "the storage root, and the record in it, stay under the forbid: {forbid}"
    );

    scene
        .compile(
            &profile(&format!(
                "{text}\nfilesystem.write = [\"${{{{ storage.state }}}}\"]"
            )),
            None,
        )
        .expect("a run writes its own storage");
    let home = scene.home().display().to_string();
    for grant in [
        scene.storage().display().to_string(),
        scene
            .storage()
            .join(crate::storage_sync::RECORD)
            .display()
            .to_string(),
        scene.storage().join("beside").display().to_string(),
        format!("{home}/.strands/box/storage"),
        format!("{home}/.strands/box/storage/other/x"),
        format!("{home}/.strands/box/packs"),
    ] {
        let error = scene
            .compile(
                &profile(&format!("{text}\nfilesystem.write = [{grant:?}]")),
                None,
            )
            .expect_err("a write grant over the box home");
        assert!(
            matches!(error, Error::WriteOverProtected { .. }),
            "{grant}: {error}"
        );
    }
}

#[test]
fn a_moved_box_home_and_the_installed_one_are_both_forbidden() {
    let scene = Scene::new();
    let moved = scene.root.join("try/home");
    let box_homes = [moved.clone(), scene.home().join(".strands/box")];
    let compile_with = |text: &str| {
        let resolved_profile = scene.resolve_with(&profile(text), &scene.context())?;
        compile(&Run {
            profile: &resolved_profile,
            policy: Some(&resolved_profile.policy),
            tool_rules: &crate::render::Rules::default(),
            workspace: &scene.workspace(),
            instance: &scene.instance(),
            home: &scene.home(),
            box_homes: &box_homes,
            trusted: &[],
            protected: &box_homes,
            resources: None,
            search_path: "/usr/bin:/bin".as_ref(),
            resolve: &resolved,
            root: false,
        })
    };
    let text = "[agent]\ncommand = [\"/usr/bin/true\"]";
    let compiled = compile_with(text).expect("a compile");
    for (id, root) in [
        ("box_home_write", moved.display().to_string()),
        ("box_home_1_write", "~/.strands/box".to_string()),
    ] {
        let forbid = compiled
            .policy
            .lines()
            .find(|line| line.starts_with(&format!("@id(\"{id}\") forbid")))
            .unwrap_or_else(|| panic!("{id} in\n{}", compiled.policy));
        assert!(forbid.contains(&format!("\"{root}\"")), "{forbid}");
    }
    let grant = moved.join("profiles").display().to_string();
    let error = compile_with(&format!("{text}\nfilesystem.write = [{grant:?}]"))
        .expect_err("a write grant over the moved box home");
    assert!(matches!(error, Error::WriteOverProtected { .. }), "{error}");
}

/// **The Shell and Monty cannot change `box`'s resources directory**, which holds the policy
/// starters that `box profile create` copies: an operator permit cannot outweigh a forbid. A
/// resources directory inside a box home, as `install.sh` lays out, is already under the box
/// home's forbids and gets no rules of its own.
#[test]
fn the_resources_directory_outside_the_box_home_is_forbidden_to_the_shell_and_monty() {
    let scene = Scene::new();
    let box_homes = [
        scene.root.join("try/home"),
        scene.home().join(".strands/box"),
    ];
    let compile_with = |resources: Option<&Path>| {
        let resolved_profile = scene.resolve_with(
            &profile("[agent]\ncommand = [\"/usr/bin/true\"]"),
            &scene.context(),
        )?;
        compile(&Run {
            profile: &resolved_profile,
            policy: Some(
                "permit (principal, action == Box::Action::\"fs:write\", resource) \
                 when { context.input.path like \"~/*\" };",
            ),
            tool_rules: &crate::render::Rules::default(),
            workspace: &scene.workspace(),
            instance: &scene.instance(),
            home: &scene.home(),
            box_homes: &box_homes,
            trusted: &[],
            protected: &box_homes,
            resources,
            search_path: "/usr/bin:/bin".as_ref(),
            resolve: &resolved,
            root: false,
        })
    };

    let outside = scene.home().join("tools/box/resources");
    let compiled = compile_with(Some(&outside)).expect("a compile");
    let below = "context.input.path == \"~/tools/box/resources\" || context.input.path like \
                 \"~/tools/box/resources/*\"";
    for (action, id) in [
        ("fs:write", "resources_write"),
        ("fs:delete", "resources_delete"),
        ("fs:move", "resources_move"),
    ] {
        let rule = format!(
            "@id({id:?}) forbid (principal, action == Box::Action::{action:?}, resource) when {{ {below} }};"
        );
        assert!(
            compiled.policy.contains(&rule),
            "{rule}\n{}",
            compiled.policy
        );
    }
    let folders = "context.input.path == \"~/tools/box\" || context.input.path == \"~/tools\"";
    for (action, id) in [
        ("fs:move", "resources_folder_move"),
        ("fs:delete", "resources_folder_delete"),
    ] {
        let rule = format!(
            "@id({id:?}) forbid (principal, action == Box::Action::{action:?}, resource) when {{ {folders} }};"
        );
        assert!(
            compiled.policy.contains(&rule),
            "{rule}\n{}",
            compiled.policy
        );
    }

    let external = scene.home().join("external-resources");
    std::fs::create_dir_all(&external).expect("a resources directory");
    std::fs::create_dir_all(scene.home().join(".strands/box")).expect("a box home");
    std::os::unix::fs::symlink(&external, scene.home().join(".strands/box/resources"))
        .expect("a link in the box home");
    let alias = scene.root.join("alias-home");
    std::os::unix::fs::symlink(scene.home(), &alias).expect("a second name for the home");
    for written in [
        scene.home().join(".strands/box/resources"),
        alias.join("external-resources"),
    ] {
        let compiled = compile_with(Some(&written)).expect("a compile");
        let rule = "@id(\"resources_write\") forbid (principal, action == Box::Action::\"fs:write\", \
                    resource) when { context.input.path == \"~/external-resources\" || \
                    context.input.path like \"~/external-resources/*\" };";
        assert!(
            compiled.policy.contains(rule),
            "{written:?}: the rules name the resolved directory\n{}",
            compiled.policy
        );
    }

    let opt = scene.root.join("opt/box/resources");
    std::fs::create_dir_all(&opt).expect("a resources directory outside the home");
    std::os::unix::fs::symlink(&opt, scene.home().join("box-res")).expect("a link in the home");
    let compiled = compile_with(Some(&scene.home().join("box-res"))).expect("a compile");
    let opt = opt.display();
    assert!(
        compiled.policy.contains(&format!(
            "when {{ context.input.path == \"{opt}\" || context.input.path like \"{opt}/*\" }};"
        )),
        "the link's target: {}",
        compiled.policy
    );
    let folder_rule = compiled
        .policy
        .lines()
        .find(|line| line.starts_with("@id(\"resources_folder_delete\")"))
        .expect("a folder rule");
    assert!(
        folder_rule.contains("context.input.path == \"~/box-res\""),
        "the link itself cannot be removed: {folder_rule}"
    );

    let installed = scene.home().join(".strands/box/packages/v1/resources");
    std::fs::create_dir_all(&installed).expect("an installed resources directory");
    std::os::unix::fs::symlink(&installed, scene.home().join("res-link"))
        .expect("a link into the box home");
    let compiled = compile_with(Some(&scene.home().join("res-link"))).expect("a compile");
    assert!(
        !compiled.policy.contains("@id(\"resources_write\")"),
        "the box home covers the directory: {}",
        compiled.policy
    );
    assert!(
        compiled.policy.contains(
            "@id(\"resources_folder_move\") forbid (principal, action == Box::Action::\"fs:move\", \
             resource) when { context.input.path == \"~/res-link\" };"
        ),
        "the link outside the box home is kept: {}",
        compiled.policy
    );

    for resources in [
        Some(scene.root.join("try/home/packages/v1/resources")),
        Some(scene.home().join(".strands/box/packages/v1/resources")),
        None,
    ] {
        let compiled = compile_with(resources.as_deref()).expect("a compile");
        assert!(
            !compiled.policy.contains("@id(\"resources_"),
            "{resources:?}: {}",
            compiled.policy
        );
    }
}

/// **Each protected root that a write grant may not reach is forbidden to the Shell and Monty
/// too.** `~/.local/bin` and an install root outside the home get their own forbids, with the
/// folders above them. A root inside a box home, the resources directory, and a trusted file keep
/// the rules they already have.
#[test]
fn each_protected_root_outside_the_box_home_is_forbidden_to_the_shell_and_monty() {
    let scene = Scene::new();
    let box_home = scene.home().join(".strands/box");
    let local_bin = scene.home().join(".local/bin");
    let install = scene.root.join("opt/box-dev/bin");
    std::fs::create_dir_all(&install).expect("an install root");
    let resources = scene.home().join("tools/box/resources");
    let profile_file = scene.home().join("profiles/mine.toml");
    let protected = [
        box_home.clone(),
        local_bin,
        box_home.join("packages/v1"),
        install.clone(),
        resources.clone(),
        profile_file.clone(),
    ];
    let resolved_profile = scene
        .resolve_with(
            &profile("[agent]\ncommand = [\"/usr/bin/true\"]"),
            &scene.context(),
        )
        .expect("a resolve");
    let compiled = compile(&Run {
        profile: &resolved_profile,
        policy: Some(
            "permit (principal, action == Box::Action::\"fs:write\", resource) \
             when { context.input.path like \"~/*\" };",
        ),
        tool_rules: &crate::render::Rules::default(),
        workspace: &scene.workspace(),
        instance: &scene.instance(),
        home: &scene.home(),
        box_homes: std::slice::from_ref(&box_home),
        trusted: std::slice::from_ref(&profile_file),
        protected: &protected,
        resources: Some(&resources),
        search_path: "/usr/bin:/bin".as_ref(),
        resolve: &resolved,
        root: false,
    })
    .expect("a compile");
    let install = install.display().to_string();
    for (index, directory) in [(0, "~/.local/bin".to_string()), (1, install.clone())] {
        let below = format!(
            "context.input.path == \"{directory}\" || context.input.path like \"{directory}/*\""
        );
        for (action, verb) in [
            ("fs:write", "write"),
            ("fs:delete", "delete"),
            ("fs:move", "move"),
        ] {
            let rule = format!(
                "@id(\"protected_{index}_{verb}\") forbid (principal, action == \
                 Box::Action::{action:?}, resource) when {{ {below} }};"
            );
            assert!(
                compiled.policy.contains(&rule),
                "{rule}\n{}",
                compiled.policy
            );
        }
    }
    let folder = |index: usize| {
        compiled
            .policy
            .lines()
            .find(|line| line.starts_with(&format!("@id(\"protected_{index}_folder_delete\")")))
            .unwrap_or_else(|| panic!("protected_{index}_folder_delete in\n{}", compiled.policy))
            .to_string()
    };
    assert!(
        folder(0).contains("context.input.path == \"~/.local\""),
        "{}",
        folder(0)
    );
    let opt = scene.root.join("opt").display().to_string();
    assert!(
        folder(1).contains(&format!("context.input.path == \"{opt}\"")),
        "{}",
        folder(1)
    );
    assert!(
        !compiled.policy.contains("@id(\"protected_2_"),
        "only two roots need their own rules: {}",
        compiled.policy
    );
    for kept in ["resources_write", "profile_file_write", "box_home_write"] {
        assert!(
            compiled.policy.contains(&format!("@id(\"{kept}\")")),
            "{kept}: {}",
            compiled.policy
        );
    }

    let linked_home = scene.root.join("linked");
    let linked_box_home = linked_home.join(".strands/box");
    let target = linked_box_home.join("bin");
    std::fs::create_dir_all(&target).expect("a folder in the box home");
    std::fs::create_dir_all(linked_home.join(".local")).expect("a ~/.local");
    let link = linked_home.join(".local/bin");
    std::os::unix::fs::symlink(&target, &link).expect("~/.local/bin links into the box home");
    let compiled = compile(&Run {
        profile: &resolved_profile,
        policy: None,
        tool_rules: &crate::render::Rules::default(),
        workspace: &scene.workspace(),
        instance: &scene.instance(),
        home: &linked_home,
        box_homes: std::slice::from_ref(&linked_box_home),
        trusted: &[],
        protected: &[linked_box_home.clone(), link],
        resources: None,
        search_path: "/usr/bin:/bin".as_ref(),
        resolve: &resolved,
        root: false,
    })
    .expect("a compile");
    assert!(
        !compiled.policy.contains("@id(\"protected_0_write\")"),
        "the box home's forbids cover the link's target: {}",
        compiled.policy
    );
    for verb in ["move", "delete"] {
        let rule = compiled
            .policy
            .lines()
            .find(|line| line.starts_with(&format!("@id(\"protected_0_folder_{verb}\")")))
            .unwrap_or_else(|| panic!("protected_0_folder_{verb} in\n{}", compiled.policy));
        assert!(
            rule.contains("context.input.path == \"~/.local/bin\""),
            "the link itself cannot be replaced: {rule}"
        );
    }
}

#[test]
fn each_route_permits_each_of_its_destination_hosts() {
    let scene = Scene::new();
    let compiled = scene
        .compile(
            &profile(
                "[agent]\ncommand = [\"/usr/bin/true\"]\n[egress.model]\n\
                 destinations = [\"a.example.com\", \"b.example.com:8443\", \"*.c.example.com/v1\"]\n\
                 secret.ref = \"env://KEY\"",
            ),
            None,
        )
        .expect("a compile");
    let rule = |id: &str| {
        compiled
            .policy
            .lines()
            .find(|line| line.starts_with(&format!("@id(\"{id}\") permit")))
            .unwrap_or_else(|| panic!("{id} in\n{}", compiled.policy))
    };
    let connect = rule("route_model_connect");
    assert!(connect.contains("\"net:connect\""), "{connect}");
    for part in [
        "(context.input.host == \"a.example.com\" && context.input.port == 443)",
        "(context.input.host == \"b.example.com\" && context.input.port == 8443)",
        "(context.input.host like \"*.c.example.com\" && context.input.port == 443)",
    ] {
        assert!(connect.contains(part), "{part} in {connect}");
    }
    let request = rule("route_model_request");
    assert!(request.contains("\"http:request\""), "{request}");
    for part in [
        "context.input.host == \"a.example.com\"",
        "context.input.host == \"b.example.com\"",
        "context.input.host like \"*.c.example.com\"",
    ] {
        assert!(request.contains(part), "{part} in {request}");
    }
}

#[test]
fn a_route_with_no_secret_gets_its_permits_and_stays_out_of_box_toml() {
    let scene = Scene::new();
    let compiled = scene
        .compile(
            &profile(
                "[agent]\ncommand = [\"/usr/bin/true\"]\n\
                 [egress.login]\ndestinations = [\"login.example.com\", \"build.example.com:8443\"]\n\
                 [egress.model]\ndestinations = [\"model.example.com\"]\nsecret.ref = \"env://KEY\"\n\
                 [mcp.docs]\ntype = \"http\"\ndestinations = [\"docs.example.com\"]\n\
                 [storage]\ndirectories = [\"config\"]",
            ),
            None,
        )
        .expect("a compile");
    let rule = |id: &str| {
        compiled
            .policy
            .lines()
            .find(|line| line.starts_with(&format!("@id(\"{id}\") permit")))
            .unwrap_or_else(|| panic!("{id} in\n{}", compiled.policy))
            .to_string()
    };
    assert_eq!(
        rule("route_login_connect"),
        "@id(\"route_login_connect\") permit (principal, action == Box::Action::\"net:connect\", \
         resource) when { (context.input.host == \"login.example.com\" && context.input.port == 443) \
         || (context.input.host == \"build.example.com\" && context.input.port == 8443) };"
    );
    assert_eq!(
        rule("route_login_request"),
        "@id(\"route_login_request\") permit (principal, action == Box::Action::\"http:request\", \
         resource) when { context.input.host == \"login.example.com\" || context.input.host == \
         \"build.example.com\" };"
    );
    let config: toml::Table = compiled.box_toml.parse().expect("box.toml");
    let egress = config["egress"]
        .as_table()
        .expect("the routes with a secret");
    assert!(egress.get("login").is_none(), "{}", compiled.box_toml);
    assert!(egress.get("model").is_some(), "{}", compiled.box_toml);
    let at = |id: &str| {
        compiled
            .policy
            .find(&format!("@id(\"{id}\")"))
            .unwrap_or_else(|| panic!("{id} in\n{}", compiled.policy))
    };
    assert!(
        at("route_login_request") < at("mcp_docs_call")
            && at("mcp_docs_call") < at("storage_0_read"),
        "{}",
        compiled.policy
    );
}

#[test]
fn a_profile_replaces_the_destinations_of_a_pack_route_with_no_secret() {
    let scene = Scene::new();
    scene.share(
        "login",
        "[egress.login]\ndestinations = [\"login.example.com\"]",
    );
    let compiled = scene
        .compile(
            &profile(
                "packs = [\"@box/login\"]\n[agent]\ncommand = [\"/usr/bin/true\"]\n\
                 [egress.login]\ndestinations = [\"sso.example.com\"]",
            ),
            None,
        )
        .expect("a compile");
    let request = compiled
        .policy
        .lines()
        .find(|line| line.starts_with("@id(\"route_login_request\")"))
        .unwrap_or_else(|| panic!("route_login_request in\n{}", compiled.policy));
    assert!(request.contains("\"sso.example.com\""), "{request}");
    assert!(!request.contains("\"login.example.com\""), "{request}");
}

#[test]
fn a_route_or_a_server_names_at_most_one_hundred_hosts() {
    let scene = Scene::new();
    let hosts = (1..=101)
        .map(|index| format!("\"h{index}.example.com\""))
        .collect::<Vec<_>>()
        .join(", ");
    for (table, owner) in [
        (
            format!("[egress.model]\ndestinations = [{hosts}]\nsecret.ref = \"env://KEY\""),
            "`[egress.model]`",
        ),
        (
            format!("[mcp.docs]\ntype = \"http\"\ndestinations = [{hosts}]"),
            "`[mcp.docs]`",
        ),
    ] {
        let text = format!("[agent]\ncommand = [\"/usr/bin/true\"]\n{table}");
        let error = scene
            .compile(&profile(&text), None)
            .expect_err("one host too many");
        assert!(
            error.to_string().contains(&format!(
                "{owner} names 101 hosts, and it holds at most 100"
            )),
            "{owner}: {error}"
        );
    }
}

#[test]
fn a_route_with_no_secret_names_plain_hosts() {
    let scene = Scene::new();
    for destination in [
        "login.example.com/v1",
        "*.example.com",
        "Login.example.com",
        "login.example.com.",
        "a b",
        "",
    ] {
        let text = format!(
            "[agent]\ncommand = [\"/usr/bin/true\"]\n[egress.login]\ndestinations = [{destination:?}]"
        );
        let error = scene.compile(&profile(&text), None).expect_err("a refusal");
        assert!(
            error
                .to_string()
                .contains("`[egress.login]` has no secret, so each destination is a host name"),
            "{destination:?}: {error}"
        );
    }
    let text = "[agent]\ncommand = [\"/usr/bin/true\"]\n[egress.login]\n\
                destinations = [\"*.example.com\", \"api.example.com/v1\"]\nsecret.ref = \"env://KEY\"";
    scene
        .compile(&profile(text), None)
        .expect("a route with a secret keeps Box Core's destination forms");
}

#[test]
fn a_route_with_no_secret_can_name_a_server_on_this_machine() {
    let scene = Scene::new();
    for destination in [
        "localhost",
        "localhost:11434",
        "app.localhost",
        "127.0.0.1",
        "127.1.2.3:8080",
        "0.0.0.0",
    ] {
        let text = format!(
            "[agent]\ncommand = [\"/usr/bin/true\"]\n[egress.local]\ndestinations = [{destination:?}]"
        );
        let compiled = scene
            .compile(&profile(&text), None)
            .unwrap_or_else(|error| panic!("{destination:?}: {error}"));
        let (host, _) = destination.rsplit_once(':').unwrap_or((destination, ""));
        assert!(
            compiled.policy.contains(&format!("{host:?}")),
            "{destination:?}: {}",
            compiled.policy
        );
    }
    // An IPv6 literal is not a host name.
    for destination in ["::1", "[::1]:8080"] {
        let text = format!(
            "[agent]\ncommand = [\"/usr/bin/true\"]\n[egress.local]\ndestinations = [{destination:?}]"
        );
        let error = scene.compile(&profile(&text), None).expect_err("a refusal");
        assert!(
            error
                .to_string()
                .contains("`[egress.local]` has no secret, so each destination is a host name"),
            "{destination:?}: {error}"
        );
    }
}

#[test]
fn a_route_with_another_key_and_no_secret_goes_to_box_core() {
    let scene = Scene::new();
    for (name, route) in [
        (
            "typo",
            "destinations = [\"login.example.com\"]\nsecrets.ref = \"env://KEY\"",
        ),
        (
            "header",
            "destinations = [\"login.example.com\"]\nheader = \"x-api-key\"",
        ),
        (
            "protocol",
            "destinations = [\"login.example.com\"]\nprotocol = \"mcp\"",
        ),
        ("string", "destinations = \"login.example.com\""),
        ("empty", "destinations = []"),
        ("number", "destinations = [443]"),
    ] {
        let text = format!("[agent]\ncommand = [\"/usr/bin/true\"]\n[egress.{name}]\n{route}");
        let compiled = scene
            .compile(&profile(&text), None)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let config: toml::Table = compiled.box_toml.parse().expect("box.toml");
        assert!(
            config["egress"].get(name).is_some(),
            "{name}: {}",
            compiled.box_toml
        );
        let routes: toml::Table = text
            .split_once("[egress.")
            .map(|(_, rest)| format!("[{rest}"))
            .and_then(|rest| rest.parse().ok())
            .expect("the route");
        assert!(crate::compile::open_routes(&routes).is_empty(), "{name}");
    }
}

#[test]
fn a_profile_that_adds_a_secret_to_a_pack_route_sends_the_route_to_box_core() {
    let scene = Scene::new();
    scene.share(
        "login",
        "[egress.login]\ndestinations = [\"api.example.com/v1\"]",
    );
    let compiled = scene
        .compile(
            &profile(
                "packs = [\"@box/login\"]\n[agent]\ncommand = [\"/usr/bin/true\"]\n\
                 [egress.login]\nsecret.ref = \"env://KEY\"",
            ),
            None,
        )
        .expect("a route with a secret keeps Box Core's destination forms");
    let config: toml::Table = compiled.box_toml.parse().expect("box.toml");
    assert_eq!(
        config["egress"]["login"]["destinations"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "{}",
        compiled.box_toml
    );
    assert_eq!(
        config["egress"]["login"]["secret"]["ref"].as_str(),
        Some("env://KEY"),
        "{}",
        compiled.box_toml
    );
}

#[test]
fn the_secret_of_a_route_takes_no_when() {
    let scene = Scene::new();
    for os in ["linux", "macos"] {
        for route in [
            format!(
                "[egress.login]\ndestinations = [\"login.example.com\"]\n\
                 [egress.login.secret]\nref = \"env://KEY\"\nwhen = \"{os}\""
            ),
            format!(
                "[egress.login]\ndestinations = [\"login.example.com\"]\n\
                 secret = {{ value = {{ ref = \"env://KEY\" }}, when = \"{os}\" }}"
            ),
        ] {
            scene.share("login", &route);
            let (path, _, reason) = scene.located("packs = [\"@box/login\"]");
            assert_eq!(
                reason,
                "`[egress.login] secret` takes no `when`, because the route without it opens its \
                 hosts with no credential",
                "{route}"
            );
            assert!(
                path.ends_with("packs/login/pack.toml"),
                "{}",
                path.display()
            );
            let (path, _, reason) = scene.located(&route);
            assert!(reason.contains("takes no `when`"), "{route}: {reason}");
            assert_eq!(path, Path::new("test.toml"));
        }
    }
}

#[test]
fn a_when_inside_a_secret_keeps_the_route_in_box_toml() {
    let scene = Scene::new();
    for os in ["linux", "macos"] {
        let text = format!(
            "[agent]\ncommand = [\"/usr/bin/true\"]\n[egress.login]\n\
             destinations = [\"login.example.com\"]\n\
             secret.ref = {{ value = \"env://KEY\", when = \"{os}\" }}"
        );
        let compiled = scene
            .compile(&profile(&text), None)
            .unwrap_or_else(|error| panic!("{os}: {error}"));
        let config: toml::Table = compiled.box_toml.parse().expect("box.toml");
        assert!(
            config["egress"]["login"].get("secret").is_some(),
            "{os}: {}",
            compiled.box_toml
        );
        let egress = config["egress"].as_table().expect("the routes");
        assert!(crate::compile::open_routes(egress).is_empty(), "{os}");
    }
}

#[test]
fn an_input_in_a_destination_needs_a_pattern_or_values() {
    let scene = Scene::new();
    let route = |declaration: &str, value: &str| {
        scene.share(
            "region",
            &format!("[inputs.region]\ndefault = \"us-east-1\"\n{declaration}"),
        );
        format!(
            "packs = [\"@box/region\"]\n{value}\n\
             [agent]\ncommand = [\"/bin/x\"]\n[egress.model]\n\
             destinations = [\"bedrock-runtime.${{{{ inputs.region }}}}.amazonaws.com\"]\n\
             secret.ref = \"env://KEY\""
        )
    };
    let reason = scene.refusal(&route("", ""));
    assert!(
        reason.contains(
            "reaches a route's destinations, so `[inputs.region]` needs `pattern` or `values`"
        ),
        "{reason}"
    );
    for declaration in [
        "values = [\"us-east-1\"]",
        "pattern = \"[a-z]{2}-[a-z]+-[0-9]\"",
    ] {
        let compiled = scene
            .compile(&profile(&route(declaration, "")), None)
            .expect("a checked input");
        assert!(
            compiled
                .policy
                .contains("context.input.host == \"bedrock-runtime.us-east-1.amazonaws.com\""),
            "{}",
            compiled.policy
        );
    }
    for (declaration, why) in [
        ("values = [\"us-east-1\"]", "is not one of us-east-1"),
        (
            "pattern = \"[a-z]{2}-[a-z]+-[0-9]\"",
            "does not match its pattern",
        ),
    ] {
        let text = route(declaration, "[options]\nregion = \"evil.example.com/\"");
        let reason = scene.resolve_refusal(&text);
        assert!(reason.contains(why), "{reason}");
    }
}

#[test]
fn an_input_in_a_backend_url_needs_a_pattern_or_values() {
    let scene = Scene::new();
    let route = |declaration: &str, value: &str| {
        scene.share(
            "gateway",
            &format!("[inputs.gateway.url]\ndefault = \"https://gw.example.com\"\n{declaration}"),
        );
        format!(
            "packs = [\"@box/gateway\"]\n{value}\n\
             [agent]\ncommand = [\"/bin/x\"]\n\
             [egress.model]\ndestinations = [\"model.example.com\"]\nsecret.ref = \"env://KEY\"\n\
             [[egress.model.backends]]\nurl = \"${{{{ inputs.gateway.url }}}}/bedrock\""
        )
    };
    let reason = scene.resolve_refusal(&route("", ""));
    assert!(
        reason.contains(
            "reaches a route's backend url, so `[inputs.gateway.url]` needs `pattern` or `values`"
        ),
        "{reason}"
    );
    for declaration in [
        "values = [\"https://gw.example.com\"]",
        "pattern = \"https://gw[.]example[.]com\"",
    ] {
        let compiled = scene
            .compile(&profile(&route(declaration, "")), None)
            .expect("a checked input");
        let config: toml::Table = compiled.box_toml.parse().expect("box.toml");
        assert_eq!(
            config["egress"]["model"]["backends"][0]["url"].as_str(),
            Some("https://gw.example.com/bedrock"),
            "{}",
            compiled.box_toml
        );
    }
    for (declaration, why) in [
        ("values = [\"https://gw.example.com\"]", "is not one of"),
        (
            "pattern = \"https://gw[.]example[.]com\"",
            "does not match its pattern",
        ),
    ] {
        let text = route(
            declaration,
            "[options]\ngateway.url = \"https://evil.example.com\"",
        );
        let reason = scene.resolve_refusal(&text);
        assert!(reason.contains(why), "{reason}");
    }
}

#[test]
fn an_env_input_fills_a_backend_url() {
    let scene = Scene::new();
    scene.share(
        "gateway",
        "[inputs.gateway.url]\nfrom = \"env:SET\"\npattern = \"[a-z-]+\"",
    );
    let text = "packs = [\"@box/gateway\"]\n\
         [agent]\ncommand = [\"/bin/x\"]\n\
         [egress.model]\ndestinations = [\"model.example.com\"]\nsecret.ref = \"env://KEY\"\n\
         [[egress.model.backends]]\nurl = \"https://${{ inputs.gateway.url }}.example.com/bedrock\"";
    let compiled = scene
        .compile(&profile(text), None)
        .expect("a checked input");
    let config: toml::Table = compiled.box_toml.parse().expect("box.toml");
    assert_eq!(
        config["egress"]["model"]["backends"][0]["url"].as_str(),
        Some("https://set-value.example.com/bedrock"),
        "{}",
        compiled.box_toml
    );
}

#[test]
fn an_input_in_a_backend_aws_region_needs_a_pattern_or_values() {
    let scene = Scene::new();
    let route = |declaration: &str, value: &str| {
        scene.share(
            "region",
            &format!("[inputs.bedrock.region]\ndefault = \"us-east-1\"\n{declaration}"),
        );
        format!(
            "packs = [\"@box/region\"]\n{value}\n\
             [agent]\ncommand = [\"/bin/x\"]\n\
             [egress.model]\ndestinations = [\"model.example.com\"]\n\
             [[egress.model.backends]]\nurl = \"https://gw.example.com/bedrock\"\n\
             auth.ref = \"aws://\"\nauth.aws.service = \"bedrock-agentcore\"\n\
             auth.aws.region = \"${{{{ inputs.bedrock.region }}}}\""
        )
    };
    let reason = scene.resolve_refusal(&route("", ""));
    assert!(
        reason.contains(
            "reaches a route's backend auth.aws.region, so `[inputs.bedrock.region]` needs `pattern` \
             or `values`"
        ),
        "{reason}"
    );
    for declaration in [
        "values = [\"us-east-1\"]",
        "pattern = \"[a-z]{2}-[a-z]+-[0-9]\"",
    ] {
        let compiled = scene
            .compile(&profile(&route(declaration, "")), None)
            .expect("a checked input");
        let config: toml::Table = compiled.box_toml.parse().expect("box.toml");
        assert_eq!(
            config["egress"]["model"]["backends"][0]["auth"]["aws"]["region"].as_str(),
            Some("us-east-1"),
            "{}",
            compiled.box_toml
        );
    }
    for (declaration, why) in [
        ("values = [\"us-east-1\"]", "is not one of"),
        (
            "pattern = \"[a-z]{2}-[a-z]+-[0-9]\"",
            "does not match its pattern",
        ),
    ] {
        let text = route(declaration, "[options]\nbedrock.region = \"US EAST 1\"");
        let reason = scene.resolve_refusal(&text);
        assert!(reason.contains(why), "{reason}");
    }
}

#[test]
fn an_env_input_fills_a_backend_aws_region() {
    let scene = Scene::new();
    scene.share(
        "region",
        "[inputs.bedrock.region]\nfrom = \"env:SET\"\npattern = \"[a-z-]+\"",
    );
    let text = "packs = [\"@box/region\"]\n\
         [agent]\ncommand = [\"/bin/x\"]\n\
         [egress.model]\ndestinations = [\"model.example.com\"]\n\
         [[egress.model.backends]]\nurl = \"https://gw.example.com/bedrock\"\n\
         auth.ref = \"aws://\"\nauth.aws.service = \"bedrock-agentcore\"\n\
         auth.aws.region = \"${{ inputs.bedrock.region }}\"";
    let compiled = scene
        .compile(&profile(text), None)
        .expect("a checked input");
    let config: toml::Table = compiled.box_toml.parse().expect("box.toml");
    assert_eq!(
        config["egress"]["model"]["backends"][0]["auth"]["aws"]["region"].as_str(),
        Some("set-value"),
        "{}",
        compiled.box_toml
    );
}

#[test]
fn a_placeholder_in_a_backend_aws_service_is_refused() {
    let scene = Scene::new();
    let text = "[agent]\ncommand = [\"/bin/x\"]\n\
         [egress.model]\ndestinations = [\"model.example.com\"]\n\
         [[egress.model.backends]]\nurl = \"https://gw.example.com\"\n\
         auth.ref = \"aws://\"\nauth.aws.service = \"${{ home }}\"\nauth.aws.region = \"us-east-1\"";
    let reason = scene.resolve_refusal(text);
    assert!(
        reason.contains("is literal and holds no placeholder"),
        "{reason}"
    );
}

#[test]
fn a_placeholder_in_a_backend_field_other_than_url_is_refused() {
    let scene = Scene::new();
    let text = "[agent]\ncommand = [\"/bin/x\"]\n\
         [egress.model]\ndestinations = [\"model.example.com\"]\nsecret.ref = \"env://KEY\"\n\
         [[egress.model.backends]]\nurl = \"https://gw.example.com\"\n\
         auth = { header = \"${{ home }}\" }";
    let reason = scene.resolve_refusal(text);
    assert!(
        reason.contains("is literal and holds no placeholder"),
        "{reason}"
    );
}

#[test]
fn an_mcp_backend_url_takes_a_bounded_env_input() {
    let scene = Scene::new();
    let server = |declaration: &str| {
        scene.share(
            "gateway",
            &format!("[inputs.gateway.url]\nfrom = \"env:SET\"\n{declaration}"),
        );
        "packs = [\"@box/gateway\"]\n\
         [agent]\ncommand = [\"/bin/x\"]\n\
         [mcp.gw]\ntype = \"http\"\ndestinations = [\"mcp.example.com\"]\n\
         [[mcp.gw.backends]]\nurl = \"https://${{ inputs.gateway.url }}.example.com/mcp\""
            .to_string()
    };
    let reason = scene.resolve_refusal(&server(""));
    assert!(
        reason.contains(
            "reaches a route's backend url, so `[inputs.gateway.url]` needs `pattern` or `values`"
        ),
        "{reason}"
    );
    let compiled = scene
        .compile(&profile(&server("pattern = \"[a-z-]+\"")), None)
        .expect("a checked input");
    let config: toml::Table = compiled.box_toml.parse().expect("box.toml");
    assert_eq!(
        config["mcp"]["gw"]["backends"][0]["url"].as_str(),
        Some("https://set-value.example.com/mcp"),
        "{}",
        compiled.box_toml
    );
}

/// A profile with the target `[telemetry.cw]` of `kind`, whose `field` holds the
/// `cloudwatch.value` input, then `rest`.
fn telemetry_target(kind: &str, field: &str, rest: &str) -> String {
    format!(
        "packs = [\"@box/cloudwatch\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
         [telemetry.cw]\nkind = \"{kind}\"\n{field} = \"box-${{{{ inputs.cloudwatch.value }}}}\"\n\
         {rest}\nsecret.ref = \"aws://default\""
    )
}

/// The pack `@box/telemetry`: `telemetry.text` reads `SET`, `telemetry.url` is a bounded URL,
/// `telemetry.free` is an unbounded URL, and `telemetry.folder` is a folder.
const TELEMETRY_INPUTS: &str = "[inputs.telemetry.text]\nfrom = \"env:SET\"\n\
     [inputs.telemetry.url]\ndefault = \"https://otel.example.com\"\npattern = \"https://[a-z.]+\"\n\
     [inputs.telemetry.free]\ndefault = \"https://anywhere.example.com\"\n\
     [inputs.telemetry.folder]\ndefault = \"/var/log/box\"\n\
     [inputs.telemetry.kind]\ndefault = \"otlp\"";

/// The kinds of a telemetry target that Box Core reads.
const TELEMETRY_KINDS: [&str; 6] = [
    "file",
    "otlp",
    "langfuse",
    "langsmith",
    "cloudwatch_logs",
    "cloudwatch_traces",
];

/// A profile that uses `@box/telemetry`, with `target` as the keys of `[telemetry.cw]`.
fn telemetry_profile(target: &str) -> String {
    format!(
        "packs = [\"@box/telemetry\"]\n[agent]\ncommand = [\"/bin/x\"]\n[telemetry.cw]\n{target}"
    )
}

#[test]
fn a_telemetry_target_of_each_kind_fills_its_settings_from_inputs_and_keeps_a_literal_file_path() {
    let scene = Scene::new();
    scene.share("telemetry", TELEMETRY_INPUTS);
    for kind in TELEMETRY_KINDS {
        let (destination, filled) = if kind == "file" {
            ("/var/log/box/records.jsonl", "/var/log/box/records.jsonl")
        } else {
            (
                "${{ inputs.telemetry.url }}/v1",
                "https://otel.example.com/v1",
            )
        };
        let mut target = format!("kind = \"{kind}\"\ndestination = \"{destination}\"\n");
        for setting in ["project", "region", "log_group", "log_stream"] {
            target.push_str(&format!(
                "{setting} = \"box-${{{{ inputs.telemetry.text }}}}\"\n"
            ));
        }
        let compiled = scene
            .compile(&profile(&telemetry_profile(&target)), None)
            .unwrap_or_else(|error| panic!("{kind}: {error}"));
        let file = table(&compiled);
        let cw = &file["telemetry"]["cw"];
        assert_eq!(cw["destination"].as_str(), Some(filled), "{kind}");
        for setting in ["project", "region", "log_group", "log_stream"] {
            assert_eq!(
                cw[setting].as_str(),
                Some("box-set-value"),
                "{kind} {setting}: {}",
                compiled.box_toml
            );
        }
    }
}

#[test]
fn the_kind_lists_headers_and_secret_of_a_telemetry_target_stay_literal() {
    let scene = Scene::new();
    scene.share("telemetry", TELEMETRY_INPUTS);
    let input = "${{ inputs.telemetry.text }}";
    for kind in TELEMETRY_KINDS {
        for (line, here) in [
            (format!("include = [\"{input}\"]"), "include.0"),
            (format!("accepts = [\"{input}\"]"), "accepts.0"),
            (format!("headers.x-team = \"{input}\""), "headers.x-team"),
            (format!("secret.ref = \"env://{input}\""), "secret.ref"),
            (format!("secret.header = \"{input}\""), "secret.header"),
            (format!("secret.prefix = \"{input}\""), "secret.prefix"),
            (
                format!("secret.placement = \"{input}\""),
                "secret.placement",
            ),
        ] {
            let reason = scene.refusal(&telemetry_profile(&format!("kind = \"{kind}\"\n{line}")));
            assert!(
                reason.contains(&format!(
                    "`telemetry.cw.{here}` is literal and holds no placeholder"
                )),
                "{kind} {here}: {reason}"
            );
        }
    }
    let reason = scene.refusal(&telemetry_profile(
        "kind = \"${{ inputs.telemetry.kind }}\"\ndestination = \"https://otel.example.com\"",
    ));
    assert!(
        reason.contains("`telemetry.cw.kind` is literal and holds no placeholder"),
        "{reason}"
    );
}

#[test]
fn a_telemetry_destination_is_a_bounded_url_and_a_file_destination_is_literal() {
    let scene = Scene::new();
    scene.share("telemetry", TELEMETRY_INPUTS);
    let unbounded = "`inputs.telemetry.free` reaches a telemetry target's `destination`, so \
                     `[inputs.telemetry.free]` needs `pattern` or `values`";
    for kind in TELEMETRY_KINDS.iter().filter(|kind| **kind != "file") {
        let reason = scene.refusal(&telemetry_profile(&format!(
            "kind = \"{kind}\"\ndestination = \"${{{{ inputs.telemetry.free }}}}\""
        )));
        assert!(reason.contains(unbounded), "{kind}: {reason}");
    }
    for target in [
        "destination = \"${{ inputs.telemetry.free }}\"",
        "kind = \"file\"\ndestination = \"/var/log/box/a.jsonl\"\n\
         [telemetry.next]\ndestination = \"${{ inputs.telemetry.free }}\"",
    ] {
        let reason = scene.refusal(&telemetry_profile(target));
        assert!(reason.contains(unbounded), "{target}: {reason}");
    }
    let literal = |text: &str| {
        let reason = scene.refusal(text);
        assert!(
            reason.contains("`telemetry.cw.destination` is literal and holds no placeholder")
                && reason.contains("the `destination` of a telemetry target that is not `file`"),
            "{text}: {reason}"
        );
    };
    for destination in [
        "${{ inputs.telemetry.text }}",
        "${{ inputs.telemetry.url }}",
        "${{ inputs.telemetry.folder }}/a.jsonl",
        "/var/${{ inputs.telemetry.text }}",
        "${{ workspace }}/records.jsonl",
        "${{ home }}/records.jsonl",
    ] {
        literal(&telemetry_profile(&format!(
            "kind = \"file\"\ndestination = \"{destination}\""
        )));
    }
    scene.share("file-kind", "[telemetry.cw]\nkind = \"file\"");
    scene.share(
        "file-path",
        "[telemetry.cw]\ndestination = \"${{ workspace }}/records.jsonl\"",
    );
    scene.share(
        "switch",
        "[inputs.switch.on]\ntype = \"bool\"\ndefault = true",
    );
    let agent = "[agent]\ncommand = [\"/bin/x\"]\n[telemetry.cw]";
    for text in [
        format!(
            "packs = [\"@box/telemetry\", \"@box/file-kind\"]\n{agent}\n\
             destination = \"${{{{ inputs.telemetry.url }}}}\""
        ),
        format!("packs = [\"@box/file-path\"]\n{agent}\nkind = \"file\""),
        format!(
            "packs = [\"@box/switch\"]\n{agent}\nkind = \"file\"\n\
             destination = {{ value = \"${{{{ workspace }}}}/a.jsonl\", \
             when = \"${{{{ inputs.switch.on }}}}\" }}"
        ),
        format!(
            "packs = [\"@box/telemetry\", \"@box/switch\"]\n{agent}\n\
             kind = {{ value = \"file\", when = \"${{{{ inputs.switch.on }}}}\" }}\n\
             destination = \"${{{{ inputs.telemetry.url }}}}\""
        ),
    ] {
        literal(&text);
    }
}

/// Sources like `Fixed`, with each of its variables set as well.
struct Variables(&'static [(&'static str, &'static str)]);

impl Sources for Variables {
    fn env(&self, name: &str) -> Option<String> {
        self.0
            .iter()
            .find(|(variable, _)| *variable == name)
            .map(|(_, value)| value.to_string())
            .or_else(|| Fixed.env(name))
    }

    fn env_with_prefix(&self, prefix: &str) -> Vec<(String, String)> {
        self.0
            .iter()
            .filter(|(variable, _)| variable.starts_with(prefix))
            .map(|(variable, value)| (variable.to_string(), value.to_string()))
            .collect()
    }

    fn program(&mut self, _: &str) -> Option<PathBuf> {
        None
    }

    fn search(&self, _: &str) -> Option<PathBuf> {
        None
    }

    fn developer_dir(&mut self) -> Result<String, String> {
        Fixed.developer_dir()
    }
}

#[test]
fn a_filled_telemetry_project_takes_what_a_header_carries_and_a_log_group_keeps_its_slashes() {
    let scene = Scene::new();
    scene.share(
        "langsmith",
        "[inputs.langsmith.env]\nfrom = \"env:LANGSMITH_PROJECT\"\n\
         [inputs.langsmith.listed]\nfrom = \"env:HEADERS\"\nkey = \"project\"\n\
         [inputs.langsmith.option]\ndescription = \"The project\"\n\
         [inputs.langsmith.group]\nfrom = \"env:LIST\"\nkey = \"group\"",
    );
    let text = |input: &str, before: &str| {
        format!(
            "packs = [\"@box/langsmith\"]\n[agent]\ncommand = [\"/bin/x\"]\n{before}\n\
             [telemetry.ls]\nkind = \"langsmith\"\n\
             project = \"${{{{ inputs.langsmith.{input} }}}}\""
        )
    };
    let logs = "[telemetry.cw]\nkind = \"cloudwatch_logs\"\nregion = \"us-west-2\"\n\
                log_group = \"${{ inputs.langsmith.group }}\"\n\
                log_stream = \"${{ inputs.langsmith.env }}\"";
    const BOT: &str = "Customer Support Bot";
    for (variables, input, before, project) in [
        (&[("LANGSMITH_PROJECT", BOT)][..], "env", logs, BOT),
        (
            &[("HEADERS", "team=a,project=Customer%20Support%20Bot")],
            "listed",
            "",
            BOT,
        ),
        (
            &[],
            "option",
            "[options.langsmith]\noption = \"Customer Support Bot\"",
            BOT,
        ),
        (
            &[],
            "option",
            "[options.langsmith]\noption = \" Customer Support Bot \"",
            " Customer Support Bot ",
        ),
        (
            &[("LANGSMITH_PROJECT", "team/a?b#c%d\\e;f")],
            "env",
            "",
            "team/a?b#c%d\\e;f",
        ),
    ] {
        let (_, compiled) = scene
            .compile_using(
                &profile(&text(input, before)),
                &mut Variables(variables),
                "/usr/bin:/bin",
            )
            .unwrap_or_else(|error| panic!("{input} {project:?}: {error}"));
        let file = table(&compiled);
        assert_eq!(
            file["telemetry"]["ls"]["project"].as_str(),
            Some(project),
            "{}",
            compiled.box_toml
        );
        if !before.is_empty() && input == "env" {
            assert_eq!(
                file["telemetry"]["cw"]["log_group"].as_str(),
                Some("/aws/runtimes/rt-DEFAULT"),
                "{}",
                compiled.box_toml
            );
        }
    }
    let control = "so it cannot hold a control character";
    let outer = "so it cannot start or end with white space";
    for (variables, input, before, value, why) in [
        (
            &[("LANGSMITH_PROJECT", "Bot\u{1b}[31m")][..],
            "env",
            "",
            "Bot\u{1b}[31m",
            control,
        ),
        (
            &[("HEADERS", "project=Support%0ABot")],
            "listed",
            "",
            "Support\nBot",
            control,
        ),
        (
            &[],
            "option",
            "[options.langsmith]\noption = \"Support\\u0007Bot\"",
            "Support\u{7}Bot",
            control,
        ),
        (&[("LANGSMITH_PROJECT", " Bot")], "env", "", " Bot", outer),
        (&[("LANGSMITH_PROJECT", "Bot ")], "env", "", "Bot ", outer),
        (&[("LANGSMITH_PROJECT", "Bot ")], "env", logs, "Bot ", outer),
        (
            &[("HEADERS", "project=Bot%20")],
            "listed",
            "",
            "Bot ",
            outer,
        ),
    ] {
        let reason = match scene.compile_using(
            &profile(&text(input, before)),
            &mut Variables(variables),
            "/usr/bin:/bin",
        ) {
            Err(Error::Profile { reason, .. }) => reason,
            other => panic!("{input} {value:?}: a refusal, not {other:?}"),
        };
        assert!(
            reason.contains(&format!(
                "`telemetry.ls.project`: `inputs.langsmith.{input}` = {value:?} fills a \
                 telemetry target's `project`, {why}"
            )),
            "{input} {value:?} after {before:?}: {reason}"
        );
    }
}

#[test]
fn a_cloudwatch_target_with_an_unset_input_names_the_field_and_the_input() {
    let scene = Scene::new();
    scene.share(
        "cloudwatch",
        "[inputs.cloudwatch.value]\nfrom = \"env:UNSET\"",
    );
    let reason = scene.refusal(&telemetry_target(
        "cloudwatch_logs",
        "log_group",
        "region = \"us-west-2\"\nlog_stream = \"stream\"",
    ));
    assert!(
        reason.contains(
            "`telemetry.cw.log_group`: `inputs.cloudwatch.value` has no value; set \
             `cloudwatch.value` in your profile's `[options]`"
        ),
        "{reason}"
    );
}

/// A profile whose `[telemetry.cw]` reads `cloudwatch.group` and `cloudwatch.stream`, which the
/// pack `@box/cloudwatch` declares in `inputs`.
fn list_target(scene: &Scene, inputs: &str) -> String {
    scene.share("cloudwatch", inputs);
    "packs = [\"@box/cloudwatch\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
     [telemetry.cw]\nkind = \"cloudwatch_logs\"\nregion = \"us-west-2\"\n\
     log_group = \"${{ inputs.cloudwatch.group }}\"\n\
     log_stream = \"${{ inputs.cloudwatch.stream }}\"\nsecret.ref = \"aws://default\""
        .to_string()
}

#[test]
fn an_input_takes_the_value_of_one_key_of_a_list_variable() {
    let scene = Scene::new();
    let text = list_target(
        &scene,
        "[inputs.cloudwatch.group]\nfrom = \"env:LIST\"\nkey = \"group\"\n\
         [inputs.cloudwatch.stream]\nfrom = \"env:LIST\"\nkey = \"stream\"\npattern = \"[a-z-]+\"",
    );
    let resolved = scene.resolve(&profile(&text)).expect("a resolve");
    let inputs: Vec<_> = resolved
        .inputs
        .iter()
        .map(|input| {
            (
                input.name.as_str(),
                input.value.as_str(),
                input.source.as_str(),
            )
        })
        .collect();
    assert!(
        inputs.contains(&("cloudwatch.group", "/aws/runtimes/rt-DEFAULT", "env:LIST")),
        "{inputs:?}"
    );
    assert!(
        inputs.contains(&("cloudwatch.stream", "otel-rt", "env:LIST")),
        "{inputs:?}"
    );
    let compiled = scene.compile(&profile(&text), None).expect("a compile");
    let file = table(&compiled);
    assert_eq!(
        file["telemetry"]["cw"]["log_group"].as_str(),
        Some("/aws/runtimes/rt-DEFAULT"),
        "{}",
        compiled.box_toml
    );
    assert_eq!(
        file["telemetry"]["cw"]["log_stream"].as_str(),
        Some("otel-rt"),
        "{}",
        compiled.box_toml
    );
}

#[test]
fn an_input_from_a_list_variable_is_checked_and_its_error_names_the_variable_and_the_key() {
    let scene = Scene::new();
    let stream = "[inputs.cloudwatch.stream]\ndefault = \"box\"";
    for (group, why) in [
        (
            "from = \"env:LIST\"\nkey = \"group\"\npattern = \"[a-z]+\"",
            "`inputs.cloudwatch.group` = \"/aws/runtimes/rt-DEFAULT\" does not match its pattern",
        ),
        (
            "from = \"env:LIST\"\nkey = \"group\"\nvalues = [\"/aws/other\"]",
            "`inputs.cloudwatch.group` = \"/aws/runtimes/rt-DEFAULT\" is not one of /aws/other",
        ),
        (
            "from = \"env:LIST\"\nkey = \"absent\"",
            "`inputs.cloudwatch.group` has no value: `LIST` holds no value for `absent`; set \
             `cloudwatch.group` in your profile's `[options]`",
        ),
        (
            "from = \"env:UNSET\"\nkey = \"group\"",
            "`inputs.cloudwatch.group` has no value: `UNSET` is not set or is empty, so it \
             holds no value for `group`; set `cloudwatch.group` in your profile's `[options]`",
        ),
        (
            "from = \"env:LIST\"\nkey = \"twice\"",
            "`inputs.cloudwatch.group` reads `twice` from `LIST`, which holds it twice",
        ),
    ] {
        let text = list_target(
            &scene,
            &format!("[inputs.cloudwatch.group]\n{group}\n{stream}"),
        );
        let reason = scene.refusal(&text);
        assert!(reason.contains(why), "{group}: {reason}");
    }
    let text = list_target(
        &scene,
        &format!(
            "[inputs.cloudwatch.group]\nfrom = \"env:LIST\"\nkey = \"absent\"\n\
             default = \"/box/fallback\"\n{stream}"
        ),
    );
    let compiled = scene.compile(&profile(&text), None).expect("a default");
    assert_eq!(
        table(&compiled)["telemetry"]["cw"]["log_group"].as_str(),
        Some("/box/fallback"),
        "a key that the list does not hold falls through to the default: {}",
        compiled.box_toml
    );
}

#[test]
fn two_packs_that_read_different_keys_for_one_input_give_different_sources() {
    let scene = Scene::new();
    scene.share(
        "group-a",
        "[inputs.cloudwatch.group]\nfrom = \"env:LIST\"\nkey = \"group\"",
    );
    let text = list_target(
        &scene,
        "[inputs.cloudwatch.group]\nfrom = \"env:LIST\"\nkey = \"stream\"\n\
         [inputs.cloudwatch.stream]\ndefault = \"box\"",
    )
    .replace(
        "packs = [\"@box/cloudwatch\"]",
        "packs = [\"@box/group-a\", \"@box/cloudwatch\"]",
    );
    let reason = scene.refusal(&text);
    assert!(
        reason.contains(
            "the packs that declare `inputs.cloudwatch.group` give different sources \
             (@box/group-a: \"env:LIST key group\", @box/cloudwatch: \"env:LIST key stream\")"
        ),
        "{reason}"
    );
}

#[test]
fn a_pack_supplies_its_inputs_and_tables_and_the_profile_sets_a_value() {
    let scene = Scene::new();
    scene.share(
        "provider",
        "[inputs.region]\npattern = \"[a-z]{2}-[a-z]+-[0-9]\"\ndefault = \"us-west-2\"\n\
         [agent.env]\nAWS_REGION = \"${{ inputs.region }}\"\n\
         [egress.model]\ndestinations = [\"m.${{ inputs.region }}.example.com\"]\n\
         secret.ref = \"env://KEY\"",
    );
    let compiled = scene
        .compile(
            &profile(
                "packs = [\"@box/provider\"]\n[options]\nregion = \"eu-west-1\"\n\
                 [agent]\ncommand = [\"/usr/bin/true\"]",
            ),
            None,
        )
        .expect("a compile");
    let file = table(&compiled);
    assert_eq!(
        file["agent"]["env"]["AWS_REGION"].as_str(),
        Some("eu-west-1")
    );
    assert_eq!(
        strings(&file["egress"]["model"]["destinations"]),
        ["m.eu-west-1.example.com"]
    );
    for key in ["packs", "options", "inputs", "pack"] {
        assert!(file.get(key).is_none(), "{key}");
    }
    let compiled = scene
        .compile(
            &profile("packs = [\"@box/provider\"]\n[agent]\ncommand = [\"/usr/bin/true\"]"),
            None,
        )
        .expect("a compile");
    assert_eq!(
        table(&compiled)["agent"]["env"]["AWS_REGION"].as_str(),
        Some("us-west-2"),
        "the pack's default"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod on_the_host {
    use super::*;
    use crate::FakeHost;
    use crate::test_support::{brew_program, operator_pack};

    /// The packs `profile` names, without the tool packs that `box` ships.
    fn agent_packs(profile: &Profile) -> Vec<String> {
        let tools = crate::lang::Lookup {
            vendored: Some(crate::resources::source_tree().join("packs")),
            operator: PathBuf::new(),
            collections: Vec::new(),
            version: crate::VERSION,
        }
        .tool_packs();
        profile
            .packs()
            .into_iter()
            .filter(|pack| !tools.contains(pack))
            .collect()
    }

    #[test]
    fn a_created_profile_uses_its_agent_and_provider_packs_and_reads_back() {
        let host = FakeHost::new();
        for (agent, provider) in [("claude", "bedrock"), ("codex", "bedrock-mantle")] {
            let created = host
                .profile()
                .with(agent)
                .with(provider)
                .tools(["cargo", "git", "node", "npm"])
                .create()
                .expect("a profile");
            assert_eq!(created.name(), agent);
            let file: toml::Table = toml::from_str(created.text()).expect("TOML");
            for key in ["name", "box_dir", "workspace", "agent", "storage"] {
                assert!(!file.contains_key(key), "{key}");
            }
            let provider = format!("@box/{provider}");
            assert!(!file.contains_key("options"), "{}", created.text());
            assert_eq!(
                created.profile().packs(),
                [
                    format!("@box/{agent}"),
                    provider.clone(),
                    "@box/cargo".to_string(),
                    "@box/git".to_string(),
                    "@box/node".to_string(),
                    "@box/npm".to_string(),
                ]
            );
            assert!(!file.contains_key("tool"), "{}", created.text());
            assert!(!created.text().contains("${{"), "{}", created.text());
            assert!(
                created
                    .text()
                    .starts_with("# Written by `box profile create`")
            );
            assert_eq!(
                Profile::parse(created.text(), &created.path()).expect("a profile"),
                *created.profile()
            );
            assert_eq!(
                created.path(),
                host.home()
                    .join(".strands/box/profiles")
                    .join(agent)
                    .join("profile.toml")
            );
        }
    }

    #[test]
    fn the_report_lists_one_step_for_each_credential() {
        let host = FakeHost::new();
        operator_pack(
            &host,
            "two",
            "[egress.a]\ndestinations = [\"a.example.com\"]\nsecret.ref = \"env://A\"\n\
             [egress.b]\ndestinations = [\"b.example.com\"]\nsecret.ref = \"aws://dev\"\n",
        );
        let steps = host
            .profile()
            .with("claude")
            .with("two")
            .create()
            .expect("a profile")
            .next_steps(false);
        for expected in [
            "  1. Put the key for a.example.com in A.\n",
            "  2. The b route signs with the AWS profile dev.",
            "  3. Start Claude Code in the box",
        ] {
            assert!(steps.contains(expected), "{expected:?} in\n{steps}");
        }
    }

    #[test]
    fn the_report_names_a_route_that_signs_with_the_default_chain() {
        let host = FakeHost::new();
        operator_pack(
            &host,
            "chain",
            "[egress.b]\ndestinations = [\"b.example.com\"]\nsecret.ref = \"aws://\"\n",
        );
        let steps = host
            .profile()
            .with("claude")
            .with("chain")
            .create()
            .expect("a profile")
            .next_steps(false);
        assert!(
            steps.contains("The b route signs with your default AWS identity."),
            "{steps}"
        );
    }

    #[test]
    fn check_names_each_pack_and_its_version_in_the_order_the_profile_names_them() {
        let host = FakeHost::new();
        host.profile()
            .with("claude")
            .with("anthropic")
            .tools(["cargo", "git", "node", "npm"])
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let preview = host
            .launcher()
            .preview("claude", &host.project())
            .expect("a preview");
        assert_eq!(
            preview.pack_list(),
            "@box/claude 1, @box/base 1, @box/anthropic 1, @box/cargo 1, @box/git 1, @box/node 1, \
             @box/npm 1"
        );
    }

    #[test]
    fn a_report_records_an_agent_the_host_lacks() {
        let host = FakeHost::new();
        host.uninstall_claude();
        let created = host
            .profile()
            .with("claude")
            .with("bedrock")
            .create()
            .expect("a profile with no agent on the host");
        assert!(
            created
                .summary(false)
                .contains("Claude Code is not on this host now"),
            "{}",
            created.summary(false)
        );
        assert!(
            created
                .guided_summary(false)
                .contains("Claude Code is not on this host. Install it before running."),
            "{}",
            created.guided_summary(false)
        );
    }

    #[test]
    fn a_set_row_points_each_run_at_its_own_box_and_show_names_keys_only() {
        let host = FakeHost::new();
        let folder = host.home().join(".strands/box/profiles/pi");
        std::fs::create_dir_all(&folder).expect("a folder");
        std::fs::write(
            folder.join("profile.toml"),
            "[agent]\ncommand = [\"/usr/bin/true\"]\n[storage]\ndirectories = [\"agent\"]\n\
             [[storage.files]]\nsource = \"${{ home }}/.pi/agent/settings.json\"\n\
             target = \"agent/settings.json\"\nkind = \"json\"\n\
             keep = [[\"defaultModel\"], [\"theme\"]]\n\
             [[storage.files.set]]\nkey = [\"shellPath\"]\nvalue = \"${{ box }}/bin/bash\"\n",
        )
        .expect("a profile");
        let pi = host.home().join(".pi/agent");
        std::fs::create_dir_all(&pi).expect("a folder");
        std::fs::write(
            pi.join("settings.json"),
            r#"{"defaultModel": "opus", "shellPath": "/opt/homebrew/bin/bash", "token": "sk-1"}"#,
        )
        .expect("settings");
        let preview = host
            .launcher()
            .preview("pi", &host.project())
            .expect("a preview");
        let part = |what: &str, names: &[&str]| {
            (
                what.to_string(),
                "agent/agent/settings.json".to_string(),
                names
                    .iter()
                    .map(|name| vec![name.to_string()])
                    .collect::<Vec<_>>(),
            )
        };
        assert_eq!(
            preview.parts,
            vec![
                part("keeps", &["defaultModel"]),
                part("drops", &["shellPath", "token"]),
                part("missing", &["theme"]),
                part("sets", &["shellPath"]),
            ]
        );
        assert!(
            !format!("{:?}", preview.parts).contains("sk-1"),
            "show prints no value"
        );
        let copy =
            storage_root(&host.home().join(".strands/box"), "pi").join("agent/agent/settings.json");
        let shell = || {
            let text = std::fs::read_to_string(&copy).expect("read");
            let value: serde_json::Value = serde_json::from_str(&text).expect("JSON");
            assert!(
                !text.contains("sk-1"),
                "a dropped key never reaches storage"
            );
            value["shellPath"].as_str().expect("a shell").to_string()
        };
        host.launcher()
            .prepare("pi", &host.project(), None)
            .expect("a first launch");
        let first = shell();
        host.launcher()
            .prepare("pi", &host.project(), None)
            .expect("a second launch");
        let second = shell();
        assert!(first.ends_with("/box/bin/bash"), "{first}");
        assert!(second.ends_with("/box/bin/bash"), "{second}");
        assert_ne!(first, second, "each run points at its own box");
        let preview = host
            .launcher()
            .preview("pi", &host.project())
            .expect("a preview");
        assert_eq!(
            preview.parts,
            vec![part("sets", &["shellPath"])],
            "keep applies once, set on every run"
        );
    }

    #[test]
    fn a_resolve_error_names_the_profile_file() {
        let host = FakeHost::new();
        let folder = host.home().join(".strands/box/profiles/unset");
        std::fs::create_dir_all(&folder).expect("a folder");
        std::fs::write(
            folder.join("profile.toml"),
            "packs = [\"unset\"]\n[agent]\ncommand = [\"/usr/bin/true\"]\n\
             env.X = \"${{ inputs.unset }}\"\n",
        )
        .expect("a profile");
        let pack = host.home().join(".strands/box/packs/unset");
        std::fs::create_dir_all(&pack).expect("an operator pack folder");
        std::fs::write(
            pack.join("pack.toml"),
            "[pack]\nname = \"unset\"\nversion = 1\nkind = \"support\"\n\
             [inputs.unset]\nfrom = \"env:BOX_TEST_UNSET\"\n",
        )
        .expect("an operator pack");
        let error = host
            .launcher()
            .prepare("unset", &host.project(), None)
            .expect_err("an unset variable");
        assert!(
            error
                .to_string()
                .starts_with(&folder.join("profile.toml").display().to_string()),
            "{error}"
        );
        assert!(
            error.to_string().contains("`inputs.unset` has no value"),
            "{error}"
        );
    }

    #[test]
    fn a_created_profile_is_not_replaced_without_force() {
        let host = FakeHost::new();
        let created = host
            .profile()
            .with("claude")
            .with("bedrock")
            .create()
            .expect("a profile");
        created.write(false).expect("a first write");
        created
            .write(false)
            .expect("an unchanged profile is left alone");
        let path = created.path();
        std::fs::write(&path, "# edited\n").expect("an edit");
        assert!(
            matches!(created.write(false), Err(Error::Exists { path: existing }) if existing == path)
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("an edit"),
            "# edited\n"
        );
        created.write(true).expect("a forced write");
        assert_eq!(
            std::fs::read_to_string(&path).expect("a profile"),
            created.text()
        );
        let profiles = Profiles::at(host.home().join(".strands/box/profiles"));
        let (profile, policy) = profiles.load("claude").expect("a load").expect("a profile");
        assert_eq!(profile, *created.profile());
        assert_eq!(policy, None, "an empty policy is not written");
    }

    #[test]
    fn a_created_profile_names_the_help_topic_and_holds_no_guide_copy() {
        let host = FakeHost::new();
        let created = host
            .profile()
            .with("claude")
            .with("bedrock")
            .create()
            .expect("a profile");
        let copy = created.folder().join("editing-box-profile.md");
        for force in [false, true] {
            created.write(force).expect("a write");
            assert!(!copy.exists(), "creation writes no guide");
        }
        assert!(
            !host
                .home()
                .join(".strands/box/editing-box-profile.md")
                .exists()
        );
        let text = std::fs::read_to_string(created.path()).expect("a profile");
        assert!(
            text.lines().any(|line| line
                == "# For help from a coding agent, tell it: Run box help agent and follow it."),
            "{text}"
        );
        assert_eq!(
            Profile::parse(&text, &created.path()).expect("a profile"),
            *created.profile()
        );
        std::fs::write(&copy, "an old copy\n").expect("a copy from an older box");
        std::fs::remove_file(created.path()).expect("a removed profile");
        for force in [false, true] {
            created
                .write(force)
                .expect("an old copy does not stop a write");
            assert_eq!(
                std::fs::read_to_string(&copy).expect("the old copy"),
                "an old copy\n"
            );
        }
    }

    #[test]
    fn the_editing_guide_depends_on_no_other_document() {
        let skill = include_str!("../../../../resources/editing-box-profile.md");
        let mut fenced = false;
        let prose = skill
            .lines()
            .filter(|line| {
                if line.starts_with("```") {
                    fenced = !fenced;
                    false
                } else {
                    !fenced
                }
            })
            .collect::<Vec<_>>();
        let anchors: std::collections::BTreeSet<String> = prose
            .iter()
            .filter(|line| line.starts_with('#'))
            .map(|line| {
                line.trim_start_matches('#')
                    .trim()
                    .to_lowercase()
                    .chars()
                    .filter(|ch| ch.is_alphanumeric() || matches!(ch, ' ' | '-' | '_'))
                    .map(|ch| if ch == ' ' { '-' } else { ch })
                    .collect()
            })
            .collect();
        let links = regex::Regex::new(r"\]\(([^)]*)\)").expect("a link pattern");
        for link in links.captures_iter(&prose.join("\n")) {
            let destination = &link[1];
            let anchor = destination.strip_prefix('#').unwrap_or_else(|| {
                panic!("the editing guide depends on another document: {destination}")
            });
            assert!(
                anchors.contains(anchor),
                "the editing guide has no section for {destination}"
            );
        }
    }

    #[test]
    fn an_existing_profile_is_checked_before_writing_the_policy_copy() {
        let host = FakeHost::new();
        let created = host
            .profile()
            .with("claude")
            .with("bedrock")
            .policy("open")
            .create()
            .expect("a profile");
        std::fs::create_dir_all(created.folder()).expect("a profile folder");
        let profile = created.path();
        std::fs::write(&profile, "# operator profile\n").expect("an existing profile");
        assert!(
            matches!(created.write(false), Err(Error::Exists { path }) if path == profile),
            "creation refuses the conflicting profile"
        );
        assert!(
            !created.policy_path().expect("a policy copy").exists(),
            "the policy was not partly written"
        );
        assert_eq!(
            std::fs::read_to_string(profile).expect("the existing profile"),
            "# operator profile\n"
        );
    }

    fn created_claude(host: &FakeHost) {
        host.profile()
            .with("claude")
            .with("bedrock")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
    }

    /// The run directory of `launch`: the folder that holds its `box.toml`.
    fn run_directory(launch: &crate::run::Launch) -> PathBuf {
        launch
            .config()
            .parent()
            .expect("a run directory")
            .to_path_buf()
    }

    #[test]
    fn every_launch_gives_box_core_its_own_box_id() {
        let host = FakeHost::new();
        created_claude(&host);
        let first = host
            .launcher()
            .prepare("claude", &host.project(), None)
            .expect("a launch");
        let name = first.name().to_string();
        assert_eq!(first.run_options().box_id.as_deref(), Some(name.as_str()));
        drop(first);
        let again = host
            .launcher()
            .prepare("claude", &host.project(), Some(&name))
            .expect("the same run again");
        assert_eq!(again.run_options().box_id.as_deref(), Some(name.as_str()));
    }

    #[test]
    fn a_run_starts_its_tools_folders_empty_and_makes_nothing_in_the_project() {
        let host = FakeHost::new();
        created_claude(&host);
        let first = host
            .launcher()
            .prepare("claude", &host.project(), None)
            .expect("a launch");
        let run = run_directory(&first);
        let name = first.name().to_string();
        for tool in ["cargo", "git", "node", "npm"] {
            let folder = run.join("tool-tmp").join(tool);
            assert!(folder.is_dir(), "{}", folder.display());
            assert_eq!(
                std::fs::read_dir(&folder).expect("list").count(),
                0,
                "{tool}"
            );
        }
        drop(first);
        let left = run.join("tool-tmp/git");
        std::fs::create_dir_all(left.join("sub")).expect("a folder from the earlier run");
        std::fs::write(left.join("sub/left.txt"), "an earlier run").expect("a file");
        let outside = host.home().join("kept");
        std::fs::create_dir_all(&outside).expect("a folder outside the run");
        std::fs::write(outside.join("kept.txt"), "not box's").expect("a file");
        std::os::unix::fs::symlink(&outside, left.join("link")).expect("a link");
        let again = host
            .launcher()
            .prepare("claude", &host.project(), Some(&name))
            .expect("the same run again");
        assert_eq!(run_directory(&again), run);
        assert_eq!(
            std::fs::read_dir(&left).expect("list").count(),
            0,
            "git's folder starts empty"
        );
        assert!(
            outside.join("kept.txt").is_file(),
            "nothing is removed through a link"
        );
        assert!(!host.project().join(".tmp").exists());
        assert!(!host.project().join("tool-tmp").exists());
    }

    #[test]
    fn a_second_runs_prepare_leaves_a_live_runs_files_alone() {
        let host = FakeHost::new();
        created_claude(&host);
        let first = host
            .launcher()
            .prepare("claude", &host.project(), None)
            .expect("a first run");
        let script = run_directory(&first).join("tool-tmp/git/activate.sh");
        std::fs::write(&script, "echo live").expect("a live run's file");
        let other = host.home().join("work/other");
        std::fs::create_dir_all(&other).expect("a second project");
        let second = host
            .launcher()
            .prepare("claude", &other, None)
            .expect("a second run");
        assert_ne!(
            run_directory(&first),
            run_directory(&second),
            "each run has its own folders"
        );
        assert!(
            script.is_file(),
            "the second run leaves the first run's files alone"
        );
    }

    #[test]
    fn a_link_at_a_tools_folder_is_refused() {
        let host = FakeHost::new();
        created_claude(&host);
        let first = host
            .launcher()
            .prepare("claude", &host.project(), None)
            .expect("a launch");
        let run = run_directory(&first);
        let name = first.name().to_string();
        drop(first);
        let folder = run.join("tool-tmp/git");
        std::fs::remove_dir_all(&folder).expect("remove git's folder");
        let target = host.home().join("elsewhere");
        std::fs::create_dir_all(&target).expect("a target");
        std::fs::write(target.join("kept.txt"), "not box's").expect("a file");
        std::os::unix::fs::symlink(&target, &folder).expect("a link");
        let error = host
            .launcher()
            .prepare("claude", &host.project(), Some(&name))
            .expect_err("a link at a tool's folder");
        assert!(matches!(error, Error::Symlink { .. }), "{error}");
        assert!(
            target.join("kept.txt").is_file(),
            "nothing is deleted through the link"
        );
    }

    #[test]
    fn a_run_and_the_trial_harness_compile_the_same_tables() {
        let host = FakeHost::new();
        host.profile()
            .with("claude")
            .with("bedrock")
            .policy("open")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let launch = host
            .launcher()
            .prepare("claude", &host.project(), None)
            .expect("a launch");
        let mut run: toml::Value =
            toml::from_str(&std::fs::read_to_string(launch.config()).expect("read")).expect("TOML");
        let mut trial: toml::Value = toml::from_str(
            host.trial()
                .with("claude")
                .with("bedrock")
                .generate()
                .expect("a configuration")
                .box_toml(),
        )
        .expect("TOML");
        for file in [&mut run, &mut trial] {
            let env = file["agent"]["env"].as_table_mut().expect("env");
            env.remove("TERM");
            env.remove("COLORTERM");
        }
        // A table's settings, with each run's own box folder and run directory masked.
        let tables = |file: &toml::Value, key: &str| {
            let folder = file["box_dir"].as_str().expect("a box folder");
            let run = Path::new(folder)
                .parent()
                .expect("the run's directory")
                .display()
                .to_string();
            toml::to_string(&file[key])
                .expect("TOML")
                .replace(folder, "<box>")
                .replace(&run, "<run>")
        };
        for key in ["agent", "tool", "egress"] {
            assert_eq!(tables(&run, key), tables(&trial, key), "{key}");
        }
        assert_ne!(run["name"], trial["name"]);
        assert_ne!(run["box_dir"], trial["box_dir"]);
    }

    #[test]
    fn three_runs_of_one_profile_get_three_boxes_and_share_storage() {
        let host = FakeHost::new();
        host.profile()
            .with("claude")
            .with("bedrock")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let launches: Vec<_> = (0..3)
            .map(|_| {
                host.launcher()
                    .prepare("claude", &host.project(), None)
                    .expect("a launch")
            })
            .collect();
        let mut box_directories = Vec::new();
        for launch in &launches {
            let file: toml::Value =
                toml::from_str(&std::fs::read_to_string(launch.config()).expect("read"))
                    .expect("TOML");
            assert!(launch.config().with_file_name("policy.dw").is_file());
            assert!(storage_root(&host.home().join(".strands/box"), "claude").is_dir());
            box_directories.push(file["box_dir"].as_str().expect("a box_dir").to_string());
        }
        box_directories.sort();
        box_directories.dedup();
        assert_eq!(box_directories.len(), 3, "{box_directories:?}");
        let storage = storage_root(&host.home().join(".strands/box"), "claude");
        for directory in ["config", "tmp"] {
            let made = storage.join("agent").join(directory);
            assert!(made.is_dir(), "{}", made.display());
            let mode = std::fs::metadata(&made).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{}", made.display());
        }
        let made: Vec<_> = std::fs::read_dir(host.project())
            .expect("list")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        if cfg!(target_os = "linux") {
            assert_eq!(
                made,
                vec![".box".to_string()],
                "on Linux box makes only .box"
            );
            assert_eq!(
                std::fs::read_dir(host.project().join(".box"))
                    .expect("list")
                    .count(),
                0,
                "the .box that box makes is empty"
            );
        } else {
            assert!(
                made.is_empty(),
                "box creates no file in the workspace: {made:?}"
            );
        }
    }

    #[test]
    fn a_linked_project_configuration_is_refused() {
        let host = FakeHost::new();
        host.profile()
            .with("claude")
            .with("bedrock")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let configuration = host.project().join(".box");
        let elsewhere = host.home().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("a directory");
        std::os::unix::fs::symlink(&elsewhere, &configuration).expect("a link");
        let error = host
            .launcher()
            .prepare("claude", &host.project(), None)
            .expect_err("a refusal");
        assert!(
            matches!(error, Error::ProjectConfiguration { .. }),
            "{error}"
        );
        std::fs::remove_file(&configuration).expect("remove");
        std::fs::write(&configuration, "").expect("a file");
        assert!(matches!(
            host.launcher().prepare("claude", &host.project(), None),
            Err(Error::ProjectConfiguration { .. })
        ));
        std::fs::remove_file(&configuration).expect("remove");
        std::fs::create_dir(&configuration).expect("a directory");
        host.launcher()
            .prepare("claude", &host.project(), None)
            .expect("a real directory is accepted");
        let runs = host.home().join(".strands/box/r");
        assert_eq!(
            std::fs::read_dir(&runs).expect("list").count(),
            1,
            "a refused run leaves no run directory"
        );
    }

    /// A box home outside the operator home, as `BOX_HOME` sets it.
    fn moved_box_home(host: &FakeHost) -> PathBuf {
        let moved = host.scratch().with_file_name("try").join("home");
        std::fs::create_dir_all(&moved).expect("a moved box home");
        moved
    }

    fn moved_profile(host: &FakeHost, moved: &Path) -> crate::NewProfile {
        host.profile()
            .box_home(moved)
            .profiles(moved.join("profiles"))
    }

    #[test]
    fn profile_creation_refuses_a_linked_strands_folder() {
        let host = FakeHost::new();
        let created = host
            .profile()
            .with("claude")
            .with("bedrock")
            .create()
            .expect("a profile");
        let target = host.home().join("elsewhere");
        std::fs::create_dir(&target).expect("a target");
        let strands = host.home().join(".strands");
        std::os::unix::fs::symlink(&target, &strands).expect("a linked Strands folder");
        let error = created.write(false).expect_err("a linked Strands folder");
        assert!(matches!(error, Error::Symlink { path } if path == strands));
        assert_eq!(std::fs::read_dir(&target).expect("list").count(), 0);
    }

    #[test]
    fn a_moved_box_home_refuses_a_linked_profiles_folder() {
        let host = FakeHost::new();
        let moved = moved_box_home(&host);
        let victim = host.home().join("victim");
        std::fs::create_dir_all(&victim).expect("a victim folder");
        std::os::unix::fs::symlink(&victim, moved.join("profiles")).expect("a link");
        let error = moved_profile(&host, &moved)
            .with("claude")
            .with("bedrock")
            .create()
            .and_then(|created| created.write(false))
            .expect_err("a linked profiles folder");
        assert!(matches!(error, Error::Symlink { .. }), "{error}");
        assert_eq!(std::fs::read_dir(&victim).expect("list").count(), 0);
    }

    #[test]
    fn a_moved_box_home_refuses_a_linked_storage_directory() {
        let host = FakeHost::new();
        let moved = moved_box_home(&host);
        moved_profile(&host, &moved)
            .with("claude")
            .with("bedrock")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let elsewhere = host.home().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("a directory");
        std::os::unix::fs::symlink(&elsewhere, moved.join("storage")).expect("a link");
        let error = host
            .launcher()
            .box_home(&moved)
            .prepare("claude", &host.project(), None)
            .expect_err("a refusal");
        assert!(matches!(error, Error::Symlink { .. }), "{error}");
        assert_eq!(std::fs::read_dir(&elsewhere).expect("list").count(), 0);
        assert!(!host.home().join(".strands/box").exists());
    }

    #[test]
    fn a_moved_box_home_takes_profiles_storage_and_mcp_imports() {
        let host = FakeHost::new();
        let moved = moved_box_home(&host);
        std::fs::write(
            host.home().join(".claude.json"),
            r#"{"mcpServers": {"remote": {"url": "https://remote.example.com/mcp"}}}"#,
        )
        .expect("host config");
        moved_profile(&host, &moved)
            .with("claude")
            .option("claude.import-mcp", "true")
            .with("bedrock")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        assert!(moved.join("profiles/claude/profile.toml").is_file());
        let launch = host
            .launcher()
            .box_home(&moved)
            .prepare("claude", &host.project(), None)
            .expect("a launch");
        assert_eq!(launch.mcp_imports().len(), 1, "{:?}", launch.mcp_imports());
        assert!(
            storage_root(&moved, "claude")
                .join("agent/config/.claude.json")
                .is_file()
        );
        assert!(run_directory(&launch).starts_with(moved.join("r")));
        assert!(!host.home().join(".strands/box").exists());
    }

    #[test]
    fn a_linked_storage_directory_is_refused() {
        let host = FakeHost::new();
        host.profile()
            .with("claude")
            .with("bedrock")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let storage = storage_root(&host.home().join(".strands/box"), "claude");
        std::fs::create_dir_all(storage.join("agent")).expect("a storage root");
        let elsewhere = host.home().join(".claude");
        std::fs::create_dir_all(&elsewhere).expect("a directory");
        std::os::unix::fs::symlink(&elsewhere, storage.join("agent/config")).expect("a link");
        let error = host
            .launcher()
            .prepare("claude", &host.project(), None)
            .expect_err("a refusal");
        assert!(matches!(error, Error::Symlink { .. }), "{error}");
        let runs = host.home().join(".strands/box/r");
        assert_eq!(
            std::fs::read_dir(&runs).expect("list").count(),
            0,
            "a run refused after its instance was minted leaves no run directory"
        );
    }

    #[test]
    fn a_missing_profile_names_the_command_that_creates_it() {
        let host = FakeHost::new();
        for (name, hints) in [
            ("codex", vec!["Create it with `box profile create codex`."]),
            (
                "mine",
                vec![
                    "isn't a starter, so box can't tell which agent it runs. Create the profile from one of these starters:",
                    "  box profile create mine --with claude   Claude Code",
                    "  box profile create mine --with codex    Codex",
                ],
            ),
        ] {
            let error = host
                .launcher()
                .prepare(name, &host.project(), None)
                .expect_err("no profile");
            assert!(matches!(error, Error::ProfileMissing { .. }), "{error}");
            let text = error.to_string();
            for hint in hints {
                assert!(text.contains(hint), "{text}");
            }
        }
        assert!(!host.home().join(".strands/box/profiles/codex").exists());
    }

    #[test]
    fn a_starter_that_your_pack_shadows_is_named_in_full_and_is_not_a_starter_name() {
        let host = FakeHost::new();
        let folder = host.home().join(".strands/box/packs/codex");
        std::fs::create_dir_all(&folder).expect("a pack folder");
        std::fs::write(
            folder.join(crate::lang::PACK_FILE),
            "\n[pack]\nname = \"codex\"\nversion = 1\nkind = \"agent\"\nextend = [\"@box/codex\"]",
        )
        .expect("a pack");
        assert!(!host.launcher().is_starter("codex").expect("a menu"));
        assert!(host.launcher().is_starter("claude").expect("a menu"));
        let names: Vec<String> = host
            .launcher()
            .starters()
            .expect("the starters")
            .into_iter()
            .map(|starter| starter.name)
            .collect();
        assert_eq!(names, ["claude", "@box/codex", "kiro"]);
        let text = host
            .launcher()
            .prepare("codex", &host.project(), None)
            .expect_err("no profile")
            .to_string();
        assert!(text.contains("codex isn't a starter"), "{text}");
        assert!(
            !text.contains("Create it with `box profile create codex`."),
            "{text}"
        );
        let error = host
            .launcher()
            .prepare("mine", &host.project(), None)
            .expect_err("no profile");
        let text = error.to_string();
        assert!(
            text.contains("  box profile create mine --with @box/codex   Codex"),
            "{text}"
        );
        assert!(
            text.contains("  box profile create mine --with claude       Claude Code"),
            "{text}"
        );
    }

    #[test]
    fn profile_list_reports_each_profile_and_an_invalid_one() {
        let host = FakeHost::new();
        host.profile()
            .with("claude")
            .with("bedrock")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let profiles = Profiles::at(host.home().join(".strands/box/profiles"));
        std::fs::create_dir_all(profiles.folder("broken")).expect("a folder");
        std::fs::write(profiles.path("broken"), "name = \"x\"\n").expect("a file");
        let listed = profiles.list().expect("a list");
        let names: Vec<&str> = listed.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, ["broken", "claude"]);
        assert!(listed[0].profile.is_err());
        assert_eq!(
            agent_packs(listed[1].profile.as_ref().expect("a profile")),
            ["@box/claude", "@box/bedrock"]
        );
    }

    #[test]
    fn policy_references_refuse_workspace_files_in_preview_and_run() {
        let host = FakeHost::new();
        let profiles = Profiles::at(host.home().join(".strands/box/profiles"));
        let folder = profiles.folder("claude");
        std::fs::create_dir_all(&folder).expect("profile folder");
        let outside = host.project().join("rules.dw");
        std::fs::write(
            &outside,
            "@id(\"planted\") permit (principal, action, resource);",
        )
        .expect("workspace policy");
        std::fs::hard_link(&outside, folder.join("linked.dw")).expect("hard link");
        for (reference, expected) in [
            (outside.to_str().unwrap(), "profile folder"),
            ("linked.dw", "hard link"),
        ] {
            std::fs::write(
                profiles.path("claude"),
                format!("policies = [{reference:?}]\n{MINIMAL}"),
            )
            .expect("profile");
            for (operation, result) in [
                (
                    "preview",
                    host.launcher()
                        .preview("claude", &host.project())
                        .map(|_| ()),
                ),
                (
                    "prepare",
                    host.launcher()
                        .prepare("claude", &host.project(), None)
                        .map(|_| ()),
                ),
            ] {
                let Err(Error::Profile { reason, .. }) = result else {
                    panic!("{operation}: an unsafe policy refusal, not {result:?}");
                };
                assert!(reason.contains(expected), "{operation}: {reason}");
            }
            assert_nothing_left(&host);
        }
    }

    #[test]
    fn policy_references_join_files_cleanly_in_preview_and_run() {
        let host = FakeHost::new();
        let profiles = Profiles::at(host.home().join(".strands/box/profiles"));
        let folder = profiles.folder("test");
        std::fs::create_dir_all(&folder).expect("profile folder");
        let first = "\t// literal ${{ workspace }}\r\n@id(\"one\") permit (principal, action, resource);  \r\n\r\n\t// final comment";
        let second = "  @id(\"two\") forbid (principal, action, resource);\t";
        std::fs::write(folder.join("empty.dw"), "").expect("empty policy");
        std::fs::write(folder.join("whitespace.dw"), " \r\n\t\n  ").expect("blank policy");
        let preview_and_run = || {
            let preview = host
                .launcher()
                .preview("test", &host.project())
                .expect("preview");
            let launch = host
                .launcher()
                .prepare("test", &host.project(), None)
                .expect("run");
            let written = std::fs::read_to_string(launch.config().with_file_name("policy.dw"))
                .expect("written policy");
            assert_eq!(preview.policy, written);
            let config: toml::Table = toml::from_str(&preview.box_toml).expect("engine config");
            assert!(!config.contains_key("policies"), "{config:?}");
            written
        };
        std::fs::write(
            profiles.path("test"),
            format!(
                "policies = [\"empty.dw\", \"one.dw\", \"whitespace.dw\", \"two.dw\"]\n{MINIMAL}\n\
                 [project]\naccess = \"write\"\n"
            ),
        )
        .expect("profile");
        let expected = format!("{first}\n\n{second}\n\n@id(\"box_home_write\")");
        for padding in ["", "\n", "\n\n\n", "\r\n \t\r\n"] {
            std::fs::write(folder.join("one.dw"), format!("{padding}{first}{padding}"))
                .expect("first policy");
            std::fs::write(folder.join("two.dw"), format!("{padding}{second}{padding}"))
                .expect("second policy");
            let policy = preview_and_run();
            assert!(policy.starts_with(&expected), "{padding:?}: {policy:?}");
            assert!(policy.contains("@id(\"project_read\") permit"), "{policy}");
            assert!(policy.ends_with(";\n"), "{policy:?}");
        }

        std::fs::write(profiles.path("test"), MINIMAL).expect("no policies");
        let generated = preview_and_run();
        for policies in ["[]", "[\"empty.dw\", \"whitespace.dw\"]"] {
            std::fs::write(
                profiles.path("test"),
                format!("policies = {policies}\n{MINIMAL}"),
            )
            .expect("empty policies");
            assert_eq!(preview_and_run(), generated, "{policies}");
        }
    }

    #[test]
    fn policy_references_refuse_duplicate_ids_across_files_before_a_run() {
        let host = FakeHost::new();
        let profiles = Profiles::at(host.home().join(".strands/box/profiles"));
        let folder = profiles.folder("test");
        std::fs::create_dir_all(&folder).expect("profile folder");
        std::fs::write(
            profiles.path("test"),
            format!("policies = [\"one.dw\", \"two.dw\"]\n{MINIMAL}"),
        )
        .expect("profile");
        for file in ["one.dw", "two.dw"] {
            std::fs::write(
                folder.join(file),
                "@id(\"repeated\") permit (principal, action, resource);",
            )
            .expect("policy");
        }
        for (operation, result) in [
            (
                "preview",
                host.launcher().preview("test", &host.project()).map(|_| ()),
            ),
            (
                "prepare",
                host.launcher()
                    .prepare("test", &host.project(), None)
                    .map(|_| ()),
            ),
        ] {
            let Err(Error::Policy { findings }) = result else {
                panic!("{operation}: a duplicate rule refusal, not {result:?}");
            };
            let [finding] = findings.as_slice() else {
                panic!("{operation}: one finding, not {findings:?}");
            };
            assert_eq!(finding.path, Path::new("policy.dw"), "{operation}");
            assert_eq!(finding.line, None, "{operation}");
            assert!(
                finding
                    .reason
                    .starts_with("rule 1 (@id \"repeated\"), rule 2 (@id \"repeated\"): "),
                "{operation}: {}",
                finding.reason
            );
        }
        assert!(host.launcher().runs().expect("runs").is_empty());
    }

    #[test]
    fn a_profile_policy_that_reuses_a_generated_rule_id_is_refused_before_the_engine_runs() {
        let host = FakeHost::new();
        let file = claude_with_policy(&host, "");
        for id in [
            "box_home_write",
            "project_read",
            "project_configuration_write",
            "package_hosts_connect",
            "package_hosts_request",
        ] {
            std::fs::write(
                &file,
                format!("// mine\n@id({id:?}) permit (principal, action, resource);\n"),
            )
            .expect("a policy");
            for (operation, result) in [
                (
                    "preview",
                    host.launcher()
                        .preview("claude", &host.project())
                        .map(|_| ()),
                ),
                (
                    "prepare",
                    host.launcher()
                        .prepare("claude", &host.project(), None)
                        .map(|_| ()),
                ),
            ] {
                let Err(Error::Policy { findings }) = result else {
                    panic!("{operation}, {id}: a refusal, not {result:?}");
                };
                let [finding] = findings.as_slice() else {
                    panic!("{operation}, {id}: one finding, not {findings:?}");
                };
                assert_eq!(
                    (finding.path.as_path(), finding.line),
                    (Path::new("policy.dw"), None),
                    "{operation}, {id}"
                );
                assert!(
                    finding
                        .reason
                        .starts_with(&format!("rule 1 (@id {id:?}), rule ")),
                    "{}",
                    finding.reason
                );
                assert!(
                    finding.reason.ends_with(&format!(
                        "; box writes a rule with the id {id:?}, so give your rule another id"
                    )),
                    "{}",
                    finding.reason
                );
            }
        }
        std::fs::write(
            &file,
            "@id(\"a\") permit (principal, action, resource);\n\n\
             @id(\"a\") forbid (principal, action, resource);\n",
        )
        .expect("a policy");
        let Err(Error::Policy { findings }) = host.launcher().preview("claude", &host.project())
        else {
            panic!("a refusal");
        };
        let [finding] = findings.as_slice() else {
            panic!("one finding, not {findings:?}");
        };
        assert_eq!(
            (finding.path.as_path(), finding.line),
            (Path::new("policy.dw"), None)
        );
        assert!(
            finding
                .reason
                .starts_with("rule 1 (@id \"a\"), rule 2 (@id \"a\"): "),
            "{}",
            finding.reason
        );
        assert!(!finding.reason.contains("box writes"), "{}", finding.reason);
        assert!(host.launcher().runs().expect("runs").is_empty());
    }

    /// A `claude` profile on `host` whose `policy.dw` is `policy`.
    fn claude_with_policy(host: &FakeHost, policy: &str) -> PathBuf {
        host.profile()
            .with("claude")
            .with("bedrock")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let path = host
            .home()
            .join(".strands/box/profiles/claude/profile.toml");
        let text = std::fs::read_to_string(&path).expect("profile text");
        std::fs::write(
            &path,
            format!("policies = [\"policy.dw\"]\n{text}\n[project]\naccess = \"write\"\n"),
        )
        .expect("explicit policy reference");
        let file = host.home().join(".strands/box/profiles/claude/policy.dw");
        std::fs::write(&file, policy).expect("a policy");
        file
    }

    #[test]
    fn box_core_checks_the_rules_of_the_largest_route() {
        let host = FakeHost::new();
        host.profile()
            .with("claude")
            .with("bedrock")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let path = host
            .home()
            .join(".strands/box/profiles/claude/profile.toml");
        let text = std::fs::read_to_string(&path).expect("profile text");
        let hosts = (1..=100)
            .map(|index| format!("\"h{index}.example.com\""))
            .collect::<Vec<_>>()
            .join(", ");
        std::fs::write(
            &path,
            format!("{text}\n[egress.many]\ndestinations = [{hosts}]\n"),
        )
        .expect("the route");
        let preview = host
            .launcher()
            .preview("claude", &host.project())
            .expect("Box Core checks the rules of a route with one hundred hosts");
        assert!(
            preview
                .open_routes
                .iter()
                .any(|(name, hosts)| name == "many"
                    && hosts.len() > 1
                    && hosts[0] == "h1.example.com"),
            "{:?}",
            preview.open_routes
        );
    }

    #[test]
    fn box_core_refuses_a_route_with_a_misspelled_secret() {
        let host = FakeHost::new();
        host.profile()
            .with("claude")
            .with("bedrock")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let path = host
            .home()
            .join(".strands/box/profiles/claude/profile.toml");
        let text = std::fs::read_to_string(&path).expect("profile text");
        std::fs::write(
            &path,
            format!(
                "{text}\n[egress.login]\ndestinations = [\"login.example.com\"]\n\
                 secrets.ref = \"env://KEY\"\n"
            ),
        )
        .expect("the route");
        let error = host
            .launcher()
            .preview("claude", &host.project())
            .expect_err("Box Core reads the route");
        assert!(
            error.to_string().contains("[egress.login.secrets]"),
            "{error}"
        );
    }

    /// The refusal of the `claude` profile by `box run` and by `box profile show`.
    fn policy_refusals(host: &FakeHost) -> Vec<Vec<PolicyFinding>> {
        [
            host.launcher()
                .prepare("claude", &host.project(), None)
                .map(|_| ()),
            host.launcher()
                .preview("claude", &host.project())
                .map(|_| ()),
        ]
        .into_iter()
        .map(|result| match result {
            Err(Error::Policy { findings }) => findings,
            other => panic!("a policy refusal, not {other:?}"),
        })
        .collect()
    }

    fn assert_nothing_left(host: &FakeHost) {
        assert!(
            !storage_root(&host.home().join(".strands/box"), "claude").exists(),
            "a refused run creates no storage"
        );
        let runs = host.home().join(".strands/box/r");
        assert_eq!(
            std::fs::read_dir(&runs).map_or(0, |entries| entries.count()),
            0,
            "a refused run leaves no run folder"
        );
        assert_eq!(
            std::fs::read_dir(host.scratch())
                .expect("the scratch directory")
                .count(),
            0,
            "a refused show leaves no file behind"
        );
    }

    #[test]
    fn a_profile_policy_with_an_unknown_action_or_field_is_refused_at_its_line_with_a_hint() {
        let host = FakeHost::new();
        let file = claude_with_policy(
            &host,
            "// mine\n\n@id(\"reads\") permit (principal, action == Box::Action::\"fs:raed\", resource);\n",
        );
        for findings in policy_refusals(&host) {
            assert_eq!(
                findings,
                [
                    PolicyFinding {
                        path: "policy.dw".into(),
                        line: Some(3),
                        reason: "unrecognized action `Box::Action::\"fs:raed\"`; did you mean \
                                 `Box::Action::\"fs:read\"`?"
                            .to_string(),
                    },
                    PolicyFinding {
                        path: "policy.dw".into(),
                        line: None,
                        reason: "rule 1 (@id \"reads\"): unable to find an applicable action \
                                 given the policy scope constraints"
                            .to_string(),
                    },
                ]
            );
        }
        assert_nothing_left(&host);
        std::fs::write(
            &file,
            "@id(\"reads\") permit (principal, action == Box::Action::\"fs:read\", resource)\n  \
             when { context.input.pth == \"/tmp/x\" };\n",
        )
        .expect("a policy");
        for findings in policy_refusals(&host) {
            let [finding] = findings.as_slice() else {
                panic!("one finding, not {findings:?}");
            };
            assert_eq!(finding.path, Path::new("policy.dw"));
            assert_eq!(finding.line, Some(2), "{}", finding.reason);
            assert!(
                finding.reason.contains("did you mean `path`?"),
                "{}",
                finding.reason
            );
        }
        assert_nothing_left(&host);
    }

    #[test]
    fn an_error_in_a_second_policy_file_names_its_line_in_the_combined_program() {
        let host = FakeHost::new();
        let profiles = Profiles::at(host.home().join(".strands/box/profiles"));
        let folder = profiles.folder("claude");
        std::fs::create_dir_all(&folder).expect("profile folder");
        std::fs::write(
            profiles.path("claude"),
            format!("policies = [\"one.dw\", \"two.dw\"]\n{MINIMAL}"),
        )
        .expect("profile");
        std::fs::write(
            folder.join("one.dw"),
            "\n\n@id(\"one\") permit (principal, action, resource);\n\n",
        )
        .expect("first policy");
        std::fs::write(
            folder.join("two.dw"),
            "\n\n\n@id(\"two\") permit (principal, action == Box::Action::\"fs:read\", resource) \
             when { context.input.pth == \"/tmp/x\" };\n\n",
        )
        .expect("second policy");
        for findings in policy_refusals(&host) {
            let [finding] = findings.as_slice() else {
                panic!("one finding, not {findings:?}");
            };
            assert_eq!(finding.path, Path::new("policy.dw"));
            assert_eq!(finding.line, Some(3), "{}", finding.reason);
            assert!(
                finding.reason.contains("did you mean `path`?"),
                "{}",
                finding.reason
            );
        }
        assert_nothing_left(&host);
    }

    #[test]
    fn a_policy_finding_with_no_location_names_its_rule_by_position_and_id() {
        let host = FakeHost::new();
        claude_with_policy(
            &host,
            "@id(\"writes\")\npermit (principal, action == Box::Action::\"fs:write\", resource);\n\n\
             @id(\"write_budget\")\n\
             permit (principal, action == Box::Action::\"fs:write\", resource)\n\
             when temporal { exists (total: Long). ((count for (t: Timepoint). where (formerly \
             within 3600s (Box::Action::\"fs:write\"::response{ input.path: _, input.operation: \
             Box::FsWriteOperation::\"write_content\" } && tp(t)))) == total && total < 3) };\n",
        );
        for findings in policy_refusals(&host) {
            let [finding] = findings.as_slice() else {
                panic!("one finding, not {findings:?}");
            };
            assert_eq!(finding.path, Path::new("policy.dw"));
            assert_eq!(finding.line, None, "{}", finding.reason);
            assert!(
                finding.reason.starts_with("rule 2 (@id \"write_budget\")"),
                "{}",
                finding.reason
            );
            assert!(
                finding.reason.contains("write the cap as a forbid"),
                "{}",
                finding.reason
            );
        }
        assert_nothing_left(&host);
    }

    #[test]
    fn each_shipped_policy_starter_is_copied_into_the_profile_and_box_core_accepts_it() {
        for (policy, name, label) in [
            ("open", "@box/open", "Open"),
            ("@box/scoped", "@box/scoped", "Scoped"),
            ("locked", "@box/locked", "Locked"),
        ] {
            let host = FakeHost::new();
            let created = host
                .profile()
                .with("claude")
                .with("bedrock")
                .policy(policy)
                .create()
                .expect("a profile");
            assert!(
                created.text().contains("\npolicies = [\"policy.dw\"]\n"),
                "{}",
                created.text()
            );
            assert!(
                !created.text().contains("base-policy"),
                "{}",
                created.text()
            );
            created.write(false).expect("a write");
            let copy = host.home().join(".strands/box/profiles/claude/policy.dw");
            assert_eq!(created.policy_path(), Some(copy.clone()));
            let text = std::fs::read_to_string(&copy).expect("the copy");
            assert!(
                text.starts_with(&format!(
                    "// Copied from {name} ({label}) by `box profile create`."
                )),
                "{text}"
            );
            let preview = host
                .launcher()
                .preview("claude", &host.project())
                .expect("a preview");
            assert_eq!(preview.warnings, Vec::<String>::new(), "{name}");
            assert_eq!(preview.policies, ["policy.dw"]);
            let open = name == "@box/open";
            assert_eq!(
                preview.policy.contains("@id(\"open_connect\")"),
                open,
                "{}",
                preview.policy
            );
            assert!(
                preview.policy.starts_with("// Copied from"),
                "{}",
                preview.policy
            );
            host.launcher()
                .prepare("claude", &host.project(), None)
                .expect("a run");
        }
        let host = FakeHost::new();
        let created = host
            .profile()
            .with("claude")
            .with("bedrock")
            .create()
            .expect("a profile with no policy");
        assert!(!created.text().contains("policies"), "{}", created.text());
        assert_eq!(created.policy_path(), None);
        created.write(false).expect("a write");
        assert!(
            !host
                .home()
                .join(".strands/box/profiles/claude/policy.dw")
                .exists()
        );
        let preview = host
            .launcher()
            .preview("claude", &host.project())
            .expect("a preview");
        assert!(preview.policies.is_empty());
        assert!(!preview.policy.contains("open_"), "{}", preview.policy);
    }

    #[test]
    fn the_copy_never_writes_through_a_link_and_force_replaces_it() {
        let host = FakeHost::new();
        let created = host
            .profile()
            .with("claude")
            .with("bedrock")
            .policy("open")
            .create()
            .expect("a profile");
        let text = created.policy_text.clone().expect("a copy");
        let folder = host.home().join(".strands/box/profiles/claude");
        std::fs::create_dir_all(&folder).expect("the folder");
        let copy = folder.join("policy.dw");
        let outside = host.home().join("outside.dw");
        let refused = |force| match created.write(force) {
            Err(Error::Exists { path }) => assert_eq!(path, copy),
            other => panic!("Exists for {}, not {other:?}", copy.display()),
        };
        std::fs::write(&outside, &text).expect("a file");
        std::fs::hard_link(&outside, &copy).expect("an identical hard link");
        refused(false);
        assert!(!created.path().exists(), "nothing is written");
        created.write(true).expect("force replaces the hard link");
        assert_eq!(
            std::os::unix::fs::MetadataExt::nlink(&std::fs::metadata(&copy).expect("the copy")),
            1
        );
        assert_eq!(std::fs::read_to_string(&outside).expect("outside"), text);
        std::fs::remove_file(&copy).expect("remove");
        std::fs::write(&outside, "// mine\n").expect("a file");
        std::os::unix::fs::symlink(&outside, &copy).expect("a symbolic link");
        refused(false);
        created.write(true).expect("force replaces the link");
        assert!(!std::fs::symlink_metadata(&copy).expect("copy").is_symlink());
        assert_eq!(std::fs::read_to_string(&copy).expect("copy"), text);
        assert_eq!(
            std::fs::read_to_string(&outside).expect("outside"),
            "// mine\n"
        );
        std::fs::write(&copy, "// my rules\n").expect("an edit");
        refused(false);
        assert_eq!(
            std::fs::read_to_string(&copy).expect("copy"),
            "// my rules\n"
        );
        created.write(true).expect("force replaces the edit");
        assert_eq!(std::fs::read_to_string(&copy).expect("copy"), text);
        created
            .write(false)
            .expect("the same files are already written");
    }

    #[test]
    fn the_copy_is_written_before_the_profile_and_a_stray_copy_is_kept() {
        let host = FakeHost::new();
        let created = host
            .profile()
            .with("claude")
            .with("bedrock")
            .policy("open")
            .create()
            .expect("a profile");
        let text = created.policy_text.clone().expect("a copy");
        let folder = host.home().join(".strands/box/profiles/claude");
        std::fs::create_dir_all(&folder).expect("the folder");
        let copy = folder.join("policy.dw");
        let outside = host.home().join("outside.dw");
        std::fs::write(&outside, "// other rules\n").expect("a file");
        std::fs::hard_link(&outside, &copy).expect("a different hard link");
        assert!(
            matches!(created.write(false), Err(Error::Exists { path }) if path == copy),
            "a different hard link is refused"
        );
        assert!(!created.path().exists(), "nothing is written");
        std::fs::remove_file(&copy).expect("remove");
        std::fs::create_dir(&copy).expect("a directory");
        assert!(
            matches!(created.write(false), Err(Error::Exists { path }) if path == copy),
            "a directory is refused"
        );
        assert!(
            matches!(created.write(true), Err(Error::Io { path, .. }) if path == copy),
            "force cannot replace a directory"
        );
        assert!(!created.path().exists(), "no profile names a missing copy");
        std::fs::remove_dir(&copy).expect("remove");
        std::fs::create_dir(created.path()).expect("a directory at profile.toml");
        assert!(
            matches!(created.write(true), Err(Error::Io { path, .. }) if path == created.path()),
            "the profile write fails"
        );
        assert_eq!(
            std::fs::read_to_string(&copy).expect("the copy is written first"),
            text
        );
        std::fs::remove_dir(created.path()).expect("remove");
        created
            .write(false)
            .expect("a stray copy with the same text is taken as written");
        assert_eq!(std::fs::read_to_string(&copy).expect("copy"), text);
        assert_eq!(
            std::fs::read_to_string(created.path()).expect("profile"),
            created.text()
        );
    }

    #[test]
    fn a_run_reads_the_profiles_copy_of_its_policy_starter() {
        let host = FakeHost::new();
        host.profile()
            .with("claude")
            .with("bedrock")
            .policy("open")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let copy = host.home().join(".strands/box/profiles/claude/policy.dw");
        let text = std::fs::read_to_string(&copy).expect("the copy");
        let start = text
            .find("// Let the agent send")
            .expect("the request rule");
        let end = text.find("// But never").expect("the loopback rule");
        std::fs::write(&copy, format!("{}{}", &text[..start], &text[end..])).expect("an edit");
        let policy = host
            .launcher()
            .preview("claude", &host.project())
            .expect("a preview")
            .policy;
        assert!(policy.contains("@id(\"open_connect\")"), "{policy}");
        assert!(!policy.contains("open_request"), "{policy}");
        let lines = std::fs::read_to_string(&copy)
            .expect("the copy")
            .lines()
            .count();
        std::fs::write(
            &copy,
            format!(
                "{}\n@id(\"reads\") permit (principal, action == Box::Action::\"fs:raed\", \
                 resource);\n",
                std::fs::read_to_string(&copy).expect("the copy").trim_end()
            ),
        )
        .expect("a bad rule");
        for findings in policy_refusals(&host) {
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.line == Some(lines + 1)
                        && finding.reason.contains("fs:raed")),
                "{findings:?}"
            );
        }
        assert_nothing_left(&host);
    }

    #[test]
    fn a_policy_that_loads_is_checked_and_show_leaves_no_file_behind() {
        let host = FakeHost::new();
        claude_with_policy(
            &host,
            "@id(\"tmp_reads\") permit (principal, action == Box::Action::\"fs:read\", resource) \
             when { context.input.path like \"/tmp/*\" };\n",
        );
        let preview = host
            .launcher()
            .preview("claude", &host.project())
            .expect("a preview");
        assert_eq!(preview.warnings, Vec::<String>::new());
        assert_eq!(
            std::fs::read_dir(host.scratch())
                .expect("the scratch directory")
                .count(),
            0
        );
        let launch = host
            .launcher()
            .prepare("claude", &host.project(), None)
            .expect("a launch");
        assert!(launch.config().with_file_name("policy.dw").is_file());
        assert!(storage_root(&host.home().join(".strands/box"), "claude").is_dir());
    }

    #[test]
    fn a_profile_with_a_long_name_is_checked_under_a_box_name_box_core_accepts() {
        let host = FakeHost::new();
        let name = "a-profile-name-longer-than-any-box-name";
        host.profile()
            .name(name)
            .with("claude")
            .with("bedrock")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let preview = host
            .launcher()
            .preview(name, &host.project())
            .expect("a preview");
        let config: toml::Value = toml::from_str(&preview.box_toml).expect("box.toml");
        assert_eq!(config["name"].as_str(), Some("b-0000000000000000"));
        assert_eq!(
            config["box_dir"].as_str(),
            host.launcher()
                .runs_root()
                .join("b-0000000000000000/box")
                .to_str()
        );
        assert!(
            !host.launcher().runs_root().exists(),
            "preview writes no run"
        );
        host.launcher()
            .prepare(name, &host.project(), None)
            .expect("a launch");
    }

    #[test]
    fn create_resolves_the_box_directory_with_a_fixed_length_preview_id() {
        let host = FakeHost::new();
        operator_pack(
            &host,
            "preview",
            "extend = [\"@box/base\"]\n[agent]\ncommand = [\"${{ box }}/bin/agent\"]\n",
        );
        for name in ["short", "a-profile-name-longer-than-any-box-name"] {
            let created = host
                .profile()
                .name(name)
                .with("preview")
                .create()
                .expect("a profile");
            assert_eq!(
                created.discovery.agent,
                Some(
                    host.home()
                        .join(".strands/box/r/b-0000000000000000/box/bin/agent")
                )
            );
        }
        assert!(
            !host.launcher().runs_root().exists(),
            "create previews write no run"
        );
    }

    #[test]
    fn a_check_that_cannot_read_its_configuration_is_an_error_that_says_so() {
        let missing = Path::new("/nonexistent/box/box.toml");
        match crate::check::policy(&crate::check::Checked {
            config: missing,
            profile: "",
            generated_ids: &[],
        }) {
            Err(error @ Error::PolicyCheck { .. }) => assert!(
                error
                    .to_string()
                    .starts_with("Box Core cannot check the policy: "),
                "{error}"
            ),
            other => panic!("a failed check, not {other:?}"),
        }
    }

    #[test]
    fn a_last_rule_with_no_semicolon_is_refused_with_no_line() {
        let host = FakeHost::new();
        claude_with_policy(
            &host,
            "@id(\"a\") permit (principal, action == Box::Action::\"fs:read\", resource);\n\n\
             @id(\"b\")\npermit (principal, action == Box::Action::\"fs:read\", resource)\n",
        );
        for findings in policy_refusals(&host) {
            assert!(!findings.is_empty());
            for finding in &findings {
                assert_eq!(finding.path, Path::new("policy.dw"), "{}", finding.reason);
                assert_eq!(finding.line, None, "{}", finding.reason);
            }
        }
        assert_nothing_left(&host);
    }

    #[test]
    fn show_reports_a_policy_warning_in_box_cores_words_and_still_succeeds() {
        let host = FakeHost::new();
        claude_with_policy(
            &host,
            "@id(\"full_path\")\n\
             permit (principal, action == Box::Action::\"shell:spawn\", resource)\n\
             when { context.input.program == \"/usr/bin/curl\" };\n",
        );
        let preview = host
            .launcher()
            .preview("claude", &host.project())
            .expect("a preview");
        let [warning] = preview.warnings.as_slice() else {
            panic!("one warning, not {:?}", preview.warnings);
        };
        assert!(
            warning.starts_with(
                "rule @id(\"full_path\") compares context.input.program with \"/usr/bin/curl\""
            ),
            "{warning}"
        );
        host.launcher()
            .prepare("claude", &host.project(), None)
            .expect("a launch");
    }

    #[test]
    fn a_commented_id_and_an_id_in_a_string_load() {
        let host = FakeHost::new();
        claude_with_policy(
            &host,
            "// @id(\"shell_commands\") permit (principal, action, resource);\n\
             // @id(\"mine\") was here\n\
             @id(\"mine\") permit (principal, action == Box::Action::\"fs:read\", resource) \
             when { context.input.path == \"/tmp/@id(\\\"mine\\\")\" };\n",
        );
        host.launcher()
            .preview("claude", &host.project())
            .expect("a preview");
        host.launcher()
            .prepare("claude", &host.project(), None)
            .expect("a launch");
    }

    #[test]
    fn an_error_in_a_rule_below_a_definition_names_the_combined_policy_line() {
        let host = FakeHost::new();
        claude_with_policy(
            &host,
            "def cedar is_tmp(?path) { ?path like \"/tmp/*\" };\n\n\
             permit (principal, action == Box::Action::\"fs:raed\", resource);\n",
        );
        for findings in policy_refusals(&host) {
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.path == Path::new("policy.dw")),
                "{findings:?}"
            );
            assert!(
                findings.iter().any(|finding| finding.line == Some(3)
                    && finding.reason.starts_with("unrecognized action")),
                "{findings:?}"
            );
        }
    }

    #[test]
    fn the_ids_box_writes_are_unique_and_every_rule_it_writes_has_one() {
        let host = FakeHost::new();
        let trialed = host
            .trial()
            .with("claude")
            .with("bedrock")
            .generate()
            .expect("a configuration");
        let ids = trialed.generated_ids();
        for prefix in ["spawn_", "route_", "storage_", "project_read", "box_home_"] {
            assert!(
                ids.iter().any(|id| id.starts_with(prefix)),
                "{prefix}: {ids:?}"
            );
        }
        for id in STARTER_RULES {
            assert!(
                !ids.iter().any(|generated| generated == id),
                "{id}: {ids:?}"
            );
        }
        let unique: std::collections::BTreeSet<&String> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "{ids:?}");
        let rules: Vec<&str> = trialed
            .policy()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert_eq!(rules.len(), ids.len(), "{}", trialed.policy());
        for (rule, id) in rules.iter().zip(ids) {
            assert!(rule.starts_with(&format!("@id({id:?}) ")), "{rule}");
        }
    }

    #[test]
    fn two_rules_with_one_id_are_refused_in_a_box_with_a_local_mcp_server() {
        let host = FakeHost::new();
        claude_with_policy(
            &host,
            "@id(\"a\") permit (principal, action == Box::Action::\"fs:read\", resource);\n\
             @id(\"a\") forbid (principal, action == local::Action::\"read\", resource);\n",
        );
        let profile = host
            .home()
            .join(".strands/box/profiles/claude/profile.toml");
        let text = std::fs::read_to_string(&profile).expect("the profile");
        std::fs::write(
            &profile,
            format!(
                "{text}\n[mcp.local]\ntype = \"stdio\"\ncommand = [\"true\"]\n\
                 env.PATH = \"/usr/bin:/bin\"\n"
            ),
        )
        .expect("a profile");
        for findings in policy_refusals(&host) {
            let [finding] = findings.as_slice() else {
                panic!("one finding, not {findings:?}");
            };
            assert_eq!(
                (finding.path.as_path(), finding.line),
                (Path::new("policy.dw"), None)
            );
            assert!(
                finding
                    .reason
                    .starts_with("rule 1 (@id \"a\"), rule 2 (@id \"a\"): "),
                "{}",
                finding.reason
            );
        }
        assert_nothing_left(&host);
    }

    #[test]
    fn an_unchecked_rule_for_a_local_mcp_server_is_not_refused() {
        let host = FakeHost::new();
        claude_with_policy(
            &host,
            "@id(\"no_read\") forbid (principal, action == local::Action::\"read\", resource);\n",
        );
        assert!(
            matches!(
                host.launcher().preview("claude", &host.project()),
                Err(Error::Policy { .. })
            ),
            "with no server of that name, the rule is checked and refused"
        );
        let profile = host
            .home()
            .join(".strands/box/profiles/claude/profile.toml");
        let text = std::fs::read_to_string(&profile).expect("the profile");
        std::fs::write(
            &profile,
            format!(
                "{text}\n[mcp.local]\ntype = \"stdio\"\ncommand = [\"true\"]\n\
                 env.PATH = \"/usr/bin:/bin\"\n"
            ),
        )
        .expect("a profile");
        let preview = host
            .launcher()
            .preview("claude", &host.project())
            .expect("a preview");
        assert!(
            preview.box_toml.contains("[mcp.local]"),
            "{}",
            preview.box_toml
        );
        host.launcher()
            .prepare("claude", &host.project(), None)
            .expect("a launch");
    }

    #[test]
    fn create_notes_an_agent_the_host_lacks_and_refuses_any_other_resolve_error() {
        let host = FakeHost::new();
        operator_pack(
            &host,
            "mine",
            "extend = [\"@box/base\"]\n[run]\ncommand = [\"${{ inputs.mine.program }}\"]\n\
             [inputs.mine.program]\ntype = \"program\"\nprogram = \"mine\"\n",
        );
        let created = host
            .profile()
            .with("mine")
            .with("bedrock")
            .option("bedrock.sign-in", "api-key")
            .create()
            .expect("an agent missing is a note");
        assert!(
            created.summary(false).contains("is not on this host now"),
            "{}",
            created.summary(false)
        );
        assert!(
            created.next_steps(false).contains(
                "1. Put the key for bedrock-runtime.${{ inputs.bedrock.region }}.amazonaws.com"
            ),
            "the steps come from the routes as written: {}",
            created.next_steps(false)
        );
        assert!(
            !created.next_steps(false).contains("default AWS identity"),
            "a route whose input `when` does not hold is left out: {}",
            created.next_steps(false)
        );
        operator_pack(
            &host,
            "gate",
            "[inputs.gate.signed]\ntype = \"bool\"\ndefault = true\n\
             [egress.signed]\ndestinations = [\"signed.example.com\"]\nsecret.ref = \"aws://\"\n\
             when = \"${{ inputs.gate.signed }}\"\n\
             [egress.keyed]\ndestinations = [\"keyed.example.com\"]\n\
             secret.ref = \"env://GATE_KEY\"\n\
             when = { variable = \"inputs.gate.signed\", equals = \"false\" }\n",
        );
        let steps = |signed: Option<&str>| {
            let mut profile = host.profile().name("gated").with("mine").with("gate");
            if let Some(signed) = signed {
                profile = profile.option("gate.signed", signed);
            }
            profile
                .create()
                .expect("an agent missing is a note")
                .next_steps(false)
        };
        let signed = steps(None);
        assert!(signed.contains("The signed route signs"), "{signed}");
        assert!(!signed.contains("GATE_KEY"), "{signed}");
        let keyed = steps(Some("false"));
        assert!(
            keyed.contains("Put the key for keyed.example.com in GATE_KEY."),
            "{keyed}"
        );
        assert!(!keyed.contains("The signed route"), "{keyed}");
        operator_pack(
            &host,
            "corp",
            "[inputs.corp.auth]\ntype = \"string\"\nvalues = [\"aws\", \"key\"]\n\
             from = \"env:CORP_AUTH\"\ndefault = \"key\"\n\
             [egress.corp-aws]\ndestinations = [\"corp.example.com\"]\nsecret.ref = \"aws://\"\n\
             when = { variable = \"inputs.corp.auth\", equals = \"aws\" }\n\
             [egress.corp-key]\ndestinations = [\"corp.example.com\"]\n\
             secret.ref = \"env://CORP_KEY\"\n\
             when = { variable = \"inputs.corp.auth\", equals = \"key\" }\n",
        );
        let host_read = host
            .profile()
            .name("corp")
            .with("mine")
            .with("corp")
            .create()
            .expect("an agent missing is a note")
            .next_steps(false);
        assert!(
            host_read.contains("The corp-aws route signs"),
            "an input that the run reads from the host keeps both routes: {host_read}"
        );
        operator_pack(
            &host,
            "tmpl",
            "[inputs.tmpl.mode]\ntype = \"string\"\ndefault = \"${{ home }}\"\n\
             [egress.tmpl]\ndestinations = [\"tmpl.example.com\"]\n\
             secret.ref = \"env://TMPL_KEY\"\n\
             when = { variable = \"inputs.tmpl.mode\", equals = \"x\" }\n",
        );
        let templated = host
            .profile()
            .name("tmpl")
            .with("mine")
            .with("tmpl")
            .create()
            .expect("an agent missing is a note")
            .next_steps(false);
        assert!(
            templated.contains("Put the key for tmpl.example.com in TMPL_KEY."),
            "a default that holds a placeholder keeps its route: {templated}"
        );
        let error = host
            .profile()
            .with("mine")
            .with("bedrock")
            .option("mine.program", "relative/mine")
            .create()
            .expect_err("a program that is not an absolute path");
        match &error {
            Error::Profile { reason, .. } => {
                assert!(reason.contains("is not an absolute path"), "{reason}")
            }
            other => panic!("a refusal, not {other:?}"),
        }
        assert!(
            !host.home().join(".strands/box/profiles/mine").exists(),
            "a refused create writes nothing"
        );
    }

    #[test]
    fn the_report_reads_a_bool_option_as_the_profile_writes_it() {
        let options: toml::Table = toml::from_str("[options]\ngate.signed = false\n").unwrap();
        let none = std::collections::BTreeMap::new();
        let route = |when: &str| -> toml::Value {
            toml::from_str(&format!(
                "destinations = [\"a.example.com\"]\nwhen = {when}\n"
            ))
            .unwrap()
        };
        let signed = route("\"${{ inputs.gate.signed }}\"");
        let keyed = route("{ variable = \"inputs.gate.signed\", equals = \"false\" }");
        assert!(crate::create::input_condition_fails(
            &signed, &options, &none
        ));
        assert!(!crate::create::input_condition_fails(
            &keyed, &options, &none
        ));
        assert!(
            !crate::create::input_condition_fails(&signed, &toml::Table::new(), &none),
            "a value that nothing sets keeps the route"
        );
        assert!(!crate::create::input_condition_fails(
            &route("\"macos\""),
            &options,
            &none
        ));
    }

    #[test]
    fn a_detected_tool_switched_off_by_when_gets_no_permit() {
        let host = FakeHost::new();
        host.profile()
            .with("claude")
            .with("bedrock")
            .tools(["git", "npm"])
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let path = host
            .home()
            .join(".strands/box/profiles/claude/profile.toml");
        let text = std::fs::read_to_string(&path).expect("read");
        let other = if std::env::consts::OS == "macos" {
            "linux"
        } else {
            "macos"
        };
        let switched = format!("{text}\n[tool.node]\nwhen = \"{other}\"\n");
        std::fs::write(&path, switched).expect("a write");
        let preview = host
            .launcher()
            .preview("claude", &host.project())
            .expect("a preview");
        let file: toml::Value = toml::from_str(&preview.box_toml).expect("TOML");
        let tools: Vec<&str> = file["tool"]
            .as_table()
            .expect("tools")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(tools, ["git"]);
        assert!(
            preview.policy.contains("@id(\"spawn_git\") permit"),
            "{}",
            preview.policy
        );
        assert!(!preview.policy.contains("spawn_node"), "{}", preview.policy);
        assert!(!preview.policy.contains("spawn_npm"), "{}", preview.policy);
        assert!(
            !preview.policy.contains("package_hosts"),
            "{}",
            preview.policy
        );
    }

    #[test]
    fn create_keeps_the_packs_named_in_with_and_adds_none() {
        let host = FakeHost::new();
        for (profile, packs) in [
            (
                host.profile().with("claude").with("bedrock"),
                vec!["@box/claude", "@box/bedrock"],
            ),
            (
                host.profile().with("claude").with("anthropic"),
                vec!["@box/claude", "@box/anthropic"],
            ),
            (
                host.profile().name("claude").with("anthropic"),
                vec!["@box/claude", "@box/anthropic"],
            ),
            (
                host.profile().with("codex").with("bedrock-mantle"),
                vec!["@box/codex", "@box/bedrock-mantle"],
            ),
        ] {
            let created = profile.create().expect("a profile");
            assert_eq!(agent_packs(created.profile()), packs, "{}", created.text());
        }
        let created = host
            .profile()
            .with("claude")
            .create()
            .expect("a profile with no provider");
        assert_eq!(
            agent_packs(created.profile()),
            ["@box/claude"],
            "{}",
            created.text()
        );
        let error = host
            .profile()
            .name("mine")
            .with("bedrock")
            .create()
            .expect_err("no agent pack");
        assert!(
            error.to_string().contains("no pack runs an agent"),
            "{error}"
        );
        let error = host
            .profile()
            .with("claude")
            .with("missing")
            .create()
            .expect_err("a pack that does not exist");
        let error = error.to_string();
        assert!(error.contains("does not exist"), "{error}");
        assert_eq!(error.matches("/missing/pack.toml").count(), 2, "{error}");
        assert!(
            error.contains(
                &host
                    .home()
                    .join(".strands/box/packs/missing/pack.toml")
                    .display()
                    .to_string()
            ),
            "both folders are named: {error}"
        );
    }

    #[test]
    fn create_writes_each_option_and_refuses_one_no_pack_declares() {
        let host = FakeHost::new();
        let created = host
            .profile()
            .with("claude")
            .with("bedrock")
            .option("bedrock.region", "eu-west-1")
            .create()
            .expect("a profile");
        let file: toml::Table = toml::from_str(created.text()).expect("TOML");
        assert_eq!(
            file["options"]["bedrock"]["region"].as_str(),
            Some("eu-west-1"),
            "{}",
            created.text()
        );
        assert!(
            created
                .text()
                .contains("[options]\nbedrock.region = \"eu-west-1\"\n"),
            "{}",
            created.text()
        );
        assert_eq!(
            agent_packs(created.profile()),
            ["@box/claude", "@box/bedrock"]
        );
        for (name, why) in [
            (
                "bedrock..region",
                "--option \"bedrock..region\" is not an input name",
            ),
            (
                "bedrock.region=",
                "--option \"bedrock.region=\" is not an input name",
            ),
            (
                "nope.x",
                "`[options] nope.x` sets an input that no pack declares",
            ),
        ] {
            let error = host
                .profile()
                .with("claude")
                .with("bedrock")
                .option(name, "x")
                .create()
                .expect_err(name);
            assert!(error.to_string().contains(why), "{name}: {error}");
        }
        let error = host
            .profile()
            .with("claude")
            .with("bedrock")
            .option("bedrock.region", "us-east-1x")
            .create()
            .expect_err("a region that breaks its pattern");
        assert!(
            error.to_string().contains("does not match its pattern"),
            "{error}"
        );
        for (region, matches) in [
            ("us-west-2", true),
            ("us-gov-west-1", true),
            ("ap-northeast-1", true),
            ("eu-central-2", true),
            ("us-wst-2", false),
            ("eu-west", false),
        ] {
            let created = host
                .profile()
                .with("claude")
                .with("bedrock")
                .option("bedrock.region", region)
                .create();
            assert_eq!(created.is_ok(), matches, "{region}");
        }
        let error = host
            .profile()
            .with("claude")
            .with("bedrock")
            .option("bedrock.region", "us-east-1")
            .option("bedrock.region", "eu-west-1")
            .create()
            .expect_err("one option given twice");
        assert_eq!(
            error.to_string(),
            "--option \"bedrock.region\" is given twice",
            "a flag refusal names no file"
        );
        let reason = host
            .profile()
            .with("claude")
            .with("bedrock")
            .option("terminal.term", "x\"\n[agent]\ncommand = [\"/bin/sh\"]")
            .create()
            .expect("a quoted value")
            .text()
            .to_string();
        let file: toml::Table = toml::from_str(&reason).expect("TOML");
        assert!(!file.contains_key("agent"), "{reason}");
    }

    #[test]
    fn mcp_import_keeps_servers_without_generated_policy() {
        for (agent, source_name, target_name, section) in [
            (
                "claude",
                ".claude.json",
                "agent/config/.claude.json",
                "mcpServers",
            ),
            (
                "codex",
                ".codex/config.toml",
                "agent/home/config.toml",
                "mcp_servers",
            ),
        ] {
            let host = FakeHost::new();
            let source = host.home().join(source_name);
            std::fs::create_dir_all(source.parent().expect("parent")).expect("directory");
            let mut original = serde_json::json!({
                section: {"docs": {"url": "https://docs.example.com/mcp"}}
            });
            let encode = |value: &serde_json::Value| {
                if agent == "claude" {
                    value.to_string()
                } else {
                    toml::to_string(&toml::Value::try_from(value).expect("TOML value"))
                        .expect("TOML")
                }
            };
            std::fs::write(&source, encode(&original)).expect("host config");
            host.profile()
                .with(agent)
                .option(format!("{agent}.import-mcp"), "true")
                .with(if agent == "claude" {
                    "bedrock"
                } else {
                    "bedrock-mantle"
                })
                .create()
                .expect("profile")
                .write(false)
                .expect("write");
            let launcher = host.launcher();
            let baseline = launcher.preview(agent, &host.project()).expect("baseline");
            original[section]["node"] = serde_json::json!({
                "command": "node", "args": ["/opt/mcp/server.js"],
                "env": {"TOKEN": "literal-node-key"}, "timeout": 30
            });
            original[section]["uv"] = serde_json::json!({
                "command": "uv", "args": ["run", "--directory", "/opt/mcp", "server"],
                "env_vars": ["UV_SERVER_TOKEN"]
            });
            original[section]["python"] = serde_json::json!({
                "command": "python3", "args": ["-m", "server"],
                "env": {"TOKEN": "${PYTHON_SERVER_TOKEN}"}
            });
            std::fs::write(&source, encode(&original)).expect("host config");
            let preview = launcher.preview(agent, &host.project()).expect("preview");
            assert_eq!(
                preview.policy, baseline.policy,
                "imported settings add no policy for unsupported commands"
            );
            let compiled: toml::Table = toml::from_str(&preview.box_toml).expect("box config");
            assert_eq!(
                compiled["mcp"]
                    .as_table()
                    .unwrap()
                    .keys()
                    .collect::<Vec<_>>(),
                ["docs"]
            );
            assert_eq!(
                preview
                    .mcp_skipped
                    .iter()
                    .map(|(name, _, _)| name.as_str())
                    .collect::<Vec<_>>(),
                ["node", "python", "uv"]
            );
            let target = storage_root(&host.home().join(".strands/box"), agent).join(target_name);
            assert!(!target.exists(), "preview writes no agent settings");
            let launch = launcher
                .prepare(agent, &host.project(), None)
                .expect("launch");
            assert_eq!(launch.mcp_imports().len(), 1);
            let saved = std::fs::read_to_string(&target).expect("agent settings");
            let imported: serde_json::Value = if agent == "claude" {
                serde_json::from_str(&saved).expect("JSON")
            } else {
                serde_json::to_value(toml::from_str::<toml::Value>(&saved).expect("TOML"))
                    .expect("JSON value")
            };
            assert_eq!(imported[section], original[section]);
            original[section]["node"]["args"] = serde_json::json!(["/opt/mcp/updated.js"]);
            std::fs::write(&source, encode(&original)).expect("host edit");
            let next = launcher
                .prepare(agent, &host.project(), None)
                .expect("next launch");
            assert_eq!(std::fs::read_to_string(&target).unwrap(), saved);
            assert_eq!(next.mcp_imports().len(), 1);
            assert!(next.mcp_imports()[0].contains("changed \"node\""));
            assert!(!next.mcp_imports()[0].contains("literal-node-key"));
            assert_eq!(std::fs::read_to_string(&source).unwrap(), encode(&original));
        }
    }

    #[test]
    fn mcp_import_preserves_argument_references_and_keeps_environment_private() {
        let host = FakeHost::new();
        brew_program(&host, "mcp-local");
        let source = host.home().join(".claude.json");
        let original = serde_json::json!({
            "oauthAccount": {"emailAddress": "private@example.com"},
            "mcpServers": {
                "local": {"command": "${MCP_PROGRAM}", "args": ["--key", "${BOX_TEST_TOKEN}", "", "two words"],
                    "env": {"TOKEN": "${PRIVATE_ENV_TOKEN}"}},
                "remote": {"url": "https://remote.example.com/mcp",
                    "headers": {"Authorization": "Bearer ${REMOTE_TOKEN}"}},
                "off": {"command": "missing", "enabled": false}
            },
            "projects": {host.project().display().to_string(): {"mcpServers": {
                "remote": {"url": "https://project.example.com/mcp",
                    "headers": {"Authorization": "Bearer ${REMOTE_TOKEN}"}}
            }}, "/another/project": {"mcpServers": {"unrelated": {"url": "https://other.example.com"}}}}
        });
        std::fs::write(&source, original.to_string()).expect("host config");
        host.profile()
            .with("claude")
            .option("claude.import-mcp", "true")
            .with("bedrock")
            .create()
            .expect("profile")
            .write(false)
            .expect("write");
        let launcher = host.launcher().environment(&[
            ("MCP_PROGRAM", "mcp-local"),
            ("BOX_TEST_TOKEN", "real-local-key"),
            ("PRIVATE_ENV_TOKEN", "private-env-key"),
            ("REMOTE_TOKEN", "real-remote-key"),
        ]);
        let target = storage_root(&host.home().join(".strands/box"), "claude")
            .join("agent/config/.claude.json");
        launcher
            .preview("claude", &host.project())
            .expect("preview");
        assert!(!target.exists(), "preview writes no config");
        launcher
            .prepare("claude", &host.project(), None)
            .expect("launch");
        let text = std::fs::read_to_string(&target).expect("generated config");
        let generated: serde_json::Value = serde_json::from_str(&text).expect("JSON");
        assert_eq!(
            generated,
            serde_json::json!({
                "mcpServers": {
                    "local": {"command": "mcp-local", "args": ["--key", "${BOX_TEST_TOKEN}", "", "two words"]},
                    "off": {"command": "missing", "enabled": false},
                },
                "projects": {resolved(&host.project()).display().to_string(): {"mcpServers": {
                    "remote": {"url": "https://project.example.com/mcp", "headers": {"Authorization": "Bearer ${REMOTE_TOKEN}"}}
                }}},
            })
        );
        assert!(
            !text.contains("private-env-key")
                && !text.contains("real-remote-key")
                && !text.contains("real-local-key")
        );
        assert_eq!(
            std::fs::read_to_string(source).expect("host config"),
            original.to_string()
        );
    }

    #[test]
    fn mcp_import_copies_once_and_preserves_the_complete_stored_file() {
        let host = FakeHost::new();
        let source = host.home().join(".codex/config.toml");
        std::fs::create_dir_all(source.parent().expect("parent")).expect("directory");
        std::fs::write(
            &source,
            "model = \"host-model\"\n[mcp_servers.docs]\nurl = \"https://docs.example.com/mcp\"\n",
        )
        .expect("host config");
        host.profile()
            .with("codex")
            .option("codex.import-mcp", "true")
            .with("bedrock-mantle")
            .create()
            .expect("profile")
            .write(false)
            .expect("write");
        let target =
            storage_root(&host.home().join(".strands/box"), "codex").join("agent/home/config.toml");
        let imported = host
            .launcher()
            .prepare("codex", &host.project(), None)
            .expect("launch");
        let shown = crate::host::tilde(&host.home(), &target);
        assert_eq!(
            imported.mcp_imports(),
            [format!("Imported MCP settings into {shown}."),]
        );
        let generated: toml::Table =
            toml::from_str(&std::fs::read_to_string(&target).expect("config")).expect("TOML");
        assert_eq!(
            generated.keys().collect::<Vec<_>>(),
            ["mcp_servers", "model"]
        );
        assert_eq!(generated["model"].as_str(), Some("host-model"));
        assert!(generated["mcp_servers"].get("docs").is_some());
        let matching = host
            .launcher()
            .prepare("codex", &host.project(), None)
            .expect("matching settings");
        assert!(
            matching.mcp_imports().is_empty(),
            "{:?}",
            matching.mcp_imports()
        );
        let edited = "# agent preference\nmodel = \"saved-model\"\n[mcp_servers.agent_only]\nurl = \"https://agent.example.com\"\n";
        std::fs::write(&target, edited).expect("agent edit");
        host.launcher()
            .prepare("codex", &host.project(), None)
            .expect("unchanged host");
        assert_eq!(std::fs::read_to_string(&target).expect("config"), edited);
        std::fs::write(
            &source,
            "[mcp_servers.new]\nurl = \"https://new.example.com\"\n",
        )
        .expect("host edit");
        let kept = host
            .launcher()
            .prepare("codex", &host.project(), None)
            .expect("changed host");
        assert_eq!(
            kept.mcp_imports(),
            [format!(
                "Saved MCP settings in {shown} differ from the current import: missing \"new\"; saved only \"agent_only\". Kept unchanged; see docs/cli/troubleshooting.md for refresh steps."
            ),]
        );
        let compiled: toml::Table =
            toml::from_str(&std::fs::read_to_string(kept.config()).unwrap()).unwrap();
        assert!(compiled["mcp"].get("new").is_some());
        assert!(compiled["mcp"].get("agent_only").is_none());
        assert_eq!(std::fs::read_to_string(&target).expect("config"), edited);
        std::fs::write(
            &target,
            "[mcp_servers.\"saved\\nname\"]\nurl = \"https://private.example.com\"\n",
        )
        .unwrap();
        let escaped = host
            .launcher()
            .prepare("codex", &host.project(), None)
            .unwrap();
        assert_eq!(escaped.mcp_imports().len(), 1);
        assert!(escaped.mcp_imports()[0].contains("saved only \"saved\\nname\""));
        assert!(!escaped.mcp_imports()[0].contains('\n'));
        assert!(!escaped.mcp_imports()[0].contains("private.example.com"));
        std::fs::write(&target, edited).unwrap();
        host.profile()
            .with("codex")
            .with("bedrock-mantle")
            .option("codex.import-mcp", "false")
            .create()
            .expect("profile")
            .write(true)
            .expect("write");
        let disabled = host
            .launcher()
            .prepare("codex", &host.project(), None)
            .expect("disabled");
        assert_eq!(disabled.mcp_imports(), Vec::<String>::new());
        assert_eq!(std::fs::read_to_string(&target).expect("config"), edited);
        std::fs::write(&target, "not valid TOML").expect("invalid saved settings");
        let disabled = host
            .launcher()
            .prepare("codex", &host.project(), None)
            .expect_err("model fill refuses invalid saved settings");
        assert!(disabled.to_string().contains("not TOML"));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "not valid TOML");
        std::fs::remove_file(&target).expect("remove target");
        host.launcher()
            .prepare("codex", &host.project(), None)
            .expect("disabled without target");
        assert!(!target.exists(), "disabled import leaves no file");
        host.profile()
            .with("codex")
            .option("codex.import-mcp", "true")
            .with("bedrock-mantle")
            .create()
            .expect("profile")
            .write(true)
            .expect("write");
        host.launcher()
            .prepare("codex", &host.project(), None)
            .expect("enabled again");
        let copied: toml::Table =
            toml::from_str(&std::fs::read_to_string(&target).expect("config")).expect("TOML");
        assert!(copied["mcp_servers"].get("new").is_some());
    }

    #[test]
    fn mcp_import_leaves_existing_sections_and_empty_sources_alone() {
        let host = FakeHost::new();
        let source = host.home().join(".claude.json");
        host.profile()
            .with("claude")
            .option("claude.import-mcp", "true")
            .with("bedrock")
            .option("claude.import-app-state", "false")
            .create()
            .expect("profile")
            .write(false)
            .expect("write");
        let target = storage_root(&host.home().join(".strands/box"), "claude")
            .join("agent/config/.claude.json");
        let saved = r#"{"saved":true,"mcpServers":{"mine":{"url":"https://mine.example.com"}}}"#;
        for contents in [Some("{}"), Some("broken"), None] {
            match contents {
                Some(text) => std::fs::write(&source, text).expect("source"),
                None => std::fs::remove_file(&source).expect("remove"),
            }
            host.launcher()
                .prepare("claude", &host.project(), None)
                .expect("empty source");
            assert!(!target.exists(), "no source entries means nothing copied");
            for contents in [saved, "", "{ broken"] {
                std::fs::write(&target, contents).expect("saved config");
                let empty = host
                    .launcher()
                    .prepare("claude", &host.project(), None)
                    .expect("empty import leaves existing target alone");
                assert!(empty.mcp_imports().is_empty());
                assert_eq!(std::fs::read_to_string(&target).expect("config"), contents);
            }
            std::fs::remove_file(&target).expect("remove target");
        }
        std::fs::write(
            &source,
            r#"{"mcpServers":{"docs":{"url":"https://docs.example.com"}}}"#,
        )
        .expect("valid source");
        let shown = crate::host::tilde(&host.home(), &target);
        for (contents, expected) in [
            (
                r#"{"model":"saved","mcpServers":{}}"#,
                format!(
                    "Saved MCP settings in {shown} differ from the current import: missing \"docs\". Kept unchanged; see docs/cli/troubleshooting.md for refresh steps."
                ),
            ),
            (
                saved,
                format!(
                    "Saved MCP settings in {shown} differ from the current import: missing \"docs\"; saved only \"mine\". Kept unchanged; see docs/cli/troubleshooting.md for refresh steps."
                ),
            ),
            (
                r#"{"mcpServers":{"docs":{"url":"https://private.example.com"}}}"#,
                format!(
                    "Saved MCP settings in {shown} differ from the current import: changed \"docs\". Kept unchanged; see docs/cli/troubleshooting.md for refresh steps."
                ),
            ),
            (
                r#"{"mcpServers":false}"#,
                format!(
                    "Saved MCP settings in {shown} have a non-table \"mcpServers\" section. Kept unchanged; see docs/cli/troubleshooting.md for refresh steps."
                ),
            ),
        ] {
            std::fs::write(&target, contents).expect("existing file");
            let launch = host
                .launcher()
                .prepare("claude", &host.project(), None)
                .expect("preserved target");
            assert_eq!(launch.mcp_imports(), [expected]);
            assert_eq!(std::fs::read_to_string(&target).expect("config"), contents);
        }
        let outside = host.home().join("must-not-change.json");
        std::fs::write(&outside, r#"{"secret":"private"}"#).expect("outside");
        std::fs::remove_file(&target).expect("remove target");
        std::os::unix::fs::symlink(&outside, &target).expect("link");
        let skipped = host
            .launcher()
            .prepare("claude", &host.project(), None)
            .expect("existing link");
        assert_eq!(
            skipped.mcp_imports(),
            [format!(
                "Did not import MCP settings into {}: the target is a link or not a regular file.",
                crate::host::tilde(&host.home(), &target)
            ),]
        );
        assert!(
            std::fs::symlink_metadata(&target)
                .expect("metadata")
                .file_type()
                .is_symlink()
        );
        std::fs::remove_file(&target).expect("remove link");
        std::fs::hard_link(&outside, &target).expect("hard link");
        let skipped = host
            .launcher()
            .prepare("claude", &host.project(), None)
            .expect("existing hard link");
        assert_eq!(
            skipped.mcp_imports(),
            [format!(
                "Did not import MCP settings into {}: the target is a link or not a regular file.",
                crate::host::tilde(&host.home(), &target)
            ),]
        );
        assert_eq!(
            std::fs::read_to_string(&target).expect("config"),
            r#"{"secret":"private"}"#
        );
        assert_eq!(
            std::fs::read_to_string(&outside).expect("outside"),
            r#"{"secret":"private"}"#
        );
        std::fs::remove_file(&target).expect("remove hard link");
        std::os::unix::fs::symlink(host.home().join("absent"), &target).expect("dangling link");
        let skipped = host
            .launcher()
            .prepare("claude", &host.project(), None)
            .expect("existing dangling link");
        assert_eq!(
            skipped.mcp_imports(),
            [format!(
                "Did not import MCP settings into {}: the target is a link or not a regular file.",
                crate::host::tilde(&host.home(), &target)
            ),]
        );
        assert!(
            std::fs::symlink_metadata(&target)
                .expect("metadata")
                .file_type()
                .is_symlink()
        );
        std::fs::remove_file(&target).expect("remove dangling link");
        std::fs::create_dir(&target).expect("existing directory");
        let skipped = host
            .launcher()
            .prepare("claude", &host.project(), None)
            .expect("preserved directory");
        assert_eq!(
            skipped.mcp_imports(),
            [format!(
                "Did not import MCP settings into {}: the target is a link or not a regular file.",
                crate::host::tilde(&host.home(), &target)
            ),]
        );
        assert!(target.is_dir());
    }

    #[test]
    fn mcp_import_can_be_enabled_after_the_agent_creates_its_config() {
        let host = FakeHost::new();
        let source = host.home().join(".claude.json");
        std::fs::write(
            &source,
            r#"{"mcpServers":{"docs":{"url":"https://docs.example.com"}}}"#,
        )
        .expect("host config");
        host.profile()
            .with("claude")
            .with("bedrock")
            .option("claude.import-mcp", "false")
            .create()
            .expect("profile")
            .write(false)
            .expect("write");
        host.launcher()
            .prepare("claude", &host.project(), None)
            .expect("disabled import");
        let target = storage_root(&host.home().join(".strands/box"), "claude")
            .join("agent/config/.claude.json");
        assert!(!target.exists());
        let agent_state = r#"{"numStartups":1,"hasCompletedOnboarding":true}"#;
        std::fs::write(&target, agent_state).expect("agent creates its config");
        host.launcher()
            .prepare("claude", &host.project(), None)
            .expect("still disabled");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), agent_state);
        host.profile()
            .with("claude")
            .option("claude.import-mcp", "true")
            .with("bedrock")
            .create()
            .expect("profile")
            .write(true)
            .expect("enable import");
        for _ in 0..2 {
            host.launcher()
                .prepare("claude", &host.project(), None)
                .expect("import into agent config");
            let saved: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&target).unwrap()).unwrap();
            assert_eq!(
                saved,
                serde_json::json!({
                    "numStartups": 1, "hasCompletedOnboarding": true,
                    "mcpServers": {"docs": {"url": "https://docs.example.com"}}
                })
            );
            std::fs::write(&target, agent_state).expect("remove only the MCP section");
        }
    }

    #[test]
    fn a_server_that_npx_starts_gets_the_shipped_launcher_pack_whatever_the_profile_lists() {
        let host = FakeHost::new();
        if !host.brew().join("bin/npx").exists() {
            let keg = brew_program(&host, "npx");
            std::fs::write(keg.join("bin/npx"), "#!/usr/bin/env node\n").expect("a Node launcher");
        }
        std::fs::write(
            host.home().join(".claude.json"),
            r#"{"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}}}"#,
        )
        .expect("a host file");
        host.profile()
            .with("claude")
            .option("claude.import-mcp", "true")
            .with("bedrock")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let preview = host
            .launcher()
            .preview("claude", &host.project())
            .expect("a preview");
        assert_eq!(
            preview.mcp_servers,
            vec![(
                "github".to_string(),
                "~/.claude.json".to_string(),
                String::new()
            )]
        );
        let file: toml::Table = toml::from_str(&preview.box_toml).expect("TOML");
        let github = file["mcp"]["github"].as_table().expect("a table");
        let cache = storage_root(&host.home().join(".strands/box"), "claude")
            .join("mcp-cache")
            .join("npx")
            .display()
            .to_string();
        assert_eq!(
            github["env"]["TMPDIR"].as_str(),
            Some(cache.as_str()),
            "a server that npx starts keeps its temporary files in its own cache"
        );
        let scratch = "/tool-tmp/".to_string();
        for list in ["read", "write"] {
            let entries: Vec<&str> = github["filesystem"]
                .get(list)
                .and_then(toml::Value::as_array)
                .map(|entries| entries.iter().filter_map(toml::Value::as_str).collect())
                .unwrap_or_default();
            assert!(
                entries
                    .iter()
                    .all(|entry| !entry.contains(scratch.as_str())),
                "the server gets no grant on a tool's folder: {list} {entries:?}"
            );
        }
        let other = host.home().join("work/other");
        std::fs::create_dir_all(&other).expect("a second project");
        let elsewhere: toml::Table = toml::from_str(
            &host
                .launcher()
                .preview("claude", &other)
                .expect("a preview")
                .box_toml,
        )
        .expect("TOML");
        assert_eq!(
            elsewhere["mcp"]["github"]["env"]["npm_config_cache"].as_str(),
            Some(cache.as_str()),
            "a server in another project of the profile shares the profile's launcher cache"
        );
        assert_eq!(
            github["env"]["npm_config_cache"].as_str(),
            Some(cache.as_str())
        );
        assert!(
            github["filesystem"]["write"]
                .as_array()
                .expect("a list")
                .contains(&toml::Value::from(cache.clone())),
            "the server writes its launcher cache"
        );
        assert!(
            !file["agent"]["filesystem"]["write"]
                .as_array()
                .expect("a list")
                .contains(&toml::Value::from(cache.clone())),
            "the agent never writes a server's cache"
        );
        for id in [
            "launcher_github_registry_connect",
            "launcher_github_registry_request",
        ] {
            assert!(preview.policy.contains(id), "{id} in\n{}", preview.policy);
        }
        assert!(preview.policy.contains("registry.npmjs.org"));
        host.launcher()
            .prepare("claude", &host.project(), None)
            .expect("a launch");
        assert!(
            std::path::Path::new(&cache).is_dir(),
            "a run makes the cache folder"
        );
    }

    #[test]
    fn the_json_preview_prints_the_key_of_an_imported_server_only_with_full() {
        let host = FakeHost::new();
        if !host.brew().join("bin/npx").exists() {
            let keg = brew_program(&host, "npx");
            std::fs::write(keg.join("bin/npx"), "#!/usr/bin/env node\n").expect("a Node launcher");
        }
        let secret = "ghp_SCRATCHSECRET";
        std::fs::write(
            host.home().join(".claude.json"),
            serde_json::json!({"mcpServers": {"github": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": secret},
            }}})
            .to_string(),
        )
        .expect("a host file");
        host.profile()
            .with("claude")
            .option("claude.import-mcp", "true")
            .with("bedrock")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let preview = host
            .launcher()
            .preview("claude", &host.project())
            .expect("a preview");
        assert!(preview.box_toml.contains(secret), "{}", preview.box_toml);
        let summary = preview.json("claude", false).expect("a document");
        assert!(!summary.to_string().contains(secret), "{summary}");
        assert_eq!(
            summary["mcp"]["servers"],
            serde_json::json!([{
                "server": "github",
                "file": "~/.claude.json",
                "detail": ", with GITHUB_PERSONAL_ACCESS_TOKEN",
            }])
        );
        let full = preview.json("claude", true).expect("a document");
        assert_eq!(
            full["box_toml"]["mcp"]["github"]["env"]["GITHUB_PERSONAL_ACCESS_TOKEN"],
            secret
        );
    }

    #[test]
    fn a_launcher_registry_rule_does_not_collide_with_a_remote_server_name() {
        let host = FakeHost::new();
        if !host.brew().join("bin/npx").exists() {
            let keg = brew_program(&host, "npx");
            std::fs::write(keg.join("bin/npx"), "#!/usr/bin/env node\n").expect("a Node launcher");
        }
        std::fs::write(
            host.home().join(".claude.json"),
            r#"{"mcpServers": {
            "github": {"command":"npx", "args":["-y", "memory"]},
            "github_registry": {"url":"https://docs.example.com/mcp"}
        }}"#,
        )
        .expect("host config");
        host.profile()
            .with("claude")
            .option("claude.import-mcp", "true")
            .with("bedrock")
            .create()
            .expect("profile")
            .write(false)
            .expect("write");
        let preview = host
            .launcher()
            .preview("claude", &host.project())
            .expect("distinct policy IDs");
        assert_eq!(preview.mcp_servers.len(), 2);
        assert_eq!(
            preview
                .policy
                .matches("@id(\"mcp_github_registry_connect\")")
                .count(),
            1
        );
    }

    #[test]
    fn a_path_entry_that_is_not_a_full_path_leaves_the_servers_and_is_reported_once() {
        let host = FakeHost::new();
        for program in ["mcp-fetch", "mcp-issues", "mcp-other"] {
            brew_program(&host, program);
        }
        std::fs::write(
            host.home().join(".claude.json"),
            r#"{"mcpServers": {"fetch": {"command": "mcp-fetch"}, "issues": {"command": "mcp-issues"}}}"#,
        )
        .expect("a host file");
        let search_path = format!("{}:~/.dotnet/tools", host.search_path());
        host.profile()
            .with("claude")
            .with("bedrock")
            .option("claude.import-mcp", "true")
            .search_path(search_path.clone())
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let path = host
            .home()
            .join(".strands/box/profiles/claude/profile.toml");
        let text = std::fs::read_to_string(&path).expect("a profile");
        std::fs::write(
            &path,
            format!("{text}\n[mcp.other]\ntype = \"stdio\"\ncommand = [\"mcp-other\"]\n"),
        )
        .expect("a profile server");
        let preview = host
            .launcher()
            .search_path(search_path.clone())
            .preview("claude", &host.project())
            .expect("a preview");
        assert_eq!(preview.mcp_skipped, Vec::new());
        assert_eq!(
            preview.mcp_path_dropped,
            vec![
                "\"~/.dotnet/tools\" from the PATH of each MCP server that inherits your PATH: it \
                 is not a full path, so it finds programs in the project"
                    .to_string()
            ]
        );
        let file: toml::Table = toml::from_str(&preview.box_toml).expect("TOML");
        for server in ["fetch", "issues", "other"] {
            assert_eq!(
                file["mcp"][server]["env"]["PATH"].as_str(),
                Some(host.search_path().as_str()),
                "{server}"
            );
        }
        let launch = host
            .launcher()
            .search_path(search_path)
            .prepare("claude", &host.project(), None)
            .expect("a launch");
        assert_eq!(
            launch.mcp_path_dropped(),
            preview.mcp_path_dropped.as_slice()
        );
    }

    #[test]
    fn a_launchers_path_holds_only_the_full_entries_of_your_path() {
        let host = FakeHost::new();
        if !host.brew().join("bin/npx").exists() {
            let keg = brew_program(&host, "npx");
            std::fs::write(keg.join("bin/npx"), "#!/usr/bin/env node\n").expect("a Node launcher");
        }
        std::fs::write(
            host.home().join(".claude.json"),
            r#"{"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}}}"#,
        )
        .expect("a host file");
        let search_path = format!("{}:.", host.search_path());
        host.profile()
            .with("claude")
            .with("bedrock")
            .option("claude.import-mcp", "true")
            .search_path(search_path.clone())
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let preview = |search_path: &str| {
            host.launcher()
                .search_path(search_path)
                .preview("claude", &host.project())
                .expect("a preview")
        };
        let launcher_path = |preview: &crate::Preview| {
            let file: toml::Table = toml::from_str(&preview.box_toml).expect("TOML");
            file["mcp"]["github"]["env"]["PATH"]
                .as_str()
                .expect("a PATH")
                .to_string()
        };
        let full = launcher_path(&preview(&host.search_path()));
        let dropped = preview(&search_path);
        assert_eq!(launcher_path(&dropped), full);
        assert_eq!(
            dropped.mcp_path_dropped,
            vec![
                "\".\" from the PATH of each MCP server that inherits your PATH: it is not a full \
                 path, so it finds programs in the project"
                    .to_string()
            ]
        );
        let path = host
            .home()
            .join(".strands/box/profiles/claude/profile.toml");
        let text = std::fs::read_to_string(&path).expect("a profile");
        std::fs::write(
            &path,
            format!("{text}\n[mcp.github.env]\nPATH = \"/usr/bin:.\"\n"),
        )
        .expect("a profile PATH");
        let own = preview(&search_path);
        assert_eq!(
            launcher_path(&own),
            "/usr/bin:.",
            "the profile's PATH is kept"
        );
        assert!(
            own.mcp_path_dropped.is_empty(),
            "no server inherits your PATH"
        );
    }

    #[test]
    fn a_profile_that_does_not_turn_on_mcp_import_declares_no_host_server() {
        let host = FakeHost::new();
        std::fs::write(
            host.home().join(".claude.json"),
            format!(
                r#"{{"mcpServers": {{"docs": {{"url": "https://docs.example.com/mcp"}}}},
                    "projects": {{"{}": {{"mcpServers": {{"local": {{"url": "https://local.example.com/mcp"}}}}}}}}}}"#,
                host.project().display()
            ),
        )
        .expect("a host file");
        std::fs::create_dir_all(host.home().join(".codex")).expect("a codex folder");
        std::fs::write(
            host.home().join(".codex/config.toml"),
            "[mcp_servers.docs]\nurl = \"https://docs.example.com/mcp\"\n",
        )
        .expect("a host file");
        for (agent, provider) in [("claude", "bedrock"), ("codex", "bedrock-mantle")] {
            host.profile()
                .with(agent)
                .with(provider)
                .create()
                .expect("a profile")
                .write(false)
                .expect("a write");
            let preview = host
                .launcher()
                .preview(agent, &host.project())
                .expect("a preview");
            assert!(preview.mcp_servers.is_empty(), "{agent}");
            assert!(!preview.box_toml.contains("example.com"), "{agent}");
            assert!(!preview.policy.contains("example.com"), "{agent}");
        }
    }

    #[test]
    fn the_policy_starter_sets_project_access_for_the_agent_its_tools_and_its_servers() {
        for (policy, access, edited, reads, writes) in [
            ("open", "write", None, true, true),
            ("locked", "read", None, true, false),
            ("open", "write", Some("none"), false, false),
        ] {
            let host = FakeHost::new();
            brew_program(&host, "mcp-fetch");
            std::fs::write(
                host.home().join(".claude.json"),
                r#"{"mcpServers": {"fetch": {"type": "stdio", "command": "mcp-fetch", "args": []}}}"#,
            )
            .expect("a host file");
            let project = host.project().display().to_string();
            let created = host
                .profile()
                .with("claude")
                .option("claude.import-mcp", "true")
                .with("bedrock")
                .policy(policy)
                .create()
                .expect("a profile");
            assert!(
                created.text().contains(&format!(
                    "# How much of your project the agent reaches: \"none\", \"read\", \
                     \"write\".\n[project]\naccess = \"{access}\"\n"
                )),
                "{policy}: {}",
                created.text()
            );
            created.write(false).expect("a write");
            if let Some(edited) = edited {
                let text = created.text().replace(
                    &format!("access = \"{access}\""),
                    &format!("access = \"{edited}\""),
                );
                std::fs::write(created.path(), text).expect("an edit");
            }
            let preview = host
                .launcher()
                .preview("claude", &host.project())
                .expect("a preview");
            let file: toml::Table = toml::from_str(&preview.box_toml).expect("TOML");
            let mut processes: Vec<(String, &toml::Value)> =
                vec![("agent".into(), &file["agent"]["filesystem"])];
            for (name, tool) in file["tool"].as_table().expect("tools") {
                processes.push((format!("tool {name}"), &tool["filesystem"]));
            }
            processes.push(("mcp fetch".into(), &file["mcp"]["fetch"]["filesystem"]));
            assert!(processes.len() > 2, "{processes:?}");
            for (name, filesystem) in processes {
                let list = |key: &str| filesystem.get(key).map(strings).unwrap_or_default();
                assert_eq!(
                    list("read").contains(&project),
                    reads,
                    "{policy} {edited:?} {name}: {filesystem}"
                );
                assert_eq!(
                    list("write").contains(&project),
                    writes,
                    "{policy} {name}: {filesystem}"
                );
            }
            for (id, expected) in [
                ("project_read", reads),
                ("project_write", writes),
                ("project_delete", writes),
                ("project_move", writes),
                ("project_configuration_write", true),
            ] {
                assert_eq!(
                    preview.policy.contains(&format!("@id(\"{id}\")")),
                    expected,
                    "{policy} {id}: {}",
                    preview.policy
                );
            }
        }
    }

    #[test]
    fn a_run_of_a_profile_without_project_says_what_to_add() {
        let host = FakeHost::new();
        let folder = host.home().join(".strands/box/profiles/bare");
        std::fs::create_dir_all(&folder).expect("a profile folder");
        let path = folder.join("profile.toml");
        for (text, notice) in [
            (
                MINIMAL.to_string(),
                Some(
                    "profile bare gives the agent no access to this project; to allow it, add \
                     `[project] access = \"write\"` to ~/.strands/box/profiles/bare/profile.toml",
                ),
            ),
            (format!("{MINIMAL}\n[project]\naccess = \"write\"\n"), None),
        ] {
            std::fs::write(&path, &text).expect("a profile");
            let launch = host
                .launcher()
                .prepare("bare", &host.project(), None)
                .expect("a launch");
            assert_eq!(launch.project_notice(), notice, "{text}");
        }
    }

    #[test]
    fn profile_show_names_the_project_access() {
        let host = FakeHost::new();
        let folder = host.home().join(".strands/box/profiles/bare");
        std::fs::create_dir_all(&folder).expect("a profile folder");
        for (project, row) in [
            ("[project]\naccess = \"write\"\n", "read and write"),
            ("[project]\naccess = \"read\"\n", "read only"),
            ("[project]\naccess = \"none\"\n", "none"),
            ("", "none (no [project] in this profile)"),
        ] {
            std::fs::write(folder.join("profile.toml"), format!("{MINIMAL}\n{project}"))
                .expect("a profile");
            let preview = host
                .launcher()
                .preview("bare", &host.project())
                .expect("a preview");
            assert_eq!(preview.project_row(), row, "{project}");
        }
    }

    #[test]
    fn a_new_policy_answer_keeps_saved_project_access_and_fills_a_missing_one() {
        let host = FakeHost::new();
        host.profile()
            .with("claude")
            .with("bedrock")
            .policy("locked")
            .create()
            .expect("a profile")
            .write(false)
            .expect("a write");
        let path = host
            .home()
            .join(".strands/box/profiles/claude/profile.toml");
        let edit = |policy: Option<&str>| {
            let edit = host.profile().edit("claude").expect("an edit");
            match policy {
                Some(policy) => edit.policy(policy),
                None => edit,
            }
            .create()
            .expect("an edited profile")
            .text()
            .to_string()
        };
        for policy in [Some("open"), None] {
            let text = edit(policy);
            assert_eq!(text.matches("[project]").count(), 1, "{policy:?}: {text}");
            assert!(
                text.contains("[project]\naccess = \"read\"\n"),
                "a saved value is kept, {policy:?}: {text}"
            );
        }
        let saved = std::fs::read_to_string(&path).expect("the profile");
        let start = saved.find("\n# How much").expect("the [project] comment");
        let end = saved
            .find("access = \"read\"\n")
            .expect("the [project] value")
            + "access = \"read\"\n".len();
        std::fs::write(&path, format!("{}{}", &saved[..start], &saved[end..])).expect("an edit");
        let filled = edit(Some("open"));
        assert!(
            filled.contains("[project]\naccess = \"write\"\n"),
            "a missing value comes from the starter: {filled}"
        );
    }

    #[test]
    fn an_own_policy_starter_without_project_writes_no_project_table() {
        let host = FakeHost::new();
        let folder = host.home().join(".strands/box/policies/mine");
        std::fs::create_dir_all(&folder).expect("a policy folder");
        std::fs::write(
            folder.join("policy.toml"),
            "[policy]\nname = \"mine\"\nlabel = \"Mine\"\ndescription = \"Mine.\"\n",
        )
        .expect("policy.toml");
        std::fs::write(folder.join("policy.dw"), "").expect("policy.dw");
        let created = host
            .profile()
            .with("claude")
            .with("bedrock")
            .policy("mine")
            .create()
            .expect("a profile");
        assert!(!created.text().contains("[project]"), "{}", created.text());
        assert_eq!(created.profile().table.get("project"), None);
    }
}

#[test]
fn an_input_used_in_env_first_is_still_checked_in_a_destination() {
    let scene = Scene::new();
    scene.share("region", "[inputs.region]\ndefault = \"evil.example.com/\"");
    let reason = scene.refusal(
        "packs = [\"@box/region\"]\n\
         [agent]\ncommand = [\"/bin/x\"]\nenv.AWS_REGION = \"${{ inputs.region }}\"\n\
         [egress.model]\ndestinations = [\"bedrock-runtime.${{ inputs.region }}.amazonaws.com\"]\n\
         secret.ref = \"env://KEY\"",
    );
    assert!(reason.contains("needs `pattern` or `values`"), "{reason}");
}

#[test]
fn a_host_variable_reaches_a_destination_only_with_a_pattern() {
    let scene = Scene::new();
    let text = |declaration: &str| {
        scene.share(
            "host",
            &format!("[inputs.host]\nfrom = \"env:SET\"\n{declaration}"),
        );
        "packs = [\"@box/host\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
         [egress.model]\ndestinations = [\"${{ inputs.host }}.example.com\"]\n\
         secret.ref = \"env://KEY\""
    };
    let reason = scene.refusal(text(""));
    assert!(reason.contains("needs `pattern` or `values`"), "{reason}");
    let compiled = scene
        .compile(&profile(text("pattern = \"[a-z-]+\"")), None)
        .expect("a bounded variable");
    assert_eq!(
        strings(&table(&compiled)["egress"]["model"]["destinations"]),
        ["set-value.example.com"]
    );
}

#[test]
fn only_a_command_path_is_checked_as_a_path() {
    let scene = Scene::new();
    scene.share(
        "args",
        "[inputs.flag]\ndefault = \"--fast\"\npattern = \"--[a-z]+\"\n\
         [inputs.part]\ndefault = \"a/../../etc\"\npattern = \".*\"",
    );
    let text = |program: &str| {
        format!(
            "packs = [\"@box/args\"]\n\
             [agent]\ncommand = [{program:?}, \"${{{{ inputs.flag }}}}\"]"
        )
    };
    scene
        .compile(&profile(&text("/bin/x")), None)
        .expect("an argument that starts with an option is not a path");
    let reason = scene.refusal(&text("/opt/${{ inputs.part }}"));
    assert!(reason.contains("a placeholder comes first"), "{reason}");
}

#[test]
fn a_grant_through_a_link_in_the_workspace_is_refused() {
    let scene = Scene::new();
    let secret = scene.home().join("secret");
    std::fs::create_dir_all(&secret).unwrap();
    std::os::unix::fs::symlink(&secret, scene.workspace().join("cache")).unwrap();
    let reason = scene
        .refusal("[agent]\ncommand = [\"/bin/x\"]\nfilesystem.read = [\"${{ workspace }}/cache\"]");
    assert!(reason.contains("resolves through a link"), "{reason}");

    let file = secret.join("policy");
    std::fs::write(&file, "policy").expect("an outside file");
    for (name, root) in [
        ("workspace", scene.workspace()),
        ("storage", scene.storage()),
    ] {
        std::fs::create_dir_all(&root).expect("a writable folder");
        let writable = root.join("policy");
        std::os::unix::fs::symlink(&file, &writable).expect("a writable link");
        let parent = scene.home().join(format!("trusted-{name}-parent"));
        std::os::unix::fs::symlink(&root, &parent).expect("a parent link");
        let leaf = scene.home().join(format!("trusted-{name}-file"));
        std::os::unix::fs::symlink(&writable, &leaf).expect("a leaf link");
        for input in [parent.join("policy"), leaf] {
            let result = scene.resolve(&profile(&format!(
                "[agent]\ncommand = [\"/bin/x\"]\nfilesystem.read_file = [{input:?}]"
            )));
            assert!(
                result.is_err(),
                "a grant through a writable link: {input:?}"
            );
            let error = result.unwrap_err();
            assert!(error.to_string().contains("can write"), "{error}");
        }
    }
}

/// A profile whose `holder` table has a write grant on `notes`, and whose agent names `entry` in
/// `list`.
fn beneath_a_write_grant(holder: &str, notes: &Path, list: &str, entry: &Path) -> String {
    let mut lists = vec![(list, vec![entry])];
    if holder == "[agent]" && list == "write" {
        lists[0].1.push(notes);
    } else if holder == "[agent]" {
        lists.push(("write", vec![notes]));
    }
    let agent: String = lists
        .iter()
        .map(|(name, entries)| format!("filesystem.{name} = {entries:?}\n"))
        .collect();
    let holder = if holder == "[agent]" {
        String::new()
    } else {
        format!("{holder}\ncommand = [\"/usr/bin/true\"]\nfilesystem.write = [{notes:?}]\n")
    };
    format!("[agent]\ncommand = [\"/bin/x\"]\n{agent}{holder}")
}

#[test]
fn a_grant_through_a_link_under_a_write_grant_is_refused() {
    let scene = Scene::new();
    let notes = scene.home().join("notes");
    let out = notes.join("out");
    let outside = scene.home().join("outside");
    std::fs::create_dir_all(&out).expect("a folder beneath the grant");
    std::fs::create_dir_all(&outside).expect("a folder that no entry names");
    let holders = ["[agent]", "[tool.t]", "[mcp.s]\ntype = \"stdio\""];
    let lists = ["read", "write", "read_file", "deny"];
    for holder in holders {
        for list in lists {
            let compiled = scene
                .compile(
                    &profile(&beneath_a_write_grant(holder, &notes, list, &out)),
                    None,
                )
                .unwrap_or_else(|error| panic!("{holder} {list}: a real folder: {error}"));
            let granted = strings(&table(&compiled)["agent"]["filesystem"][list]);
            // The agent's own grant on `notes` covers a second write grant beneath it.
            assert!(
                granted.contains(&out.display().to_string())
                    || (holder == "[agent]" && list == "write"),
                "{holder} {list}: {granted:?}"
            );
        }
    }

    std::fs::remove_dir(&out).expect("remove the folder");
    std::os::unix::fs::symlink(&outside, &out).expect("a link where the folder was");
    for holder in holders {
        for list in lists {
            let reason = scene.refusal(&beneath_a_write_grant(holder, &notes, list, &out));
            assert!(
                reason.contains(&format!(
                    "resolves through a link to {}, inside {}, which the box can write",
                    outside.display(),
                    notes.display()
                )),
                "{holder} {list}: {reason}"
            );
        }
    }
    let below = scene.refusal(&beneath_a_write_grant(
        "[agent]",
        &notes,
        "read",
        &out.join("absent"),
    ));
    assert!(below.contains("resolves through a link"), "{below}");

    std::fs::remove_file(&out).expect("remove the link");
    let nothing = scene.home().join("nothing");
    std::os::unix::fs::symlink(&nothing, &out).expect("a link to nothing");
    let dangling = scene.refusal(&beneath_a_write_grant("[agent]", &notes, "read", &out));
    assert!(
        dangling.contains(&format!("resolves through a link to {}", nothing.display())),
        "{dangling}"
    );
}

#[test]
fn a_grant_through_a_link_in_the_box_home_is_refused() {
    let scene = Scene::new();
    let shared = scene.home().join(".strands/box/shared");
    let outside = scene.home().join("outside");
    std::fs::create_dir_all(shared.join("real")).expect("a folder in the box home");
    std::fs::create_dir_all(&outside).expect("a folder that no entry names");
    std::os::unix::fs::symlink(&outside, shared.join("link")).expect("a link in the box home");
    let text = |entry: &str| {
        format!(
            "[agent]\ncommand = [\"/bin/x\"]\nfilesystem.read = [{:?}]",
            shared.join(entry)
        )
    };
    scene
        .resolve(&profile(&text("real")))
        .expect("a real folder in the box home");
    let reason = scene.resolve_refusal(&text("link"));
    assert!(
        reason.contains(&format!(
            "resolves through a link to {}, inside {}, which the box can write",
            outside.display(),
            scene.home().join(".strands/box").display()
        )),
        "{reason}"
    );
}

#[test]
fn a_tool_entry_through_a_link_under_a_write_grant_is_refused() {
    let scene = Scene::new();
    let notes = scene.home().join("notes");
    let outside = scene.home().join("outside");
    std::fs::create_dir_all(notes.join("out-real")).expect("a folder beneath the grant");
    std::fs::create_dir_all(&outside).expect("a folder that no entry names");
    scene.share(
        "rt",
        &format!(
            "kind = \"tool\"\n[inputs.rt.path]\ntype = \"program\"\nprogram = \"rt\"\n\
             search = [{{ env = \"PATH\" }}]\n[run]\ncommand = [\"${{{{ inputs.rt.path }}}}\"]\n\
             [filesystem]\nread = [{:?}]",
            notes.join("out-*")
        ),
    );
    let text = format!("packs = [\"@box/rt\"]\n{AGENT}\nfilesystem.write = [{notes:?}]");
    let resolved = detected(&scene, &text).expect("a real folder beneath the grant");
    let read = &resolved.tool["rt"].filesystem.read;
    assert!(
        read.contains(&notes.join("out-real").display().to_string()),
        "{read:?}"
    );
    std::os::unix::fs::symlink(&outside, notes.join("out-link")).expect("a link beside it");
    let refused = detected(&scene, &text).expect_err("a match that is a link");
    assert!(
        refused.to_string().contains(&format!(
            "resolves through a link to {}, inside {}, which the box can write",
            outside.display(),
            notes.display()
        )),
        "{refused}"
    );
}

#[test]
fn a_link_above_a_write_grant_is_followed() {
    let scene = Scene::new();
    let real = scene.root.join("private/notes");
    std::fs::create_dir_all(real.join("out")).expect("a folder beneath the grant");
    let above = scene.root.join("above");
    std::os::unix::fs::symlink(scene.root.join("private"), &above).expect("a link above");
    let at = scene.home().join("notes");
    std::os::unix::fs::symlink(&real, &at).expect("a link at the grant");
    let mut grants = vec![above.join("notes"), at];
    // On macOS, `/tmp` is a link that a box cannot write.
    let temporary = Path::new("/tmp")
        .is_symlink()
        .then(|| tempfile::tempdir_in("/tmp").expect("a folder in /tmp"));
    if let Some(temporary) = &temporary {
        std::fs::create_dir_all(temporary.path().join("out")).expect("a folder beneath the grant");
        grants.push(temporary.path().to_path_buf());
    }
    for notes in grants {
        let real = resolved(&notes);
        assert_ne!(real, notes, "{notes:?} holds a link");
        let compiled = scene
            .compile(
                &profile(&beneath_a_write_grant(
                    "[agent]",
                    &notes,
                    "read",
                    &notes.join("out"),
                )),
                None,
            )
            .unwrap_or_else(|error| panic!("{notes:?}: a link above the grant: {error}"));
        let filesystem = &table(&compiled)["agent"]["filesystem"];
        let text = |path: &Path| path.display().to_string();
        assert!(strings(&filesystem["write"]).contains(&text(&real)));
        assert!(strings(&filesystem["read"]).contains(&text(&real.join("out"))));
    }
}

#[test]
fn a_home_that_is_a_link_keeps_its_grants() {
    let scene = Scene::new();
    let real = scene.root.join("real-home");
    std::fs::rename(scene.home(), &real).expect("move the home");
    std::os::unix::fs::symlink(&real, scene.home()).expect("a home that is a link");
    let context = Context {
        workspace: real.join("work").join(&scene.workspace),
        os: "macos",
    };
    let notes = scene.home().join("notes");
    let out = notes.join("out");
    std::fs::create_dir_all(&out).expect("a folder beneath the grant");
    std::fs::write(scene.home().join("settings"), "").expect("a file in the home");
    let text = format!(
        "{}filesystem.read_file = [{:?}]\n",
        beneath_a_write_grant("[agent]", &notes, "read", &out),
        scene.home().join("settings")
    );
    let resolved = scene
        .resolve_with(&profile(&text), &context)
        .expect("each entry is below a home that is a link");
    let read = &resolved.agent.filesystem.read;
    assert!(
        read.contains(&real.join("notes/out").display().to_string()),
        "{read:?}"
    );

    std::fs::remove_dir(&out).expect("remove the folder");
    std::os::unix::fs::symlink(real.join("work"), &out).expect("a link where the folder was");
    let refused = scene
        .resolve_with(&profile(&text), &context)
        .expect_err("a link beneath the grant");
    assert!(
        refused.to_string().contains("resolves through a link"),
        "{refused}"
    );
}

#[test]
fn a_path_argument_under_a_write_grant_is_no_program() {
    let scene = Scene::new();
    scene
        .compile(
            &profile(
                "[storage]\ndirectories = [\"cfg\"]\n\
                 [agent]\ncommand = [\"/bin/echo\", \"--config-dir\", \"${{ storage.cfg }}\", \
                 \"-C\", \"${{ workspace }}\"]",
            ),
            None,
        )
        .expect("a directory argument under a write grant");
}

#[test]
fn a_path_component_cannot_be_empty_or_a_dot() {
    let scene = Scene::new();
    scene.share("part", "[inputs.part]\ndescription = \"One path part.\"");
    for part in ["", "."] {
        let reason = scene.refusal(&format!(
            "packs = [\"@box/part\"]\n[options]\npart = {part:?}\n\
             [agent]\ncommand = [\"/bin/x\"]\n\
             filesystem.read = [\"${{{{ home }}}}/x/${{{{ inputs.part }}}}\"]"
        ));
        assert!(
            reason.contains("is not one path component"),
            "{part:?}: {reason}"
        );
    }
}

#[test]
fn an_input_default_writes_its_escape_as_text() {
    let scene = Scene::new();
    scene.share("x", "[inputs.x]\ndefault = \"a$${{ home }}b\"");
    let compiled = scene
        .compile(
            &profile(
                "packs = [\"@box/x\"]\n\
                 [agent]\ncommand = [\"/bin/x\"]\nenv.X = \"${{ inputs.x }}\"",
            ),
            None,
        )
        .expect("a compile");
    assert_eq!(
        table(&compiled)["agent"]["env"]["X"].as_str(),
        Some("a${{ home }}b")
    );
}

#[test]
fn a_profile_and_a_pack_each_refuse_the_others_keys() {
    let scene = Scene::new();
    for (key, text) in [
        ("extend", "extend = []"),
        ("inputs", "[inputs.x]\ndefault = \"a\""),
        ("pack", "[pack]\nname = \"mine\"\nversion = 1"),
    ] {
        let reason = scene.refusal(&format!(
            "{}\n[agent]\ncommand = [\"/bin/x\"]",
            text.replace("[agent]", "")
        ));
        assert!(
            reason.contains(&format!(
                "a profile holds no `{key}`; `{key}` belongs in a pack"
            )),
            "{key}: {reason}"
        );
    }
    for (key, text) in [
        ("packs", "packs = [\"@box/other\"]"),
        ("options", "[options]\nx = \"a\""),
    ] {
        if text.starts_with('[') {
            scene.share("wrong", text);
        } else {
            scene.share_top("wrong", text, "");
        }
        let reason = scene.refusal("packs = [\"@box/wrong\"]\n[agent]\ncommand = [\"/bin/x\"]");
        assert!(
            reason.contains(&format!(
                "a pack holds no `{key}`; `{key}` belongs in a profile"
            )),
            "{key}: {reason}"
        );
    }
    let reason = scene.refusal("packs = [\"@box/none\"]\n[agent]\ncommand = [\"/bin/x\"]");
    assert!(
        reason.contains("the pack \"@box/none\" does not exist"),
        "{reason}"
    );
}

#[test]
fn a_pack_declares_no_mcp_server_and_a_profile_still_can() {
    let scene = Scene::new();
    scene.share(
        "server",
        "[mcp.fetch]\ntype = \"stdio\"\ncommand = [\"fetcher\"]",
    );
    match scene.resolve(&profile(
        "packs = [\"@box/server\"]\n[agent]\ncommand = [\"/bin/x\"]",
    )) {
        Err(Error::Profile { path, reason, .. }) => {
            assert!(
                path.ends_with("packs/server/pack.toml"),
                "{}",
                path.display()
            );
            assert!(
                reason.contains(
                    "a pack declares no MCP server; it names its agent's MCP configuration in \
                     `[[mcp-servers]]`, and `[mcp.<name>]` with a `type` belongs in a profile; \
                     a pack's `[mcp.fetch]` adds to a server this run finds, and holds only \
                     `filesystem` and `network`, not `type`"
                ),
                "{reason}"
            );
        }
        other => panic!("a refusal, not {other:?}"),
    }
    scene.share("outer", "extend = [\"@box/server\"]");
    match scene.resolve(&profile(
        "packs = [\"@box/outer\"]\n[agent]\ncommand = [\"/bin/x\"]",
    )) {
        Err(Error::Profile { path, reason, .. }) => {
            assert!(
                path.ends_with("packs/server/pack.toml"),
                "the pack an extends pulls in is named: {}",
                path.display()
            );
            assert!(reason.contains("a pack declares no MCP server"), "{reason}");
        }
        other => panic!("a refusal, not {other:?}"),
    }
    scene
        .resolve(&profile(
            "[agent]\ncommand = [\"/bin/x\"]\n[mcp.fetch]\ntype = \"stdio\"\ncommand = [\"fetcher\"]",
        ))
        .expect("a profile declares a server as the operator's own");
}

#[test]
fn a_pack_needs_a_header_with_a_name_and_a_version() {
    let scene = Scene::new();
    let name = "[pack]\nkind = \"support\"\nname = \"@box/p\"";
    for (text, why) in [
        (
            "[agent.env]\nX = \"1\"".to_string(),
            "a pack needs a `[pack]` header with `name`, `version`, and `kind`",
        ),
        (name.to_string(), "`[pack]` needs `version`"),
        (
            "[pack]\nkind = \"support\"\nversion = 1".to_string(),
            "`[pack]` needs `name`",
        ),
        (
            format!("{name}\nversion = \"0.1.0\""),
            "`[pack] version` is a whole number, such as 1",
        ),
        (
            format!("{name}\nversion = 1.5"),
            "`[pack] version` is a whole number, such as 1",
        ),
        (
            format!("{name}\nversion = -1"),
            "`[pack] version` is a whole number, such as 1",
        ),
        (
            format!("{name}\nversion = 1\nlicense = \"MIT\""),
            "`[pack]` holds the unknown key `license`",
        ),
        (
            format!("{name}\nversion = 1\nengine = \">=99.0\""),
            "this pack needs box >=99.0, and this is box",
        ),
        (
            format!("{name}\nversion = 1\nengine = \"0.1\""),
            "is not `>=X.Y.Z`",
        ),
    ] {
        scene.share_raw("p", &text);
        let reason = scene.refusal("packs = [\"@box/p\"]\n[agent]\ncommand = [\"/bin/x\"]");
        assert!(reason.contains(why), "{text}: {reason}");
    }
    let (major, minor, patch) = {
        let mut parts = crate::VERSION
            .split('.')
            .map(|part| part.parse::<u64>().expect("a number"));
        (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        )
    };
    scene.share_raw(
        "p",
        &format!(
            "{name}\nversion = 1\nengine = \">={major}.{minor}.{}\"",
            patch + 1
        ),
    );
    let reason = scene.refusal("packs = [\"@box/p\"]\n[agent]\ncommand = [\"/bin/x\"]");
    assert!(
        reason.contains(&format!("and this is box {}", crate::VERSION)),
        "the floor is checked against the CLI's own version: {reason}"
    );
    scene.share_raw(
        "p",
        &format!(
            "{name}\nversion = 1\nengine = \">={}\"",
            env!("CARGO_PKG_VERSION")
        ),
    );
    scene
        .compile(
            &profile("packs = [\"@box/p\"]\n[agent]\ncommand = [\"/bin/x\"]"),
            None,
        )
        .expect("a pack for this box");
}

#[test]
fn a_pack_that_another_pack_extends_is_checked_for_its_engine() {
    let scene = Scene::new();
    scene.share_raw(
        "newer",
        "[pack]\nname = \"@box/newer\"\nversion = 1\nkind = \"support\"\nengine = \">=99.0\"",
    );
    scene.share("base", "extend = [\"@box/newer\"]");
    let reason = scene.refusal("packs = [\"@box/base\"]\n[agent]\ncommand = [\"/bin/x\"]");
    assert!(
        reason.contains("this pack needs box >=99.0"),
        "an imported pack is checked too: {reason}"
    );
}

#[test]
fn a_key_the_language_does_not_hold_is_refused() {
    let scene = Scene::new();
    let reason = scene.refusal(
        "[storage]\ndirectories = [\"agent\"]\n[storage.unknown]\n\
         [agent]\ncommand = [\"/bin/x\"]",
    );
    assert!(
        reason.contains("`[storage]` holds the unknown key `unknown`"),
        "{reason}"
    );
    let reason = scene.refusal(
        "[storage]\ndirectories = [\"agent\"]\n[storage.files.\"agent/a.json\"]\n\
         [agent]\ncommand = [\"/bin/x\"]",
    );
    assert!(
        reason.contains("`storage.files` is a list of `[[storage.files]]` rows"),
        "a copy keyed by its target is refused: {reason}"
    );
    scene.share_raw(
        "p",
        "[pack]\nname = \"@box/p\"\nversion = 1\nkind = \"support\"\nplatforms = [\"macos\"]",
    );
    let reason = scene.refusal("packs = [\"@box/p\"]\n[agent]\ncommand = [\"/bin/x\"]");
    assert!(
        reason.contains("`[pack]` holds the unknown key `platforms`"),
        "{reason}"
    );
    scene.share("v", "[inputs.v]\ntype = \"program\"\nversion = \">=22\"");
    let reason = scene.refusal("packs = [\"@box/v\"]\n[agent]\ncommand = [\"/bin/x\"]");
    assert!(
        reason.contains("holds `version`, which is not a declaration key"),
        "{reason}"
    );
}

#[test]
fn an_unknown_key_at_the_top_of_a_pack_names_the_pack_file() {
    let scene = Scene::new();
    scene.share_top("p", "provides = [\"model\"]", "");
    match scene.compile(
        &profile("packs = [\"@box/p\"]\n[agent]\ncommand = [\"/bin/x\"]"),
        None,
    ) {
        Err(Error::Profile { path, reason, .. }) => {
            assert_eq!(path, scene.root.join("packs/p/pack.toml"));
            assert!(
                reason.contains(
                    "a pack holds no top-level `provides`; each of its keys is in a table, such \
                     as `[pack]` or `[run]`"
                ),
                "{reason}"
            );
        }
        other => panic!("a refusal, not {other:?}"),
    }
}

#[test]
fn an_unlisted_policy_beside_a_pack_is_ignored() {
    let scene = Scene::new();
    for text in [
        "[agent.env]\nX = \"1\"",
        "[inputs.git.path]\ntype = \"program\"\n\
                                            program = \"git\"\nsearch = [{ env = \"PATH\" }]\n\
                                            [run]\ncommand = [\"${{ inputs.git.path }}\"]",
    ] {
        scene.share("p", text);
        std::fs::write(
            scene.root.join("packs/p/policy.dw"),
            "@id(\"unlisted_pack_rule\") permit (principal, action, resource);",
        )
        .expect("an unlisted policy");
        let compiled = scene
            .compile(&profile(&format!("packs = [\"@box/p\"]\n{MINIMAL}")), None)
            .expect("an unlisted file has no effect");
        assert!(!compiled.policy.contains("unlisted_pack_rule"));
    }
}

/// The rules that `box` once wrote into every run, which the policy starters now hold.
const STARTER_RULES: [&str; 2] = ["shell_commands", "dev_null"];

/// The `policy.dw` of the shipped policy starter `name`.
fn starter_policy(name: &str) -> String {
    let path = crate::resources::source_tree()
        .join("policies")
        .join(name)
        .join("policy.dw");
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn the_troubleshooting_fix_for_an_earlier_profile_holds_each_starter_rule_verbatim() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/cli/troubleshooting.md");
    let page = std::fs::read_to_string(&path).expect("the troubleshooting page");
    let block = page
        .split_once("Add both to `policy.dw`:\n\n```text\n")
        .and_then(|(_, rest)| rest.split_once("\n```"))
        .map(|(block, _)| block)
        .expect("the fenced rules after \"Add both to `policy.dw`:\"");
    let rules: Vec<&str> = block.split("\n\n").collect();
    let ids: Vec<&str> = rules
        .iter()
        .map(|rule| rule.lines().next().unwrap_or_default())
        .collect();
    assert_eq!(
        ids,
        STARTER_RULES.map(|id| format!("@id(\"{id}\")")),
        "{block}"
    );
    for name in ["open", "scoped"] {
        let starter = starter_policy(name);
        for rule in &rules {
            assert!(
                starter.contains(&format!("{rule}\n")),
                "{name} does not hold, verbatim:\n{rule}"
            );
        }
    }
}

#[test]
fn the_pinned_box_core_accepts_each_policy_starter_in_a_run() {
    let scene = Scene::new();
    for name in ["open", "scoped", "locked"] {
        let policy = starter_policy(name);
        let compiled = scene
            .compile(&profile(MINIMAL), Some(&policy))
            .expect("a compile");
        let instance = scene.instance();
        std::fs::create_dir_all(&instance.directory).expect("the run directory");
        let config = instance.directory.join("box.toml");
        std::fs::write(&config, &compiled.box_toml).expect("box.toml");
        std::fs::write(instance.directory.join("policy.dw"), &compiled.policy).expect("policy.dw");
        let checked = strands_box::check_policy(config).expect("a policy check");
        assert!(
            checked.errors().is_empty(),
            "{name}: {:?}",
            checked.errors()
        );
    }
}

#[test]
fn the_pinned_box_core_accepts_a_bare_aws_secret() {
    let scene = Scene::new();
    let route = "[egress.model]\ndestinations = [\"model.example.com\"]\n";
    let backend = "[[egress.model.backends]]\nurl = \"https://gw.example.com\"\n\
                   auth = { ref = \"aws://\", aws = { service = \"bedrock\", region = \"us-east-1\" } }\n";
    for text in [
        format!("{MINIMAL}{route}secret.ref = \"aws://\"\n"),
        format!("{MINIMAL}{route}{backend}"),
        format!(
            "{MINIMAL}[mcp.docs]\ntype = \"http\"\n\
             destinations = [\"bedrock-agentcore.us-east-1.amazonaws.com\"]\nsecret.ref = \"aws://\"\n"
        ),
    ] {
        let compiled = scene.compile(&profile(&text), None).expect("a compile");
        assert!(
            compiled.box_toml.contains("ref = \"aws://\""),
            "box.toml keeps the bare reference:\n{}",
            compiled.box_toml
        );
        let instance = scene.instance();
        std::fs::create_dir_all(&instance.directory).expect("the run directory");
        let config = instance.directory.join("box.toml");
        std::fs::write(&config, &compiled.box_toml).expect("box.toml");
        std::fs::write(instance.directory.join("policy.dw"), &compiled.policy).expect("policy.dw");
        let checked = strands_box::check_policy(config).expect("a policy check");
        assert!(
            checked.errors().is_empty(),
            "{text}: {:?}",
            checked.errors()
        );
    }
}

#[test]
fn the_pinned_box_core_loads_raised_stdin_and_output_limits() {
    let scene = Scene::new();
    let compiled = scene
        .compile(
            &profile(&format!(
                "{MINIMAL}[limits]\nshell.max_stdin = 1048576\nshell.max_output = 1048576\n"
            )),
            None,
        )
        .expect("a compile");
    let instance = scene.instance();
    std::fs::create_dir_all(&instance.directory).expect("the run directory");
    let config = instance.directory.join("box.toml");
    std::fs::write(&config, &compiled.box_toml).expect("box.toml");
    std::fs::write(instance.directory.join("policy.dw"), &compiled.policy).expect("policy.dw");
    let checked = strands_box::check_policy(config).expect("Box Core loads the limits");
    assert!(checked.errors().is_empty(), "{:?}", checked.errors());
}

#[test]
fn box_writes_no_rule_that_no_table_declares_and_each_policy_starter_holds_them() {
    let scene = Scene::new();
    let compiled = scene.compile(&profile(MINIMAL), None).expect("a compile");
    for id in STARTER_RULES {
        assert!(
            !compiled.policy.contains(&format!("@id(\"{id}\")")),
            "{id} in\n{}",
            compiled.policy
        );
        assert!(
            !compiled
                .generated_ids
                .iter()
                .any(|generated| generated == id)
        );
    }
    assert!(
        !compiled.policy.contains("shell:exec"),
        "{}",
        compiled.policy
    );
    assert!(!compiled.policy.contains("loopback"), "{}", compiled.policy);
    for name in ["open", "scoped"] {
        let compiled = scene
            .compile(&profile(MINIMAL), Some(&starter_policy(name)))
            .expect("a compile");
        for id in STARTER_RULES {
            assert_eq!(
                compiled.policy.matches(&format!("@id(\"{id}\")")).count(),
                1,
                "{name}: {id} in\n{}",
                compiled.policy
            );
        }
        for id in ["metadata_hosts", "metadata_addresses"] {
            assert!(
                !compiled.policy.contains(&format!("@id(\"{id}\")")),
                "{name}: {id} in\n{}",
                compiled.policy
            );
        }
    }
    let locked = scene
        .compile(&profile(MINIMAL), Some(&starter_policy("locked")))
        .expect("a compile");
    assert!(
        !locked
            .policy
            .lines()
            .any(|line| line.starts_with("permit") && line.contains("shell:exec")),
        "{}",
        locked.policy
    );
    let compiled = scene
        .compile(
            &profile(MINIMAL),
            Some("@id(\"mine\") permit (principal, action, resource);"),
        )
        .expect("a compile");
    let mine = compiled
        .policy
        .find("@id(\"mine\")")
        .expect("the profile's rule");
    let generated = compiled
        .policy
        .find("@id(\"project_read\")")
        .expect("the generated rules");
    assert!(mine < generated, "{}", compiled.policy);
}

#[test]
fn an_option_wins_over_the_source_and_the_default() {
    let scene = Scene::new();
    scene.share(
        "o",
        "[inputs.o.value]\nfrom = \"env:SET\"\ndefault = \"d\"\n\
         [inputs.o.unset]\nfrom = \"env:UNSET\"\ndefault = \"d\"\n\
         [inputs.o.plain]\ndefault = \"d\"",
    );
    let read = |options: &str| {
        let resolved = scene
            .resolve(&profile(&format!(
                "packs = [\"@box/o\"]\n{options}\n[agent]\ncommand = [\"/bin/x\"]\n\
                 env.VALUE = \"${{{{ inputs.o.value }}}}\"\n\
                 env.UNSET = \"${{{{ inputs.o.unset }}}}\"\n\
                 env.PLAIN = \"${{{{ inputs.o.plain }}}}\""
            )))
            .expect("a resolve");
        let mut inputs: Vec<(String, String, String)> = resolved
            .inputs
            .into_iter()
            .map(|input| (input.name, input.value, input.source))
            .collect();
        inputs.sort();
        inputs
    };
    let row = |name: &str, value: &str, source: &str| {
        (name.to_string(), value.to_string(), source.to_string())
    };
    assert_eq!(
        read(""),
        [
            row("o.plain", "d", "default"),
            row("o.unset", "d", "default"),
            row("o.value", "set-value", "env:SET"),
        ]
    );
    assert_eq!(
        read("[options]\no.value = \"mine\"\no.unset = \"mine\"\no.plain = 7"),
        [
            row("o.plain", "7", "your profile"),
            row("o.unset", "mine", "your profile"),
            row("o.value", "mine", "your profile"),
        ]
    );
    assert_eq!(
        read("[options.o]\nvalue = \"nested\"")[2],
        row("o.value", "nested", "your profile"),
        "a dotted name and a nested table are one name"
    );
}

#[test]
fn an_option_is_a_literal_value_for_an_input_a_pack_declares() {
    let scene = Scene::new();
    scene.share("o", "[inputs.o]\ndefault = \"d\"");
    for (options, why) in [
        (
            "nope = \"x\"",
            "`[options] nope` sets an input that no pack declares",
        ),
        (
            "o.deeper = \"x\"",
            "`[options] o.deeper` sets an input that no pack declares",
        ),
        (
            "o = \"${{ home }}\"",
            "`[options] o` holds a placeholder; a value is literal",
        ),
        (
            "o = [\"a\"]",
            "`[options] o` is not a string, a number, or true or false",
        ),
    ] {
        let reason = scene.refusal(&format!(
            "packs = [\"@box/o\"]\n[options]\n{options}\n[agent]\ncommand = [\"/bin/x\"]"
        ));
        assert!(reason.contains(why), "{options}: {reason}");
    }
}

#[test]
fn two_packs_share_one_input_and_its_value_satisfies_both() {
    let scene = Scene::new();
    scene.share(
        "a",
        "[inputs.shared]\npattern = \"[a-z0-9]+\"\ndefault = \"abc\"",
    );
    scene.share(
        "b",
        "[inputs.shared]\nvalues = [\"abc\", \"ABC\"]\ndefault = \"abc\"",
    );
    let text = |options: &str| {
        format!(
            "packs = [\"@box/a\", \"@box/b\"]\n{options}\n[agent]\ncommand = [\"/bin/x\"]\n\
             env.S = \"${{{{ inputs.shared }}}}\""
        )
    };
    let resolved = scene.resolve(&profile(&text(""))).expect("one default");
    assert_eq!(resolved.agent.env["S"], "abc");
    for (value, why) in [
        ("ABC", "does not match its pattern"),
        ("xyz", "is not one of abc, ABC"),
    ] {
        let reason = scene.resolve_refusal(&text(&format!("[options]\nshared = {value:?}")));
        assert!(reason.contains(why), "{value}: {reason}");
    }
}

#[test]
fn packs_that_give_one_input_different_defaults_or_sources_need_an_option() {
    let scene = Scene::new();
    scene.share("c", "[inputs.d]\ndefault = \"p\"");
    scene.share("e", "[inputs.d]\ndefault = \"q\"");
    scene.share("f", "[inputs.d]\ndefault = \"p\"");
    scene.share("g", "[inputs.d]\nfrom = \"env:SET\"");
    scene.share("h", "[inputs.d]\nfrom = \"env:OTHER\"");
    let text = |packs: &str, options: &str| {
        format!(
            "packs = [{packs}]\n{options}\n[agent]\ncommand = [\"/bin/x\"]\n\
             env.D = \"${{{{ inputs.d }}}}\""
        )
    };
    let reason = scene.resolve_refusal(&text("\"@box/c\", \"@box/e\"", ""));
    assert!(
        reason.contains(
            "the packs that declare `inputs.d` give different defaults (@box/c: \"p\", @box/e: \"q\"); \
             set `d` in your profile's `[options]`"
        ),
        "{reason}"
    );
    let reason = scene.resolve_refusal(&text("\"@box/g\", \"@box/h\"", ""));
    assert!(reason.contains("give different sources"), "{reason}");
    for packs in ["\"@box/c\", \"@box/e\"", "\"@box/g\", \"@box/h\""] {
        let resolved = scene
            .resolve(&profile(&text(packs, "[options]\nd = \"set\"")))
            .expect("an option settles it");
        assert_eq!(resolved.agent.env["D"], "set");
    }
    let resolved = scene
        .resolve(&profile(&text("\"@box/c\", \"@box/f\"", "")))
        .expect("one default from two packs");
    assert_eq!(resolved.agent.env["D"], "p");
}

#[test]
fn two_packs_cannot_give_one_input_two_types() {
    let scene = Scene::new();
    scene.share("i", "[inputs.t]\ntype = \"bool\"\ndefault = true");
    scene.share("j", "[inputs.t]\ndefault = \"x\"");
    let reason = scene.refusal("packs = [\"@box/i\", \"@box/j\"]\n[agent]\ncommand = [\"/bin/x\"]");
    assert!(
        reason.contains("`inputs.t` is a bool in @box/i and a string in @box/j"),
        "{reason}"
    );
}

#[test]
fn an_input_in_a_command_needs_a_pattern_values_or_a_bool_type() {
    let scene = Scene::new();
    scene.share(
        "args",
        "[inputs.free]\ndefault = \"x\"\n\
         [inputs.bounded]\ndefault = \"x\"\npattern = \"[a-z]+\"\n\
         [inputs.picked]\ndefault = \"x\"\nvalues = [\"x\"]\n\
         [inputs.flag]\ntype = \"bool\"\ndefault = false",
    );
    let text = |rest: &str| format!("packs = [\"@box/args\"]\n{rest}");
    for input in ["bounded", "picked", "flag"] {
        scene
            .compile(
                &profile(&text(&format!(
                    "[agent]\ncommand = [\"/bin/x\", \"--a=${{{{ inputs.{input} }}}}\"]"
                ))),
                None,
            )
            .expect(input);
    }
    scene
        .compile(
            &profile(&text(
                "[agent]\ncommand = [\"/bin/x\"]\nenv.FREE = \"${{ inputs.free }}\"",
            )),
            None,
        )
        .expect("a free-form value goes through env");
    for rest in [
        "[agent]\ncommand = [\"/bin/x\", \"-c\", \"${{ inputs.free }}\"]",
        "[agent]\ncommand = [\"/bin/x\"]\n[tool.t]\ncommand = [\"/usr/bin/true\", \"${{ inputs.free }}\"]",
    ] {
        let reason = scene.refusal(&text(rest));
        assert!(
            reason.contains(
                "`inputs.free` reaches `command`, so `[inputs.free]` needs `pattern` or `values`"
            ),
            "{rest}: {reason}"
        );
    }
}

#[test]
fn a_bool_input_switches_a_table_and_an_entry() {
    let scene = Scene::new();
    scene.share("flag", "[inputs.flag.on]\ntype = \"bool\"\ndefault = true");
    let text = |options: &str| {
        format!(
            "packs = [\"@box/flag\"]\n{options}\n\
             [agent]\ncommand = [\"/bin/x\"]\n\
             filesystem.read = [{{ path = \"/opt/flagged\", when = \"${{{{ inputs.flag.on }}}}\" }}, \"/opt/always\"]\n\
             [egress.extra]\nwhen = \"${{{{ inputs.flag.on }}}}\"\n\
             destinations = [\"extra.example.com\"]\nsecret.ref = \"env://KEY\"\n\
             [mcp.m]\nwhen = \"${{{{ inputs.flag.on }}}}\"\ntype = \"stdio\"\ncommand = [\"true\"]"
        )
    };
    let on = scene.resolve(&profile(&text(""))).expect("on by default");
    assert_eq!(on.agent.filesystem.read, ["/opt/flagged", "/opt/always"]);
    assert!(on.egress.contains_key("extra") && on.mcp.contains_key("m"));
    assert!(
        !on.egress["extra"]
            .as_table()
            .expect("a route")
            .contains_key("when")
    );
    let off = scene
        .resolve(&profile(&text("[options]\nflag.on = false")))
        .expect("off by the profile");
    assert_eq!(off.agent.filesystem.read, ["/opt/always"]);
    assert!(off.egress.is_empty() && off.mcp.is_empty());
    let compiled = scene
        .compile(&profile(&text("[options]\nflag.on = false")), None)
        .expect("a compile");
    assert!(
        !compiled.policy.contains("route_extra"),
        "{}",
        compiled.policy
    );
}

#[test]
fn a_bool_input_switches_a_detected_tool_table() {
    let scene = Scene::new();
    scene.share("flag", "[inputs.flag.on]\ntype = \"bool\"\ndefault = true");
    let text = |options: &str| {
        format!(
            "packs = [\"@box/flag\"]\n{options}\n[agent]\ncommand = [\"/bin/x\"]\n\
             [tool.git]\nprogram = \"git\"\nwhen = \"${{{{ inputs.flag.on }}}}\""
        )
    };
    let on = scene
        .resolve_using(&profile(&text("")), &scene.context(), &mut Detecting)
        .expect("a resolve");
    assert_eq!(on.tool["git"].command, [real("/usr/bin/true")]);
    let off = scene
        .resolve_using(
            &profile(&text("[options]\nflag.on = false")),
            &scene.context(),
            &mut Detecting,
        )
        .expect("a resolve");
    assert!(off.tool.is_empty(), "{:?}", off.tool);
}

#[test]
fn a_when_holds_an_os_or_a_bool_input() {
    let scene = Scene::new();
    scene.share(
        "w",
        "[inputs.flag]\ntype = \"bool\"\ndefault = true\n[inputs.text]\ndefault = \"maybe\"",
    );
    let text = |when: &str, options: &str| {
        format!(
            "packs = [\"@box/w\"]\n{options}\n[agent]\ncommand = [\"/bin/x\"]\n\
             [mcp.m]\nwhen = {when:?}\ntype = \"stdio\"\ncommand = [\"true\"]"
        )
    };
    for (os, kept) in [("macos", false), ("linux", true)] {
        let resolved = scene
            .resolve_with(
                &profile(&text("linux", "")),
                &Context {
                    os,
                    ..scene.context()
                },
            )
            .expect("a resolve");
        assert_eq!(resolved.mcp.contains_key("m"), kept, "{os}");
    }
    for (when, options, why) in [
        (
            "windows",
            "",
            "use macos, linux, or a placeholder for a bool input",
        ),
        ("${{ inputs.text }}", "", "is \"maybe\", not true or false"),
        (
            "${{ inputs.flag }}",
            "[options]\nflag = \"yes\"",
            "`inputs.flag` = \"yes\" is not true or false",
        ),
    ] {
        let reason = scene.resolve_refusal(&text(when, options));
        assert!(reason.contains(why), "{when}: {reason}");
    }
}

/// A profile that runs the `program` input `tool.program`, set to `path`.
fn program_profile(path: &Path) -> String {
    format!(
        "packs = [\"@box/tool\"]\n[options]\ntool.program = {:?}\n\
         [agent]\ncommand = [\"${{{{ inputs.tool.program }}}}\"]",
        path.display().to_string()
    )
}

#[test]
fn a_program_input_where_a_box_can_write_is_refused_before_it_runs() {
    let scene = Scene::new();
    scene.share("tool", "[inputs.tool.program]\ntype = \"program\"");
    let marker = scene.root.join("probed");
    let body = format!("touch '{}'; echo v30.0.0", marker.display());
    for (program, what) in [
        (scene.storage().join("bin/node"), "the run's storage"),
        (scene.home().join(".strands/box/bin/node"), "the box home"),
        (scene.workspace().join("bin/node"), "the workspace"),
    ] {
        script(&program, &body);
        let reason = scene.refusal(&program_profile(&program));
        assert!(
            reason.contains(&format!("lies in {what}, which a box can write")),
            "{}: {reason}",
            program.display()
        );
        assert!(!marker.exists(), "{} ran", program.display());
    }
    let outside = scene.root.join("tools/node");
    script(&outside, &body);
    let compiled = scene
        .compile(&profile(&program_profile(&outside)), None)
        .expect("a program outside every write grant");
    assert!(!marker.exists(), "box runs no program input");
    assert_eq!(
        strings(&table(&compiled)["agent"]["command"]),
        [outside.display().to_string()],
        "a program input needs no pattern as the command's program"
    );
}

#[test]
fn a_program_input_is_an_executable_at_an_absolute_path() {
    let scene = Scene::new();
    scene.share("tool", "[inputs.tool.program]\ntype = \"program\"");
    let named = scene.root.join("tools/node");
    script(&named, "exit 1");
    scene
        .compile(&profile(&program_profile(&named)), None)
        .expect("an executable at an absolute path");
    let plain = scene.root.join("plain");
    std::fs::write(&plain, "").expect("a file");
    for (path, why) in [
        (Path::new("node"), "is not an absolute path"),
        (plain.as_path(), "is not an executable file"),
    ] {
        let reason = scene.refusal(&program_profile(path));
        assert!(reason.contains(why), "{}: {reason}", path.display());
    }
}

#[test]
fn a_program_input_is_exempt_from_the_bound_only_as_the_commands_program() {
    let scene = Scene::new();
    let program = scene.root.join("tools/node");
    script(&program, "echo v30.0.0");
    scene.share(
        "tool",
        &format!(
            "[inputs.tool.program]\ntype = \"program\"\ndefault = {:?}\n\
             [inputs.tool.bounded]\ntype = \"program\"\ndefault = {:?}\npattern = \"/.*\"",
            program.display().to_string(),
            program.display().to_string()
        ),
    );
    let text = |command: &str| format!("packs = [\"@box/tool\"]\n[agent]\ncommand = {command}");
    scene
        .compile(
            &profile(&text("[\"${{ inputs.tool.program }}\", \"--version\"]")),
            None,
        )
        .expect("a program input as the command's program");
    for command in [
        "[\"/bin/x\", \"${{ inputs.tool.program }}\"]",
        "[\"/bin/x\", \"--tool=${{ inputs.tool.program }}\"]",
    ] {
        let reason = scene.refusal(&text(command));
        assert!(
            reason.contains(
                "`inputs.tool.program` reaches `command`, so `[inputs.tool.program]` needs \
                 `pattern` or `values`"
            ),
            "{command}: {reason}"
        );
    }
    scene
        .compile(
            &profile(&text("[\"/bin/x\", \"${{ inputs.tool.bounded }}\"]")),
            None,
        )
        .expect("a bounded program input anywhere in the command");
    let reason = scene.refusal(&format!(
        "{}\n[tool.t]\ncommand = [\"/usr/bin/true\", \"${{{{ inputs.tool.program }}}}\"]",
        text("[\"/bin/x\"]")
    ));
    assert!(reason.contains("reaches `command`"), "{reason}");
}

#[test]
fn a_pack_header_names_the_pack_as_it_is_imported() {
    let scene = Scene::new();
    scene.share_raw(
        "p",
        "[pack]\nname = \"@box/other\"\nversion = 1\nkind = \"support\"",
    );
    let reason = scene.refusal("packs = [\"@box/p\"]\n[agent]\ncommand = [\"/bin/x\"]");
    assert!(
        reason.contains("`[pack] name = \"@box/other\"`, but this pack is imported as \"@box/p\""),
        "{reason}"
    );
    let folder = scene.home().join(".strands/box/packs/mine");
    std::fs::create_dir_all(&folder).expect("an operator pack folder");
    for (name, accepted) in [("@box/mine", false), ("mine", true)] {
        std::fs::write(
            folder.join("pack.toml"),
            format!("[pack]\nname = {name:?}\nversion = 1\nkind = \"support\"\n[agent.env]\nMINE = \"1\""),
        )
        .expect("an operator pack");
        let result = scene.compile(
            &profile("packs = [\"mine\"]\n[agent]\ncommand = [\"/bin/x\"]"),
            None,
        );
        match (result, accepted) {
            (Ok(compiled), true) => {
                assert_eq!(table(&compiled)["agent"]["env"]["MINE"].as_str(), Some("1"));
            }
            (Err(Error::Profile { reason, .. }), false) => {
                assert!(
                    reason.contains("but this pack is imported as \"mine\""),
                    "{reason}"
                );
            }
            (other, _) => panic!("{name}: {other:?}"),
        }
    }
}

#[test]
fn a_pack_refuses_every_key_of_one_run() {
    let scene = Scene::new();
    for (text, key) in [
        ("name = \"x\"", "`name`"),
        ("box_dir = \"/x\"", "`box_dir`"),
        ("workspace = \"/x\"", "`workspace`"),
        ("[agent]\nworkspace = \"/x\"", "`[agent] workspace`"),
        (
            "[tool.git]\ncommand = [\"/bin/git\"]\nworkspace = \"/x\"",
            "`[tool.git] workspace`",
        ),
    ] {
        if text.starts_with('[') {
            scene.share("p", text);
        } else {
            scene.share_top("p", text, "");
        }
        let reason = scene.refusal("packs = [\"@box/p\"]\n[agent]\ncommand = [\"/bin/x\"]");
        assert!(
            reason.contains(&format!(
                "a pack holds no {key}, because `box run` sets it for each run"
            )),
            "{text}: {reason}"
        );
    }
}

#[test]
fn a_program_input_under_a_write_grant_is_refused_before_it_runs() {
    let scene = Scene::new();
    scene.share("tool", "[inputs.tool.program]\ntype = \"program\"");
    let marker = scene.root.join("probed");
    let tools = scene.root.join("x/tools");
    let program = tools.join("node");
    script(
        &program,
        &format!("touch '{}'; echo v30.0.0", marker.display()),
    );
    let link = scene.root.join("bin/node");
    std::fs::create_dir_all(link.parent().expect("a parent")).expect("a folder");
    std::os::unix::fs::symlink(&program, &link).expect("a link");
    let grant = tools.display().to_string();
    let file = program.display().to_string();
    for (path, grants, named) in [
        (
            &program,
            format!("[agent.filesystem]\nwrite = [{grant:?}]"),
            &grant,
        ),
        (
            &link,
            format!("[agent.filesystem]\nwrite = [{grant:?}]"),
            &grant,
        ),
        (
            &program,
            format!("[agent.filesystem]\nwrite_file = [{file:?}]"),
            &file,
        ),
        (
            &program,
            format!("[tool.t]\ncommand = [\"/usr/bin/true\"]\nfilesystem.write = [{grant:?}]"),
            &grant,
        ),
        (
            &program,
            format!(
                "[mcp.m]\ntype = \"stdio\"\ncommand = [\"true\"]\n\
                 filesystem.write = [{grant:?}]"
            ),
            &grant,
        ),
    ] {
        let reason = scene.refusal(&format!("{}\n{grants}", program_profile(path)));
        assert!(
            reason.contains(&format!(
                "lies under the write grant {named}, which is not allowed because the agent in \
                 the box can rewrite it. Remove the grant, or set `"
            )),
            "{grants}: {reason}"
        );
        assert!(!marker.exists(), "{grants}: the program ran");
    }
    scene
        .compile(&profile(&program_profile(&program)), None)
        .expect("a program under no write grant");
}

#[test]
fn a_destination_that_is_a_url_is_refused() {
    let reason = Scene::new().refusal(
        "[agent]\ncommand = [\"/bin/x\"]\n[egress.model]\n\
         destinations = [\"https://a.example.com\"]\nsecret.ref = \"env://KEY\"",
    );
    assert!(
        reason.contains("destination \"https://a.example.com\" is a URL; write the host"),
        "{reason}"
    );
}

#[test]
fn an_input_whose_default_names_itself_is_refused() {
    let scene = Scene::new();
    for declarations in [
        "[inputs.a]\ndefault = \"x${{ inputs.a }}\"",
        "[inputs.a]\ndefault = \"${{ inputs.b }}\"\n[inputs.b]\ndefault = \"${{ inputs.a }}\"",
    ] {
        scene.share("loop", declarations);
        let reason = scene.refusal(
            "packs = [\"@box/loop\"]\n[agent]\ncommand = [\"/bin/x\"]\nenv.A = \"${{ inputs.a }}\"",
        );
        assert!(
            reason.contains("`inputs.a` depends on itself"),
            "{declarations}: {reason}"
        );
    }
}

#[test]
fn a_key_that_holds_a_placeholder_is_refused() {
    let reason =
        Scene::new().refusal("[agent]\ncommand = [\"/bin/x\"]\nenv.\"${{ home }}\" = \"1\"");
    assert!(
        reason.contains("`agent.env` has the key \"${{ home }}\"; a key holds no placeholder"),
        "{reason}"
    );
}

#[test]
fn a_storage_files_row_resolves_its_source_and_its_target_in_storage() {
    let scene = Scene::new();
    scene.share(
        "agent",
        "[storage]\ndirectories = [\"config\"]\n\
         [[storage.files]]\nsource = \"${{ home }}/.claude/CLAUDE.md\"\n\
         target = \"config/CLAUDE.md\"\noptional = true\n\
         [[storage.files]]\nsource = \"~/.claude/skills\"\ntarget = \"config/skills\"",
    );
    let resolved = scene
        .resolve(&profile(
            "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
             [[storage.files]]\nsource = \"${{ home }}/notes/team.md\"\n\
             target = \"config/rules/team.md\"",
        ))
        .expect("a resolve");
    let files: Vec<_> = resolved
        .storage
        .files
        .iter()
        .map(|file| {
            (
                file.source.clone(),
                file.target.clone(),
                file.relative.clone(),
                file.optional,
            )
        })
        .collect();
    let config = scene.storage().join("agent/config");
    assert_eq!(
        files,
        vec![
            (
                scene.home().join(".claude/CLAUDE.md"),
                config.join("CLAUDE.md"),
                "agent/config/CLAUDE.md".to_string(),
                true
            ),
            (
                scene.home().join(".claude/skills"),
                config.join("skills"),
                "agent/config/skills".to_string(),
                false
            ),
            (
                scene.home().join("notes/team.md"),
                config.join("rules/team.md"),
                "agent/config/rules/team.md".to_string(),
                false
            ),
        ],
        "rows from every pack and the profile join"
    );
}

#[test]
fn two_rows_with_one_target_are_refused_with_both_files_named() {
    let scene = Scene::new();
    let row = "[[storage.files]]\nsource = \"${{ home }}/a.md\"\ntarget = \"config/a.md\"";
    scene.share(
        "first",
        &format!("[storage]\ndirectories = [\"config\"]\n{row}"),
    );
    scene.share("second", row);
    let reason =
        scene.refusal("packs = [\"@box/first\", \"@box/second\"]\n[agent]\ncommand = [\"/bin/x\"]");
    assert!(
        reason.contains("is in both @box/first and @box/second"),
        "{reason}"
    );
    let reason = scene.refusal(&format!(
        "packs = [\"@box/first\"]\n[agent]\ncommand = [\"/bin/x\"]\n{row}"
    ));
    assert!(
        reason.contains("is in both @box/first and the profile"),
        "a profile cannot replace a pack's copy: {reason}"
    );
    let reason = scene.refusal(
        "packs = [\"@box/first\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
         [[storage.files]]\nsource = \"${{ home }}/b.md\"\ntarget = \"config/a.md/b.md\"",
    );
    assert!(
        reason.contains("`target = \"config/a.md\"` in @box/first overlap"),
        "a target inside another is refused: {reason}"
    );
}

#[test]
fn a_storage_files_target_is_a_declared_directory_and_a_path_below_it() {
    let scene = Scene::new();
    for (target, expected) in [
        (
            "/abs/CLAUDE.md",
            "is not a storage directory and a path below it",
        ),
        (
            "config",
            "is not a storage directory and a path below it, such as \"config/notes.md\"",
        ),
        (
            "config/../x",
            "is not a storage directory and a path below it",
        ),
        (
            "config//x",
            "is not a storage directory and a path below it",
        ),
        (
            "other/x",
            "starts with `other`, which `[storage] directories` does not name",
        ),
        (
            "config/${{ home }}",
            "fills a placeholder with more than one name",
        ),
        ("${{ workspace.dashed }}/x", "starts with a placeholder"),
    ] {
        let reason = scene.refusal(&format!(
            "[storage]\ndirectories = [\"config\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
             [[storage.files]]\nsource = \"${{{{ home }}}}/a.md\"\ntarget = {target:?}"
        ));
        assert!(reason.contains(expected), "{target}: {reason}");
    }
}

#[test]
fn a_storage_files_row_takes_only_its_keys_and_an_absolute_source() {
    let scene = Scene::new();
    let base = "[storage]\ndirectories = [\"config\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
                [[storage.files]]\ntarget = \"config/a.md\"\n";
    for (row, expected) in [
        (
            "source = \"/a.md\"\nlink = true",
            "holds the unknown key `link`",
        ),
        (
            "source = \"/a.md\"\nmode = 1",
            "`storage.files[0] mode` is \"copy\", \"link\", or \"link-children\"",
        ),
        (
            "source = \"/a.md\"\nmode = \"link\"",
            "`storage.files[0] mode = \"link\"` works only in a tool's storage; the agent's rows copy",
        ),
        (
            "source = \"/a.md\"\nmode = \"link-children\"",
            "works only in a tool's storage; the agent's rows copy",
        ),
        ("", "needs `source`"),
        ("source = \"relative/a.md\"", "is not an absolute path"),
        ("source = \"/x/../a.md\"", "holds `..`"),
        (
            "source = \"/a.md\"\noptional = \"yes\"",
            "`storage.files[0] optional` is not true or false",
        ),
        (
            "source = \"/a.md\"\nsync = \"yes\"",
            "`storage.files[0] sync` is not true or false",
        ),
        (
            "source = \"/a.md\"\nsync = true\nkind = \"json\"\nkeep = [[\"a\"]]",
            "`storage.files[0] sync = true` works only on a row without `kind`",
        ),
    ] {
        let reason = scene.refusal(&format!("{base}{row}"));
        assert!(reason.contains(expected), "{row}: {reason}");
    }
    let copy = scene
        .resolve(&profile(&format!(
            "{base}source = \"/a.md\"\noptional = true\nmode = \"copy\""
        )))
        .expect("`mode = \"copy\"` is the agent row's default, written out");
    assert_eq!(copy.storage.files.len(), 1);
    assert!(copy.storage.links.is_empty());
    let resolved = scene
        .resolve(&profile(&format!("{base}source = \"/a.md\"\nsync = true")))
        .expect("a resolve");
    assert!(resolved.storage.files[0].sync);
    let resolved = scene
        .resolve(&profile(&format!("{base}source = \"/a.md\"")))
        .expect("a resolve");
    assert!(
        !resolved.storage.files[0].sync,
        "a row copies once unless it says sync"
    );
}

#[test]
fn a_storage_files_edit_fills_each_key_and_value_as_a_template_field() {
    let scene = Scene::new();
    let resolved = scene
        .resolve(&profile(
            "[storage]\ndirectories = [\"home\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
             [[storage.files]]\nsource = \"${{ home }}/.example/settings.toml\"\n\
             target = \"home/settings.toml\"\nkind = \"toml\"\n\
             keep = [[\"model\"], [\"projects\", \"${{ workspace }}\"]]\n\
             [[storage.files.set]]\nkey = [\"projects\", \"${{ workspace }}\", \"trust_level\"]\n\
             value = \"trusted\"\n\
             [[storage.files.set]]\nkey = [\"shell\"]\nvalue = \"${{ box }}/bin/bash\"",
        ))
        .expect("a resolve");
    let edit = resolved.storage.files[0].edit.clone().expect("an edit");
    let workspace = scene.workspace().display().to_string();
    assert_eq!(edit.kind, crate::mcp::Format::Toml);
    assert_eq!(
        edit.keep,
        Some(vec![
            vec!["model".to_string()],
            vec!["projects".to_string(), workspace.clone()]
        ])
    );
    assert_eq!(
        edit.set
            .iter()
            .map(|setting| (setting.key.clone(), setting.value.clone()))
            .collect::<Vec<_>>(),
        vec![
            (
                vec!["projects".to_string(), workspace, "trust_level".to_string()],
                "trusted".into()
            ),
            (
                vec!["shell".to_string()],
                format!("{}/bin/bash", scene.instance().box_directory.display()).into()
            ),
        ]
    );
}

#[test]
fn a_storage_files_set_value_can_be_a_number_a_boolean_or_a_list_with_placeholders() {
    let scene = Scene::new();
    let resolved = scene
        .resolve(&profile(
            "[storage]\ndirectories = [\"home\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
             [[storage.files]]\nsource = \"${{ home }}/.example/settings.json\"\n\
             target = \"home/settings.json\"\nkind = \"json\"\n\
             [[storage.files.set]]\nkey = [\"onboarded\"]\nvalue = true\n\
             [[storage.files.set]]\nkey = [\"retries\"]\nvalue = 3\n\
             [[storage.files.set]]\nkey = [\"dirs\"]\nvalue = [\"${{ workspace }}\", [1.5]]",
        ))
        .expect("a resolve");
    let edit = resolved.storage.files[0].edit.clone().expect("an edit");
    let workspace = scene.workspace().display().to_string();
    assert_eq!(
        edit.set
            .iter()
            .map(|setting| setting.value.clone())
            .collect::<Vec<_>>(),
        vec![
            toml::Value::Boolean(true),
            toml::Value::Integer(3),
            toml::Value::Array(vec![
                workspace.into(),
                toml::Value::Array(vec![toml::Value::Float(1.5)])
            ]),
        ]
    );
}

#[test]
fn a_pack_row_fills_in_the_folders_above_the_workspace() {
    let scene = Scene::new();
    scene.share(
        "trust",
        "[storage]\ndirectories = [\"home\"]\n\
         [[storage.files]]\nsource = \"${{ home }}/.example/trust.json\"\n\
         target = \"home/trust.json\"\nkind = \"json\"\n\
         [[storage.files.set]]\nkey = [\"${{ workspace.parent }}\"]\n\
         value = [\"${{ workspace }}\", \"${{ workspace.parent }}\", \"${{ workspace.parent.parent }}\"]",
    );
    let resolved = scene
        .resolve(&profile(
            "packs = [\"@box/trust\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
             env.UP = \"${{ workspace.parent }}/shared\"",
        ))
        .expect("a resolve");
    let edit = resolved.storage.files[0].edit.clone().expect("an edit");
    let text = |path: &Path| path.display().to_string();
    let workspace = scene.workspace();
    let parent = workspace.parent().expect("a parent");
    let grandparent = parent.parent().expect("a grandparent");
    assert_eq!(
        edit.set
            .iter()
            .map(|setting| (setting.key.clone(), setting.value.clone()))
            .collect::<Vec<_>>(),
        vec![(
            vec![text(parent)],
            toml::Value::Array(vec![
                text(&workspace).into(),
                text(parent).into(),
                text(grandparent).into(),
            ])
        )]
    );
    assert_eq!(
        resolved.agent.env.get("UP").map(String::as_str),
        Some(format!("{}/shared", text(parent)).as_str())
    );
}

#[test]
fn a_workspace_parent_is_refused_where_one_name_goes() {
    let scene = Scene::new();
    let base = "[storage]\ndirectories = [\"config\"]\n[agent]\ncommand = [\"/bin/x\"]\n";
    for (row, expected) in [
        (
            "[[storage.files]]\nsource = \"${{ home }}/a.md\"\n\
             target = \"config/${{ workspace.parent }}\"",
            "fills a placeholder with more than one name",
        ),
        (
            "filesystem.read = [\"${{ home }}/${{ workspace.parent }}\"]",
            "is not one path component",
        ),
        (
            "env.UP = \"${{ workspace.parent.dashed }}\"",
            "`dashed` comes only right after `workspace`, as `workspace.dashed`",
        ),
        (
            "env.UP = \"${{ workspace.up }}\"",
            "`up` is not a step of `workspace`; use `parent`",
        ),
    ] {
        let reason = scene.refusal(&format!("{base}{row}"));
        assert!(reason.contains(expected), "{row}: {reason}");
    }
    let reason = scene.refusal("[agent]\ncommand = [\"/bin/x\", \"${{ workspace.parent }}/../x\"]");
    assert!(
        reason.contains("holds `..`"),
        "a command element that starts with `workspace.parent` is a path: {reason}"
    );
}

#[test]
fn a_storage_files_edit_needs_its_kind_and_well_formed_rows() {
    let scene = Scene::new();
    let base = "[storage]\ndirectories = [\"config\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
                [[storage.files]]\nsource = \"/a.json\"\ntarget = \"config/a.json\"\n";
    for (row, expected) in [
        (
            "keep = [[\"model\"]]",
            "`storage.files[0]` needs `kind`, \"json\" or \"toml\", for `keep` and `set`",
        ),
        (
            "kind = \"json\"\nfill = true",
            "`storage.files[0] fill` needs `keep`",
        ),
        (
            "kind = \"json\"\nkeep = [[\"a\"]]\nfill = 1",
            "`storage.files[0] fill` is not true or false",
        ),
        (
            "kind = \"json\"\nkeep = [[\"a\"]]\nfill = true\n\
             [[storage.files.set]]\nkey = [\"b\"]\nvalue = \"c\"",
            "`storage.files[0]` holds `fill` and `set`",
        ),
        (
            "kind = \"json\"",
            "`storage.files[0] kind` applies only with `keep` or `set`",
        ),
        (
            "kind = \"yaml\"\nkeep = [[\"a\"]]",
            "`storage.files[0] kind = \"yaml\"` is not \"json\" or \"toml\"",
        ),
        (
            "kind = \"json\"\nkeep = []",
            "`storage.files[0] keep` is a list of one or more key lists",
        ),
        (
            "kind = \"json\"\nset = []",
            "`storage.files[0] set` is a list of one or more `[[storage.files.set]]` rows",
        ),
        (
            "kind = \"json\"\nset = [1]",
            "`storage.files[0] set[0]` is not a `[[storage.files.set]]` row",
        ),
        (
            "kind = \"json\"\n[[storage.files.set]]\nvalue = \"b\"",
            "`storage.files[0] set[0]` needs `key`",
        ),
        (
            "kind = \"json\"\nkeep = [[]]",
            "`storage.files[0] keep[0]` is a list of one or more keys",
        ),
        (
            "kind = \"json\"\nkeep = [[1]]",
            "`storage.files[0] keep[0][0]` is not a string",
        ),
        (
            "kind = \"json\"\n[[storage.files.set]]\nkey = [\"a\"]",
            "`storage.files[0] set[0]` needs `value`",
        ),
        (
            "kind = \"json\"\n[[storage.files.set]]\nkey = [\"a\"]\nvalue = { b = 1 }",
            "`storage.files[0] set[0] value` is not a string, a number, true or false, or a list of those",
        ),
        (
            "kind = \"json\"\n[[storage.files.set]]\nkey = [\"a\"]\nvalue = 1979-05-27",
            "`storage.files[0] set[0] value` is not a string, a number, true or false, or a list of those",
        ),
        (
            "kind = \"json\"\n[[storage.files.set]]\nkey = [\"a\"]\nvalue = nan",
            "`storage.files[0] set[0] value` is not a string, a number, true or false, or a list of those",
        ),
        (
            "kind = \"json\"\n[[storage.files.set]]\nkey = [\"a\"]\nvalue = [\"b\", { c = 1 }]",
            "`storage.files[0] set[0] value[1]` is not a string, a number, true or false, or a list of those",
        ),
        (
            "kind = \"json\"\n[[storage.files.set]]\nkey = [\"a\"]\nvalue = \"b\"\noptional = true",
            "`storage.files[0] set[0]` holds the unknown key `optional`; a row holds `key`, `value`, \
             and `when`",
        ),
        (
            "kind = \"json\"\n[[storage.files.set]]\nkey = [\"a\"]\nvalue = \"b\"\nwhen = 3",
            "`storage.files[0] set[0] when` is not a when",
        ),
        (
            "kind = \"json\"\n[[storage.files.set]]\nkey = \"a\"\nvalue = \"b\"",
            "`storage.files[0] set[0] key` is a list of one or more keys",
        ),
        (
            "kind = \"json\"\n[[storage.files.set]]\nkey = [\"a\", \"b\"]\nvalue = \"x\"\n\
             [[storage.files.set]]\nkey = [\"a\"]\nvalue = \"y\"",
            "`storage.files[0] set[0]` and `storage.files[0] set[1]` both set a",
        ),
        (
            "kind = \"json\"\n[[storage.files.set]]\nkey = [\"a\"]\nvalue = \"x\"\n\
             [[storage.files.set]]\nkey = [\"a\"]\nvalue = \"y\"",
            "both set a; each row sets one value that no other row holds",
        ),
    ] {
        let reason = scene.refusal(&format!("{base}{row}"));
        assert!(reason.contains(expected), "{row}: {reason}");
    }
}

#[test]
fn a_storage_files_row_applies_only_when_its_when_holds() {
    let scene = Scene::new();
    scene.share(
        "agent",
        "[inputs.agent.import-skills]\ntype = \"bool\"\ndefault = true\n\
         [storage]\ndirectories = [\"config\"]\n\
         [[storage.files]]\nsource = \"${{ home }}/skills\"\ntarget = \"config/skills\"\n\
         when = { variable = \"inputs.agent.import-skills\", equals = \"true\" }\n\
         [[storage.files]]\nsource = \"${{ home }}/linux.md\"\ntarget = \"config/linux.md\"\n\
         when = \"linux\"",
    );
    let targets = |text: &str| -> Vec<String> {
        scene
            .resolve(&profile(text))
            .expect("a resolve")
            .storage
            .files
            .iter()
            .map(|file| file.relative.clone())
            .collect()
    };
    let packs = "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]";
    assert_eq!(targets(packs), vec!["agent/config/skills".to_string()]);
    assert_eq!(
        targets(&format!("{packs}\n[options]\nagent.import-skills = false")),
        Vec::<String>::new(),
        "a profile turns a gated copy off through its input"
    );
}

#[test]
fn a_storage_files_set_row_writes_its_value_only_when_its_when_holds() {
    let scene = Scene::new();
    scene.share(
        "agent",
        "[inputs.agent.host]\ntype = \"string\"\nvalues = [\"cloud\", \"own\"]\ndefault = \"cloud\"\n\
         [inputs.agent.quiet]\ntype = \"bool\"\ndefault = false\n\
         [storage]\ndirectories = [\"config\"]\n\
         [[storage.files]]\nsource = \"${{ home }}/settings.json\"\n\
         target = \"config/settings.json\"\nkind = \"json\"\noptional = true\n\
         [[storage.files.set]]\nkey = [\"always\"]\nvalue = true\n\
         [[storage.files.set]]\nkey = [\"cloud\"]\nvalue = true\n\
         when = { variable = \"inputs.agent.host\", equals = \"cloud\" }\n\
         [[storage.files.set]]\nkey = [\"quiet\"]\nvalue = true\n\
         when = \"${{ inputs.agent.quiet }}\"\n\
         [[storage.files.set]]\nkey = [\"mac\"]\nvalue = true\nwhen = \"macos\"\n\
         [[storage.files.set]]\nkey = [\"linux\"]\nvalue = true\nwhen = \"linux\"",
    );
    let keys = |options: &str| -> Vec<String> {
        scene
            .resolve(&profile(&format!(
                "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]\n[options]\n{options}"
            )))
            .expect("a resolve")
            .storage
            .files[0]
            .edit
            .clone()
            .expect("an edit")
            .set
            .iter()
            .map(|setting| setting.key.join("."))
            .collect()
    };
    assert_eq!(keys(""), ["always", "cloud", "mac"]);
    assert_eq!(
        keys("agent.host = \"own\"\nagent.quiet = true"),
        ["always", "quiet", "mac"],
        "a row whose when does not hold writes nothing"
    );
}

#[test]
fn a_storage_files_set_row_with_a_when_that_never_holds_does_not_collide_with_another_row() {
    let scene = Scene::new();
    let resolved = scene
        .resolve(&profile(
            "[storage]\ndirectories = [\"config\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
             [[storage.files]]\nsource = \"/a.json\"\ntarget = \"config/a.json\"\nkind = \"json\"\n\
             [[storage.files.set]]\nkey = [\"a\"]\nvalue = \"mac\"\nwhen = \"macos\"\n\
             [[storage.files.set]]\nkey = [\"a\"]\nvalue = \"linux\"\nwhen = \"linux\"",
        ))
        .expect("one row applies on each system");
    let edit = resolved.storage.files[0].edit.clone().expect("an edit");
    assert_eq!(
        edit.set
            .iter()
            .map(|setting| setting.value.clone())
            .collect::<Vec<_>>(),
        vec![toml::Value::String("mac".to_string())],
        "the scene runs as macos"
    );
}

#[test]
fn a_profile_replaces_a_packs_copy_only_after_it_turns_the_copy_off() {
    let scene = Scene::new();
    scene.share(
        "agent",
        "[inputs.agent.import-settings]\ntype = \"bool\"\ndefault = true\n\
         [storage]\ndirectories = [\"config\"]\n\
         [[storage.files]]\nsource = \"${{ home }}/settings.json\"\n\
         target = \"config/settings.json\"\n\
         when = { variable = \"inputs.agent.import-settings\", equals = \"true\" }",
    );
    let own = "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
               [[storage.files]]\nsource = \"${{ home }}/mine.json\"\n\
               target = \"config/settings.json\"";
    let reason = format!(
        "{:?}",
        scene.resolve(&profile(own)).expect_err("two active rows")
    );
    assert!(
        reason.contains("set `agent.import-settings = false` under `[options]`"),
        "{reason}"
    );
    let resolved = scene
        .resolve(&profile(&format!(
            "{own}\n[options]\nagent.import-settings = false"
        )))
        .expect("the pack's copy is off");
    let sources: Vec<_> = resolved
        .storage
        .files
        .iter()
        .map(|file| (file.relative.clone(), file.source.clone()))
        .collect();
    assert_eq!(
        sources,
        vec![(
            "agent/config/settings.json".to_string(),
            scene.home().join("mine.json")
        )]
    );
}

#[test]
fn a_storage_files_source_where_a_box_can_write_is_refused() {
    let scene = Scene::new();
    let row = |source: &str| {
        format!(
            "[storage]\ndirectories = [\"config\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
             filesystem.write = [\"${{{{ home }}}}/shared\"]\n\
             [[storage.files]]\nsource = {source:?}\ntarget = \"config/x\"\noptional = true"
        )
    };
    for (source, expected) in [
        ("${{ workspace }}/CLAUDE.md", "lies in the workspace"),
        ("${{ home }}/work", "holds the workspace"),
        (
            "${{ home }}/.strands/box/packs/notes.md",
            "lies in the box home",
        ),
        ("${{ home }}/shared/notes.md", "lies in a write grant"),
        ("${{ home }}", "holds the workspace"),
    ] {
        let reason = scene.refusal(&row(source));
        assert!(
            reason.contains(expected) && reason.contains("box copies no file from there"),
            "{source}: {reason}"
        );
    }
    let linked = scene.home().join("notes");
    std::os::unix::fs::symlink(scene.workspace(), &linked).expect("a link");
    let reason = scene.refusal(&row("${{ home }}/notes"));
    assert!(
        reason.contains("(a link to ~/work/project) is the workspace"),
        "a link to the workspace is refused as its real path: {reason}"
    );
    scene
        .resolve(&profile(&row("${{ home }}/.claude/CLAUDE.md")))
        .expect("an instruction file is accepted");
}

#[test]
fn a_copy_from_boxs_own_packs_passes_only_where_no_box_can_write_them() {
    let scene = Scene::new();
    let installed = scene.home().join(".strands/box/packages/1/resources/packs");
    let in_workspace = scene.workspace().join("resources/packs");
    let in_storage = scene.storage().join("config/packs");
    let in_grant = scene.home().join("shared/packs");
    for packs in [&installed, &in_workspace, &in_storage, &in_grant] {
        std::fs::create_dir_all(packs.join("kiro")).expect("a pack folder");
        std::fs::write(packs.join("kiro/box.md"), "guidance").expect("guidance");
    }
    std::fs::write(scene.workspace().join("notes.md"), "notes").expect("notes");
    std::os::unix::fs::symlink(
        scene.workspace().join("notes.md"),
        installed.join("kiro/notes.md"),
    )
    .expect("a link out of the packs");
    let link = scene.workspace().join("link.md");
    std::os::unix::fs::symlink(installed.join("kiro/box.md"), &link)
        .expect("a link into the packs");
    let resolve = |packs: &Path, source: &Path| {
        let text = format!(
            "[storage]\ndirectories = [\"config\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
             filesystem.write = [\"${{{{ home }}}}/shared\"]\n\
             [[storage.files]]\nsource = {:?}\ntarget = \"config/box.md\"",
            source.display().to_string()
        );
        scene.resolve_shipped(&profile(&text), &scene.context(), &mut Fixed, packs)
    };
    resolve(&installed, &installed.join("kiro/box.md"))
        .expect("a copy from box's own packs in ~/.strands/box");
    for (packs, source, expected) in [
        (
            &in_workspace,
            in_workspace.join("kiro/box.md"),
            "lies in the workspace",
        ),
        (
            &in_storage,
            in_storage.join("kiro/box.md"),
            "lies in the run's storage",
        ),
        (
            &in_grant,
            in_grant.join("kiro/box.md"),
            "lies in a write grant",
        ),
        (
            &installed,
            installed.join("kiro/notes.md"),
            "(a link to ~/work/project/notes.md)",
        ),
        (
            &installed,
            link.clone(),
            "link.md (a link to ~/.strands/box/packages/1/resources/packs/kiro/box.md) lies in the workspace",
        ),
    ] {
        match resolve(packs, &source) {
            Err(Error::Profile { reason, .. }) => {
                assert!(reason.contains(expected), "{}: {reason}", source.display());
            }
            other => panic!("{}: a refusal, not {other:?}", source.display()),
        }
    }
}

/// Sources like `Fixed`, where each program is the executable of that name in one directory.
struct OnPath(PathBuf);

impl Sources for OnPath {
    fn env(&self, name: &str) -> Option<String> {
        Fixed.env(name)
    }

    fn env_with_prefix(&self, prefix: &str) -> Vec<(String, String)> {
        Fixed.env_with_prefix(prefix)
    }

    fn search(&self, name: &str) -> Option<PathBuf> {
        Some(self.0.join(name)).filter(|candidate| candidate.is_file())
    }

    fn developer_dir(&mut self) -> Result<String, String> {
        Err("ran xcode-select, which this host never runs".to_string())
    }

    fn program(&mut self, name: &str) -> Option<PathBuf> {
        Some(self.0.join(name)).filter(|candidate| candidate.is_file())
    }

    fn search_path(&self) -> Vec<PathBuf> {
        vec![self.0.clone()]
    }
}

/// A pack that reads the servers in `~/.agent.json`, for the operator and for this workspace.
const SERVERS_PACK: &str = "[inputs.agent.import-mcp]\ntype = \"bool\"\ndefault = true\n\
     [[mcp-servers]]\nfile = \"${{ home }}/.agent.json\"\nkind = \"json\"\nkey = [\"mcpServers\"]\n\
     when = { variable = \"inputs.agent.import-mcp\", equals = \"true\" }\n\
     [[mcp-servers]]\nfile = \"${{ home }}/.agent.json\"\n\
     kind = \"json\"\nkey = [\"projects\", \"${{ workspace }}\", \"mcpServers\"]\n\
     when = { variable = \"inputs.agent.import-mcp\", equals = \"true\" }";

/// A scene with `SERVERS_PACK` and a `fetcher` program, and the program's directory.
fn servers_scene() -> (Scene, PathBuf) {
    let scene = Scene::new();
    scene.share("agent", SERVERS_PACK);
    let bin = scene.root.join("bin");
    script(&bin.join("fetcher"), "exit 0");
    (scene, bin)
}

#[test]
fn an_addition_with_destinations_permits_the_servers_own_host_and_each_added_host() {
    let (scene, bin) = servers_scene();
    std::fs::write(
        scene.home().join(".agent.json"),
        r#"{"mcpServers": {"docs": {"type": "http", "url": "https://docs.example.com/mcp"}}}"#,
    )
    .expect("a host file");
    let packs = "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
                 [mcp.docs]\ndestinations = [\"cdn.example.com\"]";
    let (_, compiled) = scene
        .compile_using(&profile(packs), &mut OnPath(bin), "/usr/bin:/bin")
        .expect("a compile");
    assert_eq!(
        table(&compiled)["mcp"]["docs"]["destinations"],
        toml::Value::from(vec!["docs.example.com", "cdn.example.com"])
    );
    for rule in [
        "@id(\"mcp_docs_connect\") permit (principal, action == Box::Action::\"net:connect\", resource) when { (context.input.host == \"docs.example.com\" && context.input.port == 443) || (context.input.host == \"cdn.example.com\" && context.input.port == 443) };",
        "@id(\"mcp_docs_request\") permit (principal, action == Box::Action::\"http:request\", resource) when { context.input.host == \"docs.example.com\" || context.input.host == \"cdn.example.com\" };",
    ] {
        assert!(
            compiled.policy.contains(rule),
            "{rule}\nin\n{}",
            compiled.policy
        );
    }
}

#[test]
fn a_pack_names_its_mcp_sources_and_each_server_becomes_a_table_with_its_permits() {
    let (scene, bin) = servers_scene();
    let workspace = scene.workspace().display().to_string();
    std::fs::write(
        scene.home().join(".agent.json"),
        format!(
            r#"{{"mcpServers": {{"fetch": {{"command": "fetcher", "args": ["--quiet"]}}}},
                "projects": {{"{workspace}": {{"mcpServers": {{"docs": {{"type": "http", "url": "https://docs.example.com/mcp"}}}}}}}}}}"#
        ),
    )
    .expect("a host file");
    let packs = "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
                 filesystem.deny = [\"${{ home }}/.ssh\"]";
    let (resolved, compiled) = scene
        .compile_using(&profile(packs), &mut OnPath(bin.clone()), "/usr/bin:/bin")
        .expect("a compile");
    let file = table(&compiled);
    let expected: toml::Table = toml::from_str(&format!(
        r#"
        [docs]
        type = "http"
        destinations = ["docs.example.com"]

        [fetch]
        type = "stdio"
        command = ["fetcher", "--quiet"]
        filesystem.read = [{workspace:?}, {bin:?}]
        filesystem.read_file = [{shell:?}]
        filesystem.write = [{workspace:?}]
        filesystem.deny = [{ssh:?}, {configuration:?}]
        "#,
        shell = crate::test_support::shell(),
        bin = bin.display().to_string(),
        ssh = scene.home().join(".ssh").display().to_string(),
        configuration = format!("{workspace}/.box"),
    ))
    .expect("TOML");
    assert_eq!(file["mcp"].as_table(), Some(&expected));
    assert!(
        !compiled.box_toml.contains("mcp-servers"),
        "{}",
        compiled.box_toml
    );
    let program = bin.join("fetcher").display().to_string();
    for rule in [
        "@id(\"mcp_fetch_call\") permit (principal, action == Box::Action::\"mcp:call\", resource) when { context.input.server == \"fetch\" };".to_string(),
        format!("@id(\"mcp_fetch_spawn\") permit (principal, action == Box::Action::\"shell:spawn\", resource) when {{ context.input.program_path == {program:?} && context.input.program == \"fetcher\" }};"),
        "@id(\"mcp_docs_call\") permit (principal, action == Box::Action::\"mcp:call\", resource) when { context.input.server == \"docs\" };".to_string(),
        "@id(\"mcp_docs_connect\") permit (principal, action == Box::Action::\"net:connect\", resource) when { (context.input.host == \"docs.example.com\" && context.input.port == 443) };".to_string(),
        "@id(\"mcp_docs_request\") permit (principal, action == Box::Action::\"http:request\", resource) when { context.input.host == \"docs.example.com\" };".to_string(),
    ] {
        assert!(compiled.policy.contains(&rule), "{rule}\nin\n{}", compiled.policy);
    }
    assert_eq!(
        resolved.servers.detected_lines(&scene.home()),
        vec![
            (
                "docs".to_string(),
                "~/.agent.json".to_string(),
                String::new()
            ),
            (
                "fetch".to_string(),
                "~/.agent.json".to_string(),
                String::new()
            ),
        ]
    );
    let (resolved, compiled) = scene
        .compile_using(
            &profile(&format!("{packs}\n[options]\nagent.import-mcp = false")),
            &mut OnPath(bin),
            "/usr/bin:/bin",
        )
        .expect("a compile");
    assert!(resolved.servers.sources.is_empty());
    assert!(
        !table(&compiled)
            .as_table()
            .expect("a table")
            .contains_key("mcp")
    );
    assert!(!compiled.policy.contains("mcp_"), "{}", compiled.policy);
}

#[test]
fn a_server_whose_argument_names_a_workspace_file_is_declared_and_the_run_compiles() {
    let (scene, bin) = servers_scene();
    for name in ["sqlite", "playwright", "notes", "tuiwright"] {
        script(&bin.join(name), "exit 0");
    }
    let workspace = scene.workspace();
    for file in [
        "data.sqlite",
        "playwright-mcp.json",
        "notes.md",
        "tuiwright.toml",
    ] {
        std::fs::write(workspace.join(file), "").expect("a project file");
    }
    let relative = workspace
        .strip_prefix(scene.home())
        .expect("a workspace in the home")
        .display()
        .to_string();
    let workspace = workspace.display().to_string();
    std::fs::write(
        scene.home().join(".agent.json"),
        format!(
            r#"{{"mcpServers": {{
                "sqlite": {{"command": "sqlite", "args": ["--db-path", "{workspace}/data.sqlite"]}},
                "playwright": {{"command": "playwright", "args": ["--config={workspace}/playwright-mcp.json"]}},
                "notes": {{"command": "notes", "args": ["~/{relative}/notes.md"]}},
                "tuiwright": {{"command": "tuiwright", "args": ["--config", "tuiwright.toml"]}}
            }}}}"#
        ),
    )
    .expect("a host file");
    let packs = "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]";
    let (resolved, compiled) = scene
        .compile_using(&profile(packs), &mut OnPath(bin), "/usr/bin:/bin")
        .expect("a server's arguments are not programs");
    assert!(
        resolved.servers.skipped.is_empty(),
        "{:?}",
        resolved.servers
    );
    let file = table(&compiled);
    assert_eq!(
        strings(&file["mcp"]["sqlite"]["command"]),
        [
            "sqlite".to_string(),
            "--db-path".to_string(),
            format!("{workspace}/data.sqlite")
        ]
    );
    assert_eq!(
        strings(&file["mcp"]["playwright"]["command"]),
        [
            "playwright".to_string(),
            format!("--config={workspace}/playwright-mcp.json")
        ]
    );
    assert_eq!(
        strings(&file["mcp"]["notes"]["command"]),
        ["notes".to_string(), format!("~/{relative}/notes.md")]
    );
    assert_eq!(
        strings(&file["mcp"]["tuiwright"]["command"]),
        ["tuiwright", "--config", "tuiwright.toml"]
    );
}

#[test]
fn a_hand_written_server_that_runs_a_workspace_file_is_refused() {
    let scene = Scene::new();
    let workspace = scene.workspace().display().to_string();
    std::fs::write(scene.workspace().join("server.js"), "").expect("a script");
    let secret = scene.root.join("secret");
    std::fs::create_dir_all(&secret).expect("a folder");
    let text = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\n[mcp.m]\ntype = \"stdio\"\n\
         command = [\"true\", \"{workspace}/server.js\"]\nfilesystem.read = [{secret:?}]",
        secret = secret.display().to_string()
    );
    let error = scene.compile(&profile(&text), None).expect_err("a refusal");
    assert!(matches!(error, Error::ProgramUnderWrite { .. }), "{error}");
}

#[test]
fn a_detected_server_with_an_addition_keeps_the_argument_check() {
    let (scene, bin) = servers_scene();
    let workspace = scene.workspace().display().to_string();
    std::fs::write(scene.workspace().join("data.sqlite"), "").expect("a project file");
    let data = scene.home().join("data");
    std::fs::create_dir_all(&data).expect("a folder");
    let link = data.join("linked.sqlite");
    std::os::unix::fs::symlink(scene.workspace().join("data.sqlite"), &link).expect("a link");
    std::os::unix::fs::symlink(
        scene.workspace().join("data.sqlite"),
        scene.workspace().join("-data.sqlite"),
    )
    .expect("a file whose name starts with a dash");
    let packs = "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]";
    let extended = format!("{packs}\n[mcp.fetch.filesystem]\nread = [\"${{{{ home }}}}/data\"]");
    let relative_home = scene
        .workspace()
        .strip_prefix(scene.home())
        .expect("under home")
        .to_path_buf();
    for args in [
        vec!["--db-path".to_string(), format!("{workspace}/data.sqlite")],
        vec!["--db-path".to_string(), "data.sqlite".to_string()],
        vec![format!("--db-path={workspace}/data.sqlite")],
        vec!["--db-path=./data.sqlite".to_string()],
        vec!["--db-path=-data.sqlite".to_string()],
        vec![format!(
            "--db-path=~/{}/data.sqlite",
            relative_home.display()
        )],
        vec![format!("--db-path={}", link.display())],
    ] {
        std::fs::write(
            scene.home().join(".agent.json"),
            serde_json::json!({"mcpServers": {"fetch": {"command": "fetcher", "args": args}}})
                .to_string(),
        )
        .expect("a host file");
        scene
            .compile_using(&profile(packs), &mut OnPath(bin.clone()), "/usr/bin:/bin")
            .expect("an unextended detected server's arguments are not programs");
        let error = scene
            .compile_using(
                &profile(&extended),
                &mut OnPath(bin.clone()),
                "/usr/bin:/bin",
            )
            .expect_err(&format!(
                "an addition keeps the argument check for {args:?}"
            ));
        match error {
            Error::ProgramUnderWrite { program, grant, .. } => {
                assert_eq!(program, scene.workspace().join("data.sqlite"), "{args:?}");
                assert_eq!(grant, scene.workspace(), "{args:?}");
            }
            other => panic!("a writable argument file is refused for {args:?}: {other}"),
        }
    }
    scene.share(
        "extra",
        "[mcp.fetch.filesystem]\nread = [\"${{ home }}/data\"]",
    );
    let error = scene
        .compile_using(
            &profile("packs = [\"@box/agent\", \"@box/extra\"]\n[agent]\ncommand = [\"/bin/x\"]"),
            &mut OnPath(scene.root.join("bin")),
            "/usr/bin:/bin",
        )
        .expect_err("a pack's addition keeps the argument check");
    match error {
        Error::ProgramUnderWrite { program, grant, .. } => {
            assert_eq!(program, scene.workspace().join("data.sqlite"));
            assert_eq!(grant, scene.workspace());
        }
        other => panic!("a writable argument file is refused: {other}"),
    }
}

#[test]
fn an_extended_detected_server_checks_fixed_files_beside_wildcard_arguments() {
    let (scene, bin) = servers_scene();
    std::fs::write(scene.workspace().join("*"), "literal-star").expect("a project file");
    std::fs::write(scene.workspace().join("data.sqlite"), "").expect("a project file");
    let text = "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
        [mcp.fetch.filesystem]\nread = [\"${{ home }}/data\"]";
    for fixed in ["--verbose", "--db-path=data.sqlite"] {
        std::fs::write(
            scene.home().join(".agent.json"),
            serde_json::json!({"mcpServers": {
                "fetch": {"command": "fetcher", "args": ["${UNSET}", fixed]}
            }})
            .to_string(),
        )
        .expect("a host file");
        let result = scene.compile_using(&profile(text), &mut OnPath(bin.clone()), "/usr/bin:/bin");
        if fixed == "--verbose" {
            let (_, compiled) = result.expect("wildcard slots are not literal file paths");
            let config = table(&compiled);
            assert!(
                config.get("mcp").and_then(|mcp| mcp.get("fetch")).is_some(),
                "the variable-argument server is declared: {config:?}"
            );
            assert_eq!(
                strings(&config["mcp"]["fetch"]["command"]),
                ["fetcher", "*", fixed]
            );
            assert_eq!(
                config["mcp"]["fetch"]["argument_wildcards"].as_bool(),
                Some(true)
            );
        } else {
            match result.expect_err("a fixed writable file stays refused") {
                Error::ProgramUnderWrite { program, grant, .. } => {
                    assert_eq!(program, scene.workspace().join("data.sqlite"));
                    assert_eq!(grant, scene.workspace());
                }
                other => panic!("a writable file refusal: {other}"),
            }
        }
    }
}

#[test]
fn an_extended_detected_server_keeps_read_only_files_and_other_arguments_as_written() {
    let (scene, bin) = servers_scene();
    let data = scene.home().join("data");
    std::fs::create_dir_all(&data).expect("a folder");
    let file = data.join("settings.json");
    std::fs::write(&file, "{}").expect("a read-only argument file");
    let args = vec![
        "--config".to_string(),
        file.display().to_string(),
        "../../data/settings.json".to_string(),
        "--config=../../data/settings.json".to_string(),
        "--config=~/data/settings.json".to_string(),
        "--db-path=not-created.sqlite".to_string(),
        "--verbose".to_string(),
        "".to_string(),
    ];
    std::fs::write(
        scene.home().join(".agent.json"),
        serde_json::json!({"mcpServers": {"fetch": {"command": "fetcher", "args": args}}})
            .to_string(),
    )
    .expect("a host file");
    let text = "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
        [mcp.fetch.filesystem]\nread = [\"${{ home }}/data\"]";
    let (_, compiled) = scene
        .compile_using(&profile(text), &mut OnPath(bin), "/usr/bin:/bin")
        .expect("read-only files and other arguments remain accepted");
    let expected = std::iter::once("fetcher".to_string())
        .chain(args)
        .collect::<Vec<_>>();
    assert_eq!(
        strings(&table(&compiled)["mcp"]["fetch"]["command"]),
        expected
    );
}

#[test]
fn a_profiles_own_server_wins_and_every_server_table_gets_its_permits() {
    let (scene, bin) = servers_scene();
    std::fs::write(
        scene.home().join(".agent.json"),
        r#"{"mcpServers": {"fetch": {"command": "fetcher"}, "lone": {"command": "absent"}}}"#,
    )
    .expect("a host file");
    let text = "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
                [mcp.fetch]\ntype = \"stdio\"\ncommand = [\"fetcher\", \"--mine\"]\n\
                [mcp.elsewhere]\ntype = \"stdio\"\ncommand = [\"not-installed\"]\n\
                [mcp.remote]\ntype = \"http\"\ndestinations = [\"api.example.com:8443\"]";
    let (resolved, compiled) = scene
        .compile_using(
            &profile(text),
            &mut OnPath(bin.clone()),
            &bin.display().to_string(),
        )
        .expect("a compile");
    assert_eq!(
        strings(&table(&compiled)["mcp"]["fetch"]["command"]),
        ["fetcher", "--mine"]
    );
    assert_eq!(
        resolved.servers.skipped_lines(&scene.home()),
        vec![
            (
                "fetch".to_string(),
                "~/.agent.json".to_string(),
                "the profile declares `[mcp.fetch]`, which takes its place".to_string()
            ),
            (
                "lone".to_string(),
                "~/.agent.json".to_string(),
                "runs absent, which is not on your PATH outside the project".to_string()
            ),
        ]
    );
    let program = bin.join("fetcher").display().to_string();
    for rule in [
        format!("@id(\"mcp_fetch_spawn\") permit (principal, action == Box::Action::\"shell:spawn\", resource) when {{ context.input.program_path == {program:?} && context.input.program == \"fetcher\" }};"),
        "@id(\"mcp_remote_connect\") permit (principal, action == Box::Action::\"net:connect\", resource) when { (context.input.host == \"api.example.com\" && context.input.port == 8443) };".to_string(),
        "@id(\"mcp_remote_call\") permit (principal, action == Box::Action::\"mcp:call\", resource) when { context.input.server == \"remote\" };".to_string(),
    ] {
        assert!(compiled.policy.contains(&rule), "{rule}\nin\n{}", compiled.policy);
    }
    assert!(
        !compiled.policy.contains("mcp_elsewhere_spawn"),
        "{}",
        compiled.policy
    );
    assert_eq!(
        strings(&table(&compiled)["mcp"]["fetch"]["filesystem"]["deny"]),
        [format!("{}/.box", scene.workspace().display())],
        "a hand-written server keeps only the project configuration deny"
    );
}

#[test]
fn a_table_without_a_type_adds_to_the_detected_server_of_its_name() {
    let (scene, bin) = servers_scene();
    std::fs::write(
        scene.home().join(".agent.json"),
        r#"{"mcpServers": {"fetch": {"command": "fetcher"}}}"#,
    )
    .expect("a host file");
    let data = scene.home().join("data");
    std::fs::create_dir_all(&data).expect("a folder");
    let text = "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
                [mcp.fetch.filesystem]\nread = [\"${{ home }}/data\"]";
    let (resolved, compiled) = scene
        .compile_using(&profile(text), &mut OnPath(bin.clone()), "/usr/bin:/bin")
        .expect("a compile");
    assert!(
        resolved.servers.skipped.is_empty(),
        "{:?}",
        resolved.servers
    );
    let file = table(&compiled);
    assert_eq!(
        strings(&file["mcp"]["fetch"]["filesystem"]["read"]),
        [
            scene.workspace().display().to_string(),
            bin.display().to_string(),
            data.display().to_string(),
        ]
    );
    assert_eq!(file["mcp"]["fetch"]["type"].as_str(), Some("stdio"));
    assert!(
        compiled.policy.contains(&format!(
            "context.input.program_path == {:?}",
            bin.join("fetcher").display().to_string()
        )),
        "{}",
        compiled.policy
    );
    let (resolved, compiled) = scene
        .compile_using(
            &profile(&format!("{text}\n[options]\nagent.import-mcp = false")),
            &mut OnPath(bin),
            "/usr/bin:/bin",
        )
        .expect("an addition with no server is skipped, and the run goes on");
    assert!(!compiled.box_toml.contains("[mcp"), "{}", compiled.box_toml);
    assert_eq!(
        resolved.servers.skipped[0].reason,
        "`[mcp.fetch]` has no `type`, so it adds to a server this run finds, and this run finds \
         no server named fetch"
    );
}

#[test]
fn a_packs_addition_joins_a_detected_server_and_the_profile_wins_on_a_key() {
    let (scene, bin) = servers_scene();
    std::fs::write(
        scene.home().join(".agent.json"),
        r#"{"mcpServers": {"fetch": {"command": "fetcher"}}}"#,
    )
    .expect("a host file");
    let data = scene.home().join("data");
    let more = scene.home().join("more");
    for folder in [&data, &more] {
        std::fs::create_dir_all(folder).expect("a folder");
    }
    scene.share(
        "extra",
        "[mcp.fetch.filesystem]\nread = [\"${{ home }}/data\"]\n\
         [mcp.fetch.network]\ncontain_egress = false",
    );
    let packs = "packs = [\"@box/agent\", \"@box/extra\"]\n[agent]\ncommand = [\"/bin/x\"]";
    let (resolved, compiled) = scene
        .compile_using(&profile(packs), &mut OnPath(bin.clone()), "/usr/bin:/bin")
        .expect("a compile");
    assert!(
        resolved.servers.skipped.is_empty(),
        "{:?}",
        resolved.servers
    );
    let file = table(&compiled);
    assert_eq!(
        strings(&file["mcp"]["fetch"]["filesystem"]["read"]),
        [
            scene.workspace().display().to_string(),
            bin.display().to_string(),
            data.display().to_string(),
        ]
    );
    assert_eq!(
        file["mcp"]["fetch"]["network"]["contain_egress"].as_bool(),
        Some(false)
    );
    let text = format!(
        "{packs}\n[mcp.fetch.filesystem]\nread = [\"${{{{ home }}}}/more\"]\n\
         [mcp.fetch.network]\ncontain_egress = true"
    );
    let (_, compiled) = scene
        .compile_using(&profile(&text), &mut OnPath(bin.clone()), "/usr/bin:/bin")
        .expect("a compile");
    let file = table(&compiled);
    assert_eq!(
        strings(&file["mcp"]["fetch"]["filesystem"]["read"]),
        [
            scene.workspace().display().to_string(),
            bin.display().to_string(),
            data.display().to_string(),
            more.display().to_string(),
        ],
        "the pack's list and the profile's list join"
    );
    assert_eq!(
        file["mcp"]["fetch"]["network"]["contain_egress"].as_bool(),
        Some(true),
        "the profile wins over the pack on one key"
    );
}

#[test]
fn a_packs_addition_carries_file_and_write_entries_and_gates_an_entry_on_the_os() {
    let (scene, bin) = servers_scene();
    std::fs::write(
        scene.home().join(".agent.json"),
        r#"{"mcpServers": {"fetch": {"command": "fetcher"}}}"#,
    )
    .expect("a host file");
    let settings = scene.home().join("settings.json");
    let platform = scene.home().join("platform.cnf");
    for file in [&settings, &platform] {
        std::fs::write(file, "").expect("a file");
    }
    let state = scene.home().join("state");
    std::fs::create_dir_all(&state).expect("a folder");
    scene.share(
        "extra",
        "[mcp.fetch.filesystem]\n\
         read_file = [\n\
         \"${{ home }}/settings.json\",\n\
         { path = \"${{ home }}/platform.cnf\", optional = true, when = \"macos\" },\n\
         ]\n\
         write = [\"${{ home }}/state\"]",
    );
    let packs = "packs = [\"@box/agent\", \"@box/extra\"]\n[agent]\ncommand = [\"/bin/x\"]";
    let shown = |path: &PathBuf| path.display().to_string();
    for (os, read_file) in [
        ("macos", vec![shown(&settings), shown(&platform)]),
        ("linux", vec![shown(&settings)]),
    ] {
        let (resolved, compiled) = scene
            .compile_using_in(
                &profile(packs),
                &Context {
                    os,
                    ..scene.context()
                },
                &mut OnPath(bin.clone()),
                "/usr/bin:/bin",
            )
            .expect("a compile");
        assert!(
            resolved.servers.skipped.is_empty(),
            "{os}: {:?}",
            resolved.servers
        );
        let filesystem = &table(&compiled)["mcp"]["fetch"]["filesystem"];
        let home = shown(&scene.home());
        let from_the_pack: Vec<String> = strings(&filesystem["read_file"])
            .into_iter()
            .filter(|entry| entry.starts_with(&home))
            .collect();
        assert_eq!(from_the_pack, read_file, "{os}");
        assert_eq!(
            strings(&filesystem["write"]),
            [shown(&scene.workspace()), shown(&state)],
            "{os}"
        );
    }
}

#[test]
fn a_server_with_direct_network_access_keeps_its_own_proxy_and_ca_variables() {
    let (scene, bin) = servers_scene();
    let certs = scene.home().join(".certs");
    std::fs::create_dir_all(&certs).expect("a folder");
    let ca = certs.join("corp.pem");
    std::fs::write(&ca, "pem").expect("a CA file");
    let ca = std::fs::canonicalize(&ca).expect("a real path");
    let linked = certs.join("linked.pem");
    std::os::unix::fs::symlink(&ca, &linked).expect("a link");
    let missing = certs.join("gone.pem");
    std::fs::write(
        scene.home().join(".agent.json"),
        format!(
            r#"{{"mcpServers": {{"fetch": {{"command": "fetcher", "env": {{
            "HTTPS_PROXY": "http://proxy.corp.example:8080", "NODE_EXTRA_CA_CERTS": "{}",
            "SSL_CERT_FILE": "{}", "REQUESTS_CA_BUNDLE": "{}", "USER": "someone"}}}}}}}}"#,
            linked.display(),
            ca.display(),
            missing.display()
        ),
    )
    .expect("a host file");
    let packs = "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]";
    let (resolved, compiled) = scene
        .compile_using(&profile(packs), &mut OnPath(bin.clone()), "/usr/bin:/bin")
        .expect("a compile");
    assert!(table(&compiled)["mcp"]["fetch"].get("env").is_none());
    assert_eq!(
        resolved.servers.detected[0]
            .dropped
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        [
            "HTTPS_PROXY",
            "NODE_EXTRA_CA_CERTS",
            "REQUESTS_CA_BUNDLE",
            "SSL_CERT_FILE",
            "USER"
        ],
        "a server that goes through the gateway gets the box's own proxy and CA"
    );
    let text = format!("{packs}\n[mcp.fetch.network]\ncontain_egress = false");
    let (resolved, compiled) = scene
        .compile_using(&profile(&text), &mut OnPath(bin), "/usr/bin:/bin")
        .expect("a compile");
    let file = table(&compiled);
    let env = file["mcp"]["fetch"]["env"].as_table().expect("an env");
    assert_eq!(
        env.iter()
            .map(|(name, value)| (name.as_str(), value.as_str().unwrap_or_default()))
            .collect::<Vec<_>>(),
        [
            ("HTTPS_PROXY", "http://proxy.corp.example:8080"),
            ("NODE_EXTRA_CA_CERTS", ca.to_str().expect("a path")),
            ("SSL_CERT_FILE", ca.to_str().expect("a path")),
        ],
        "a linked CA path becomes the file it links to"
    );
    assert!(
        strings(&file["mcp"]["fetch"]["filesystem"]["read_file"])
            .contains(&ca.display().to_string()),
        "the server reads the CA file it names: {}",
        compiled.box_toml
    );
    assert_eq!(
        resolved.servers.detected[0].dropped,
        [
            (
                "REQUESTS_CA_BUNDLE".to_string(),
                "its REQUESTS_CA_BUNDLE names ~/.certs/gone.pem, which is not a file here"
                    .to_string()
            ),
            ("USER".to_string(), "the box sets it itself".to_string()),
        ]
    );
    assert_eq!(
        resolved.servers.detected[0].env,
        ["HTTPS_PROXY", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"]
    );
}

#[test]
fn a_packs_addition_that_no_server_takes_is_dropped_and_names_the_pack() {
    let (scene, bin) = servers_scene();
    std::fs::write(
        scene.home().join(".agent.json"),
        r#"{"mcpServers": {"fetch": {"command": "fetcher"}}}"#,
    )
    .expect("a host file");
    scene.share(
        "extra",
        "[mcp.absent.filesystem]\nread = [\"/usr\"]\n[mcp.absent.network]\ncontain_egress = false",
    );
    let (resolved, compiled) = scene
        .compile_using(
            &profile("packs = [\"@box/agent\", \"@box/extra\"]\n[agent]\ncommand = [\"/bin/x\"]"),
            &mut OnPath(bin),
            "/usr/bin:/bin",
        )
        .expect("a skip never stops the run");
    let file = table(&compiled);
    assert!(file["mcp"].get("absent").is_none(), "{}", compiled.box_toml);
    assert!(file["mcp"].get("fetch").is_some(), "{}", compiled.box_toml);
    let [skip] = resolved.servers.skipped.as_slice() else {
        panic!("one skip: {:?}", resolved.servers.skipped);
    };
    assert_eq!(skip.name, "absent");
    assert!(
        skip.source.ends_with("packs/extra/pack.toml"),
        "the pack that holds the addition is named: {}",
        skip.source.display()
    );
    assert_eq!(
        skip.reason,
        "`[mcp.absent]` has no `type`, so it adds to a server this run finds, and this run finds \
         no server named absent"
    );
    let (resolved, _) = scene
        .compile_using(
            &profile(
                "packs = [\"@box/agent\", \"@box/extra\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
                 [mcp.absent.filesystem]\nread = [\"/usr\"]",
            ),
            &mut OnPath(scene.root.join("bin")),
            "/usr/bin:/bin",
        )
        .expect("a skip never stops the run");
    let [skip] = resolved.servers.skipped.as_slice() else {
        panic!("one skip: {:?}", resolved.servers.skipped);
    };
    assert!(
        !skip.source.ends_with("pack.toml"),
        "the profile names a table it holds too: {}",
        skip.source.display()
    );
}

#[test]
fn a_packs_addition_holds_only_grants() {
    let (scene, _) = servers_scene();
    for (key, text) in [
        ("command", "command = [\"sh\", \"-c\", \"id\"]"),
        ("env", "env.MODE = \"pack\""),
        ("destinations", "destinations = [\"cdn.example.com\"]"),
        ("secret", "secret.ref = \"env://TOKEN\""),
        ("when", "when = \"linux\""),
    ] {
        scene.share("extra", &format!("[mcp.fetch]\n{text}"));
        match scene.resolve(&profile(
            "packs = [\"@box/agent\", \"@box/extra\"]\n[agent]\ncommand = [\"/bin/x\"]",
        )) {
            Err(Error::Profile { path, reason, .. }) => {
                assert!(path.ends_with("packs/extra/pack.toml"), "{key}: {path:?}");
                assert!(
                    reason.ends_with(&format!(
                        "holds only `filesystem` and `network`, not `{key}`"
                    )),
                    "{key}: {reason}"
                );
            }
            other => panic!("{key}: a refusal, not {other:?}"),
        }
    }
    scene.share(
        "extra",
        "[mcp.fetch.filesystem]\nwhen = \"linux\"\nread = [\"/usr\"]",
    );
    match scene.resolve(&profile(
        "packs = [\"@box/agent\", \"@box/extra\"]\n[agent]\ncommand = [\"/bin/x\"]",
    )) {
        Err(Error::Profile { reason, .. }) => assert!(
            reason.starts_with("a pack's `[mcp.fetch.filesystem]` takes no `when`"),
            "{reason}"
        ),
        other => panic!("a refusal, not {other:?}"),
    }
}

#[test]
fn an_additions_write_grant_counts_and_its_skipped_server_is_reported_once() {
    let (scene, bin) = servers_scene();
    std::fs::write(
        scene.home().join(".agent.json"),
        r#"{"mcpServers": {"fetch": {"command": "fetcher"}, "zeta": {"type": "sse", "url": "https://x.example.com"}}}"#,
    )
    .expect("a host file");
    let text = format!(
        "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
         [mcp.fetch.filesystem]\nwrite = [{:?}]\n\
         [mcp.absent.filesystem]\nread = [\"/usr\"]",
        bin.display().to_string()
    );
    let (resolved, compiled) = scene
        .compile_using(&profile(&text), &mut OnPath(bin.clone()), "/usr/bin:/bin")
        .expect("a skip never stops the run");
    assert!(!compiled.box_toml.contains("[mcp"), "{}", compiled.box_toml);
    let lines: Vec<(String, String)> = resolved
        .servers
        .skipped
        .iter()
        .map(|skip| (skip.name.clone(), skip.reason.clone()))
        .collect();
    let names: Vec<&str> = lines.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["absent", "fetch", "zeta"], "{lines:?}");
    assert!(
        lines[1].1.contains("a write grant"),
        "the addition's write grant is checked: {lines:?}"
    );
    assert!(
        lines[0].1.contains("this run finds no server named absent"),
        "{lines:?}"
    );
}

#[test]
fn a_server_searches_its_path_as_box_core_does() {
    let scene = Scene::new();
    script(&scene.home().join("tools/srv"), "exit 0");
    let planted = scene.workspace().join("bin");
    script(&planted.join("srv"), "exit 0");
    let bin = scene.root.join("bin");
    script(&bin.join("srv"), "exit 0");
    let server = |path: &str| {
        format!(
            "[agent]\ncommand = [\"/usr/bin/true\"]\n\
             [mcp.local]\ntype = \"stdio\"\ncommand = [\"srv\"]\nenv.PATH = {path:?}"
        )
    };
    let compile = |text: &str, search_path: &str| {
        scene
            .compile_in(&scene.workspace(), &profile(text), None, search_path)
            .expect("a compile")
    };
    for tilde in ["~/tools:/usr/bin", "~/work/project/bin:/usr/bin"] {
        let compiled = compile(&server(tilde), "/usr/bin:/bin");
        assert!(
            !compiled.policy.contains("mcp_local_spawn"),
            "a ~ entry is not searched: {}",
            compiled.policy
        );
        assert_eq!(
            compiled.unstarted,
            [(
                "local".to_string(),
                "box finds no srv on its env.PATH".to_string()
            )]
        );
    }
    let compiled = compile(
        "[agent]\ncommand = [\"/usr/bin/true\"]\n\
         [mcp.local]\ntype = \"stdio\"\ncommand = [\"true\"]\nenv.PATH = \"\"",
        &bin.display().to_string(),
    );
    let true_path = format!("context.input.program_path == {:?}", real("/usr/bin/true"));
    assert!(
        compiled.policy.contains(&true_path),
        "an empty env.PATH searches /usr/bin:/bin, not the operator's PATH: {}",
        compiled.policy
    );
    let compiled = compile(&server(""), &bin.display().to_string());
    assert!(
        !compiled.policy.contains("mcp_local_spawn"),
        "srv is only on the operator's PATH: {}",
        compiled.policy
    );
    let compiled = compile(
        "[agent]\ncommand = [\"/usr/bin/true\"]\n\
         [mcp.local]\ntype = \"stdio\"\ncommand = [\"true\"]",
        "",
    );
    assert!(
        compiled.policy.contains(&true_path),
        "an empty PATH searches /usr/bin:/bin: {}",
        compiled.policy
    );
}

/// The end of the `dropped` line for `entry`, a `PATH` entry that is not a full path.
fn path_dropped(entry: &str) -> String {
    format!(
        "{entry:?} from the PATH of each MCP server that inherits your PATH: it is not a full \
         path, so it finds programs in the project"
    )
}

#[test]
fn each_stdio_server_that_inherits_your_path_gets_only_its_full_entries() {
    let scene = Scene::new();
    let text = "[agent]\ncommand = [\"/usr/bin/true\"]\n\
                [mcp.own]\ntype = \"stdio\"\ncommand = [\"true\"]\n\
                [mcp.gone]\ntype = \"stdio\"\ncommand = [\"not-installed\"]\n\
                [mcp.mine]\ntype = \"stdio\"\ncommand = [\"true\", \"--mine\"]\n\
                env.PATH = \"~/bin:.:/usr/bin\"\n\
                [mcp.remote]\ntype = \"http\"\ndestinations = [\"api.example.com\"]";
    let compiled = scene
        .compile_in(
            &scene.workspace(),
            &profile(text),
            None,
            "/usr/bin:~/.dotnet/tools:.:/bin:.",
        )
        .expect("a compile");
    let file = table(&compiled);
    for server in ["own", "gone"] {
        assert_eq!(
            file["mcp"][server]["env"]["PATH"].as_str(),
            Some("/usr/bin:/bin"),
            "{server}"
        );
    }
    assert_eq!(
        file["mcp"]["mine"]["env"]["PATH"].as_str(),
        Some("~/bin:.:/usr/bin"),
        "the profile's own PATH is kept"
    );
    assert!(file["mcp"]["remote"].get("env").is_none());
    assert_eq!(
        compiled.path_dropped,
        [path_dropped("~/.dotnet/tools"), path_dropped(".")]
    );
    assert_eq!(
        compiled.unstarted,
        [(
            "gone".to_string(),
            "box finds no not-installed on your PATH".to_string()
        )]
    );
    let compiled = scene
        .compile_in(&scene.workspace(), &profile(text), None, "/usr/bin:/bin")
        .expect("a compile");
    let file = table(&compiled);
    assert!(
        file["mcp"]["own"].get("env").is_none(),
        "a full PATH changes nothing"
    );
    assert!(compiled.path_dropped.is_empty());
}

#[test]
fn with_no_server_that_inherits_your_path_nothing_is_dropped() {
    let scene = Scene::new();
    let compile = |text: &str| {
        scene
            .compile_in(
                &scene.workspace(),
                &profile(&format!("[agent]\ncommand = [\"/usr/bin/true\"]\n{text}")),
                None,
                ".:/usr/bin:/bin",
            )
            .expect("a compile")
    };
    let compiled =
        compile("[mcp.mine]\ntype = \"stdio\"\ncommand = [\"true\"]\nenv.PATH = \"/usr/bin\"");
    assert_eq!(
        table(&compiled)["mcp"]["mine"]["env"]["PATH"].as_str(),
        Some("/usr/bin")
    );
    assert!(compiled.path_dropped.is_empty());
    let compiled = compile("[mcp.remote]\ntype = \"http\"\ndestinations = [\"api.example.com\"]");
    assert!(table(&compiled)["mcp"]["remote"].get("env").is_none());
    assert!(compiled.path_dropped.is_empty());
}

#[test]
fn a_path_with_no_full_entry_changes_no_table() {
    let scene = Scene::new();
    let text = "[agent]\ncommand = [\"/usr/bin/true\"]\n\
                [mcp.own]\ntype = \"stdio\"\ncommand = [\"true\"]";
    for (search_path, unstarted) in [
        (
            ".",
            vec![(
                "own".to_string(),
                "box finds no true on your PATH".to_string(),
            )],
        ),
        ("", Vec::new()),
    ] {
        let compiled = scene
            .compile_in(&scene.workspace(), &profile(text), None, search_path)
            .expect("a compile");
        assert!(
            table(&compiled)["mcp"]["own"].get("env").is_none(),
            "{search_path:?}"
        );
        assert!(compiled.path_dropped.is_empty(), "{search_path:?}");
        assert_eq!(compiled.unstarted, unstarted, "{search_path:?}");
    }
}

#[test]
fn a_skipped_environment_import_still_validates_its_source_and_target() {
    let scene = Scene::new();
    for (suffix, edit, expected) in [
        ("/../config.toml", "", "holds `..`"),
        ("/config.toml", "", "overlaps a `storage.files` target"),
        ("/config.toml", "kind = 'invalid'\n", "kind"),
    ] {
        scene.share(
            "import",
            &format!(
                "[inputs.home]\nfrom = 'env:SET'\n\
                 [storage]\ndirectories = ['config']\n\
                 [[storage.files]]\nsource = '${{{{ inputs.home }}}}{suffix}'\n\
                 target = 'config/agent.toml'\noptional = true\n{edit}\
                 [[mcp-servers]]\nfile = '${{{{ home }}}}/mcp.toml'\n\
                 kind = 'toml'\nkey = ['mcp_servers']\n\
                 target = 'config/agent.toml'\ntarget-key = 'mcp_servers'\n"
            ),
        );
        let reason =
            scene.resolve_refusal("packs = ['@box/import']\n[agent]\ncommand = ['/bin/x']");
        assert!(reason.contains(expected), "{suffix} {edit}: {reason}");
    }
}

#[test]
fn mcp_import_targets_require_a_storage_file_and_one_format_and_key() {
    let scene = Scene::new();
    let profile_text = "packs = [\"@box/import\"]\n[agent]\ncommand = [\"/bin/x\"]";
    let row = |target: &str, key: &str| {
        format!(
            "[[mcp-servers]]\nfile = \"${{{{ home }}}}/source.json\"\nkind = \"json\"\nkey = [\"servers\"]\ntarget = {target:?}\ntarget-key = {key:?}\n"
        )
    };
    for target in [
        "/tmp/config.json",
        "config/../escape.json",
        "undeclared/config.json",
        "config",
    ] {
        scene.share(
            "import",
            &format!(
                "[storage]\ndirectories = [\"config\"]\n{}",
                row(target, "servers")
            ),
        );
        assert!(scene.resolve(&profile(profile_text)).is_err(), "{target}");
    }
    scene.share(
        "import",
        &format!(
            "[storage]\ndirectories = [\"config\"]\n{}{}",
            row("config/agent.json", "one"),
            row("config/agent.json", "two")
        ),
    );
    scene
        .resolve(&profile(profile_text))
        .expect("two sections of one file, neither inside the other");
    scene.share(
        "import",
        &format!(
            "[storage]\ndirectories = [\"config\"]\n{}{}",
            row("config/agent.json", "one"),
            row("config/agent.json", "one")
                .replace("target-key = \"one\"", "target-key = [\"one\", \"inner\"]")
        ),
    );
    assert!(
        scene
            .resolve_refusal(profile_text)
            .contains("overlaps another MCP target")
    );
    scene.share(
        "import",
        &format!(
            "[storage]\ndirectories = [\"config\"]\n{}{}",
            row("config/agent.json", "one")
                .replace("target-key = \"one\"", "target-key = [\"one\", \"inner\"]"),
            row("config/agent.json", "one"),
        ),
    );
    assert!(
        scene
            .resolve_refusal(profile_text)
            .contains("overlaps another MCP target"),
        "the inner row first"
    );
    scene.share(
        "import",
        &format!(
            "[storage]\ndirectories = [\"config\"]\n{}{}",
            row("config/agent.json", "one"),
            row("config/agent.json", "one").replace("kind = \"json\"", "kind = \"toml\"")
        ),
    );
    assert!(
        scene
            .resolve_refusal(profile_text)
            .contains("overlaps another MCP target")
    );

    scene.share("import", &format!("[storage]\ndirectories = [\"config\"]\n[[storage.files]]\nsource = \"${{{{ home }}}}/instructions\"\ntarget = \"config/agent.json\"\n{}", row("config/agent.json", "servers")));
    assert!(
        scene
            .resolve_refusal(profile_text)
            .contains("overlaps a `storage.files` target")
    );
    let fill = |keep: &str| {
        format!(
            "[storage]\ndirectories = [\"config\"]\n[[storage.files]]\n\
             source = \"${{{{ home }}}}/agent.json\"\ntarget = \"config/agent.json\"\n\
             kind = \"json\"\nfill = true\nkeep = [{keep}]\n{}",
            row("config/agent.json", "servers")
        )
    };
    scene.share("import", &fill("[\"onboarded\"]"));
    scene
        .resolve(&profile(profile_text))
        .expect("a fill beside the MCP section");
    scene.share(
        "import",
        &fill("[\"onboarded\"]").replace("kind = \"json\"", "kind = \"toml\""),
    );
    scene
        .resolve(&profile(profile_text))
        .expect("a TOML fill beside the MCP section");
    scene.share(
        "import",
        &fill("[\"onboarded\"]").replacen("kind = \"json\"", "kind = \"toml\"", 1),
    );
    assert!(
        scene
            .resolve_refusal(profile_text)
            .contains("overlaps a `storage.files` target"),
        "the fill and MCP formats must match"
    );
    for keep in [
        "[\"onboarded\"], [\"servers\", \"mine\"]",
        "[\"onboarded\"], [\"servers\"]",
    ] {
        scene.share("import", &fill(keep));
        assert!(
            scene
                .resolve_refusal(profile_text)
                .contains("overlaps a `storage.files` target"),
            "{keep}"
        );
    }
    let nested = |keep: &str| {
        format!(
            "[storage]\ndirectories = [\"config\"]\n[[storage.files]]\n\
             source = \"${{{{ home }}}}/agent.json\"\ntarget = \"config/agent.json\"\n\
             kind = \"json\"\nfill = true\nkeep = [{keep}]\n{}",
            row("config/agent.json", "servers").replace(
                "target-key = \"servers\"",
                "target-key = [\"projects\", \"p\", \"servers\"]"
            )
        )
    };
    scene.share("import", &nested("[\"projects\", \"p\", \"trust\"]"));
    scene
        .resolve(&profile(profile_text))
        .expect("a fill beside a nested MCP section");
    scene.share("import", &nested("[\"projects\"]"));
    assert!(
        scene
            .resolve_refusal(profile_text)
            .contains("overlaps a `storage.files` target"),
        "a fill above the MCP section"
    );
    for (extra, why) in [
        ("target = \"config/agent.json\"", "needs both `target`"),
        ("target-key = \"servers\"", "needs both `target`"),
        (
            "target = \"config/agent.json\"\ntarget-key = \"\"",
            "target-key` is a nonempty literal key",
        ),
        (
            "target = \"config/agent.json\"\ntarget-key = []",
            "target-key` is a nonempty literal key",
        ),
        (
            "target = \"config/agent.json\"\ntarget-key = [\"a\", 1]",
            "target-key` is a nonempty literal key",
        ),
    ] {
        scene.share("import", &format!("[[mcp-servers]]\nfile = \"/source.json\"\nkind = \"json\"\nkey = [\"servers\"]\n{extra}"));
        let reason = scene.resolve_refusal(profile_text);
        assert!(reason.contains(why), "{extra}: {reason}");
    }
}

#[test]
fn an_mcp_servers_row_is_checked_where_it_is_written() {
    let scene = Scene::new();
    let packs = "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]";
    for (row, expected) in [
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nformat = \"json\"",
            "`mcp-servers[0]` holds the unknown key `format`; a row holds `file`, `kind`, `key`, \
             `env-var-locations`, `env-var-syntax`, `command-prefix`, `target`, `target-key`, \
             and `when`",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nenv-var-locations = { headers = \"header-references\" }",
            "`mcp-servers[0] env-var-locations.headers` is `header-references`, which needs the row's \
             `env-var-syntax`",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nenv-var-syntax = \"$VAR\"",
            "`mcp-servers[0] env-var-syntax = \"$VAR\"` holds `NAME` once",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nenv-var-syntax = \"NAME}\"",
            "`mcp-servers[0] env-var-syntax = \"NAME}\"` holds `NAME` once",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nenv-var-syntax = [\"${NAME}\", \"$VAR\"]",
            "`mcp-servers[0] env-var-syntax = \"$VAR\"` holds `NAME` once",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nenv-var-syntax = 1",
            "`mcp-servers[0] env-var-syntax` is not a string or a list of strings",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nenv-var-syntax = \"${NAME}NAME\"",
            "`mcp-servers[0] env-var-syntax = \"${NAME}NAME\"` holds `NAME` once",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nenv-var-syntax = \"${NAME}\"\ncommand-prefix = 1",
            "`mcp-servers[0] command-prefix` is not a string",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nenv-var-syntax = []",
            "`mcp-servers[0] env-var-syntax` is not a string or a list of strings",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nenv-var-syntax = [\"${NAME}\", 1]",
            "`mcp-servers[0] env-var-syntax` is not a string or a list of strings",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\ncommand-prefix = \"!\"",
            "`mcp-servers[0] command-prefix` needs the row's `env-var-syntax`",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nenv-var-syntax = \"${NAME}\"\ncommand-prefix = \"\"",
            "`mcp-servers[0] command-prefix` is empty",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nenv-var-locations = { token = \"token\" }",
            "`mcp-servers[0] env-var-locations.token` names no role; known: bearer-variable, \
             header-variables, header-references, references, variable-names",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nenv-var-locations = { url = \"bearer-variable\" }",
            "`mcp-servers[0] env-var-locations.url` names a field box already reads",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nenv-var-locations = { env = \"variable-names\" }",
            "`mcp-servers[0] env-var-locations.env` names a field box already reads",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nenv-var-syntax = \"${NAME}\"\nenv-var-locations = { url = \"references\" }",
            "`mcp-servers[0] env-var-locations.url` is `references`, which goes on `command`, \
             `args`, or `env`",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nenv-var-locations = { env = \"references\" }",
            "`mcp-servers[0] env-var-locations.env` is `references`, which needs the row's \
             `env-var-syntax`",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = [\"s\"]\nenv-var-locations = \"env\"",
            "`mcp-servers[0] env-var-locations` is a table from a server field to what it holds",
        ),
        (
            "kind = \"json\"\nkey = [\"s\"]",
            "`mcp-servers[0]` needs `file`",
        ),
        (
            "file = \"/a.json\"\nkey = [\"s\"]",
            "`mcp-servers[0]` needs `kind`, \"json\" or \"toml\"",
        ),
        (
            "file = \"/a.json\"\nkind = \"yaml\"\nkey = [\"s\"]",
            "`mcp-servers[0] kind = \"yaml\"` is not \"json\" or \"toml\"",
        ),
        (
            "file = \"/a.json\"\nkind = 1\nkey = [\"s\"]",
            "`mcp-servers[0] kind` is not a string",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nat = [\"s\"]",
            "`mcp-servers[0]` holds the unknown key `at`",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = \"s\"",
            "`mcp-servers[0] key` is a list of one or more keys",
        ),
        (
            "file = \"/a.json\"\nkind = \"json\"\nkey = []",
            "`mcp-servers[0] key` is a list of one or more keys",
        ),
    ] {
        scene.share("agent", &format!("[[mcp-servers]]\n{row}"));
        match scene.resolve(&profile(packs)) {
            Err(Error::Profile { path, reason, .. }) => {
                assert!(
                    path.ends_with("packs/agent/pack.toml"),
                    "{}",
                    path.display()
                );
                assert!(reason.contains(expected), "{row}: {reason}");
            }
            other => panic!("{row}: a refusal, not {other:?}"),
        }
    }
    scene.share(
        "agent",
        "[[mcp-servers]]\nfile = \"relative.json\"\nkind = \"json\"\nkey = [\"s\"]",
    );
    let reason = match scene.resolve(&profile(packs)) {
        Err(Error::Profile { reason, .. }) => reason,
        other => panic!("a refusal, not {other:?}"),
    };
    assert!(reason.contains("is not an absolute path"), "{reason}");
    let reason = scene.resolve_refusal(
        "[agent]\ncommand = [\"/bin/x\"]\n[[mcp-servers]]\nfile = \"/a.json\"\n\
         kind = \"json\"\nkey = [\"s\"]",
    );
    assert!(
        reason.contains("a profile holds no `mcp-servers`; `mcp-servers` belongs in a pack"),
        "{reason}"
    );
}

#[test]
fn an_mcp_servers_rows_kind_and_not_its_extension_selects_the_format() {
    let scene = Scene::new();
    scene.share(
        "agent",
        "[[mcp-servers]]\nfile = \"${{ home }}/servers.cfg\"\nkind = \"toml\"\n\
         key = [\"mcp_servers\"]\n\
         [[mcp-servers]]\nfile = \"${{ home }}/other.toml\"\nkind = \"json\"\nkey = [\"s\"]",
    );
    std::fs::write(
        scene.home().join("servers.cfg"),
        "[mcp_servers.notes]\ncommand = \"notes\"\n",
    )
    .expect("a host file");
    std::fs::write(
        scene.home().join("other.toml"),
        r#"{"s": {"docs": {"url": "https://docs.example.com"}}}"#,
    )
    .expect("a host file");
    let resolved = scene
        .resolve(&profile(
            "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]",
        ))
        .expect("a resolve");
    let mut found: Vec<String> = resolved
        .servers
        .detected
        .iter()
        .map(|server| server.name.clone())
        .chain(
            resolved
                .servers
                .skipped
                .iter()
                .map(|server| server.name.clone()),
        )
        .collect();
    found.sort();
    assert_eq!(found, ["docs", "notes"]);
}

#[test]
fn an_mcp_source_where_a_box_can_write_is_not_read_and_the_run_goes_on() {
    let scene = Scene::new();
    scene.share(
        "agent",
        "[[mcp-servers]]\nfile = \"${{ workspace }}/.mcp.json\"\nkind = \"json\"\n\
         key = [\"mcpServers\"]\n\
         [[mcp-servers]]\nfile = \"${{ home }}/broken.json\"\nkind = \"json\"\n\
         key = [\"mcpServers\"]",
    );
    std::fs::write(
        scene.workspace().join(".mcp.json"),
        r#"{"mcpServers": {"planted": {"url": "https://evil.example.com"}}}"#,
    )
    .expect("a project file");
    std::fs::write(scene.home().join("broken.json"), "{").expect("a host file");
    let (resolved, compiled) = scene
        .compile_using(
            &profile("packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]"),
            &mut Fixed,
            "/usr/bin:/bin",
        )
        .expect("a run goes on");
    assert!(!compiled.box_toml.contains("evil"), "{}", compiled.box_toml);
    let unread = resolved.servers.unread_lines(&scene.home());
    assert_eq!(unread.len(), 2, "{unread:?}");
    assert_eq!(
        unread[0],
        (
            "~/work/project/.mcp.json".to_string(),
            "~/work/project/.mcp.json lies in the workspace, ~/work/project; box reads no MCP \
             configuration from there"
                .to_string()
        )
    );
    assert!(unread[1].1.starts_with("it is not JSON"), "{unread:?}");
}

#[test]
fn every_server_table_gets_its_permits() {
    let scene = Scene::new();
    let bin = scene.root.join("bin");
    script(&bin.join("fetcher"), "exit 0");
    let text = "[agent]\ncommand = [\"/bin/x\"]\n\
                [mcp.fetch]\ntype = \"stdio\"\ncommand = [\"fetcher\", \"--mine\"]\n\
                [mcp.elsewhere]\ntype = \"stdio\"\ncommand = [\"not-installed\"]\n\
                [mcp.remote]\ntype = \"http\"\ndestinations = [\"api.example.com:8443\"]";
    let compiled = scene
        .compile_in(
            &scene.workspace(),
            &profile(text),
            None,
            &bin.display().to_string(),
        )
        .expect("a compile");
    let program = bin.join("fetcher").display().to_string();
    for rule in [
        "@id(\"mcp_fetch_call\") permit (principal, action == Box::Action::\"mcp:call\", resource) when { context.input.server == \"fetch\" };".to_string(),
        "@id(\"mcp_elsewhere_call\") permit (principal, action == Box::Action::\"mcp:call\", resource) when { context.input.server == \"elsewhere\" };".to_string(),
        format!("@id(\"mcp_fetch_spawn\") permit (principal, action == Box::Action::\"shell:spawn\", resource) when {{ context.input.program_path == {program:?} && context.input.program == \"fetcher\" }};"),
        "@id(\"mcp_remote_call\") permit (principal, action == Box::Action::\"mcp:call\", resource) when { context.input.server == \"remote\" };".to_string(),
        "@id(\"mcp_remote_connect\") permit (principal, action == Box::Action::\"net:connect\", resource) when { (context.input.host == \"api.example.com\" && context.input.port == 8443) };".to_string(),
        "@id(\"mcp_remote_request\") permit (principal, action == Box::Action::\"http:request\", resource) when { context.input.host == \"api.example.com\" };".to_string(),
    ] {
        assert!(compiled.policy.contains(&rule), "{rule}\nin\n{}", compiled.policy);
    }
    assert!(
        !compiled.policy.contains("mcp_elsewhere_spawn"),
        "a program box cannot find gets no permit the agent could use: {}",
        compiled.policy
    );
    assert_eq!(
        compiled.unstarted,
        [(
            "elsewhere".to_string(),
            "box finds no not-installed on your PATH".to_string()
        )]
    );
    let reason = scene.refusal(
        "[agent]\ncommand = [\"/bin/x\"]\n[mcp.remote]\ntype = \"http\"\n\
         destinations = [\"https://api.example.com\"]",
    );
    assert!(reason.contains("is a URL"), "{reason}");
}

#[test]
fn absolute_mcp_profile_commands_keep_the_selected_path_and_policy_name() {
    let scene = Scene::new();
    let executable = scene.root.join("selected tools/actual-server");
    let invoked = scene.root.join("selected tools/srv");
    script(&executable, "exit 0");
    std::os::unix::fs::symlink(&executable, &invoked).expect("an invocation name");
    let decoy = scene.root.join("decoy");
    script(&decoy.join("srv"), "exit 1");
    for search_path in ["", decoy.to_str().unwrap()] {
        let compiled = scene
            .compile_in(
                &scene.workspace(),
                &profile(&format!(
                    "[agent]\ncommand = [\"/usr/bin/true\"]\n\
                     [mcp.local]\ntype = \"stdio\"\ncommand = [{invoked:?}, \"--stdio\"]\n\
                     env.PATH = {search_path:?}",
                )),
                None,
                search_path,
            )
            .expect("an absolute MCP command");
        assert_eq!(
            strings(&table(&compiled)["mcp"]["local"]["command"]),
            [invoked.display().to_string(), "--stdio".to_string()]
        );
        assert!(
            compiled.policy.contains(&format!(
                "context.input.program_path == {executable:?} && context.input.program == \"srv\""
            )),
            "{}",
            compiled.policy
        );
        assert!(compiled.unstarted.is_empty(), "{:?}", compiled.unstarted);
    }
}

#[test]
fn an_absolute_mcp_command_drops_an_entirely_relative_inherited_path() {
    let scene = Scene::new();
    let executable = scene.root.join("installation/srv");
    script(&executable, "exit 0");
    for search_path in [".", "~/.local/bin:.:"] {
        let compiled = scene
            .compile_in(
                &scene.workspace(),
                &profile(&format!(
                    "[agent]\ncommand = [\"/usr/bin/true\"]\n\
                     [mcp.local]\ntype = \"stdio\"\ncommand = [{executable:?}]"
                )),
                None,
                search_path,
            )
            .expect("an absolute MCP command");
        assert_eq!(
            table(&compiled)["mcp"]["local"]["env"]["PATH"].as_str(),
            Some("/usr/bin:/bin"),
            "{search_path:?}"
        );
        assert_eq!(
            compiled.path_dropped,
            std::env::split_paths(search_path)
                .map(|entry| path_dropped(entry.to_str().unwrap()))
                .collect::<Vec<_>>()
        );
        assert!(compiled.unstarted.is_empty(), "{:?}", compiled.unstarted);
    }
}

#[test]
fn absolute_mcp_profile_commands_never_fall_back_to_path() {
    let scene = Scene::new();
    let missing = scene.root.join("not installed/srv");
    let decoy = scene.root.join("decoy");
    script(&decoy.join("srv"), "exit 0");
    let compiled = scene
        .compile_in(
            &scene.workspace(),
            &profile(&format!(
                "[agent]\ncommand = [\"/usr/bin/true\"]\n\
                 [mcp.local]\ntype = \"stdio\"\ncommand = [{missing:?}]",
            )),
            None,
            decoy.to_str().unwrap(),
        )
        .expect("an unavailable server does not stop compilation");
    assert!(
        !compiled.policy.contains("mcp_local_spawn"),
        "{}",
        compiled.policy
    );
    assert_eq!(compiled.unstarted.len(), 1);
    assert!(
        compiled.unstarted[0].1.contains(missing.to_str().unwrap()),
        "{:?}",
        compiled.unstarted
    );
}

#[test]
fn absolute_mcp_profile_commands_refuse_writable_intermediate_links() {
    let scene = Scene::new();
    let installation = scene.root.join("installation");
    let executable = installation.join("srv");
    script(&executable, "exit 0");
    std::fs::create_dir_all(installation.join("inner")).expect("a selected installation");
    let extra = scene.root.join("extra");
    for (writable, grant) in [
        (scene.workspace(), String::new()),
        (
            scene.storage().join("agent/files"),
            "[storage]\ndirectories = ['files']".to_string(),
        ),
        (extra.clone(), format!("filesystem.write = [{extra:?}]")),
    ] {
        std::fs::create_dir_all(&writable).expect("a writable folder");
        let link = writable.join("switch");
        std::os::unix::fs::symlink(installation.join("inner"), &link).expect("a writable link");
        let invoked = link.join("../srv");
        assert_eq!(invoked.canonicalize().unwrap(), executable);
        let error = scene
            .compile(
                &profile(&format!(
                    "[agent]\ncommand = ['/usr/bin/true']\n{grant}\n\
                     [mcp.local]\ntype = 'stdio'\ncommand = [{invoked:?}]"
                )),
                None,
            )
            .expect_err("a writable link cannot select an executable");
        assert!(
            error
                .to_string()
                .contains("is a link out of a folder the box can write"),
            "{error}"
        );
    }
    let trusted = scene.root.join("trusted");
    std::os::unix::fs::symlink(installation.join("inner"), &trusted).expect("a trusted link");
    scene
        .compile(
            &profile(&format!(
                "[agent]\ncommand = ['/usr/bin/true']\n\
                 [mcp.local]\ntype = 'stdio'\ncommand = [{:?}]",
                trusted.join("../srv")
            )),
            None,
        )
        .expect("a trusted intermediate link remains usable");
}

#[test]
fn a_server_program_that_is_a_relative_path_is_refused_by_name() {
    let scene = Scene::new();
    for program in ["~/bin/srv", "node_modules/.bin/x"] {
        let error = scene
            .compile(
                &profile(&format!(
                    "[agent]\ncommand = [\"/usr/bin/true\"]\n\
                     [mcp.local]\ntype = \"stdio\"\ncommand = [{program:?}]"
                )),
                None,
            )
            .expect_err("a relative path is no program name");
        match error {
            Error::Profile { path, reason, .. } => {
                assert_eq!(path, PathBuf::from("[mcp.local] command"), "{program}");
                assert!(
                    reason.starts_with(&format!("{program:?} is not an absolute path")),
                    "{program}: {reason}"
                );
            }
            other => panic!("{program}: a profile refusal, not {other:?}"),
        }
    }
}

#[test]
fn a_destination_port_outside_one_to_65535_is_refused() {
    let scene = Scene::new();
    for (table, owner) in [
        (
            "[egress.api]\nsecret.ref = \"env://KEY\"",
            "[egress.api] destinations",
        ),
        ("[mcp.api]\ntype = \"http\"", "[mcp.api] destinations"),
    ] {
        for port in ["", "0", "65536", "99999"] {
            let error = scene
                .compile(
                    &profile(&format!(
                        "[agent]\ncommand = [\"/usr/bin/true\"]\n{table}\n\
                         destinations = [\"api.example.com:{port}\"]"
                    )),
                    None,
                )
                .expect_err("a port out of range");
            match error {
                Error::Profile { path, reason, .. } => {
                    assert_eq!(path, PathBuf::from(owner));
                    assert!(
                        reason.contains(&format!("names the port {port:?}; a port is 1 to 65535")),
                        "{table} {port}: {reason}"
                    );
                }
                other => panic!("{table} {port}: a profile refusal, not {other:?}"),
            }
        }
    }
}

/// The real file at `path`, as this host links it.
fn real(path: &str) -> String {
    Path::new(path)
        .canonicalize()
        .expect("a real file")
        .display()
        .to_string()
}

/// `root.parent` of the real file that `Detecting` finds for every program.
fn detected_root() -> String {
    let root = crate::tool::root(Path::new(&real("/usr/bin/true")));
    root.parent().expect("a parent").display().to_string()
}

/// Write the operator's pack `name`, with a `[pack]` header after `text`.
fn operator_pack(scene: &Scene, name: &str, text: &str) {
    let folder = scene.home().join(".strands/box/packs").join(name);
    std::fs::create_dir_all(&folder).expect("a pack folder");
    std::fs::write(
        folder.join("pack.toml"),
        format!(
            "[pack]\nname = \"{name}\"\nversion = 1\n{}{text}",
            crate::lang::test_kind_line(text)
        ),
    )
    .expect("a pack");
}

const AGENT: &str = "[agent]\ncommand = [\"/bin/x\"]";

fn detected(scene: &Scene, text: &str) -> Result<Resolved, Error> {
    scene.resolve_using(&profile(text), &scene.context(), &mut Detecting)
}

#[test]
fn a_tool_pack_resolves_as_the_tool_its_name_ends_with() {
    let scene = Scene::new();
    let root = detected_root();
    scene.share(
        "rt",
        "kind = \"tool\"\n[inputs.rt.path]\ntype = \"program\"\nprogram = \"rt\"\n\
         search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.rt.path }}\"]\n\
         hosts = [\"example.com\"]\n[env]\nRT = \"1\"\n[filesystem]\n\
         read = [\"${{ root.parent }}/bin\"]\nexec = [\"${{ root.parent }}/bin\"]\n\
         deny = [\"${{ root.parent }}/bin/false\"]",
    );
    scene.share(
        "off",
        "kind = \"tool\"\n[inputs.off.path]\ntype = \"program\"\nprogram = \"off\"\n\
                        search = [{ env = \"PATH\" }]\n[run]\n\
                        command = [\"${{ inputs.off.path }}\"]\nwhen = \"linux\"",
    );
    operator_pack(
        &scene,
        "own",
        "kind = \"tool\"\n[inputs.own.path]\ntype = \"program\"\nprogram = \"own\"\n\
         search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.own.path }}\"]\n[env]\n\
         OWN = \"1\"",
    );
    let resolved = detected(
        &scene,
        &format!("packs = [\"@box/rt\", \"@box/off\", \"own\"]\n{AGENT}"),
    )
    .expect("a resolve");
    let names: Vec<&str> = resolved.tool.keys().map(String::as_str).collect();
    assert_eq!(names, ["own", "rt"], "a `when` covers the whole tool table");
    let rt = &resolved.tool["rt"];
    assert_eq!(rt.env["RT"], "1");
    assert!(
        rt.filesystem.read.contains(&format!("{root}/bin")),
        "{rt:?}"
    );
    assert_eq!(rt.filesystem.exec, [format!("{root}/bin")]);
    assert_eq!(rt.filesystem.deny, [real(&format!("{root}/bin/false"))]);
    assert_eq!(resolved.tool["own"].env["OWN"], "1");
    let packs: Vec<(&str, &str)> = resolved
        .tools
        .found
        .iter()
        .map(|found| (found.name.as_str(), found.pack.as_str()))
        .collect();
    assert_eq!(packs, [("own", "own"), ("rt", "@box/rt")]);
    let rt = resolved
        .tools
        .found
        .iter()
        .find(|found| found.name == "rt")
        .expect("rt");
    assert_eq!(rt.hosts, ["example.com"]);
}

#[test]
fn root_outside_a_tool_pack_is_refused() {
    let scene = Scene::new();
    operator_pack(
        &scene,
        "old",
        "[tool.old]\nprogram = \"old\"\n[tool.old.filesystem]\nread = [\"${{ root }}/bin\"]",
    );
    for text in [
        format!("packs = [\"old\"]\n{AGENT}"),
        format!(
            "{AGENT}\n[tool.git]\nprogram = \"git\"\nfilesystem.read = [\"${{{{ root }}}}/bin\"]"
        ),
        format!(
            "{AGENT}\n[tool.git]\nprogram = \"git\"\nfilesystem.read = [{{ path = \"${{{{ root }}}}/bin\", when = \"macos\" }}, {{ path = \"${{{{ root }}}}/bin\", when = \"linux\" }}]"
        ),
    ] {
        match detected(&scene, &text) {
            Err(Error::Profile { reason, .. }) => assert!(
                reason.contains("valid only in a tool pack or an `[agent]` table; for a tool elsewhere, use `tool.<name>.root`"),
                "{text}: {reason}"
            ),
            other => panic!("{text}: a refusal, not {other:?}"),
        }
    }
}

#[test]
fn box_writes_a_base_path_and_tmpdir_and_a_pack_value_wins() {
    let scene = Scene::new();
    let root = scene.root.join("installed");
    let bin = root.join("bin");
    for name in ["plain", "own", "full"] {
        crate::test_support::binary(&bin.join(name));
    }
    let root = root.display().to_string();
    scene.share(
        "plain",
        "kind = \"tool\"\n[inputs.plain.path]\ntype = \"program\"\n\
                          program = \"plain\"\nsearch = [{ env = \"PATH\" }]\n[run]\n\
                          command = [\"${{ inputs.plain.path }}\"]",
    );
    scene.share(
        "own",
        "kind = \"tool\"\n[inputs.own.path]\ntype = \"program\"\nprogram = \"own\"\n\
         search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.own.path }}\"]\n[env]\n\
         PATH = \"${{ root.parent }}/sbin:/bin\"\nTMPDIR = \"${{ workspace }}/own\"",
    );
    let resolved = scene
        .resolve_using(
            &profile(&format!(
                "packs = [\"@box/plain\", \"@box/own\"]\n{AGENT}\n[tool.full]\nprogram = \"full\"\n\
                 [tool.listed]\ncommand = [\"/usr/bin/true\"]"
            )),
            &scene.context(),
            &mut OnPath(bin),
        )
        .expect("a resolve");
    let workspace = scene.workspace().display().to_string();
    for name in ["plain", "full"] {
        let tool = &resolved.tool[name];
        let tmpdir = &tool.env["TMPDIR"];
        assert_eq!(tool.env["PATH"], "/usr/bin:/bin", "{name}");
        assert!(
            tmpdir.ends_with(&format!("/tool-tmp/{name}")),
            "{name}: {tmpdir}"
        );
        assert!(tool.filesystem.write.contains(tmpdir), "{name}");
        assert!(tool.filesystem.read.contains(tmpdir), "{name}");
    }
    assert!(
        resolved.tool["own"]
            .filesystem
            .write
            .iter()
            .all(|entry| !entry.contains("/tool-tmp/")),
        "a tool that sets its own TMPDIR gets no scratch grant"
    );
    let env = &resolved.tool["own"].env;
    assert_eq!(env["PATH"], format!("{root}/sbin:/bin"));
    assert_eq!(env["TMPDIR"], format!("{workspace}/own"));
    assert!(
        resolved.tool["listed"].env.is_empty(),
        "a table that names no program gets no default: {:?}",
        resolved.tool["listed"]
    );
}

#[test]
fn an_old_full_form_operator_pack_still_resolves() {
    let scene = Scene::new();
    let root = detected_root();
    operator_pack(
        &scene,
        "old",
        "[tool.old]\nprogram = \"old\"\n[tool.old.env]\nOLD = \"1\"\n[tool.old.filesystem]\n\
         read = [\"${{ tool.old.root.parent }}/bin\"]",
    );
    let resolved = detected(&scene, &format!("packs = [\"old\"]\n{AGENT}")).expect("a resolve");
    let old = &resolved.tool["old"];
    assert_eq!(old.command, [real("/usr/bin/true")]);
    assert_eq!(old.env["OLD"], "1");
    assert_eq!(old.env["PATH"], "/usr/bin:/bin");
    assert!(
        old.filesystem.read.contains(&format!("{root}/bin")),
        "{old:?}"
    );
    assert_eq!(resolved.tools.found[0].pack, "old");
}

#[test]
fn a_full_form_profile_addition_merges_onto_a_tool_pack() {
    let scene = Scene::new();
    let root = detected_root();
    scene.share(
        "rt",
        "kind = \"tool\"\n[inputs.rt.path]\ntype = \"program\"\nprogram = \"rt\"\n\
         search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.rt.path }}\"]\n[env]\n\
         RT = \"1\"\n[filesystem]\nread = [\"${{ root.parent }}/bin\"]",
    );
    let resolved = detected(
        &scene,
        &format!(
            "packs = [\"@box/rt\"]\n{AGENT}\n[tool.rt.env]\nMINE = \"2\"\n[tool.rt.filesystem]\n\
             read = [\"${{{{ tool.rt.root.parent }}}}/lib\"]"
        ),
    )
    .expect("a resolve");
    let rt = &resolved.tool["rt"];
    assert_eq!(rt.env["RT"], "1");
    assert_eq!(rt.env["MINE"], "2");
    for folder in ["bin", "lib"] {
        assert!(
            rt.filesystem.read.contains(&format!("{root}/{folder}")),
            "{folder}: {rt:?}"
        );
    }
}

#[test]
fn a_tool_table_holds_no_key_that_a_tool_pack_keeps_at_its_top() {
    for key in ["pack", "extend", "include", "inputs"] {
        let reason = Scene::new().refusal(&format!(
            "{AGENT}\n[tool.git]\nprogram = \"git\"\n{key} = []"
        ));
        assert!(
            reason.contains(&format!(
                "`[tool.git] {key}` is a key of a pack, not of a tool"
            )),
            "{key}: {reason}"
        );
    }
}

#[test]
fn a_full_form_tool_table_keeps_an_absent_path_as_written() {
    let scene = Scene::new();
    let resolved = detected(
        &scene,
        &format!(
            "{AGENT}\n[tool.jq]\ncommand = [\"/usr/bin/true\"]\n[tool.jq.filesystem]\n\
             read = [\"/absent/box-117/x\", \"/absent/box-117/y*\"]"
        ),
    )
    .expect("a resolve");
    assert_eq!(
        resolved.tool["jq"].filesystem,
        crate::profile::Filesystem {
            read: vec![
                "/absent/box-117/x".to_string(),
                "/absent/box-117/y*".to_string()
            ],
            ..crate::profile::Filesystem::default()
        }
    );
    assert!(
        resolved.tools.dropped.is_empty(),
        "{:?}",
        resolved.tools.dropped
    );
}

#[test]
fn an_absent_storage_entry_of_a_program_tool_is_kept_before_the_run_creates_it() {
    let scene = Scene::new();
    scene.share(
        "rt",
        "kind = \"tool\"\n[inputs.rt.path]\ntype = \"program\"\nprogram = \"rt\"\n\
         search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.rt.path }}\"]\n[storage]\n\
         directories = [\"prefix\"]\n[filesystem]\nread = [\"${{ storage.prefix }}\"]\n\
         write = [\"${{ storage.prefix }}\"]",
    );
    let resolved = detected(&scene, &format!("packs = [\"@box/rt\"]\n{AGENT}")).expect("a resolve");
    let state = resolved.storage.root.join("tool/rt/prefix");
    assert!(!state.exists());
    let filesystem = &resolved.tool["rt"].filesystem;
    let text = state.display().to_string();
    assert!(filesystem.read.contains(&text), "{:?}", filesystem.read);
    assert!(filesystem.write.contains(&text), "{:?}", filesystem.write);
    assert!(
        !resolved
            .tools
            .dropped
            .iter()
            .any(|(_, path)| Path::new(path) == state),
        "{:?}",
        resolved.tools.dropped
    );
    assert_eq!(resolved.storage.tool_states, vec![state]);
}

#[test]
fn an_absent_deny_of_a_tool_pack_reaches_the_table_as_written() {
    let scene = Scene::new();
    let root = detected_root();
    scene.share(
        "rt",
        "kind = \"tool\"\n[inputs.rt.path]\ntype = \"program\"\nprogram = \"rt\"\n\
         search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.rt.path }}\"]\n\
         [filesystem]\nread = [\"${{ root.parent }}/bin\"]\n\
         deny = [\"${{ workspace }}/.env\", \"${{ root.parent }}/absent-secret\"]",
    );
    let resolved = detected(&scene, &format!("packs = [\"@box/rt\"]\n{AGENT}")).expect("a resolve");
    let deny = &resolved.tool["rt"].filesystem.deny;
    let workspace = scene.context().workspace.display().to_string();
    for expected in [format!("{workspace}/.env"), format!("{root}/absent-secret")] {
        assert!(deny.contains(&expected), "{expected} in {deny:?}");
    }
    assert!(
        !resolved
            .tools
            .dropped
            .iter()
            .any(|(_, path)| path.ends_with("absent-secret") || path.ends_with(".env")),
        "{:?}",
        resolved.tools.dropped
    );
}

#[test]
fn a_star_in_a_deny_of_a_tool_pack_is_refused() {
    let scene = Scene::new();
    scene.share(
        "rt",
        "kind = \"tool\"\n[inputs.rt.path]\ntype = \"program\"\nprogram = \"rt\"\n\
         search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.rt.path }}\"]\n\
         [filesystem]\ndeny = [\"${{ root.parent }}/secret-*\"]",
    );
    match detected(&scene, &format!("packs = [\"@box/rt\"]\n{AGENT}")) {
        Err(Error::Profile { reason, .. }) => {
            assert!(reason.contains("a `deny` entry names one path"), "{reason}")
        }
        other => panic!("a refusal, not {other:?}"),
    }
}

const AGENT_PACK: &str =
    "[run]\ncommand = [\"/bin/agent\", \"--skip\", { slot = \"agent-args\" }, \"--last\"]";

#[test]
fn a_profile_fills_the_slot_of_the_pack_command() {
    let scene = Scene::new();
    scene.share("agent", AGENT_PACK);
    let compiled = scene
        .compile(
            &profile(
                "packs = [\"@box/agent\"]\n\
                 agent-args = [\"--model\", \"m-1\", \"--verbose\"]",
            ),
            None,
        )
        .expect("a profile with agent-args");
    let file = table(&compiled);
    assert_eq!(
        strings(&file["agent"]["command"]),
        [
            "/bin/agent",
            "--skip",
            "--model",
            "m-1",
            "--verbose",
            "--last"
        ]
    );
    assert!(file.get("agent-args").is_none(), "{}", compiled.box_toml);
    let compiled = scene
        .compile(&profile("packs = [\"@box/agent\"]"), None)
        .expect("a profile with no agent-args");
    assert_eq!(
        strings(&table(&compiled)["agent"]["command"]),
        ["/bin/agent", "--skip", "--last"],
        "an empty slot leaves the command"
    );
}

#[test]
fn agent_args_replaces_the_slot_default() {
    let scene = Scene::new();
    scene.share(
        "agent",
        "[run]\ncommand = [\"/bin/agent\", { slot = \"agent-args\", default = [\"--quiet\"] }]",
    );
    for (text, expected) in [
        ("", vec!["/bin/agent", "--quiet"]),
        (
            "agent-args = [\"--verbose\"]",
            vec!["/bin/agent", "--verbose"],
        ),
        ("agent-args = []", vec!["/bin/agent"]),
    ] {
        let compiled = scene
            .compile(&profile(&format!("packs = [\"@box/agent\"]\n{text}")), None)
            .expect("a slot with a default");
        assert_eq!(
            strings(&table(&compiled)["agent"]["command"]),
            expected,
            "{text}"
        );
    }
}

#[test]
fn a_profile_that_sets_its_own_command_places_its_own_slot() {
    let scene = Scene::new();
    scene.share("agent", AGENT_PACK);
    let compiled = scene
        .compile(
            &profile(
                "packs = [\"@box/agent\"]\n\
                 agent-args = [\"--verbose\"]\n\
                 [agent]\ncommand = [\"/bin/agent\", { slot = \"agent-args\" }, \"--x\"]",
            ),
            None,
        )
        .expect("a profile with a command and agent-args");
    assert_eq!(
        strings(&table(&compiled)["agent"]["command"]),
        ["/bin/agent", "--verbose", "--x"]
    );
}

#[test]
fn the_slot_of_an_agent_with_when_is_filled() {
    let scene = Scene::new();
    scene.share(
        "agent",
        "[run]\nwhen = { variable = \"inputs.agent.on\", equals = \"true\" }\n\
         command = [\"/bin/agent\", { slot = \"agent-args\" }]\n[inputs.agent.on]\n\
         type = \"bool\"\ndefault = true",
    );
    let compiled = scene
        .compile(
            &profile("packs = [\"@box/agent\"]\nagent-args = [\"--verbose\"]"),
            None,
        )
        .expect("an agent with when");
    assert_eq!(
        strings(&table(&compiled)["agent"]["command"]),
        ["/bin/agent", "--verbose"]
    );
}

#[test]
fn a_slot_is_one_agent_args_element_after_the_program() {
    let scene = Scene::new();
    for (command, expected) in [
        (
            "\"/bin/agent\"",
            "has no `{ slot = \"agent-args\" }` to put it in",
        ),
        (
            "{ slot = \"agent-args\" }, \"/bin/agent\"",
            "starts with a slot",
        ),
        (
            "\"/bin/agent\", { slot = \"agent-args\" }, { slot = \"agent-args\" }",
            "holds more than one slot",
        ),
        (
            "\"/bin/agent\", { slot = \"args\" }",
            "is `slot = \"agent-args\"`",
        ),
        (
            "\"/bin/agent\", { slot = \"agent-args\", when = \"x\" }",
            "a slot holds `slot` and `default`, not `when`",
        ),
        (
            "\"/bin/agent\", { value = { slot = \"agent-args\" }, when = { variable = \"workspace\", equals = \"x\" } }",
            "a slot in `[agent] command` takes no `when`",
        ),
        (
            "\"/bin/agent\", { slot = \"agent-args\", default = \"--x\" }",
            "`default` is a list",
        ),
    ] {
        scene.share("agent", &format!("[run]\ncommand = [{command}]"));
        let error = scene
            .resolve(&profile(
                "packs = [\"@box/agent\"]\nagent-args = [\"--verbose\"]",
            ))
            .expect_err("a refusal");
        let Error::Profile { path, reason, .. } = error else {
            panic!("a profile error, not {error:?}");
        };
        assert!(reason.contains(expected), "{command}: {reason}");
        let named = if expected.contains("has no") {
            "test.toml"
        } else {
            "packs/agent/pack.toml"
        };
        assert!(path.ends_with(named), "{command}: {}", path.display());
    }
}

#[test]
fn a_slot_goes_only_in_the_agent_command() {
    let scene = Scene::new();
    scene.share("agent", AGENT_PACK);
    for (table, section) in [
        (
            "[tool.t]\ncommand = [\"/bin/t\", { slot = \"agent-args\" }]",
            "tool.t",
        ),
        (
            "[mcp.m]\ncommand = [\"/bin/m\", { slot = \"agent-args\" }]",
            "mcp.m",
        ),
    ] {
        let reason = scene.resolve_refusal(&format!("packs = [\"@box/agent\"]\n{table}"));
        assert!(
            reason.contains(&format!(
                "`[{section}] command` holds a slot; only `[agent] command` takes"
            )),
            "{table}: {reason}"
        );
    }
}

#[test]
fn a_pack_holds_no_agent_args() {
    let scene = Scene::new();
    scene.share_top(
        "agent",
        "agent-args = [\"--verbose\"]",
        "[run]\ncommand = [\"/bin/agent\", { slot = \"agent-args\" }]",
    );
    let error = scene
        .resolve(&profile("packs = [\"@box/agent\"]"))
        .expect_err("a pack with agent-args");
    let Error::Profile { path, reason, .. } = error else {
        panic!("a profile error, not {error:?}");
    };
    assert!(
        reason.contains("a pack holds no `agent-args`; `agent-args` belongs in a profile"),
        "{reason}"
    );
    assert!(
        path.ends_with("packs/agent/pack.toml"),
        "{}",
        path.display()
    );
}

#[test]
fn an_agent_args_element_resolves_as_a_command_element_does() {
    let scene = Scene::new();
    scene.share(
        "agent",
        &format!(
            "{AGENT_PACK}\n\
             [inputs.agent.model]\ndefault = \"m-1\"\npattern = \"[a-z0-9-]+\"\n\
             [inputs.agent.free]\ndefault = \"x\""
        ),
    );
    let text = |args: &str| format!("packs = [\"@box/agent\"]\nagent-args = [{args}]");
    let compiled = scene
        .compile(
            &profile(&text("\"--model\", \"${{ inputs.agent.model }}\"")),
            None,
        )
        .expect("agent-args with a bounded input");
    assert_eq!(
        strings(&table(&compiled)["agent"]["command"]),
        ["/bin/agent", "--skip", "--model", "m-1", "--last"]
    );
    let reason = scene.refusal(&text("\"${{ inputs.agent.free }}\""));
    assert!(
        reason.contains(
            "`agent-args.0`: `inputs.agent.free` reaches `agent-args`, so `[inputs.agent.free]` needs"
        ),
        "{reason}"
    );
}

#[test]
fn agent_args_holds_no_when() {
    let scene = Scene::new();
    scene.share("agent", AGENT_PACK);
    let reason = scene.resolve_refusal(
        "packs = [\"@box/agent\"]\n\
         agent-args = [\"--a\", { value = \"--verbose\", when = { variable = \"workspace\", equals = \"x\" } }]",
    );
    assert!(
        reason.contains("`agent-args` element 1 is not a string")
            && reason.contains("no `{ value, when }`"),
        "{reason}"
    );
}

#[test]
fn agent_args_is_a_list() {
    let scene = Scene::new();
    scene.share("agent", AGENT_PACK);
    for text in [
        "agent-args = \"--verbose\"",
        "agent-args = \"${{ workspace }}\"",
        "agent-args = { a = \"b\" }",
    ] {
        let reason = scene.resolve_refusal(&format!("packs = [\"@box/agent\"]\n{text}"));
        assert!(
            reason.contains("`agent-args` is a list"),
            "{text}: {reason}"
        );
        let loaded = profile(&format!("packs = [\"@box/agent\"]\n{text}"));
        match crate::lang::chain(
            &loaded.table,
            &loaded.text,
            &loaded.path,
            None,
            &scene.lookup(),
        ) {
            Err(Error::Profile { reason, .. }) => {
                assert!(
                    reason.contains("`agent-args` is a list"),
                    "{text}: {reason}"
                )
            }
            other => panic!("{text}: refused when the file loads, not {other:?}"),
        }
    }
    let reason = scene.resolve_refusal("agent-args = [\"--verbose\"]");
    assert!(reason.contains("nothing sets a command"), "{reason}");
}

#[test]
fn an_agent_args_element_that_starts_with_a_path_name_is_a_path() {
    let scene = Scene::new();
    scene.share("agent", AGENT_PACK);
    let text = |arg: &str| format!("packs = [\"@box/agent\"]\nagent-args = [{arg:?}]");
    let reason = scene.refusal(&text("${{ workspace }}/../etc"));
    assert!(reason.contains("holds `..`"), "{reason}");
    let compiled = scene
        .compile(&profile(&text("--dir=${{ workspace }}")), None)
        .expect("a flag that holds a path later is not a path");
    assert_eq!(
        strings(&table(&compiled)["agent"]["command"])[2],
        format!("--dir={}", scene.workspace().display())
    );
}

#[test]
fn a_program_input_first_in_agent_args_still_needs_a_pattern() {
    let scene = Scene::new();
    scene.share(
        "agent",
        &format!("{AGENT_PACK}\n[inputs.agent.helper]\ntype = \"program\"\ndefault = \"/bin/x\""),
    );
    let reason =
        scene.refusal("packs = [\"@box/agent\"]\nagent-args = [\"${{ inputs.agent.helper }}\"]");
    assert!(
        reason.contains(
            "`inputs.agent.helper` reaches `agent-args`, so `[inputs.agent.helper]` needs"
        ),
        "{reason}"
    );
}

#[test]
fn the_slot_of_a_command_written_with_when_is_filled() {
    let scene = Scene::new();
    scene.share(
        "agent",
        "[run]\n\
         command = { value = [\"/bin/agent\", { slot = \"agent-args\" }], when = { variable = \"inputs.agent.on\", equals = \"true\" } }\n\
         [inputs.agent.on]\ntype = \"bool\"\ndefault = true",
    );
    let compiled = scene
        .compile(
            &profile("packs = [\"@box/agent\"]\nagent-args = [\"--verbose\"]"),
            None,
        )
        .expect("a command written with when");
    assert_eq!(
        strings(&table(&compiled)["agent"]["command"]),
        ["/bin/agent", "--verbose"]
    );
}

#[test]
fn a_slot_default_that_agent_args_replaces_is_never_resolved() {
    let scene = Scene::new();
    scene.share(
        "agent",
        "[run]\n\
         command = [\"/bin/agent\", { slot = \"agent-args\", default = [\"${{ agent.unknown }}\"] }]",
    );
    let compiled = scene
        .compile(
            &profile("packs = [\"@box/agent\"]\nagent-args = [\"--chosen\"]"),
            None,
        )
        .expect("an unused default");
    assert_eq!(
        strings(&table(&compiled)["agent"]["command"]),
        ["/bin/agent", "--chosen"]
    );
}

#[test]
fn a_refusal_in_agent_args_names_the_agent_args_element() {
    let scene = Scene::new();
    scene.share(
        "agent",
        "[run]\n\
         command = [\"/bin/agent\", { value = \"--gone\", when = { variable = \"inputs.agent.off\", equals = \"true\" } }, \"--skip\", { slot = \"agent-args\" }, \"--last\"]\n\
         [inputs.agent.off]\ntype = \"bool\"\ndefault = false",
    );
    let text = |args: &str| format!("packs = [\"@box/agent\"]\nagent-args = [{args}]");
    let reason = scene.refusal(&text("\"--a\", \"${{ nope }}\""));
    assert!(
        reason.starts_with("`agent-args.1`: `nope` is not a name"),
        "{reason}"
    );
    let reason = scene.refusal(&text("\"${{ home }}/../etc\""));
    assert!(reason.starts_with("`agent-args.0`"), "{reason}");
    let compiled = scene
        .compile(&profile(&text("\"--a\", \"--b\"")), None)
        .expect("a pack element dropped before the slot");
    assert_eq!(
        strings(&table(&compiled)["agent"]["command"]),
        ["/bin/agent", "--skip", "--a", "--b", "--last"]
    );
}

#[test]
fn agent_args_with_no_agent_left_after_when_is_refused() {
    let scene = Scene::new();
    scene.share(
        "agent",
        "[run]\nwhen = { variable = \"inputs.agent.on\", equals = \"true\" }\n\
         command = [\"/bin/agent\", { slot = \"agent-args\" }]\n[inputs.agent.on]\n\
         type = \"bool\"\ndefault = false",
    );
    let reason = scene.refusal("packs = [\"@box/agent\"]\nagent-args = [\"--a\"]");
    assert!(reason.contains("nothing sets a command"), "{reason}");
}

#[test]
fn the_program_of_a_command_takes_no_when() {
    let scene = Scene::new();
    let pack = |on: bool, table: &str| {
        format!("{table}\n[inputs.agent.on]\ntype = \"bool\"\ndefault = {on}")
    };
    let gated = |program: &str, rest: &str| {
        format!("[{{ value = \"{program}\", when = \"${{{{ inputs.agent.on }}}}\" }}, {rest}]")
    };
    let tables = [
        (
            "[agent] command",
            format!("[run]\ncommand = {}", gated("/bin/a", "\"--skip\"")),
        ),
        (
            "[agent] command",
            format!(
                "[run]\ncommand = {}",
                gated("/bin/a", "{ slot = \"agent-args\" }")
            ),
        ),
        (
            "[agent] command",
            format!(
                "[run]\ncommand = {{ value = {}, when = \"${{{{ inputs.agent.on }}}}\" }}",
                gated("/bin/a", "\"--skip\"")
            ),
        ),
        (
            "[tool.t] command",
            format!("[tool.t]\ncommand = {}", gated("/bin/t", "\"--skip\"")),
        ),
    ];
    for (at, table) in &tables {
        for on in [true, false] {
            scene.share("agent", &pack(on, table));
            let (path, _, reason) = scene.located("packs = [\"@box/agent\"]");
            assert_eq!(
                reason,
                format!("`{at}` element 0 is the program, so it takes no `when`"),
                "{table} on={on}"
            );
            assert!(
                path.ends_with("packs/agent/pack.toml"),
                "{}",
                path.display()
            );
        }
    }
    let mcp = format!(
        "packs = [\"@box/agent\"]\n[mcp.m]\ncommand = {}",
        gated("/bin/m", "\"--skip\"")
    );
    scene.share("agent", &pack(true, ""));
    let (path, _, reason) = scene.located(&mcp);
    assert_eq!(
        reason,
        "`[mcp.m] command` element 0 is the program, so it takes no `when`"
    );
    assert_eq!(path, Path::new("test.toml"));
    let later = "[run]\ncommand = [\"/bin/a\", \"--skip\", \
                 { value = \"--verbose\", when = \"${{ inputs.agent.on }}\" }]";
    for (on, command) in [
        (true, &["/bin/a", "--skip", "--verbose"][..]),
        (false, &["/bin/a", "--skip"][..]),
    ] {
        scene.share("agent", &pack(on, later));
        let compiled = scene
            .compile(&profile("packs = [\"@box/agent\"]"), None)
            .expect("a when on a later element");
        assert_eq!(strings(&table(&compiled)["agent"]["command"]), command);
    }
}

/// A `program` input that a pack finds with `program` and `search`.
mod search {
    use std::path::{Path, PathBuf};

    use super::{Fixed, Scene, profile, real, table};
    use crate::error::Error;
    use crate::reference::Sources;
    use crate::test_support::{link, script};

    /// Sources like `Fixed`, where `PATH` is the first value and each pair is a variable.
    struct OnPath(String, Vec<(&'static str, String)>);

    impl Sources for OnPath {
        fn env(&self, name: &str) -> Option<String> {
            if name == "PATH" {
                return Some(self.0.clone());
            }
            if let Some((_, value)) = self.1.iter().find(|(set, _)| *set == name) {
                return Some(value.clone());
            }
            Fixed.env(name)
        }

        fn env_with_prefix(&self, prefix: &str) -> Vec<(String, String)> {
            self.1
                .iter()
                .filter(|(set, _)| set.starts_with(prefix))
                .map(|(set, value)| (set.to_string(), value.clone()))
                .chain(Fixed.env_with_prefix(prefix))
                .collect()
        }

        fn program(&mut self, name: &str) -> Option<PathBuf> {
            Fixed.program(name)
        }

        fn search(&self, name: &str) -> Option<PathBuf> {
            Fixed.search(name)
        }

        fn developer_dir(&mut self) -> Result<String, String> {
            Fixed.developer_dir()
        }
    }

    /// The pack `@box/mine`, whose agent is the `mine` that `search` finds first.
    fn mine(scene: &Scene, search: &str) {
        scene.share(
            "mine",
            &format!(
                "[filesystem]\nexec = [\"${{{{ inputs.mine.path }}}}\"]\n[run]\n\
                 command = [\"${{{{ inputs.mine.path }}}}\"]\n[inputs.mine.path]\n\
                 type = \"program\"\nprogram = \"mine\"\nsearch = {search}"
            ),
        );
    }

    fn agent(scene: &Scene, path: &str, options: &str) -> Result<(String, String), Error> {
        agent_with(scene, OnPath(path.to_string(), Vec::new()), options)
    }

    fn agent_with(
        scene: &Scene,
        mut sources: OnPath,
        options: &str,
    ) -> Result<(String, String), Error> {
        let (resolved, compiled) = scene.compile_using(
            &profile(&format!("packs = [\"@box/mine\"]\n{options}")),
            &mut sources,
            "/usr/bin:/bin",
        )?;
        let command = table(&compiled)["agent"]["command"][0]
            .as_str()
            .expect("a program")
            .to_string();
        let source = resolved
            .inputs
            .iter()
            .find(|input| input.name == "mine.path")
            .expect("the input")
            .source
            .clone();
        Ok((command, source))
    }

    fn found(scene: &Scene, path: &str) -> String {
        agent(scene, path, "").expect("an agent").0
    }

    fn shown(path: &Path) -> String {
        path.display().to_string()
    }

    #[test]
    fn search_takes_the_first_folder_that_holds_the_program_in_the_order_it_lists() {
        let scene = Scene::new();
        let home = scene.home();
        let on_path = scene.root.join("bin");
        mine(
            &scene,
            r#"["${{ home }}/first", { env = "PATH" }, "${{ home }}/last"]"#,
        );
        script(&home.join("last/mine"), "true");
        assert_eq!(
            found(&scene, &shown(&on_path)),
            shown(&home.join("last/mine"))
        );
        script(&on_path.join("mine"), "true");
        let path = format!("relative:{}:", shown(&on_path));
        assert_eq!(found(&scene, &path), shown(&on_path.join("mine")));
        script(&home.join("first/mine"), "true");
        let (command, source) = agent(&scene, &path, "").expect("an agent");
        assert_eq!(command, shown(&home.join("first/mine")));
        assert_eq!(source, "search");
    }

    #[test]
    fn a_star_in_a_search_folder_takes_the_newest_version_first() {
        let scene = Scene::new();
        let home = scene.home();
        mine(&scene, r#"["${{ home }}/versions/*"]"#);
        for version in ["1.0.0", "2.0.0", "10.0.0"] {
            script(&home.join("versions").join(version).join("mine"), "true");
        }
        assert_eq!(found(&scene, ""), shown(&home.join("versions/10.0.0/mine")));
        for version in ["10.0.0.1", "10.0.1-beta"] {
            script(&home.join("versions").join(version).join("mine"), "true");
        }
        assert_eq!(
            found(&scene, ""),
            shown(&home.join("versions/10.0.1-beta/mine")),
            "number by number, so 10.0.1 is newer than 10.0.0.1"
        );
    }

    #[test]
    fn a_star_sorts_more_numbers_first_then_by_name_in_reverse() {
        let scene = Scene::new();
        let home = scene.home();
        mine(&scene, r#"["${{ home }}/versions/*"]"#);
        for version in ["2.1z", "2.1.0"] {
            script(&home.join("versions").join(version).join("mine"), "true");
        }
        assert_eq!(
            found(&scene, ""),
            shown(&home.join("versions/2.1.0/mine")),
            "more numbers first, though 2.1z sorts after 2.1.0 by name"
        );
        script(&home.join("versions/a-2.1.0/mine"), "true");
        assert_eq!(
            found(&scene, ""),
            shown(&home.join("versions/a-2.1.0/mine"))
        );
    }

    #[test]
    fn the_matches_of_one_entry_come_before_the_next_entry() {
        let scene = Scene::new();
        let home = scene.home();
        mine(&scene, r#"["${{ home }}/b/*", "${{ home }}/a/9.0"]"#);
        script(&home.join("a/9.0/mine"), "true");
        script(&home.join("b/1.0/mine"), "true");
        assert_eq!(found(&scene, ""), shown(&home.join("b/1.0/mine")));
    }

    #[test]
    fn search_never_runs_a_candidate() {
        let scene = Scene::new();
        let home = scene.home();
        let marker = home.join("ran");
        mine(&scene, r#"["${{ home }}/bin"]"#);
        script(
            &home.join("bin/mine"),
            &format!("touch '{}'", marker.display()),
        );
        assert_eq!(found(&scene, ""), shown(&home.join("bin/mine")));
        assert!(!marker.exists(), "the search ran the program");
    }

    #[test]
    fn a_from_source_comes_before_the_search() {
        let scene = Scene::new();
        scene.share(
            "mine",
            "[run]\ncommand = [\"${{ inputs.mine.path }}\"]\n[inputs.mine.path]\n\
             type = \"program\"\nprogram = \"mine\"\nfrom = \"env:MINE\"",
        );
        let on_path = scene.root.join("bin");
        script(&on_path.join("mine"), "true");
        let sources = OnPath(shown(&on_path), vec![("MINE", "/usr/bin/true".to_string())]);
        let (command, source) = agent_with(&scene, sources, "").expect("an agent");
        assert_eq!(command, real("/usr/bin/true"));
        assert_eq!(source, "env:MINE");
        assert_eq!(
            found(&scene, &shown(&on_path)),
            shown(&on_path.join("mine"))
        );
    }

    #[test]
    fn an_env_folder_is_each_absolute_folder_of_its_variable() {
        let scene = Scene::new();
        let home = scene.home();
        mine(&scene, r#"[{ env = "TOOLS" }, "${{ home }}/last"]"#);
        script(&home.join("last/mine"), "true");
        script(&home.join("second/mine"), "true");
        let tools = |value: String| OnPath(String::new(), vec![("TOOLS", value)]);
        let value = format!(
            "relative:{}:{}",
            shown(&home.join("first")),
            shown(&home.join("second"))
        );
        assert_eq!(
            agent_with(&scene, tools(value), "").expect("an agent").0,
            shown(&home.join("second/mine"))
        );
        assert_eq!(
            found(&scene, ""),
            shown(&home.join("last/mine")),
            "an unset variable adds no folder"
        );
    }

    #[test]
    fn search_passes_over_a_program_in_storage_or_the_box_home_as_written_or_real() {
        let scene = Scene::new();
        let home = scene.home();
        let storage = scene.storage();
        mine(
            &scene,
            r#"["${{ home }}/.strands/box/bin", "${{ home }}/storage-bin", "${{ home }}/linked", "${{ home }}/last"]"#,
        );
        script(&home.join(".strands/box/bin/mine"), "true");
        script(&storage.join("bin/mine"), "true");
        link(&shown(&storage.join("bin")), &home.join("storage-bin"));
        link(
            &shown(&home.join(".strands/box/bin/mine")),
            &home.join("linked/mine"),
        );
        let error = agent(&scene, "", "").expect_err("nothing the box can run");
        for path in [
            home.join(".strands/box/bin/mine"),
            home.join("storage-bin/mine"),
            home.join("linked/mine"),
        ] {
            assert!(
                error
                    .to_string()
                    .contains(&format!("{} (in ", shown(&path))),
                "{}: {error}",
                path.display()
            );
        }
        script(&home.join("last/mine"), "true");
        assert_eq!(found(&scene, ""), shown(&home.join("last/mine")));
    }

    #[test]
    fn a_program_link_under_a_write_grant_is_refused_from_an_option_or_the_search() {
        let scene = Scene::new();
        let home = scene.home();
        mine(&scene, r#"["${{ home }}/.local/bin"]"#);
        let real = home.join(".local/share/mine/versions/2.1.9");
        script(&real, "true");
        let planted = home.join(".local/bin/mine");
        link(&shown(&real), &planted);
        let write = format!(
            "[agent.filesystem]\nwrite = [{:?}]",
            shown(&home.join(".local/bin"))
        );
        for options in [
            String::new(),
            format!("[options]\nmine.path = {:?}\n", shown(&planted)),
        ] {
            let error = agent(&scene, "", &format!("{options}{write}"))
                .expect_err("a box could repoint the link");
            assert!(
                error.to_string().contains(&format!(
                    "lies under the write grant {}, which is not allowed because the agent in \
                     the box can rewrite it. Remove the grant, or set `mine.path` in your \
                     profile's `[options]` to a program outside it",
                    shown(&home.join(".local/bin"))
                )),
                "{options}: {error}"
            );
        }
    }

    #[test]
    fn root_in_the_agent_table_is_the_folder_of_the_program_the_agent_runs() {
        let scene = Scene::new();
        let home = scene.home();
        scene.share(
            "mine",
            "[env]\nROOT = \"${{ root }}\"\nUP = \"${{ root.parent }}\"\n[run]\n\
             command = [\"${{ inputs.mine.path }}\"]\n[inputs.mine.path]\ntype = \"program\"\n\
             program = \"mine\"\n\
             search = [\"${{ home }}/flat/1.0\", \"${{ home }}/opt/mine/2.0/bin\"]",
        );
        let env = |scene: &Scene| {
            let (_, compiled) = scene
                .compile_using(
                    &profile("packs = [\"@box/mine\"]"),
                    &mut OnPath(String::new(), Vec::new()),
                    "/usr/bin:/bin",
                )
                .expect("a compile");
            let env = &table(&compiled)["agent"]["env"];
            ["ROOT", "UP"].map(|key| env[key].as_str().expect(key).to_string())
        };
        script(&home.join("opt/mine/2.0/bin/mine"), "true");
        assert_eq!(
            env(&scene),
            [
                shown(&home.join("opt/mine/2.0/bin")),
                shown(&home.join("opt/mine/2.0")),
            ]
        );
        script(&home.join("flat/1.0/mine"), "true");
        assert_eq!(
            env(&scene),
            [shown(&home.join("flat/1.0")), shown(&home.join("flat")),]
        );
    }

    #[test]
    fn root_is_refused_outside_a_tool_pack_and_the_agent_table() {
        let scene = Scene::new();
        for text in [
            "[agent]\ncommand = [\"/usr/bin/true\"]\n[storage]\ndirectories = [\"a\"]\n\
             [[storage.files]]\nsource = \"${{ root.parent }}/x\"\ntarget = \"a/x\"",
            "[agent]\ncommand = [\"/usr/bin/true\"]\n[tool.git]\ncommand = [\"/usr/bin/git\"]\n\
             env.X = \"${{ root }}\"",
        ] {
            let reason = scene.refusal(text);
            assert!(
                reason.contains("is valid only in a tool pack or an `[agent]` table"),
                "{text}: {reason}"
            );
        }
        let reason = scene.refusal("[agent]\ncommand = [\"${{ root }}/mine\"]");
        assert!(
            reason.contains("`[agent] command` element 0 names the program that `root` comes from"),
            "{reason}"
        );
    }

    #[test]
    fn two_packs_that_search_differently_for_one_input_stop_the_run() {
        let scene = Scene::new();
        mine(&scene, r#"["${{ home }}/a"]"#);
        scene.share(
            "other",
            "[inputs.mine.path]\ntype = \"program\"\nprogram = \"mine\"\nsearch = [\"/opt\"]",
        );
        let reason = scene.resolve_refusal("packs = [\"@box/mine\", \"@box/other\"]");
        assert!(
            reason
                .contains("the packs that declare `inputs.mine.path` give different search lists"),
            "{reason}"
        );
    }

    #[test]
    fn a_program_with_no_search_looks_on_path() {
        let scene = Scene::new();
        let on_path = scene.root.join("bin");
        scene.share(
            "mine",
            "[run]\ncommand = [\"${{ inputs.mine.path }}\"]\n[inputs.mine.path]\n\
             type = \"program\"\nprogram = \"mine\"",
        );
        script(&on_path.join("mine"), "true");
        assert_eq!(
            found(&scene, &shown(&on_path)),
            shown(&on_path.join("mine"))
        );
    }

    #[test]
    fn search_follows_a_link_to_the_real_program() {
        let scene = Scene::new();
        let home = scene.home();
        mine(&scene, r#"["${{ home }}/.local/bin"]"#);
        let real = home.join(".local/share/mine/versions/2.1.9");
        script(&real, "true");
        link(&shown(&real), &home.join(".local/bin/mine"));
        assert_eq!(found(&scene, ""), shown(&real));
    }

    #[test]
    fn search_passes_over_a_program_the_box_cannot_run_and_names_why_when_none_is_left() {
        let scene = Scene::new();
        let home = scene.home();
        let workspace = scene.workspace();
        mine(
            &scene,
            r#"["${{ workspace }}/bin", "${{ home }}/node", "${{ home }}/other", "${{ home }}/plain", "${{ home }}/last"]"#,
        );
        script(&workspace.join("bin/mine"), "true");
        crate::test_support::write(&home.join("node/mine"), "#!/usr/bin/env node\n");
        crate::test_support::executable(&home.join("node/mine"));
        crate::test_support::write(
            &home.join("other/mine"),
            "#!/usr/bin/env -P /opt/node/bin node\n",
        );
        crate::test_support::executable(&home.join("other/mine"));
        crate::test_support::write(&home.join("plain/mine"), "not a program");
        let error = agent(&scene, "", "").expect_err("no program the box can run");
        let Error::NotOnHost { reason, .. } = &error else {
            panic!("a host absence, not {error:?}");
        };
        for why in [
            "no `mine` that the box can run in the folders `[inputs.mine.path] search` names",
            &format!("{} (", shown(&workspace.join("bin/mine"))),
            &format!(
                "{} (a node script, which the box cannot start)",
                shown(&home.join("node/mine"))
            ),
            &format!(
                "{} (a node script, which the box cannot start)",
                shown(&home.join("other/mine"))
            ),
            &format!(
                "{} (not an executable file)",
                shown(&home.join("plain/mine"))
            ),
            "set `mine.path` in your profile's `[options]`",
        ] {
            assert!(reason.contains(why), "{why}: {reason}");
        }
        script(&home.join("last/mine"), "true");
        assert_eq!(found(&scene, ""), shown(&home.join("last/mine")));
    }

    #[test]
    fn an_input_with_no_search_refuses_a_node_script_from_an_option_or_a_default() {
        let scene = Scene::new();
        let home = scene.home();
        let node = home.join("node/mine");
        crate::test_support::write(&node, "#!/usr/bin/env node\n");
        crate::test_support::executable(&node);
        let plain = home.join("plain/mine");
        script(&plain, "true");
        let share = |default: &Path| {
            scene.share(
                "mine",
                &format!(
                    "[run]\ncommand = [\"${{{{ inputs.mine.path }}}}\"]\n[inputs.mine.path]\n\
                     type = \"program\"\ndefault = {:?}",
                    shown(default)
                ),
            );
        };
        share(&plain);
        assert_eq!(agent(&scene, "", "").expect("an agent").0, shown(&plain));
        let refused = |options: &str| {
            let error = agent(&scene, "", options).expect_err("a node script");
            assert!(
                error
                    .to_string()
                    .contains("is a node script, which the box cannot start"),
                "{options}: {error}"
            );
        };
        refused(&format!("[options]\nmine.path = {:?}", shown(&node)));
        share(&node);
        refused("");
        let link = home.join("bin/mine++");
        crate::test_support::link("../plain/mine", &link);
        for (tool, kept) in [(&node, &node), (&link, &link)] {
            scene.share(
                "mine",
                &format!(
                    "[run]\ncommand = [{:?}]\n[inputs.mine.path]\ntype = \"program\"\n\
                     default = {:?}\n[tool.t]\ncommand = [\"${{{{ inputs.mine.path }}}}\"]",
                    shown(&plain),
                    shown(tool)
                ),
            );
            let (_, compiled) = scene
                .compile_using(
                    &profile("packs = [\"@box/mine\"]"),
                    &mut OnPath(String::new(), Vec::new()),
                    "/usr/bin:/bin",
                )
                .expect("a tool may run a node script or a link");
            assert_eq!(
                table(&compiled)["tool"]["t"]["command"][0].as_str(),
                Some(shown(kept).as_str()),
                "a tool keeps the path as written"
            );
        }
    }

    #[test]
    fn an_option_names_the_program_and_search_is_not_read() {
        let scene = Scene::new();
        mine(&scene, r#"["${{ home }}/none"]"#);
        let (command, source) =
            agent(&scene, "", "[options]\nmine.path = \"/usr/bin/true\"").expect("an agent");
        assert_eq!(command, real("/usr/bin/true"));
        assert_eq!(source, "your profile");
        let error = agent(&scene, "", "[options]\nmine.path = \"relative/mine\"")
            .expect_err("a relative program");
        assert!(
            error.to_string().contains("is not an absolute path"),
            "{error}"
        );
        let home = scene.home();
        let real = home.join(".local/share/mine/versions/2.1.9");
        script(&real, "true");
        link(&shown(&real), &home.join(".local/bin/mine"));
        let linked = format!(
            "[options]\nmine.path = {:?}",
            shown(&home.join(".local/bin/mine"))
        );
        let (command, source) = agent(&scene, "", &linked).expect("an agent");
        assert_eq!(command, shown(&real), "the option's link is followed");
        assert_eq!(source, "your profile");
        crate::test_support::write(&home.join("node/mine"), "#!/usr/bin/env node\n");
        crate::test_support::executable(&home.join("node/mine"));
        let node = format!(
            "[options]\nmine.path = {:?}",
            shown(&home.join("node/mine"))
        );
        let error = agent(&scene, "", &node).expect_err("a node script");
        assert!(
            error
                .to_string()
                .contains("is a node script, which the box cannot start"),
            "{error}"
        );
    }

    #[test]
    fn an_env_folder_cannot_read_a_credential_variable() {
        let scene = Scene::new();
        scene.share(
            "mine",
            "[run]\ncommand = [\"${{ inputs.mine.path }}\"]\n[inputs.mine.path]\n\
             type = \"program\"\nprogram = \"mine\"\nsearch = [{ env = \"MY_KEY\" }]\n\
             [egress.model]\ndestinations = [\"example.com\"]\nsecret.ref = \"env://MY_KEY\"",
        );
        let reason = scene.refusal("packs = [\"@box/mine\"]");
        assert!(
            reason.contains("would give the workload the host's `MY_KEY`, which a route or a server names as its credential"),
            "{reason}"
        );
    }

    #[test]
    fn program_and_search_come_together_on_a_program_input() {
        let scene = Scene::new();
        for (declaration, why) in [
            (
                "type = \"program\"\nsearch = [\"/opt\"]",
                "`[inputs.mine.path] search` needs `program`",
            ),
            (
                "program = \"mine\"\nsearch = [\"/opt\"]",
                "`program` and `search` are only for `type = \"program\"`",
            ),
            (
                "type = \"program\"\nprogram = \"mine\"\ndefault = \"/bin/x\"",
                "holds `program` and `default`",
            ),
            (
                "type = \"program\"\nprogram = \"bin/mine\"\nsearch = [\"/opt\"]",
                "is not a program name",
            ),
            (
                "type = \"program\"\nprogram = \"mine\"\nsearch = \"/opt\"",
                "is a list of folders",
            ),
            (
                "type = \"program\"\nprogram = \"mine\"\nsearch = [{ path = \"/opt\" }]",
                "takes only `env`",
            ),
            (
                "type = \"program\"\nprogram = \"mine\"\nsearch = [1]",
                "is a list of folders",
            ),
        ] {
            scene.share(
                "mine",
                &format!(
                    "[run]\ncommand = [\"${{{{ inputs.mine.path }}}}\"]\n[inputs.mine.path]\n\
                     {declaration}"
                ),
            );
            let reason = scene.refusal("packs = [\"@box/mine\"]");
            assert!(reason.contains(why), "{declaration}: {reason}");
        }
    }

    #[test]
    fn the_agent_and_detect_names_are_gone() {
        let scene = Scene::new();
        for value in [r#""${{ agent.claude }}""#, r#""${{ detect.node }}""#] {
            let reason = scene.refusal(&format!(
                "[agent]\ncommand = [\"/bin/x\"]\nenv.VALUE = {value}"
            ));
            assert!(reason.contains("is not a name"), "{value}: {reason}");
        }
    }
}

#[test]
fn cache_references_belong_to_a_tool_and_do_not_create_workspace_state() {
    let scene = Scene::new();
    assert!(
        scene
            .resolve_refusal("[agent]\ncommand = ['/usr/bin/true']\nenv.CACHE = '${{ cache }}'")
            .contains("`cache` is valid only in a tool table")
    );
    let traversal = scene.resolve_refusal("[agent]\ncommand = ['/usr/bin/true']\n[tool.fetch]\ncommand = ['/usr/bin/true', '${{ cache }}/../outside']");
    assert!(
        traversal.contains(".."),
        "cache command paths reject traversal: {traversal}"
    );
    let resolved = scene.resolve(&profile("[agent]\ncommand = ['/usr/bin/true']\n[tool.fetch]\ncommand = ['/usr/bin/true']\nenv.CACHE = '${{ cache }}'"))
        .expect("a contextual tool cache");
    let cache = scene.workspace().join(".cache/fetch");
    assert_eq!(
        resolved.tool["fetch"].env["CACHE"],
        cache.display().to_string()
    );
    assert!(resolved.storage.tool_states.is_empty());
    crate::run::prepare_storage(&resolved.storage, &scene.home()).expect("storage");
    assert!(!cache.exists());
}

#[test]
fn a_tools_storage_lies_outside_the_workspace_and_the_agent_gets_no_grant_to_it() {
    let scene = Scene::new();
    let resolved = scene
        .resolve(&profile(
            "[agent]\ncommand = ['/usr/bin/true']\n[storage]\ndirectories = ['config']\n\
             [tool.fetch]\ncommand = ['/usr/bin/true']\nstorage.directories = ['prefix']\n\
             env.PREFIX = '${{ storage.prefix }}/bin'\nenv.CONFIG = '${{ storage.config }}'\n\
             filesystem.write = ['${{ storage.prefix }}']",
        ))
        .expect("a tool storage");
    let state = resolved
        .storage
        .root
        .join("tool")
        .join("fetch")
        .join("prefix");
    assert!(!state.starts_with(scene.workspace()), "{}", state.display());
    let env = &resolved.tool["fetch"].env;
    assert_eq!(env["PREFIX"], state.join("bin").display().to_string());
    assert_eq!(
        env["CONFIG"],
        resolved
            .storage
            .root
            .join("agent/config")
            .display()
            .to_string(),
        "a tool still names the agent's storage"
    );
    assert_eq!(resolved.storage.tool_states, vec![state.clone()]);
    assert!(!resolved.storage.directories.contains(&state));
    let agent = &resolved.agent.filesystem;
    for list in [
        &agent.read,
        &agent.write,
        &agent.read_file,
        &agent.write_file,
    ] {
        assert!(
            !list
                .iter()
                .any(|entry| Path::new(entry).starts_with(&state) || state.starts_with(entry)),
            "{list:?}"
        );
    }
    crate::run::prepare_storage(&resolved.storage, &scene.home()).expect("storage");
    assert!(state.is_dir());
    let refused = |text: &str| match scene.resolve(&profile(text)) {
        Err(Error::Profile { reason, .. }) => reason,
        other => panic!("a refusal, not {other:?}"),
    };
    let shared = scene
        .resolve(&profile(
            "[agent]\ncommand = ['/usr/bin/true']\nenv.CONFIG = '${{ storage.config }}'\n\
             [storage]\ndirectories = ['config']\n\
             [tool.fetch]\ncommand = ['/usr/bin/true']\nstorage.directories = ['config']\n\
             env.CONFIG = '${{ storage.config }}'",
        ))
        .expect("a tool directory may share a name with an agent directory");
    assert_eq!(
        shared.tool["fetch"].env["CONFIG"],
        shared
            .storage
            .root
            .join("tool/fetch/config")
            .display()
            .to_string(),
        "in a tool table, the tool's own directory comes first"
    );
    assert_eq!(
        shared.agent.env["CONFIG"],
        shared
            .storage
            .root
            .join("agent/config")
            .display()
            .to_string()
    );
    assert!(
        refused(
            "[agent]\ncommand = ['/usr/bin/true']\n[tool.fetch]\ncommand = ['/usr/bin/true']\n\
             storage.directories = ['a/b']"
        )
        .contains("is not one directory name")
    );
    assert!(
        refused(
            "[agent]\ncommand = ['/usr/bin/true']\nenv.X = '${{ storage.prefix }}'\n\
             [tool.fetch]\ncommand = ['/usr/bin/true']\nstorage.directories = ['prefix']"
        )
        .contains("is not in `[storage] directories`"),
        "the agent cannot name a tool's storage"
    );
}

#[test]
fn a_tool_packs_storage_is_its_own_and_a_profile_adds_to_it() {
    let scene = Scene::new();
    scene.share(
        "rt",
        "kind = \"tool\"\n[inputs.rt.path]\ntype = \"program\"\nprogram = \"rt\"\n\
         search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.rt.path }}\"]\n[storage]\n\
         directories = [\"prefix\"]\n[env]\nPREFIX = \"${{ storage.prefix }}\"",
    );
    let resolved = detected(
        &scene,
        &format!("packs = [\"@box/rt\"]\n{AGENT}\n[tool.rt.storage]\ndirectories = [\"cache\"]"),
    )
    .expect("a resolve");
    let root = resolved.storage.root.join("tool/rt");
    assert_eq!(
        resolved.tool["rt"].env["PREFIX"],
        root.join("prefix").display().to_string()
    );
    let mut states = resolved.storage.tool_states.clone();
    states.sort();
    assert_eq!(states, vec![root.join("cache"), root.join("prefix")]);
}

#[test]
fn link_rows_link_host_entries_into_a_tools_storage_and_leave_what_is_there() {
    let scene = Scene::new();
    let host = scene.home().join(".rustup");
    std::fs::create_dir_all(host.join("toolchains/stable")).expect("a toolchain");
    std::fs::create_dir_all(host.join("toolchains/beta")).expect("a toolchain");
    std::fs::write(host.join("settings.toml"), "profile = \"minimal\"\n").expect("settings");
    let tool = |links: &str| {
        profile(&format!(
            "[agent]\ncommand = ['/usr/bin/true']\n[tool.fetch]\ncommand = ['/usr/bin/true']\n\
             filesystem.write = ['${{{{ storage.rustup }}}}']\n\
             storage.directories = ['rustup']\nstorage.files = [{links}]"
        ))
    };
    let resolved = scene
        .resolve(&tool(
            "{ source = '~/.rustup/settings.toml', target = 'rustup/settings.toml', mode = 'link' }, \
             { source = '~/.rustup/toolchains', target = 'rustup/toolchains', \
               mode = 'link-children' }, \
             { source = '~/.rustup/absent', target = 'rustup/absent', mode = 'link' }",
        ))
        .expect("link rows");
    let state = resolved.storage.root.join("tool/fetch");
    assert_eq!(resolved.storage.tool_states, vec![state.join("rustup")]);
    assert_eq!(resolved.storage.links.len(), 3);
    assert!(resolved.storage.files.is_empty());
    assert!(resolved.tool["fetch"].env.is_empty());
    crate::run::prepare_storage(&resolved.storage, &scene.home()).expect("storage");
    std::fs::create_dir_all(state.join("rustup/toolchains/nightly")).expect("an installed one");
    crate::run::link_storage(&resolved.storage).expect("links");
    let link = |name: &str| std::fs::read_link(state.join("rustup").join(name)).ok();
    assert_eq!(
        link("settings.toml"),
        Some(host.join("settings.toml")),
        "a single link"
    );
    assert_eq!(
        link("toolchains/stable"),
        Some(host.join("toolchains/stable"))
    );
    assert_eq!(link("toolchains/beta"), Some(host.join("toolchains/beta")));
    assert!(state.join("rustup/toolchains/nightly").is_dir());
    assert!(!state.join("rustup/absent").exists());
    std::fs::remove_dir(host.join("toolchains/beta")).expect("the operator removes one");
    crate::run::link_storage(&resolved.storage).expect("links again");
    assert!(
        std::fs::symlink_metadata(state.join("rustup/toolchains/beta")).is_err(),
        "a link to a removed entry goes"
    );
    assert!(state.join("rustup/toolchains/stable").is_dir());
    assert!(state.join("rustup/toolchains/nightly").is_dir());
    std::os::unix::fs::symlink(scene.workspace(), state.join("rustup/toolchains/planted"))
        .expect("a box plants a link");
    let moved = scene.home().join("rustup-elsewhere");
    std::fs::create_dir_all(moved.join("toolchains/stable")).expect("a moved toolchain");
    std::fs::write(moved.join("settings.toml"), "").expect("moved settings");
    let mut storage = resolved.storage.clone();
    for link in &mut storage.links {
        link.source = moved.join(link.source.strip_prefix(&host).expect("under the home"));
    }
    crate::run::link_storage(&storage).expect("links to the moved home");
    assert_eq!(link("settings.toml"), Some(moved.join("settings.toml")));
    assert_eq!(
        link("toolchains/stable"),
        Some(moved.join("toolchains/stable"))
    );
    assert!(
        std::fs::symlink_metadata(state.join("rustup/toolchains/planted")).is_err(),
        "a link to anything but a source entry goes"
    );
    assert!(state.join("rustup/toolchains/nightly").is_dir());
    std::fs::remove_dir_all(state.join("rustup/toolchains")).expect("the box clears it");
    std::os::unix::fs::symlink(scene.workspace(), state.join("rustup/toolchains"))
        .expect("a box plants a link");
    assert!(
        matches!(
            crate::run::link_storage(&resolved.storage),
            Err(Error::Symlink { .. })
        ),
        "no link is made through a link"
    );
    let file = scene
        .resolve(&tool(
            "{ source = '~/.rustup/settings.toml', target = 'rustup/conf', \
               mode = 'link-children' }",
        ))
        .expect("a row whose source is not read yet");
    crate::run::prepare_storage(&file.storage, &scene.home()).expect("storage");
    assert!(
        matches!(
            crate::run::link_storage(&file.storage),
            Err(Error::Copy { reason, .. }) if reason.contains("needs a folder, and this is a file")
        ),
        "link-children with a file source stops the run"
    );
    let off = scene
        .resolve(&profile(
            "[agent]\ncommand = ['/usr/bin/true']\n[tool.fetch]\ncommand = ['/usr/bin/true']\n\
             when = 'linux'\nstorage.directories = ['rustup']\n\
             storage.files = [{ source = '${{ workspace }}/x', target = 'rustup/x', mode = 'link' }]",
        ))
        .expect("a tool that is off adds no storage, and its rows are not checked");
    assert!(!off.tool.contains_key("fetch"));
    assert!(
        off.storage.tool_states.is_empty(),
        "{:?}",
        off.storage.tool_states
    );
    assert!(off.storage.links.is_empty());
    let refused = |links: &str| match scene.resolve(&tool(links)) {
        Err(Error::Profile { reason, .. }) => reason,
        other => panic!("a refusal, not {other:?}"),
    };
    assert!(
        refused("{ source = '${{ workspace }}/bin', target = 'rustup/bin', mode = 'link' }")
            .contains("box links nothing from there")
    );
    assert!(
        refused("{ source = '~/.rustup', target = 'rustup/../up', mode = 'link' }")
            .contains("is not a tool storage directory and one or more names")
    );
    assert!(
        refused("{ source = '~/.rustup', target = 'rustup', mode = 'link' }")
            .contains("is not a tool storage directory and one or more names")
    );
    assert!(
        refused("{ source = '~/.rustup', target = 'other/a', mode = 'link' }")
            .contains("does not start with one of the tool's `[storage] directories`")
    );
    assert!(
        refused("{ source = '~/.rustup', target = 'rustup/a', mode = 'link', when = 'macos' }")
            .contains("holds the key `when`")
    );
    assert!(
        refused("{ source = '~/.rustup', target = 'rustup/a', mode = 'link', each = true }")
            .contains("holds the key `each`")
    );
    assert!(
        refused(
            "{ source = '~/.rustup', target = 'rustup/a', mode = 'link' }, \
             { source = '~/.rustup', target = 'rustup/a/b', mode = 'link' }"
        )
        .contains("cannot link at the target of another")
    );
}

#[test]
fn copy_rows_copy_host_files_into_a_tools_storage_and_the_agent_gets_no_grant() {
    let scene = Scene::new();
    let host = scene.home().join(".rustup");
    std::fs::create_dir_all(host.join("toolchains/stable")).expect("a toolchain");
    std::fs::create_dir_all(host.join("notes")).expect("notes");
    std::fs::write(host.join("notes/a.md"), "a\n").expect("a note");
    std::fs::write(
        host.join("settings.toml"),
        "profile = \"minimal\"\ntoken = \"secret\"\n",
    )
    .expect("settings");
    let tool = |rows: &str| {
        profile(&format!(
            "[agent]\ncommand = ['/usr/bin/true']\n[storage]\ndirectories = ['rustup']\n\
             [tool.fetch]\ncommand = ['/usr/bin/true']\n\
             filesystem.write = ['${{{{ storage.rustup }}}}']\n\
             storage.directories = ['rustup']\nstorage.files = [{rows}]"
        ))
    };
    let resolved = scene
        .resolve(&tool(
            "{ mode = 'copy', source = '~/.rustup/settings.toml', target = 'rustup/settings.toml', \
               kind = 'toml', keep = [['profile']], \
               set = [{ key = ['default_toolchain'], value = 'stable' }] }, \
             { source = '~/.rustup/notes', target = 'rustup/notes', mode = 'copy' }, \
             { mode = 'copy', source = '~/.rustup/absent', target = 'rustup/absent', when = 'linux' }, \
             { source = '~/.rustup/toolchains', target = 'rustup/toolchains', \
               mode = 'link-children' }",
        ))
        .expect("copy rows");
    let root = resolved.storage.root.clone();
    let state = root.join("tool/fetch/rustup");
    let files = &resolved.storage.files;
    assert_eq!(
        files.len(),
        2,
        "a row whose `when` is false copies nothing: {files:?}"
    );
    assert_eq!(files[0].target, state.join("settings.toml"));
    assert_eq!(files[0].relative, "tool/fetch/rustup/settings.toml");
    assert_eq!(files[0].at, "tool.fetch.storage.files[0]");
    assert_eq!(files[1].target, state.join("notes"));
    assert_eq!(resolved.storage.links.len(), 1);
    assert_eq!(resolved.storage.tool_states, vec![state.clone()]);
    assert_eq!(
        resolved.storage.directories,
        vec![root.join("agent/rustup")]
    );
    let agent = &resolved.agent.filesystem;
    for list in [
        &agent.read,
        &agent.write,
        &agent.read_file,
        &agent.write_file,
    ] {
        assert!(
            !list
                .iter()
                .any(|entry| Path::new(entry).starts_with(&state) || state.starts_with(entry)),
            "{list:?}"
        );
    }
    assert!(
        resolved.tool["fetch"]
            .filesystem
            .write
            .contains(&state.display().to_string()),
        "the tool reaches its copies through its own grant"
    );
    let run = scene.root.join("run");
    std::fs::create_dir_all(&run).expect("a run directory");
    crate::run::prepare_storage(&resolved.storage, &scene.home()).expect("storage");
    crate::run::link_storage(&resolved.storage).expect("links");
    crate::storage_sync::copy_files(&resolved.storage, &run, &scene.home(), &scene.home())
        .expect("copies");
    let settings = std::fs::read_to_string(state.join("settings.toml")).expect("a copy");
    assert!(settings.contains("profile = \"minimal\""), "{settings}");
    assert!(
        settings.contains("default_toolchain = \"stable\""),
        "{settings}"
    );
    assert!(
        !settings.contains("secret"),
        "keep drops the rest: {settings}"
    );
    assert_eq!(
        std::fs::read_to_string(state.join("notes/a.md")).expect("a copied note"),
        "a\n"
    );
    assert!(
        !root.join("rustup/settings.toml").exists(),
        "not in the agent's storage"
    );
    assert_eq!(
        std::fs::read_link(state.join("toolchains/stable")).ok(),
        Some(host.join("toolchains/stable"))
    );
    std::fs::write(
        state.join("settings.toml"),
        "profile = \"default\"\ndefault_toolchain = \"beta\"\n",
    )
    .expect("the tool changes its copy");
    crate::storage_sync::copy_files(&resolved.storage, &run, &scene.home(), &scene.home())
        .expect("copies again");
    let settings = std::fs::read_to_string(state.join("settings.toml")).expect("a copy");
    assert!(
        settings.contains("profile = \"default\""),
        "a copy stays: {settings}"
    );
    assert!(
        settings.contains("default_toolchain = \"stable\""),
        "each run sets the value again: {settings}"
    );
    let off = scene
        .resolve(&profile(
            "[agent]\ncommand = ['/usr/bin/true']\n[tool.fetch]\ncommand = ['/usr/bin/true']\n\
             when = 'linux'\nstorage.directories = ['rustup']\n\
             storage.files = [{ mode = 'copy', source = '${{ workspace }}/x', target = 'rustup/x' }]",
        ))
        .expect("a tool that is off adds no copy, and its rows are not checked");
    assert!(off.storage.files.is_empty(), "{:?}", off.storage.files);
    let gone = scene
        .resolve(&profile(
            "[agent]\ncommand = ['/usr/bin/true']\n[tool.fetch]\nprogram = 'no-such-program'\n\
             storage.directories = ['rustup']\n\
             storage.files = [{ mode = 'copy', source = '${{ workspace }}/x', target = 'rustup/x' }]",
        ))
        .expect("a tool whose program is missing adds no copy");
    assert!(!gone.tool.contains_key("fetch"));
    assert!(gone.storage.files.is_empty(), "{:?}", gone.storage.files);
    let refused = |rows: &str| match scene.resolve(&tool(rows)) {
        Err(Error::Profile { reason, .. }) => reason,
        other => panic!("a refusal, not {other:?}"),
    };
    for (rows, expected) in [
        (
            "{ mode = 'copy', source = '${{ workspace }}/x', target = 'rustup/x' }",
            "`tool.fetch.storage.files[0] source`",
        ),
        (
            "{ mode = 'copy', source = '${{ storage.rustup }}', target = 'rustup/x' }",
            "`tool.fetch.storage.files[0] source`",
        ),
        (
            "{ mode = 'copy', source = '~/.strands/box/x', target = 'rustup/x' }",
            "`tool.fetch.storage.files[0] source`",
        ),
        (
            "{ source = '~/.rustup/settings.toml', target = 'rustup/x' }",
            "`tool.fetch.storage.files[0]` needs `mode`",
        ),
        (
            "{ mode = 'copy', source = '~/.rustup/settings.toml', target = 'other/x' }",
            "which `[tool.fetch.storage] directories` does not name",
        ),
        (
            "{ mode = 'copy', source = '~/.rustup/settings.toml', target = 'rustup' }",
            "is not a storage directory and a path below it",
        ),
        (
            "{ mode = 'copy', source = '~/.rustup/settings.toml', target = 'rustup/a' }, \
             { mode = 'copy', source = '~/.rustup/notes', target = 'rustup/a/b' }",
            "cannot copy to the target of another or inside it",
        ),
        (
            "{ mode = 'copy', source = '~/.rustup/notes', target = 'rustup/a/b' }, \
             { source = '~/.rustup', target = 'rustup/a', mode = 'link-children' }",
            "a copy and a link cannot share a target or lie one inside the other",
        ),
        (
            "{ mode = 'copy', source = '~/.rustup/notes', target = 'rustup/a' }, \
             { source = '~/.rustup', target = 'rustup/a', mode = 'link' }",
            "a copy and a link cannot share a target",
        ),
        (
            "{ mode = 'copy', source = '~/.rustup/notes', target = 'rustup/a', each = true }",
            "holds the unknown key `each`",
        ),
        (
            "{ source = '~/.rustup/notes', target = 'rustup/a', mode = 'move' }",
            "`tool.fetch.storage.files[0] mode` is \"copy\", \"link\", or \"link-children\"",
        ),
        (
            "{ mode = 'copy', source = '~/.rustup/settings.toml', target = 'rustup/a', keep = [['a']] }",
            "needs `kind`",
        ),
    ] {
        let reason = refused(rows);
        assert!(reason.contains(expected), "{rows}: {reason}");
    }
    let granted = scene.refusal(
        "[agent]\ncommand = ['/usr/bin/true']\nfilesystem.write = ['~/scratch']\n\
         [tool.fetch]\ncommand = ['/usr/bin/true']\nstorage.directories = ['rustup']\n\
         storage.files = [{ mode = 'copy', source = '~/scratch/x', target = 'rustup/x' }]",
    );
    assert!(
        granted.contains("`tool.fetch.storage.files[0] source`")
            && granted.contains("a write grant"),
        "{granted}"
    );
}

#[test]
fn a_copy_row_replaces_the_link_an_earlier_link_row_left_at_its_target() {
    let scene = Scene::new();
    let host = scene.home().join(".rustup");
    std::fs::create_dir_all(host.join("toolchains/stable")).expect("a toolchain");
    std::fs::write(host.join("settings.toml"), "profile = \"minimal\"\n").expect("settings");
    let tool = |row: &str| {
        profile(&format!(
            "[agent]\ncommand = ['/usr/bin/true']\n\
             [tool.fetch]\ncommand = ['/usr/bin/true']\n\
             storage.directories = ['rustup']\nstorage.files = [{row}]"
        ))
    };
    let run = scene.root.join("run");
    std::fs::create_dir_all(&run).expect("a run directory");
    let step = |row: &str| {
        let resolved = scene.resolve(&tool(row)).expect("a row");
        crate::run::prepare_storage(&resolved.storage, &scene.home()).expect("storage");
        crate::run::link_storage(&resolved.storage).expect("links");
        crate::storage_sync::copy_files(&resolved.storage, &run, &scene.home(), &scene.home())
    };
    let state = scene.storage().join("tool/fetch/rustup");
    step("{ source = '~/.rustup/settings.toml', target = 'rustup/settings.toml', mode = 'link' }")
        .expect("a link");
    assert!(state.join("settings.toml").is_symlink());
    for row in [
        "{ mode = 'copy', source = '~/.rustup/settings.toml', target = 'rustup/settings.toml' }",
        "{ mode = 'copy', source = '~/.rustup/settings.toml', target = 'rustup/settings.toml', kind = 'toml', \
           set = [{ key = ['default_toolchain'], value = 'stable' }] }",
    ] {
        step(row).expect("a copy");
        let target = state.join("settings.toml");
        assert!(!target.is_symlink(), "the old link is gone: {row}");
        let copy = std::fs::read_to_string(&target).expect("a copy");
        assert!(copy.contains("profile = \"minimal\""), "{copy}");
        std::fs::write(host.join("settings.toml"), "profile = \"minimal\"\n").expect("unchanged");
    }
    assert!(
        !host.join("settings.toml").is_symlink()
            && std::fs::read_to_string(host.join("settings.toml"))
                .expect("the host file")
                .contains("minimal"),
        "removing the link leaves the host file alone"
    );
    std::fs::create_dir_all(host.join("conf")).expect("a folder");
    std::fs::write(host.join("conf/a.toml"), "a = 1\n").expect("a file in it");
    step("{ source = '~/.rustup/conf', target = 'rustup/conf', mode = 'link' }")
        .expect("a folder link");
    assert!(state.join("conf").is_symlink());
    step(
        "{ mode = 'copy', source = '~/.rustup/conf/a.toml', target = 'rustup/conf/a.toml', kind = 'toml', \
           set = [{ key = ['b'], value = 'two' }] }",
    )
    .expect("a copy below the old folder link");
    assert!(
        !state.join("conf").is_symlink(),
        "the old folder link is gone"
    );
    assert!(state.join("conf").is_dir());
    let copy = std::fs::read_to_string(state.join("conf/a.toml")).expect("a copy");
    assert!(
        copy.contains("a = 1") && copy.contains("b = \"two\""),
        "{copy}"
    );
    assert_eq!(
        std::fs::read_to_string(host.join("conf/a.toml")).expect("the host file"),
        "a = 1\n",
        "the host file is untouched"
    );
    step(
        "{ source = '~/.rustup/toolchains', target = 'rustup/toolchains', \
           mode = 'link-children' }",
    )
    .expect("a folder of links");
    let error =
        step("{ mode = 'copy', source = '~/.rustup/toolchains', target = 'rustup/toolchains' }")
            .expect_err("a folder of old links");
    let text = error.to_string();
    assert!(
        text.contains("an earlier `link-children` row") && text.contains("toolchains"),
        "{text}"
    );
    assert!(
        state.join("toolchains/stable").is_symlink(),
        "the folder is left as it is"
    );
}

#[test]
fn preparation_does_not_follow_a_workspace_cache_link() {
    let scene = Scene::new();
    let workspace = scene.root.join("external-project");
    let escaped = scene.root.join("escaped");
    std::fs::create_dir_all(&workspace).expect("workspace");
    std::fs::create_dir_all(&escaped).expect("other directory");
    std::os::unix::fs::symlink(&escaped, workspace.join(".cache")).expect("link");
    let context = Context {
        workspace: workspace.clone(),
        os: "macos",
    };
    let resolved = scene.resolve_with(&profile("[agent]\ncommand = ['/usr/bin/true']\n[tool.fetch]\ncommand = ['/usr/bin/true']\nenv.CACHE = '${{ cache }}'"), &context).expect("profile");
    crate::run::prepare_storage(&resolved.storage, &scene.home()).expect("storage");
    assert!(
        !escaped.join("fetch").exists(),
        "no host write through the link"
    );
}

#[test]
fn the_shipped_yarn_pack_points_yarn_at_the_boxs_proxy() {
    let (scene, _) = servers_scene();
    let bin = scene.root.join("installed/bin");
    scene.share_raw(
        "yarn",
        include_str!("../../../../resources/packs/yarn/pack.toml"),
    );
    scene.share_raw(
        "node",
        include_str!("../../../../resources/packs/node/pack.toml"),
    );
    crate::test_support::binary(&bin.join("yarn"));
    crate::test_support::binary(&bin.join("node"));
    let resolved = scene
        .resolve_using(
            &profile("packs = ['@box/yarn']\n[agent]\ncommand = ['/usr/bin/true']"),
            &scene.context(),
            &mut OnPath(bin),
        )
        .expect("profile");
    let env = &resolved.tool["yarn"].env;
    let yarn: Vec<(&str, &str)> = env
        .iter()
        .filter(|(name, _)| name.starts_with("YARN_"))
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    assert_eq!(
        yarn,
        [
            ("YARN_CACHE_FOLDER", env["YARN_CACHE_FOLDER"].as_str()),
            ("YARN_ENABLE_GLOBAL_CACHE", "false"),
            ("YARN_ENABLE_TELEMETRY", "0"),
            ("YARN_GLOBAL_FOLDER", env["YARN_GLOBAL_FOLDER"].as_str()),
            ("YARN_HTTPS__PROXY", "${HTTPS_PROXY:-}"),
            ("YARN_HTTP__PROXY", "${HTTP_PROXY:-}"),
        ],
        "Yarn 1 reads a single-underscore YARN_*_PROXY as written"
    );
}

#[test]
fn the_shipped_node_pack_reads_the_hosts_file() {
    let (scene, _) = servers_scene();
    let bin = scene.root.join("installed/bin");
    scene.share_raw(
        "node",
        include_str!("../../../../resources/packs/node/pack.toml"),
    );
    crate::test_support::binary(&bin.join("node"));
    let resolved = scene
        .resolve_using(
            &profile("packs = ['@box/node']\n[agent]\ncommand = ['/usr/bin/true']"),
            &Context {
                workspace: scene.workspace(),
                os: std::env::consts::OS,
            },
            &mut OnPath(bin),
        )
        .expect("profile");
    let hosts = if cfg!(target_os = "macos") {
        "/private/etc/hosts"
    } else {
        "/etc/hosts"
    };
    let expected: Vec<String> = std::fs::canonicalize(hosts)
        .map(|path| vec![path.display().to_string()])
        .unwrap_or_default();
    assert_eq!(resolved.tool["node"].filesystem.read_file, expected);
}

#[test]
fn the_shipped_launchers_that_run_node_as_a_helper_read_the_hosts_file() {
    for pack in [
        include_str!("../../../../resources/packs/bunx/pack.toml"),
        include_str!("../../../../resources/packs/pnpx/pack.toml"),
    ] {
        let table: toml::Table = pack.parse().expect("TOML");
        let read_file = table["filesystem"]["read_file"].as_array().expect("a list");
        let paths: Vec<(&str, &str)> = read_file
            .iter()
            .map(|entry| {
                (
                    entry["path"].as_str().expect("a path"),
                    entry["when"].as_str().expect("a when"),
                )
            })
            .collect();
        assert_eq!(
            paths,
            [("/private/etc/hosts", "macos"), ("/etc/hosts", "linux")]
        );
    }
}

#[test]
fn the_shipped_bunx_pack_checks_its_node_helper_through_resolution() {
    for writable in [false, true] {
        let (scene, _) = servers_scene();
        let bin = scene.root.join("installed/bin");
        scene.share_raw(
            "bunx",
            include_str!("../../../../resources/packs/bunx/pack.toml"),
        );
        scene.share_raw(
            "node",
            include_str!("../../../../resources/packs/node/pack.toml"),
        );
        crate::test_support::binary(&bin.join("bunx"));
        let node = if writable {
            scene.workspace().join("node/bin/node")
        } else {
            scene.root.join("node/bin/node")
        };
        crate::test_support::binary(&node);
        std::os::unix::fs::symlink(&node, bin.join("node")).expect("node link");
        std::fs::write(
            scene.home().join(".agent.json"),
            r#"{"mcpServers":{"memory":{"command":"bunx","args":["memory"]}}}"#,
        )
        .expect("config");
        let resolved = scene
            .resolve_using(
                &profile("packs = ['@box/agent']\n[agent]\ncommand = ['/usr/bin/true']"),
                &scene.context(),
                &mut OnPath(bin),
            )
            .expect("profile");
        if writable {
            assert!(!resolved.mcp.contains_key("memory"));
            let skipped = format!("{:?}", resolved.servers.skipped);
            assert!(skipped.contains("@box/bunx"), "{skipped}");
            assert!(skipped.contains("helper node"), "{skipped}");
            assert!(skipped.contains("workspace"), "{skipped}");
        } else {
            assert!(
                resolved.servers.skipped.is_empty(),
                "{:?}",
                resolved.servers.skipped
            );
            let reads = strings(&resolved.mcp["memory"]["filesystem"]["read"]);
            assert!(
                reads.contains(&node.parent().unwrap().display().to_string()),
                "the shipped helper supplies its runtime directory: {reads:?}"
            );
        }
    }
}

#[test]
fn a_missing_absolute_launcher_is_refused_as_not_executable_without_path() {
    for pack in ["npx", "uvx"] {
        let (scene, bin) = servers_scene();
        scene.share(pack, &crate::lang::test_tool_pack(pack, ""));
        let missing = scene.root.join("missing install/bin").join(pack);
        std::fs::write(
            scene.home().join(".agent.json"),
            serde_json::json!({"mcpServers": {"s": {"command": missing, "args": ["pkg"]}}})
                .to_string(),
        )
        .expect("the host configuration");
        let resolved = scene
            .resolve_using(
                &profile(&format!(
                    "packs = ['@box/agent', '@box/{pack}']\n[agent]\ncommand = ['/usr/bin/true']"
                )),
                &scene.context(),
                &mut OnPath(bin.clone()),
            )
            .expect("a skipped server does not stop resolution");
        assert!(resolved.mcp.is_empty(), "{pack}");
        assert_eq!(
            resolved
                .servers
                .skipped
                .iter()
                .map(|skip| skip.reason.as_str())
                .collect::<Vec<_>>(),
            [format!(
                "runs {}, which is not an executable file",
                missing.display()
            )],
            "{pack}"
        );
    }
}

#[test]
fn absolute_mcp_commands_resolve_each_launchers_selected_installation() {
    for (program, pack) in [("npx", "npx"), ("uvx", "uvx")] {
        let (scene, bin) = servers_scene();
        crate::test_support::binary(&bin.join(pack));
        scene.share(
            pack,
            &crate::lang::test_tool_pack(
                pack,
                "[env]\nSELECTED_ROOT = '${{ root }}'\n[filesystem]\nread = ['${{ root.parent }}/support']",
            ),
        );
        std::fs::create_dir_all(scene.root.join("support")).expect("the PATH tool's support");
        let mut entries = serde_json::Map::new();
        let mut selected = Vec::new();
        for name in ["first", "second"] {
            let installation = scene.root.join(format!("{name} installation"));
            let executable = installation.join("bin").join(program);
            crate::test_support::binary(&executable);
            std::fs::create_dir_all(installation.join("support")).expect("runtime support");
            let args = vec![format!("{name}-server")];
            entries.insert(
                name.to_string(),
                serde_json::json!({"command": executable, "args": args}),
            );
            selected.push((name, executable, installation));
        }
        std::fs::write(
            scene.home().join(".agent.json"),
            serde_json::json!({"mcpServers": entries}).to_string(),
        )
        .expect("the host configuration");
        let resolved = scene
            .resolve_using(
                &profile(&format!(
                    "packs = ['@box/agent', '@box/{pack}']\n[agent]\ncommand = ['/usr/bin/true']"
                )),
                &scene.context(),
                &mut OnPath(bin.clone()),
            )
            .expect("independent runtime resolution");
        assert_eq!(resolved.mcp.len(), 2, "{:?}", resolved.servers.skipped);
        for (name, executable, installation) in &selected {
            let server = &resolved.mcp[*name];
            assert_eq!(server["command"][0].as_str(), executable.to_str());
            assert_eq!(
                server["env"]["SELECTED_ROOT"].as_str(),
                installation.join("bin").to_str()
            );
            let reads = strings(&server["filesystem"]["read"]);
            assert!(
                reads.contains(&installation.join("support").display().to_string()),
                "{reads:?}"
            );
            assert!(
                !reads.contains(&scene.root.join("support").display().to_string()),
                "a server does not inherit the PATH tool's installation: {reads:?}"
            );
            for (_, _, other) in selected.iter().filter(|(other, _, _)| other != name) {
                assert!(
                    !reads.contains(&other.join("support").display().to_string()),
                    "a server does not inherit another selected installation: {reads:?}"
                );
            }
        }
        assert_eq!(
            resolved.tool[pack].env["SELECTED_ROOT"],
            bin.display().to_string(),
            "the agent's tool keeps its PATH-selected installation"
        );
    }
}

/// A profile with a server that `npx` starts, the agent's `config` directory, and the tool
/// `fetch`'s `prefix` state.
const LAUNCHER_CACHE_PROFILE: &str = "packs = ['@box/agent', '@box/npx']\n\
     [agent]\ncommand = ['/usr/bin/true']\n[storage]\ndirectories = ['config']\n\
     [tool.fetch]\ncommand = ['/usr/bin/true']\nstorage.directories = ['prefix']";

/// A scene whose host file names the server `memory`, which `npx` starts.
fn launcher_cache_scene() -> (Scene, PathBuf) {
    let (scene, bin) = servers_scene();
    crate::test_support::binary(&bin.join("npx"));
    scene.share("npx", &crate::lang::test_tool_pack("npx", ""));
    std::fs::write(
        scene.home().join(".agent.json"),
        r#"{"mcpServers":{"memory":{"command":"npx","args":["memory"]}}}"#,
    )
    .expect("the host configuration");
    (scene, bin)
}

/// **The Shell and Monty cannot write a launcher cache**, which a later run's MCP server runs
/// code from: the box home's forbids name no launcher cache, so no operator permit opens one. They
/// still leave the agent's storage directories and each tool's state to the permits.
#[test]
fn the_box_home_forbids_cover_launcher_caches_and_spare_storage_and_tool_states() {
    let (scene, bin) = launcher_cache_scene();
    let (resolved, compiled) = scene
        .compile_using(
            &profile(LAUNCHER_CACHE_PROFILE),
            &mut OnPath(bin),
            "/usr/bin:/bin",
        )
        .expect("a compile");
    let root = &resolved.storage.root;
    let cache = root.join("mcp-cache/npx");
    assert!(
        strings(&resolved.mcp["memory"]["filesystem"]["write"])
            .contains(&cache.display().to_string()),
        "the server writes its launcher cache"
    );
    let tilde = |path: &Path| {
        format!(
            "~/{}",
            path.strip_prefix(scene.home())
                .expect("below the home")
                .display()
        )
    };
    for verb in ["write", "delete", "move"] {
        let forbid = compiled
            .policy
            .lines()
            .find(|line| line.starts_with(&format!("@id(\"box_home_{verb}\") forbid")))
            .unwrap_or_else(|| panic!("box_home_{verb} in\n{}", compiled.policy));
        assert!(
            !forbid.contains("mcp-cache"),
            "a launcher cache stays under the forbid: {forbid}"
        );
        let spared: Vec<&PathBuf> = resolved
            .storage
            .directories
            .iter()
            .chain(&resolved.storage.tool_states)
            .collect();
        assert_eq!(spared.len(), 2, "one storage directory and one tool state");
        for spared in spared {
            let spared = tilde(spared);
            assert!(
                forbid.contains(&format!(
                    "(context.input.path == \"{spared}\" || context.input.path like \
                     \"{spared}/*\")"
                )),
                "{spared} is left to the permits: {forbid}"
            );
        }
    }
}

/// **Only a launcher cache's own servers hold a write grant in it.** The agent, a tool, and any
/// other server are refused, as for any other folder that a later run trusts. A tool's state
/// stays writable by any grant.
#[test]
fn a_write_grant_in_a_launcher_cache_passes_only_for_its_own_servers() {
    let (scene, bin) = launcher_cache_scene();
    let resolved = scene
        .resolve_using(
            &profile(LAUNCHER_CACHE_PROFILE),
            &scene.context(),
            &mut OnPath(bin.clone()),
        )
        .expect("a resolve");
    let cache = resolved.storage.root.join("mcp-cache/npx");
    let state = resolved.storage.root.join("tool/fetch/prefix");
    let compile = |extra: &str| {
        scene.compile_using(
            &profile(&format!("{LAUNCHER_CACHE_PROFILE}\n{extra}")),
            &mut OnPath(bin.clone()),
            "/usr/bin:/bin",
        )
    };
    compile(&format!(
        "[mcp.memory]\nfilesystem.write = [{:?}]",
        cache.join("extra").display().to_string()
    ))
    .expect("the cache's own server writes in it");
    compile(&format!(
        "[agent.filesystem]\nwrite = [{:?}]",
        state.display().to_string()
    ))
    .expect("a grant in a tool's state passes");
    let (_, opted_out) = compile(
        "[experimental-features]\nnative-filesystem-policy = true\n\
         [mcp.memory]\nnative-filesystem-policy = false",
    )
    .expect("a launcher server opts out of native filesystem policy");
    assert_eq!(
        table(&opted_out)["mcp"]["memory"]["native-filesystem-policy"].as_bool(),
        Some(false),
        "{}",
        opted_out.box_toml
    );
    assert!(opted_out.unstarted.is_empty(), "{:?}", opted_out.unstarted);
    for selection in [
        "[experimental-features]\nnative-filesystem-policy = true",
        "[mcp.memory]\nnative-filesystem-policy = true",
    ] {
        let (_, selected) = compile(selection).expect("a launcher server under native policy");
        let reason = selected
            .unstarted
            .iter()
            .find(|(server, _)| server == "memory")
            .map(|(_, reason)| reason.as_str())
            .unwrap_or_else(|| panic!("{selection}: memory starts: {:?}", selected.unstarted));
        assert!(
            reason.contains("native-filesystem-policy = false") && reason.contains("[mcp.memory]"),
            "{selection}: {reason}"
        );
        assert!(
            !selected.policy.contains("mcp_memory_spawn"),
            "{selection}: {}",
            selected.policy
        );
    }
    for (table, grant) in [
        ("[agent.filesystem]", cache.clone()),
        ("[agent.filesystem]", cache.join("_npx")),
        ("[tool.fetch.filesystem]", cache.clone()),
        (
            "[mcp.other]\ntype = 'stdio'\ncommand = ['/usr/bin/true']\n[mcp.other.filesystem]",
            cache.clone(),
        ),
    ] {
        let error = compile(&format!(
            "{table}\nwrite = [{:?}]",
            grant.display().to_string()
        ))
        .expect_err("a grant in a server's launcher cache");
        assert!(
            matches!(&error, Error::WriteOverProtected { grant: refused, .. } if *refused == grant),
            "{table} {}: {error}",
            grant.display()
        );
    }
}

#[test]
fn launcher_resolution_keeps_profile_credentials_private_and_skips_only_that_server() {
    for (requirements, reason) in [
        (
            "[inputs.secret]\nfrom = 'env:SET'\n[env]\nSECRET = '${{ inputs.secret }}'",
            "credential",
        ),
        (
            "[filesystem]\nmetadata = ['${{ root }}']",
            "filesystem grants",
        ),
        ("[filesystem]\nexec = ['${{ root }}']", "filesystem grants"),
        (
            "[filesystem]\nwrite = ['${{ home }}/extra']",
            "filesystem grants",
        ),
        (
            "[filesystem]\nwrite_file = ['${{ home }}/extra-file']",
            "filesystem grants",
        ),
        (
            "[inputs.bad]\ndefault = 'relative'\n[filesystem]\nread = ['${{ inputs.bad }}']",
            "not an absolute path",
        ),
        (
            "helpers = ['missing-helper']\n[env]\nCACHE = '${{ cache }}'",
            "",
        ),
        ("when = 'linux'", "not enabled"),
        (
            "hosts = ['registry.npmjs.org']\nupgrade_http = ['registry.npmjs.org']",
            "upgrade_http",
        ),
    ] {
        let (scene, bin) = servers_scene();
        for launcher in ["npx", "uvx"] {
            crate::test_support::binary(&bin.join(launcher));
        }
        std::fs::create_dir_all(scene.home().join("extra")).expect("write directory");
        std::fs::write(scene.home().join("extra-file"), "test").expect("write file");
        scene.share(
            "npx",
            &format!(
                "kind = \"tool\"\n[inputs.npx.path]\ntype = \"program\"\n\
                                     program = \"npx\"\nsearch = [{{ env = \"PATH\" }}]\n[run]\n\
                                     command = [\"${{{{ inputs.npx.path }}}}\"]\n{requirements}"
            ),
        );
        scene.share(
            "uvx",
            "kind = \"tool\"\n[inputs.uvx.path]\ntype = \"program\"\nprogram = \"uvx\"\n\
             search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.uvx.path }}\"]\n[env]\n\
             CACHE = '${{ cache }}'\n[filesystem]\ndeny = ['${{ home }}/private-launcher-file']",
        );
        std::fs::write(
            scene.home().join(".agent.json"),
            r#"{"mcpServers":{"memory":{"command":"npx"},"time":{"command":"uvx"}}}"#,
        )
        .expect("config");
        let text = "packs = ['@box/agent']\n[agent]\ncommand = ['/usr/bin/true']\n[egress.model.secret]\nref = 'env://SET'";
        let resolved = scene
            .resolve_using(&profile(text), &scene.context(), &mut OnPath(bin))
            .expect("the profile still resolves");
        assert!(
            resolved.mcp.contains_key("time"),
            "the other launcher still resolves"
        );
        assert!(resolved.tool.is_empty(), "no implicit agent tools");
        assert!(
            resolved.mcp["time"]["filesystem"]["deny"]
                .as_array()
                .expect("denies")
                .contains(&toml::Value::from(
                    scene
                        .home()
                        .join("private-launcher-file")
                        .display()
                        .to_string()
                )),
            "the ordinary pack's deny reaches MCP"
        );
        if reason.is_empty() {
            assert!(
                resolved.mcp.contains_key("memory"),
                "absent optional helpers do not skip the launcher"
            );
        } else {
            assert!(!resolved.mcp.contains_key("memory"));
            let skipped = format!("{:?}", resolved.servers.skipped);
            assert!(skipped.contains(reason), "{skipped}");
            assert!(
                !skipped.contains("set-value"),
                "the credential stays private: {skipped}"
            );
        }
    }
}

/// The keys of a `[[storage.hooks]]` row for a file that holds a list of hooks.
const HOOK_LAYOUT: &str = "kind = \"json\"\nkey = [\"hooks\", \"*\"]\ncommand = [\"run\"]\n\
     [[storage.hooks.set]]\nkey = [\"run\"]\nvalue = \". ${{ script }}\"\n";

#[test]
fn an_agent_ingress_reaches_box_toml_and_turns_on_the_ingress_switch() {
    let scene = Scene::new();
    let text = "[agent]\ncommand = [\"/bin/x\"]\n\
                [[agent.ingress]]\nlisten = \"127.0.0.1:8080\"\nworkload_port = 8081\n\
                [[agent.ingress]]\nlisten = \"0.0.0.0:8000\"\nworkload_port = 8001\n";
    let compiled = scene.compile(&profile(text), None).expect("a compile");
    let file = table(&compiled);
    // The whole value, so a key the condition walk leaves behind, such as a `when`, fails here.
    assert_eq!(
        file["agent"]["ingress"],
        toml::Value::Array(vec![
            toml::toml! { listen = "127.0.0.1:8080" workload_port = 8081 }.into(),
            toml::toml! { listen = "0.0.0.0:8000" workload_port = 8001 }.into(),
        ]),
        "{}",
        compiled.box_toml
    );
    assert_eq!(
        file["experimental-features"]["ingress"].as_bool(),
        Some(true),
        "{}",
        compiled.box_toml
    );
}

/// **An `[egress.<name>]` backend and a telemetry target reach `box.toml` as written**, because a
/// profile carries both sections as tables and Box Core owns their keys. The same holds for an
/// agent's `[[agent.ingress]]`, which `box` passes through for Box Core to validate.
#[test]
fn egress_backends_and_telemetry_targets_reach_box_toml_unchanged() {
    let scene = Scene::new();
    let text = "[agent]\ncommand = [\"/bin/x\"]\n\
                [egress.model]\ndestinations = [\"bedrock-runtime.us-west-2.amazonaws.com\"]\n\
                [[egress.model.backends]]\nname = \"agentcore-gateway\"\n\
                url = \"https://gw.example.com\"\nauth.ref = \"aws://default\"\n\
                [telemetry.xray]\nkind = \"cloudwatch_traces\"\nregion = \"us-west-2\"\n\
                secret.ref = \"aws://default\"\n";
    let compiled = scene.compile(&profile(text), None).expect("a compile");
    let file = table(&compiled);
    assert_eq!(
        file["egress"]["model"]["backends"],
        toml::Value::Array(vec![
            toml::toml! {
                name = "agentcore-gateway"
                url = "https://gw.example.com"
                auth = { ref = "aws://default" }
            }
            .into()
        ]),
        "{}",
        compiled.box_toml
    );
    assert_eq!(
        file["telemetry"]["xray"],
        toml::Value::Table(toml::toml! {
            kind = "cloudwatch_traces"
            region = "us-west-2"
            secret = { ref = "aws://default" }
        }),
        "a profile's own target keeps its keys, and `box` adds none: {}",
        compiled.box_toml
    );
    assert!(
        file["telemetry"]["records"]["include"].is_array(),
        "`box` fills its own records target: {}",
        compiled.box_toml
    );
    assert!(
        compiled
            .policy
            .contains("bedrock-runtime.us-west-2.amazonaws.com"),
        "policy decides the route's own destination: {}",
        compiled.policy
    );
}

/// **An agent pack declares no ingress**: a top-level `[[ingress]]` in it is refused as an unknown
/// key, as in a support pack or a profile, so the only spellings are `[[agent.ingress]]` in a
/// profile or a support pack.
#[test]
fn an_agent_pack_declares_no_ingress() {
    let scene = Scene::new();
    scene.share_raw(
        "srv",
        "[pack]\nname = \"@box/srv\"\nversion = 1\nkind = \"agent\"\n\
         [run]\ncommand = [\"/bin/srv\"]\n\
         [[ingress]]\nlisten = \"0.0.0.0:8080\"\nworkload_port = 8081\n",
    );
    let error = scene
        .compile(&profile("packs = [\"@box/srv\"]"), None)
        .expect_err("an agent pack's ingress is refused");
    assert!(error.to_string().contains("ingress"), "{error}");
}

/// **A profile's `[[agent.ingress]]` entries add to a pack's**, packs first, and an active profile
/// row replaces the pack rows for its `workload_port`.
#[test]
fn ingress_entries_from_a_pack_and_a_profile_add_up() {
    let scene = Scene::new();
    scene.share(
        "srv",
        "[[agent.ingress]]\nlisten = \"127.0.0.1:9000\"\nworkload_port = 9001\n",
    );
    let compiled = scene
        .compile(
            &profile(
                "packs = [\"@box/srv\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
                 [[agent.ingress]]\nlisten = \"127.0.0.1:8080\"\nworkload_port = 8081\n",
            ),
            None,
        )
        .expect("a compile");
    let file = table(&compiled);
    assert_eq!(
        file["agent"]["ingress"],
        toml::Value::Array(vec![
            toml::toml! { listen = "127.0.0.1:9000" workload_port = 9001 }.into(),
            toml::toml! { listen = "127.0.0.1:8080" workload_port = 8081 }.into(),
        ]),
        "{}",
        compiled.box_toml
    );

    // A profile row for the pack's `workload_port` replaces the pack's row, so a profile can keep
    // a pack's `0.0.0.0` listener on loopback.
    let scene = Scene::new();
    scene.share(
        "srv",
        "[[agent.ingress]]\nlisten = \"0.0.0.0:8080\"\nworkload_port = 8081\n",
    );
    let narrowed = scene
        .compile(
            &profile(
                "packs = [\"@box/srv\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
                 [[agent.ingress]]\nlisten = \"127.0.0.1:8080\"\nworkload_port = 8081\n",
            ),
            None,
        )
        .expect("a compile");
    assert_eq!(
        table(&narrowed)["agent"]["ingress"],
        toml::Value::Array(vec![
            toml::toml! { listen = "127.0.0.1:8080" workload_port = 8081 }.into(),
        ]),
        "the profile's row replaces the pack's for one workload port: {}",
        narrowed.box_toml
    );

    // Rows of one layer never replace each other, so a profile's one-row-per-OS listeners for one
    // port survive a pack that declares ingress on another port.
    let scene = Scene::new();
    scene.share(
        "srv",
        "[[agent.ingress]]\nlisten = \"127.0.0.1:9000\"\nworkload_port = 9001\n",
    );
    let per_os = scene
        .compile(
            &profile(
                "packs = [\"@box/srv\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
                 [[agent.ingress]]\nlisten = \"127.0.0.1:8080\"\nworkload_port = 8081\nwhen = \"macos\"\n\
                 [[agent.ingress]]\nlisten = \"0.0.0.0:8080\"\nworkload_port = 8081\nwhen = \"linux\"\n",
            ),
            None,
        )
        .expect("a compile on macOS");
    assert_eq!(
        table(&per_os)["agent"]["ingress"],
        toml::Value::Array(vec![
            toml::toml! { listen = "127.0.0.1:9000" workload_port = 9001 }.into(),
            toml::toml! { listen = "127.0.0.1:8080" workload_port = 8081 }.into(),
        ]),
        "a layer's own rows keep their `when`: {}",
        per_os.box_toml
    );

    // A pack row and a profile's per-OS rows on the same port: the profile's layer replaces the pack
    // row, and each of its rows reaches `when`, so the macOS row survives on macOS.
    let scene = Scene::new();
    scene.share(
        "srv",
        "[[agent.ingress]]\nlisten = \"0.0.0.0:8080\"\nworkload_port = 8081\n",
    );
    let same_port = scene
        .compile(
            &profile(
                "packs = [\"@box/srv\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
                 [[agent.ingress]]\nlisten = \"127.0.0.1:8080\"\nworkload_port = 8081\nwhen = \"macos\"\n\
                 [[agent.ingress]]\nlisten = \"127.0.0.1:9090\"\nworkload_port = 8081\nwhen = \"linux\"\n",
            ),
            None,
        )
        .expect("a compile on macOS");
    assert_eq!(
        table(&same_port)["agent"]["ingress"],
        toml::Value::Array(vec![
            toml::toml! { listen = "127.0.0.1:8080" workload_port = 8081 }.into(),
        ]),
        "the profile replaces the pack's port, and its macOS row stays: {}",
        same_port.box_toml
    );

    // A profile row replaces only on a run where its `when` holds, so a Linux-only row keeps the
    // pack's row on macOS.
    let scene = Scene::new();
    scene.share(
        "srv",
        "[[agent.ingress]]\nlisten = \"0.0.0.0:8080\"\nworkload_port = 8081\n",
    );
    let inactive = scene
        .compile(
            &profile(
                "packs = [\"@box/srv\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
                 [[agent.ingress]]\nlisten = \"127.0.0.1:8080\"\nworkload_port = 8081\nwhen = \"linux\"\n",
            ),
            None,
        )
        .expect("a compile on macOS");
    assert_eq!(
        table(&inactive)["agent"]["ingress"],
        toml::Value::Array(vec![
            toml::toml! { listen = "0.0.0.0:8080" workload_port = 8081 }.into(),
        ]),
        "a profile row a false `when` drops replaces nothing: {}",
        inactive.box_toml
    );

    // Two packs never replace each other's rows, so both reach Box Core, which refuses the clash.
    let scene = Scene::new();
    scene.share(
        "a",
        "[[agent.ingress]]\nlisten = \"127.0.0.1:8080\"\nworkload_port = 8081\n",
    );
    scene.share(
        "b",
        "[[agent.ingress]]\nlisten = \"0.0.0.0:8080\"\nworkload_port = 8081\n",
    );
    let siblings = scene
        .compile(
            &profile("packs = [\"@box/a\", \"@box/b\"]\n[agent]\ncommand = [\"/bin/x\"]\n"),
            None,
        )
        .expect("a compile");
    assert_eq!(
        table(&siblings)["agent"]["ingress"],
        toml::Value::Array(vec![
            toml::toml! { listen = "127.0.0.1:8080" workload_port = 8081 }.into(),
            toml::toml! { listen = "0.0.0.0:8080" workload_port = 8081 }.into(),
        ]),
        "two packs' rows for one port both stay: {}",
        siblings.box_toml
    );
    let instance = scene.instance();
    std::fs::create_dir_all(&instance.directory).expect("the run directory");
    let config = instance.directory.join("box.toml");
    std::fs::write(&config, &siblings.box_toml).expect("box.toml");
    std::fs::write(instance.directory.join("policy.dw"), &siblings.policy).expect("policy.dw");
    let refused = match strands_box::check_policy(config) {
        Err(error) => error.to_string(),
        Ok(checked) => format!("{:?}", checked.errors()),
    };
    assert!(
        refused.contains("two entries"),
        "Box Core refuses two pack rows that clash: {refused}"
    );

    let scene = Scene::new();
    let dropped = scene
        .compile(
            &profile(
                "[agent]\ncommand = [\"/bin/x\"]\n\
                 [[agent.ingress]]\nlisten = \"127.0.0.1:8080\"\nworkload_port = 8081\n\
                 when = \"linux\"\n",
            ),
            None,
        )
        .expect("a compile on macOS");
    let file = table(&dropped);
    assert!(
        file["agent"].get("ingress").is_none()
            && file
                .get("experimental-features")
                .and_then(|features| features.get("ingress"))
                .is_none(),
        "a dropped entry writes no ingress and no switch: {}",
        dropped.box_toml
    );
}

#[test]
fn an_agent_without_ingress_turns_on_no_ingress_switch() {
    let compiled = Scene::new()
        .compile(&profile("[agent]\ncommand = [\"/bin/x\"]\n"), None)
        .expect("a compile");
    let file = table(&compiled);
    assert!(
        file["agent"].get("ingress").is_none(),
        "{}",
        compiled.box_toml
    );
    assert!(
        file.get("experimental-features")
            .and_then(|features| features.get("ingress"))
            .is_none(),
        "{}",
        compiled.box_toml
    );
}

#[test]
fn a_tool_ingress_is_refused() {
    let text = "[agent]\ncommand = [\"/bin/x\"]\n[tool.git]\nprogram = \"git\"\n\
                [[tool.git.ingress]]\nlisten = \"127.0.0.1:8080\"\nworkload_port = 8081\n";
    let error = Scene::new()
        .resolve(&profile(text))
        .expect_err("only [agent] takes ingress");
    assert!(
        error
            .to_string()
            .contains("`[tool.git]` holds the unknown key `ingress`"),
        "{error}"
    );
}

#[test]
fn a_storage_hooks_row_keeps_its_row_when_its_when_is_false() {
    let scene = Scene::new();
    scene.share(
        "agent",
        &format!(
            "[inputs.agent.import-hooks]\ntype = \"bool\"\ndefault = false\n\
             [storage]\ndirectories = [\"config\"]\n\
             [[storage.hooks]]\nsource = \"${{{{ home }}}}/.agent/hooks.json\"\n\
             target = \"config/hooks.json\"\n\
             when = {{ variable = \"inputs.agent.import-hooks\", equals = \"true\" }}\n{HOOK_LAYOUT}"
        ),
    );
    let rows = |text: &str| -> Vec<(String, bool)> {
        scene
            .resolve(&profile(text))
            .expect("a resolve")
            .storage
            .hooks
            .iter()
            .map(|row| (row.relative.clone(), row.import))
            .collect()
    };
    let packs = "packs = [\"@box/agent\"]\n[agent]\ncommand = [\"/bin/x\"]";
    assert_eq!(
        rows(packs),
        vec![("agent/config/hooks.json".to_string(), false)],
        "a row that imports nothing still removes the copy's hooks"
    );
    assert_eq!(
        rows(&format!("{packs}\n[options]\nagent.import-hooks = true")),
        vec![("agent/config/hooks.json".to_string(), true)]
    );
}

#[test]
fn a_storage_hooks_row_takes_only_its_keys_and_one_target() {
    let scene = Scene::new();
    let base = "[storage]\ndirectories = [\"config\"]\n[agent]\ncommand = [\"/bin/x\"]\n";
    let row = "[[storage.hooks]]\nsource = \"/s.json\"\ntarget = \"config/settings.json\"\n";
    let whole = format!("{row}{HOOK_LAYOUT}");
    for (text, expected) in [
        (
            format!("{row}mode = 1\n{HOOK_LAYOUT}"),
            "holds the unknown key `mode`",
        ),
        (row.to_string(), "needs `kind = \"json\"`"),
        (format!("{row}kind = \"toml\""), "is not \"json\""),
        (whole.replace("/s.json", ""), "source` is not a full path"),
        (
            format!("{whole}{whole}"),
            "is the target of another hooks row",
        ),
        (
            format!(
                "[[storage.files]]\nsource = \"/c\"\ntarget = \"config/agent\"\n\
                 [[storage.hooks]]\nsource = \"/s.json\"\ntarget = \"config/agent/settings.json\"\n\
                 {HOOK_LAYOUT}"
            ),
            "overlaps `storage.files[0]`",
        ),
    ] {
        let reason = scene.refusal(&format!("{base}{text}"));
        assert!(reason.contains(expected), "{text}: {reason}");
    }
    let resolved = scene
        .resolve(&profile(&format!(
            "{base}[[storage.files]]\nsource = \"/s.json\"\ntarget = \"config/settings.json\"\n\
             kind = \"json\"\nkeep = [[\"theme\"]]\n{whole}"
        )))
        .expect("a hooks row may share a copy's target");
    assert_eq!(resolved.storage.hooks.len(), 1);
}

/// A row with the harness name that `kind` once held stops the load, and the message says what
/// `kind` is.
#[test]
fn a_storage_hooks_row_whose_kind_names_a_harness_is_refused() {
    let scene = Scene::new();
    let reason = scene.refusal(
        "[storage]\ndirectories = [\"config\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
         [[storage.hooks]]\nsource = \"/s.json\"\ntarget = \"config/settings.json\"\n\
         kind = \"claude-code\"",
    );
    assert!(
        reason.contains("`storage.hooks[0] kind = \"claude-code\"` is not \"json\"")
            && reason.contains("`kind` is the format of the file"),
        "{reason}"
    );
}

/// A row states its layout in full, and each wrong shape stops the load with the key it names.
#[test]
fn a_storage_hooks_row_with_a_wrong_layout_is_refused() {
    let scene = Scene::new();
    let base = "[storage]\ndirectories = [\"config\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
                [[storage.hooks]]\nsource = \"/s.json\"\ntarget = \"config/settings.json\"\n\
                kind = \"json\"\n";
    let set = "[[storage.hooks.set]]\nkey = [\"run\"]\nvalue = \". ${{ script }}\"\n";
    let layout = "key = [\"hooks\", \"*\"]\ncommand = [\"run\"]\n";
    for (text, expected) in [
        (format!("command = [\"run\"]\n{set}"), "needs `key`"),
        (
            format!("key = [\"hooks\", \"*\"]\n{set}"),
            "needs `command`",
        ),
        (layout.to_string(), "needs `set`"),
        (
            format!("key = [\"*\", \"hooks\"]\ncommand = [\"run\"]\n{set}"),
            "starts with a top-level key and ends with \"*\"",
        ),
        (
            format!("key = [\"hooks\"]\ncommand = [\"run\"]\n{set}"),
            "starts with a top-level key and ends with \"*\"",
        ),
        (
            format!("key = \"hooks\"\ncommand = [\"run\"]\n{set}"),
            "is a list of one or more keys",
        ),
        (
            format!("{layout}keep-above = [1]\n{set}"),
            "`storage.hooks[0] keep-above` is a list of keys",
        ),
        (
            format!("{layout}only = \"command\"\n{set}"),
            "`storage.hooks[0] only` is a `{ key, equals }` table",
        ),
        (
            format!("{layout}only = {{ key = [\"type\"] }}\n{set}"),
            "`storage.hooks[0] only` needs `equals`",
        ),
        (
            format!("{layout}only = {{ key = [\"type\"], equals = \"c\", not = 1 }}\n{set}"),
            "holds the unknown key `not`",
        ),
        (
            format!("{layout}keep = [\"timeout\"]\n{set}"),
            "`storage.hooks[0] keep[0]` is a list of one or more keys",
        ),
        (
            format!("{layout}keep = [[\"run\"]]\n{set}"),
            "`storage.hooks[0] command` and `storage.hooks[0] keep[0]` both name run",
        ),
        (
            format!("{layout}drop = [\"note\"]\n{set}"),
            "`storage.hooks[0] drop[0]` is a list of one or more keys",
        ),
        (
            format!("{layout}drop = [{{ key = [\"shell\"] }}]\n{set}"),
            "`storage.hooks[0] drop[0]` needs `equals`",
        ),
        (
            format!("{layout}drop = [{{ equals = \"bash\" }}]\n{set}"),
            "`storage.hooks[0] drop[0]` needs `key`",
        ),
        (
            format!("{layout}drop = [{{ key = [\"shell\"], equals = 5 }}]\n{set}"),
            "`storage.hooks[0] drop[0] equals` is not a string",
        ),
        (
            format!("{layout}drop = [{{ key = [\"shell\"], equals = \"bash\", not = 1 }}]\n{set}"),
            "`storage.hooks[0] drop[0]` holds the unknown key `not`",
        ),
        (
            format!("{layout}drop = \"shell\"\n{set}"),
            "`storage.hooks[0] drop` is a list of key lists",
        ),
        (
            format!("{layout}keep = [[\"a\"]]\ndrop = [[\"a\", \"b\"]]\n{set}"),
            "`storage.hooks[0] keep[0]` and `storage.hooks[0] drop[0]` both name",
        ),
        (
            format!(
                "{layout}keep = [[\"timeout\"]]\n{set}[[storage.hooks.set]]\n\
                 key = [\"timeout\"]\nvalue = 5\n"
            ),
            "`storage.hooks[0] keep[0]` and `storage.hooks[0] set[1] key` both name timeout",
        ),
        (
            format!("{layout}[[storage.hooks.set]]\nkey = [\"run\"]\nvalue = \"true\"\n"),
            "holds `${{ script }}` once",
        ),
        (
            format!(
                "{layout}[[storage.hooks.set]]\nkey = [\"run\"]\n\
                 value = \"${{{{ script }}}} ${{{{ script }}}}\"\n"
            ),
            "holds `${{ script }}` once",
        ),
        (
            format!("{layout}[[storage.hooks.set]]\nkey = [\"run\"]\nvalue = {{ a = 1 }}\n"),
            "is not a string, a number, true or false, or a list of those",
        ),
        (
            format!("{layout}[[storage.hooks.set]]\nkey = [\"run\"]\nvalue = \"x\"\nmode = 1\n"),
            "`storage.hooks[0] set[0]` holds the unknown key `mode`",
        ),
        (
            format!("{layout}disable-key = \"\"\n{set}"),
            "`storage.hooks[0] disable-key` is empty",
        ),
        (
            format!(
                "key = [\"hooks\", \"*\", \"hooks\", \"*\"]\ncommand = [\"run\"]\n\
                 keep-above = [\"hooks\"]\n{set}"
            ),
            "`storage.hooks[0] keep-above` names `hooks`, which is a key of",
        ),
        (
            format!(
                "{layout}[[storage.hooks.set]]\nkey = [\"run\"]\n\
                 value = \". ${{{{ script }}}} ${{{{ home }}}}\"\n"
            ),
            "holds `${{ home }}`; a hook's `set` value holds text and `${{ script }}` only",
        ),
        (
            format!("{layout}{set}[[storage.hooks.set]]\nkey = [\"n\"]\nvalue = inf\n"),
            "is not a string, a number, true or false, or a list of those",
        ),
        (
            format!("{layout}disable-key = \"hooks\"\n{set}"),
            "`storage.hooks[0] disable-key` is the first key",
        ),
        (
            format!("{layout}disable-key = true\n{set}"),
            "`storage.hooks[0] disable-key` is not a string",
        ),
    ] {
        let reason = scene.refusal(&format!("{base}{text}"));
        assert!(reason.contains(expected), "{text}: {reason}");
    }
}

/// A row resolves each key of its layout, and a `set` value holds the script's place and each
/// other placeholder filled in.
#[test]
fn a_storage_hooks_row_resolves_its_layout() {
    use crate::lang::{HookSetting, HookValue};
    let scene = Scene::new();
    let resolved = scene
        .resolve(&profile(
            "[storage]\ndirectories = [\"config\"]\n[agent]\ncommand = [\"/bin/x\"]\n\
             [[storage.hooks]]\nsource = \"/s.json\"\ntarget = \"config/settings.json\"\n\
             kind = \"json\"\nkey = [\"hooks\", \"*\", \"*\", \"hooks\", \"*\"]\n\
             keep-above = [\"matcher\"]\nonly = { key = [\"type\"], equals = \"command\" }\n\
             command = [\"command\"]\nargs = [\"args\"]\nkeep = [[\"type\"], [\"timeout\"]]\n\
             drop = [{ key = [\"shell\"], equals = \"bash\" }, [\"note\"]]\n\
             disable-key = \"disableAllHooks\"\n\
             [[storage.hooks.set]]\nkey = [\"command\"]\nvalue = \"bash\"\n\
             [[storage.hooks.set]]\nkey = [\"args\"]\n\
             value = [\"-c\", \". ${{ script }}\", 5, true]\n",
        ))
        .expect("a resolve");
    let [row] = resolved.storage.hooks.as_slice() else {
        panic!("one row, got {:?}", resolved.storage.hooks);
    };
    let path = |keys: &[&str]| keys.iter().map(|key| key.to_string()).collect::<Vec<_>>();
    assert_eq!(row.key, path(&["hooks", "*", "*", "hooks", "*"]));
    assert_eq!(row.keep_above, path(&["matcher"]));
    assert_eq!(row.only, Some((path(&["type"]), "command".to_string())));
    assert_eq!(row.command, path(&["command"]));
    assert_eq!(row.args, Some(path(&["args"])));
    assert_eq!(row.keep, vec![path(&["type"]), path(&["timeout"])]);
    assert_eq!(
        row.drop,
        vec![
            crate::lang::HookDrop {
                key: path(&["shell"]),
                equals: Some("bash".to_string()),
            },
            crate::lang::HookDrop {
                key: path(&["note"]),
                equals: None,
            },
        ]
    );
    assert_eq!(row.disable_key.as_deref(), Some("disableAllHooks"));
    assert!(row.import, "a row with no `when` imports");
    assert_eq!(
        row.set,
        vec![
            HookSetting {
                key: path(&["command"]),
                value: HookValue::Text(vec!["bash".into()]),
            },
            HookSetting {
                key: path(&["args"]),
                value: HookValue::List(vec![
                    HookValue::Text(vec!["-c".into()]),
                    HookValue::Text(vec![". ".into(), String::new()]),
                    HookValue::Fixed(toml::Value::Integer(5)),
                    HookValue::Fixed(toml::Value::Boolean(true)),
                ]),
            },
        ]
    );
}
#[test]
fn a_pack_holds_no_profile_header() {
    let scene = Scene::new();
    scene.share("p", "[profile]\nname = \"weather\"");
    let (path, _, reason) = scene.located("packs = [\"@box/p\"]\n[agent]\ncommand = [\"/bin/x\"]");
    assert_eq!(path, scene.root.join("packs/p/pack.toml"));
    assert!(reason.contains("unknown key `profile`"), "{reason}");
}

#[test]
fn a_profile_header_holds_only_a_name() {
    let (_, _, reason) = Scene::new()
        .located("[profile]\nname = \"weather\"\nnmae = \"x\"\n[agent]\ncommand = [\"/bin/x\"]");
    assert!(
        reason.contains("`[profile]` holds the unknown key `nmae`"),
        "{reason}"
    );
}

mod plugins;

mod linux_storage_mounts_tests {
    use super::*;

    fn declarations(root: &Path) -> String {
        format!(
            "[experimental-features]\nlinux-storage-mounts = true\n[storage]\nmounts = [{:?}]\n",
            root.display().to_string()
        )
    }

    #[test]
    fn settings_reach_core_without_creating_incoming_directories() {
        let scene = Scene::new();
        let incoming = scene.root.join("incoming");
        let compiled = scene
            .compile(
                &profile(&format!("{}{AGENT}", declarations(&incoming))),
                None,
            )
            .expect("incoming storage declarations compile");
        let config = table(&compiled);
        assert_eq!(
            config["experimental-features"]["linux-storage-mounts"].as_bool(),
            Some(true)
        );
        assert_eq!(
            config["storage"]["mounts"].as_array().unwrap(),
            &[toml::Value::String(incoming.display().to_string())]
        );
        assert!(!compiled.storage.directories.contains(&incoming));
        crate::run::prepare_storage(&compiled.storage, &scene.home())
            .expect("managed storage preparation");
        assert!(
            !incoming.exists(),
            "the trusted mounter owns incoming roots"
        );
    }

    #[test]
    fn pending_program_tool_literals_survive_but_optional_and_unrelated_paths_do_not() {
        let scene = Scene::new();
        let incoming = scene.root.join("incoming");
        let unrelated = scene.root.join("unrelated");
        let text = format!(
            "{}{AGENT}\n[tool.reader]\nprogram = \"reader\"\n[tool.reader.filesystem]\n\
             read = [{read:?}, {unrelated:?}, {{ path = {optional:?}, optional = true }}]\n\
             write = [{write:?}]\ndeny_write = [{frozen:?}]\ndeny = [{denied:?}]\n\
             read_file = [{file_read:?}]\nwrite_file = [{file_write:?}]\n\
             list = [{listed:?}]\nmetadata = [{metadata:?}]\nexec = [{executable:?}]",
            declarations(&incoming),
            read = incoming.join("read").display().to_string(),
            write = incoming.join("write").display().to_string(),
            frozen = incoming.join("write/frozen").display().to_string(),
            denied = incoming.join("secret").display().to_string(),
            optional = incoming.join("optional").display().to_string(),
            unrelated = unrelated.display().to_string(),
            file_read = incoming.join("file-read").display().to_string(),
            file_write = incoming.join("file-write").display().to_string(),
            listed = incoming.join("listed").display().to_string(),
            metadata = incoming.join("metadata").display().to_string(),
            executable = incoming.join("executable").display().to_string(),
        );
        let resolved = detected(&scene, &text).expect("program tool resolves before storage");
        let fs = &resolved.tool["reader"].filesystem;
        assert!(
            fs.write
                .contains(&incoming.join("write").display().to_string()),
            "a required pending write must reach Core"
        );
        assert!(
            fs.read
                .contains(&incoming.join("read").display().to_string())
        );
        for (entries, leaf) in [
            (&fs.read_file, "file-read"),
            (&fs.write_file, "file-write"),
            (&fs.list, "listed"),
            (&fs.metadata, "metadata"),
            (&fs.exec, "executable"),
        ] {
            assert!(
                entries.contains(&incoming.join(leaf).display().to_string()),
                "pending {leaf} must reach Core"
            );
        }
        assert!(
            fs.deny_write
                .contains(&incoming.join("write/frozen").display().to_string())
        );
        assert!(
            fs.deny
                .contains(&incoming.join("secret").display().to_string())
        );
        assert!(!fs.read.contains(&unrelated.display().to_string()));
        assert!(
            !fs.read
                .contains(&incoming.join("optional").display().to_string())
        );
    }

    #[test]
    fn placeholder_aliases_cannot_redirect_or_remove_write_restrictions() {
        let scene = Scene::new();
        let incoming = scene.root.join("incoming");
        let outside = scene.root.join("outside");
        std::fs::create_dir_all(&incoming).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, incoming.join("frozen")).unwrap();
        let fields = format!(
            "filesystem.write = [{:?}]\nfilesystem.deny_write = [{:?}]\n",
            incoming.display().to_string(),
            incoming.join("frozen").display().to_string()
        );
        let text = format!(
            "{}{AGENT}\n{fields}[tool.writer]\ncommand = [\"/usr/bin/true\"]\n{fields}[mcp.local]\ntype = \"stdio\"\ncommand = [\"/usr/bin/true\"]\n{fields}",
            declarations(&incoming)
        );
        let compiled = scene
            .compile(&profile(&text), None)
            .expect("pending restrictions survive");
        let config = table(&compiled);
        for process in [
            &config["agent"],
            &config["tool"]["writer"],
            &config["mcp"]["local"],
        ] {
            assert_eq!(
                process["filesystem"]["deny_write"].as_array().unwrap(),
                &[toml::Value::String(
                    incoming.join("frozen").display().to_string()
                )]
            );
        }
        assert!(
            compiled
                .policy
                .contains(&incoming.join("frozen").display().to_string()),
            "generated policy must retain the authored path: {}",
            compiled.policy
        );
        assert!(
            !compiled.policy.contains(&outside.display().to_string()),
            "placeholder bytes must not choose the policy target"
        );
        assert_eq!(
            std::fs::read_link(incoming.join("frozen")).unwrap(),
            outside
        );
    }

    #[test]
    fn a_writable_outside_alias_into_pending_storage_is_still_refused() {
        let scene = Scene::new();
        let incoming = scene.root.join("incoming");
        std::fs::create_dir_all(&incoming).unwrap();
        let alias = scene.workspace().join("incoming-alias");
        std::os::unix::fs::symlink(&incoming, &alias).unwrap();
        let text = format!(
            "{}{AGENT}\nfilesystem.read = [{:?}]\n",
            declarations(&incoming),
            alias.join("data").display().to_string()
        );
        let error = match scene.compile(&profile(&text), None) {
            Ok(_) => panic!("a writable outside alias must remain refused"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("resolves through a link"), "{error}");
        assert!(error.contains("box can write"), "{error}");
    }

    #[test]
    fn external_read_file_alias_survives_ancestor_read_deduplication() {
        let scene = Scene::new();
        let incoming = scene.root.join("incoming");
        std::fs::create_dir_all(&incoming).unwrap();
        std::fs::write(incoming.join("value"), "placeholder").unwrap();
        let alias = scene.root.join("alias");
        std::os::unix::fs::symlink(incoming.join("value"), &alias).unwrap();
        let text = format!(
            "{}{AGENT}\n[tool.reader]\nprogram = \"reader\"\n[tool.reader.filesystem]\nread = [{:?}]\nread_file = [{:?}]",
            declarations(&incoming),
            scene.root.display().to_string(),
            alias.display().to_string()
        );
        let resolved = detected(&scene, &text).expect("external file alias resolves");
        assert!(
            resolved.tool["reader"]
                .filesystem
                .read_file
                .contains(&alias.display().to_string()),
            "the alias needs its own captured-source projection: {:?}",
            resolved.tool["reader"].filesystem
        );
    }

    #[test]
    fn experimental_switch_keeps_false_and_conditional_values() {
        let scene = Scene::new();
        for selected in [false, true] {
            let compiled = scene.compile(&profile(&format!("[experimental-features]\nlinux-storage-mounts = {{ value = {selected}, when = \"macos\" }}\n{AGENT}")), None).unwrap();
            assert_eq!(
                table(&compiled)["experimental-features"]["linux-storage-mounts"].as_bool(),
                Some(selected)
            );
        }
        let compiled = scene.compile(&profile(&format!("[experimental-features]\nlinux-storage-mounts = {{ value = true, when = \"linux\" }}\n{AGENT}")), None).unwrap();
        assert!(table(&compiled).get("experimental-features").is_none());
    }
    #[test]
    fn pending_writes_keep_external_protections_until_core_can_resolve_the_alias() {
        let scene = Scene::new();
        let incoming = scene.root.join("incoming");
        let protected = scene.root.join("protected");
        let absent = scene.root.join("required-but-absent");
        std::fs::create_dir_all(&protected).unwrap();
        let fields = format!(
            "filesystem.write = [{:?}]\nfilesystem.deny_write = [{:?}, {:?}]\n",
            incoming.join("future-alias").display().to_string(),
            protected.display().to_string(),
            absent.display().to_string()
        );
        let text = format!(
            "{}{AGENT}\n{fields}[tool.writer]\ncommand = [\"/usr/bin/true\"]\n{fields}[mcp.local]\ntype = \"stdio\"\ncommand = [\"/usr/bin/true\"]\n{fields}[tool.static]\ncommand = [\"/usr/bin/true\"]\nfilesystem.deny_write = [{:?}]\n",
            declarations(&incoming),
            absent.display().to_string()
        );
        let compiled = scene.compile(&profile(&text), None).unwrap();
        let config = table(&compiled);
        for process in [
            &config["agent"],
            &config["tool"]["writer"],
            &config["mcp"]["local"],
        ] {
            let denied = process["filesystem"]["deny_write"].as_array().unwrap();
            assert!(denied.contains(&toml::Value::String(protected.display().to_string())));
            assert!(
                denied.contains(&toml::Value::String(absent.display().to_string())),
                "Core must decide whether the future alias reaches this required target"
            );
        }
        assert!(
            config["tool"]["static"]
                .get("filesystem")
                .and_then(|fs| fs.get("deny_write"))
                .is_none(),
            "ordinary roles still prune unrelated protections"
        );
        assert!(compiled.policy.contains(&protected.display().to_string()));
        assert!(compiled.policy.contains(&absent.display().to_string()));
    }

    #[test]
    fn dangling_external_file_alias_is_retained_and_optional_alias_is_omitted() {
        let scene = Scene::new();
        let incoming = scene.root.join("incoming");
        let alias = scene.root.join("alias");
        let optional = scene.root.join("optional-alias");
        std::os::unix::fs::symlink(incoming.join("value"), &alias).unwrap();
        std::os::unix::fs::symlink(incoming.join("optional"), &optional).unwrap();
        let text = format!(
            "{}{AGENT}\n[tool.reader]\nprogram = \"reader\"\nfilesystem.read_file = [{:?}, {{ path = {:?}, optional = true }}]",
            declarations(&incoming),
            alias.display().to_string(),
            optional.display().to_string()
        );
        let resolved = detected(&scene, &text).unwrap();
        assert!(
            resolved.tool["reader"]
                .filesystem
                .read_file
                .contains(&alias.display().to_string())
        );
        assert!(
            !resolved.tool["reader"]
                .filesystem
                .read_file
                .contains(&optional.display().to_string())
        );
        assert!(!incoming.exists());
    }

    #[test]
    fn roots_expand_home_templates_and_conditions_without_becoming_managed_storage() {
        let scene = Scene::new();
        let text = format!(
            "[experimental-features]\nlinux-storage-mounts = true\n[storage]\ndirectories = [\"agent\"]\nmounts = [\"${{{{ home }}}}/incoming\", {{ value = \"~/other\", when = \"macos\" }}, {{ value = \"~/omitted\", when = \"linux\" }}]\n{AGENT}"
        );
        let compiled = scene.compile(&profile(&text), None).unwrap();
        let expected = vec![scene.home().join("incoming"), scene.home().join("other")];
        assert_eq!(compiled.storage.mounts, expected);
        assert_eq!(
            table(&compiled)["storage"]["mounts"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(compiled.storage.directories.len(), 1);
        assert!(
            expected
                .iter()
                .all(|root| !compiled.storage.directories.contains(root))
        );
    }

    #[test]
    fn incoming_settings_refuse_malformed_values_and_pack_owned_roots() {
        let scene = Scene::new();
        for value in ["1", "\"yes\""] {
            let reason = scene.refusal(&format!(
                "[experimental-features]\nlinux-storage-mounts = {value}\n{AGENT}"
            ));
            assert!(reason.contains("is `true` or `false`"), "{reason}");
        }
        for value in ["\"/incoming\"", "[1]", "[\"relative\"]"] {
            let reason = scene.refusal(&format!("[storage]\nmounts = {value}\n{AGENT}"));
            assert!(reason.contains("list of absolute paths"), "{reason}");
        }
        scene.share_raw("p", "[pack]\nname = \"@box/p\"\nversion = 1\nkind = \"support\"\nplatforms = [\"macos\"]\n[storage]\nmounts = [\"/incoming\"]");
        let reason = scene.refusal(&format!("packs = [\"@box/p\"]\n{AGENT}"));
        assert!(
            reason.contains("a pack holds no `storage.mounts`"),
            "{reason}"
        );
    }

    #[test]
    fn pending_file_writes_also_keep_external_denials() {
        let scene = Scene::new();
        let incoming = scene.root.join("incoming");
        let protected = scene.root.join("protected");
        std::fs::create_dir_all(&protected).unwrap();
        let fields = format!(
            "filesystem.write_file = [{:?}]\nfilesystem.deny_write = [{:?}]\n",
            incoming.join("future-file-alias").display().to_string(),
            protected.display().to_string()
        );
        let text = format!(
            "{}{AGENT}\n{fields}[tool.writer]\ncommand = [\"/usr/bin/true\"]\n{fields}[mcp.local]\ntype = \"stdio\"\ncommand = [\"/usr/bin/true\"]\n{fields}",
            declarations(&incoming)
        );
        let compiled = scene.compile(&profile(&text), None).unwrap();
        let config = table(&compiled);
        for process in [
            &config["agent"],
            &config["tool"]["writer"],
            &config["mcp"]["local"],
        ] {
            assert_eq!(
                process["filesystem"]["deny_write"].as_array().unwrap(),
                &[toml::Value::String(protected.display().to_string())]
            );
        }
    }

    #[test]
    fn incoming_program_globs_fail_without_enumerating_the_placeholder() {
        let scene = Scene::new();
        let incoming = scene.root.join("incoming");
        let text = format!(
            "{}{AGENT}\n[tool.reader]\nprogram = \"reader\"\nfilesystem.read = [{:?}]",
            declarations(&incoming),
            incoming.join("*").display().to_string()
        );
        let reason = detected(&scene, &text).unwrap_err().to_string();
        assert!(
            reason.contains("wildcard inside incoming storage"),
            "{reason}"
        );
    }
    #[test]
    fn pending_write_parent_guards_match_ancestors_without_covering_siblings() {
        let scene = Scene::new();
        let incoming = scene.root.join("incoming");
        let parent = scene.root.join("external/parent");
        let protected = parent.join("protected");
        let sibling = parent.join("permitted-sibling");
        std::fs::create_dir_all(&protected).unwrap();
        let text = format!(
            "{}{AGENT}\nfilesystem.write = [{:?}]\nfilesystem.deny_write = [{:?}]",
            declarations(&incoming),
            incoming.join("future-alias").display().to_string(),
            protected.display().to_string()
        );
        let compiled = scene.compile(&profile(&text), None).unwrap();
        for (id, action) in [
            ("deny_write_parent_move_0", "fs:move"),
            ("deny_write_parent_delete_0", "fs:delete"),
        ] {
            let rule = generated_rule(&compiled.policy, id)
                .expect("pending aliases retain ancestor guards");
            assert!(
                rule.contains(&format!("action == Box::Action::{action:?}")),
                "{rule}"
            );
            assert!(
                rule.contains(&format!(
                    "context.input.path == {:?}",
                    parent.display().to_string()
                )),
                "{rule}"
            );
            assert!(
                !rule.contains(" like "),
                "ancestor guards must never recursively deny siblings: {rule}"
            );
            assert!(!rule.contains(&sibling.display().to_string()), "{rule}");
            assert!(
                !rule.contains("fs:write"),
                "ancestor identity cannot deny writing sibling files: {rule}"
            );
        }
    }
    #[test]
    fn a_glob_that_discovers_an_incoming_alias_cannot_expand_its_placeholder() {
        let scene = Scene::new();
        let incoming = scene.root.join("incoming");
        let aliases = scene.root.join("aliases");
        std::fs::create_dir_all(&incoming).unwrap();
        std::fs::create_dir_all(&aliases).unwrap();
        std::fs::write(incoming.join("child"), "placeholder").unwrap();
        std::os::unix::fs::symlink(&incoming, aliases.join("provider")).unwrap();
        for pattern in ["*/child", "*/*"] {
            let text = format!(
                "{}{AGENT}\n[tool.reader]\nprogram = \"reader\"\nfilesystem.read = [{:?}]",
                declarations(&incoming),
                aliases.join(pattern).display().to_string()
            );
            let reason = detected(&scene, &text).unwrap_err().to_string();
            assert!(
                reason.contains("wildcard inside incoming storage"),
                "{reason}"
            );
        }
    }
    #[test]
    fn unrelated_optional_program_alias_keeps_existing_matching_behavior() {
        let scene = Scene::new();
        let incoming = scene.root.join("incoming");
        let alias = scene.root.join("unrelated-alias");
        std::os::unix::fs::symlink(scene.root.join("unrelated-missing"), &alias).unwrap();
        for settings in [String::new(), declarations(&incoming)] {
            let text = format!(
                "{settings}{AGENT}\n[tool.reader]\nprogram = \"reader\"\nfilesystem.read_file = [{{ path = {:?}, optional = true }}]",
                alias.display().to_string()
            );
            let resolved = detected(&scene, &text).unwrap();
            assert!(
                resolved.tool["reader"]
                    .filesystem
                    .read_file
                    .contains(&alias.display().to_string()),
                "unrelated program matching keeps its existing symlink-metadata semantics"
            );
        }
    }
}
