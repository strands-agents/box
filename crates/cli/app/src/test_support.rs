//! A fake host and the helpers that the tests of `box` and of its shipped packs share.

use std::path::PathBuf;

use crate::create::NewProfile;
#[cfg(test)]
pub(crate) use crate::fixtures::shell;
pub(crate) use crate::fixtures::{binary, executable, link, npm_script, script, write};
use crate::run::Launcher;
#[cfg(all(
    any(test, feature = "test-support"),
    any(target_os = "macos", target_os = "linux")
))]
pub use trial::{Trial, Trialed};

/// A fake operator host: a home, a project, and one install of each tool that `box` ships a pack
/// for.
pub struct FakeHost {
    _root: tempfile::TempDir,
    root: PathBuf,
    project: String,
    alternate: bool,
}

impl FakeHost {
    /// Lay out the host under a fresh temporary directory: rustup, and Homebrew node.
    pub fn new() -> Self {
        Self::with_project("project")
    }

    /// Lay out the host with the project in a folder of this name under the home.
    pub fn with_project(name: &str) -> Self {
        Self::laid_out(name, false)
    }

    /// Lay out the other common installs: Homebrew rust without rustup, and an nvm node in the home.
    pub fn alternate() -> Self {
        Self::laid_out("project", true)
    }

    fn laid_out(project: &str, alternate: bool) -> Self {
        let directory = tempfile::Builder::new()
            .prefix("bx")
            .tempdir_in("/tmp")
            .expect("a temporary root");
        let root = directory.path().canonicalize().expect("a canonical root");
        let host = Self {
            _root: directory,
            root,
            project: project.to_string(),
            alternate,
        };
        host.lay_out();
        host
    }

    /// The operator home.
    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    /// The project the agent works in.
    pub fn project(&self) -> PathBuf {
        self.home().join(&self.project)
    }

    /// Where `box profile show` writes the files it checks.
    pub fn scratch(&self) -> PathBuf {
        self.root.join("scratch")
    }

    /// The Homebrew prefix.
    pub fn brew(&self) -> PathBuf {
        self.root.join("brew")
    }

    /// The search path that finds each fake tool.
    pub fn search_path(&self) -> String {
        let first = if self.alternate {
            self.nvm().join("bin")
        } else {
            self.home().join(".cargo/bin")
        };
        format!(
            "{}:{}:{}:/usr/bin:/bin",
            first.display(),
            self.brew().join("bin").display(),
            self.root.join("git/bin").display(),
        )
    }

    /// The fake Apple developer folder, which `xcode-select -p` reports on this host.
    pub fn developer(&self) -> PathBuf {
        self.root.join("developer")
    }

    /// The command `xcode-select -p`, as the shipped packs run it.
    fn xcode_select() -> [&'static str; 2] {
        ["/usr/bin/xcode-select", "-p"]
    }

    /// The search path without the system folders, so no program of the real host is found.
    pub fn own_search_path(&self) -> String {
        self.search_path().replace(":/usr/bin:/bin", "")
    }

    /// A starter compiled for the fake project the way `box run` compiles it.
    #[cfg(all(
        any(test, feature = "test-support"),
        any(target_os = "macos", target_os = "linux")
    ))]
    pub fn trial(&self) -> Trial {
        Trial::for_project(self.project())
            .search_path(self.search_path())
            .home(self.home())
            .command_output(
                &Self::xcode_select(),
                &self.developer().display().to_string(),
            )
            .resources(crate::resources::source_tree())
    }

    /// A `NewProfile` that sees only this host and writes under its home.
    pub fn profile(&self) -> NewProfile {
        NewProfile::from_host()
            .search_path(self.search_path())
            .home(self.home())
            .command_output(
                &Self::xcode_select(),
                &self.developer().display().to_string(),
            )
            .environment(&[])
            .resources(crate::resources::source_tree())
            .profiles(self.home().join(".strands/box/profiles"))
    }

    /// A `Launcher` that runs this host's profiles.
    pub fn launcher(&self) -> Launcher {
        std::fs::create_dir_all(self.scratch()).expect("a scratch directory");
        Launcher::from_host()
            .without_resources()
            .scratch(self.scratch())
            .home(self.home())
            .search_path(self.search_path())
            .command_output(
                &Self::xcode_select(),
                &self.developer().display().to_string(),
            )
            .environment(&[])
    }

    /// The fake Claude Code that the standalone installer put in its versions folder.
    pub fn claude_install(&self) -> PathBuf {
        self.home().join(".local/share/claude/versions/2.1.280")
    }

    /// The fake Codex on the search path.
    pub fn codex_install(&self) -> PathBuf {
        self.brew().join("bin/codex")
    }

    /// Remove the fake Claude Code and the link that the installer made to it.
    pub fn uninstall_claude(&self) {
        std::fs::remove_file(self.home().join(".local/bin/claude")).expect("remove the link");
        std::fs::remove_dir_all(self.home().join(".local/share/claude")).expect("remove");
    }

    /// Remove the fake Codex.
    pub fn uninstall_codex(&self) {
        std::fs::remove_file(self.codex_install()).expect("remove");
    }

    fn nvm(&self) -> PathBuf {
        self.home().join(".nvm/versions/node/v22.0.0")
    }

    fn lay_out(&self) {
        let home = self.home();
        let brew = self.brew();
        std::fs::create_dir_all(self.project()).expect("a project");
        std::fs::create_dir_all(self.developer().join("usr/bin")).expect("a developer directory");
        binary(&self.developer().join("usr/bin/cc"));
        std::fs::create_dir_all(self.developer().join("SDKs/MacOSX.sdk")).expect("an SDK");
        std::fs::create_dir_all(brew.join("opt")).expect("opt");

        script(&self.claude_install(), "echo '2.1.280 (Claude Code)'");
        link(
            &self.claude_install().display().to_string(),
            &home.join(".local/bin/claude"),
        );
        script(&self.codex_install(), "echo 'codex-cli 0.157.0'");
        script(&home.join(".local/bin/kiro-cli"), "echo 'kiro-cli 3.1.0'");
        binary(&self.root.join("git/bin/git"));
        std::fs::create_dir_all(self.root.join("git/libexec/git-core")).expect("git-core");

        if self.alternate {
            let keg = brew.join("Cellar/rust/1.90.0");
            binary(&keg.join("bin/cargo"));
            binary(&keg.join("bin/rustc"));
            std::fs::create_dir_all(keg.join("lib/rustlib")).expect("rustlib");
            link("../Cellar/rust/1.90.0", &brew.join("opt/rust"));
            link("../Cellar/rust/1.90.0/bin/cargo", &brew.join("bin/cargo"));
            let nvm = self.nvm();
            binary(&nvm.join("bin/node"));
            npm_script(&nvm.join("lib/node_modules/npm"));
            link(
                "../lib/node_modules/npm/bin/npm-cli.js",
                &nvm.join("bin/npm"),
            );
            return;
        }

        binary(&home.join(".cargo/bin/rustup"));
        link("rustup", &home.join(".cargo/bin/cargo"));
        link("rustup", &home.join(".cargo/bin/rustc"));
        std::fs::create_dir_all(home.join(".rustup/toolchains/stable-aarch64-apple-darwin/bin"))
            .expect("a toolchain");

        let keg = brew.join("Cellar/node/26.9.0");
        binary(&keg.join("bin/node"));
        std::fs::create_dir_all(brew.join("etc/openssl@3")).expect("etc");
        link("../Cellar/node/26.9.0", &brew.join("opt/node"));
        link("../Cellar/node/26.9.0/bin/node", &brew.join("bin/node"));
        npm_script(&brew.join("lib/node_modules/npm"));
        link(
            "../lib/node_modules/npm/bin/npm-cli.js",
            &brew.join("bin/npm"),
        );
        let pi = brew.join("lib/node_modules/@earendil-works/pi-coding-agent");
        write(&pi.join("dist/bundle/cli.js"), "#!/usr/bin/env node\n");
        executable(&pi.join("dist/bundle/cli.js"));
        link(
            "../lib/node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js",
            &brew.join("bin/pi"),
        );
    }
}

impl Default for FakeHost {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(
    any(test, feature = "test-support"),
    any(target_os = "macos", target_os = "linux")
))]
mod trial {
    use std::path::{Path, PathBuf};

    use crate::compile::Instance;
    use crate::create::{Resolution, Settings, settings_builder};
    use crate::error::Error;
    use crate::host::{canonical, within};
    use crate::profile::PROFILE_FILE;
    use crate::run::{
        Loaded, RunSettings, compile_run, profiles_root, refuse_linked_project_configuration,
    };

    /// A starter to resolve and compile for one project, with every variable unset.
    pub struct Trial {
        project: PathBuf,
        settings: Settings,
        variables: Vec<(String, String)>,
        agent_args: Option<Vec<String>>,
    }

    /// What one trial compiled.
    #[derive(Debug)]
    pub struct Trialed {
        project: PathBuf,
        box_toml: String,
        policy: String,
        generated_ids: Vec<String>,
        journal: PathBuf,
        storage: PathBuf,
        directories: Vec<PathBuf>,
        agent: PathBuf,
        resolutions: Vec<Resolution>,
        skipped: Vec<(String, String)>,
        dropped: Vec<(String, String)>,
        inputs: Vec<(String, String, String)>,
        hooks: Vec<crate::lang::HookImport>,
    }

    #[allow(unreachable_pub, dead_code)]
    impl Trial {
        /// A trial that compiles for `project`.
        pub fn for_project(project: impl Into<PathBuf>) -> Self {
            let mut settings = Settings::current();
            settings.host.apple_stubs = PathBuf::from("/nonexistent-apple-stubs");
            Self {
                project: project.into(),
                settings,
                variables: Vec::new(),
                agent_args: None,
            }
        }

        /// Set the profile's `agent-args`.
        pub fn agent_args(mut self, args: &[&str]) -> Self {
            self.agent_args = Some(args.iter().map(|arg| arg.to_string()).collect());
            self
        }

        /// Set the variable `name` of the shell that runs `box`.
        pub fn variable(mut self, name: &str, value: impl Into<String>) -> Self {
            self.variables.push((name.to_string(), value.into()));
            self
        }

        /// Compile as `box` does on `os`.
        pub fn os(mut self, os: &'static str) -> Self {
            self.settings.host.os = os;
            self
        }

        /// Resolve as a host with the CPU architecture `arch`, as `std::env::consts::ARCH`
        /// names it.
        pub fn arch(mut self, arch: &'static str) -> Self {
            self.settings.host.arch = arch;
            self
        }

        /// Treat `folder` as the folder of Apple's `xcode-select` stubs.
        pub fn apple_stubs(mut self, folder: impl Into<PathBuf>) -> Self {
            self.settings.host.apple_stubs = folder.into();
            self
        }

        settings_builder!();

        /// Resolve and compile the starter, as `box run` does.
        pub fn generate(self) -> Result<Trialed, Error> {
            let host = &self.settings.host;
            if host.home.as_os_str().is_empty() {
                return Err(Error::NoHome);
            }
            let project = canonical(&self.project)
                .filter(|project| project.is_dir())
                .ok_or_else(|| Error::Project {
                    path: self.project.clone(),
                })?;
            if within(&host.home, &project) {
                return Err(Error::ProjectHoldsHome { path: project });
            }
            refuse_linked_project_configuration(&project)?;
            let name = self
                .settings
                .with
                .first()
                .map(|pack| crate::starter::short_name(pack).to_string())
                .unwrap_or_else(|| "claude".to_string());
            let path = profiles_root(&host.box_home).join(&name).join(PROFILE_FILE);
            let mut profile = self.settings.draft(&name, &path, None)?.profile;
            // The `[project]` that `@box/open` gives a created profile.
            profile
                .table
                .entry(crate::lang::PROJECT.to_string())
                .or_insert_with(|| {
                    toml::Value::Table(toml::Table::from_iter([(
                        "access".to_string(),
                        toml::Value::from("write"),
                    )]))
                });
            if let Some(args) = &self.agent_args {
                profile.table.insert(
                    "agent-args".to_string(),
                    toml::Value::Array(args.iter().cloned().map(toml::Value::String).collect()),
                );
            }
            let directory = host.box_home.join("r/b-0000000000000000");
            let instance = Instance {
                name: "b-0000000000000000".to_string(),
                box_directory: directory.join("box"),
                directory,
            };
            // The trial's home is a stand-in, while Box Core's policy check reads the real `HOME`,
            // which can hold the source tree's resources, so the run protects no folder of them.
            let protected: Vec<PathBuf> = Vec::new();
            let crate::run::CompiledRun {
                compiled,
                discovery,
                resolved,
                ..
            } = compile_run(
                Loaded {
                    profile: &profile,
                    name: &name,
                    policy: None,
                    trusted: &[],
                    by_path: false,
                },
                host,
                &project,
                &instance,
                &protected,
                &|name: &str| {
                    self.variables
                        .iter()
                        .find(|(set, _)| set == name)
                        .map(|(_, value)| value.clone())
                },
                RunSettings {
                    display: crate::run::Display::Direct,
                    observations: None,
                    resources: None,
                    install: None,
                },
            )?;
            let _ = discovery;
            let agent = PathBuf::from(
                resolved
                    .agent
                    .command
                    .first()
                    .expect("a starter names its agent"),
            );
            Ok(Trialed {
                resolutions: resolved
                    .tools
                    .found
                    .into_iter()
                    .map(Resolution::from)
                    .collect(),
                project,
                box_toml: compiled.box_toml,
                policy: compiled.policy,
                generated_ids: compiled.generated_ids,
                journal: compiled.journal,
                storage: compiled.storage.root,
                hooks: compiled.storage.hooks,
                directories: compiled.storage.directories,
                agent,
                skipped: resolved.tools.skipped,
                dropped: resolved.tools.dropped,
                inputs: resolved
                    .inputs
                    .into_iter()
                    .map(|input| (input.name, input.value, input.source))
                    .collect(),
            })
        }
    }

    impl Trialed {
        /// The canonical project folder.
        pub fn project(&self) -> &Path {
            &self.project
        }

        /// The compiled `box.toml`.
        pub fn box_toml(&self) -> &str {
            &self.box_toml
        }

        /// The IDs of the generated policy rules.
        pub fn generated_ids(&self) -> &[String] {
            &self.generated_ids
        }

        /// The compiled `policy.dw`.
        pub fn policy(&self) -> &str {
            &self.policy
        }

        /// The journal folder of the run.
        pub fn journal(&self) -> &Path {
            &self.journal
        }

        /// The storage folder of the profile.
        pub fn storage(&self) -> &Path {
            &self.storage
        }

        /// Each `[[storage.hooks]]` row of the run.
        pub fn hooks(&self) -> &[crate::lang::HookImport] {
            &self.hooks
        }

        /// The folders that the run creates.
        pub fn directories(&self) -> &[PathBuf] {
            &self.directories
        }

        /// The agent program that the run starts.
        pub fn agent(&self) -> &Path {
            &self.agent
        }

        /// What each tool resolved to.
        pub fn resolutions(&self) -> &[Resolution] {
            &self.resolutions
        }

        /// Each skipped tool, with the reason.
        pub fn skipped(&self) -> &[(String, String)] {
            &self.skipped
        }

        /// Each dropped path, with the tool that named it.
        pub fn dropped(&self) -> &[(String, String)] {
            &self.dropped
        }

        /// Each input that the run read: its name, its value, and where it came from.
        pub fn inputs(&self) -> &[(String, String, String)] {
            &self.inputs
        }
    }
}

/// Fake install trees and readers of a trial, for the tests of this crate and of the shipped packs.
#[cfg(all(
    any(test, feature = "test-support"),
    any(target_os = "macos", target_os = "linux")
))]
mod shared {
    use std::path::{Path, PathBuf};

    use super::{FakeHost, Trial, Trialed, binary, link, npm_script, script, write};
    use crate::error::Error;

    /// The `resources` folder of the source tree, which holds the packs that `box` ships.
    pub fn resources() -> PathBuf {
        crate::resources::source_tree()
    }

    /// The folder that holds the profiles under `box_home`.
    pub fn profiles_root(box_home: &Path) -> PathBuf {
        crate::run::profiles_root(box_home)
    }

    /// The `-c` settings of a Codex `[agent] command`, after the program.
    pub fn codex_settings(command: &toml::Value) -> Vec<&str> {
        command.as_array().unwrap()[1..]
            .chunks(2)
            .map(|pair| {
                assert_eq!(pair[0].as_str(), Some("-c"), "{pair:?}");
                pair[1].as_str().unwrap()
            })
            .collect()
    }

    /// Assert that `error` says the host has no `program` that the box can run.
    pub fn no_agent(error: &Error, program: &str) {
        assert!(
            matches!(error, Error::NotOnHost { .. }),
            "a host absence, not {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains(&format!("no `{program}` that the box can run")),
            "{error}"
        );
    }

    /// The resolution of the tool `name` in `generated`.
    pub fn resolution<'a>(generated: &'a Trialed, name: &str) -> &'a crate::create::Resolution {
        generated
            .resolutions()
            .iter()
            .find(|tool| tool.name == name)
            .unwrap_or_else(|| panic!("{name} was resolved"))
    }

    /// Write the operator pack `name` as `text`, with a `[pack]` header.
    pub fn operator_pack(host: &FakeHost, name: &str, text: &str) {
        let folder = host.home().join(".strands/box/packs").join(name);
        std::fs::create_dir_all(&folder).expect("an operator pack folder");
        std::fs::write(
            folder.join("pack.toml"),
            format!(
                "[pack]\nname = {name:?}\nversion = 1\n{}{text}",
                crate::lang::test_kind_line(text)
            ),
        )
        .expect("an operator pack");
    }

    /// A Homebrew keg that holds the program `name`, linked into the fake host's `PATH`.
    pub fn brew_program(host: &FakeHost, name: &str) -> PathBuf {
        let keg = host.brew().join("Cellar").join(name).join("1.0.0");
        script(&keg.join("bin").join(name), "exit 0");
        std::fs::write(
            keg.join("INSTALL_RECEIPT.json"),
            r#"{"runtime_dependencies":[]}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(
            keg.join("bin").join(name),
            host.brew().join("bin").join(name),
        )
        .expect("a link");
        keg
    }

    /// Install trees outside the fake home, as a package manager lays them out.
    pub struct Trees {
        _root: tempfile::TempDir,
        /// The folder that holds the tree.
        pub root: PathBuf,
    }

    impl Default for Trees {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Trees {
        /// An empty tree in a new temporary folder.
        pub fn new() -> Self {
            let directory = tempfile::tempdir().expect("a temporary root");
            let root = directory.path().canonicalize().expect("a canonical root");
            Self {
                _root: directory,
                root,
            }
        }

        /// The path `relative` in the tree.
        pub fn path(&self, relative: &str) -> PathBuf {
            self.root.join(relative)
        }

        /// The folder `relative` in the tree, created.
        pub fn folder(&self, relative: &str) -> PathBuf {
            let path = self.path(relative);
            std::fs::create_dir_all(&path).expect("a folder");
            path
        }

        /// dnf's git, node 20, and npm under `<root>/usr`.
        pub fn dnf(&self) -> PathBuf {
            binary(&self.path("usr/bin/git"));
            self.folder("usr/libexec/git-core");
            self.folder("usr/share/git-core");
            binary(&self.path("usr/bin/node-20"));
            link("node-20", &self.path("usr/bin/node"));
            self.folder("usr/share/node-20");
            let package = self.path("usr/lib/nodejs20/lib/node_modules/npm");
            write(&package.join("package.json"), r#"{"name":"npm"}"#);
            script_with(
                &package.join("bin/npm-cli.js"),
                &format!("#!{}\n", self.path("usr/bin/node-20").display()),
            );
            link(
                "../lib/nodejs20/lib/node_modules/npm/bin/npm-cli.js",
                &self.path("usr/bin/npm"),
            );
            self.path("usr/bin")
        }

        /// Homebrew's git and node kegs, its npm, `etc`, and the `opt/node@22` spelling.
        pub fn homebrew(&self) -> PathBuf {
            let git = self.path("brew/Cellar/git/2.56.0_1");
            binary(&git.join("bin/git"));
            self.folder("brew/Cellar/git/2.56.0_1/libexec/git-core");
            link("../Cellar/git/2.56.0_1/bin/git", &self.path("brew/bin/git"));
            binary(&self.path("brew/Cellar/node/26.10.0_1/bin/node"));
            link(
                "../Cellar/node/26.10.0_1/bin/node",
                &self.path("brew/bin/node"),
            );
            binary(&self.path("brew/Cellar/node@22/22.1.0/bin/node"));
            link("../Cellar/node@22/22.1.0", &self.path("brew/opt/node@22"));
            npm_script(&self.path("brew/lib/node_modules/npm"));
            link(
                "../lib/node_modules/npm/bin/npm-cli.js",
                &self.path("brew/bin/npm"),
            );
            self.folder("brew/etc/openssl@3");
            write(
                &self.path("brew/Cellar/openssl@3/3.0/INSTALL_RECEIPT.json"),
                r#"{"runtime_dependencies":[]}"#,
            );
            link("../Cellar/openssl@3/3.0", &self.path("brew/opt/openssl@3"));
            for keg in ["node/26.10.0_1", "node@22/22.1.0"] {
                write(
                    &self.path(&format!("brew/Cellar/{keg}/INSTALL_RECEIPT.json")),
                    r#"{"runtime_dependencies":[{"full_name":"openssl@3"}]}"#,
                );
            }
            self.path("brew")
        }

        /// Apple's `/usr/bin/git` stub, and the developer folder it forwards to.
        pub fn apple(&self) -> (PathBuf, PathBuf) {
            binary(&self.path("apple/usr/bin/git"));
            let developer = self.folder("apple/CommandLineTools");
            binary(&developer.join("usr/bin/git"));
            (self.path("apple/usr/bin"), developer)
        }
    }

    /// Write `text` to `path` as an executable script.
    pub fn script_with(path: &Path, text: &str) {
        write(path, text);
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("mode 0755");
    }

    /// A trial of `host` that finds programs only in `search` and the system folders.
    pub fn trial(host: &FakeHost, search: &[&Path]) -> Trial {
        let mut path: Vec<String> = search.iter().map(|dir| dir.display().to_string()).collect();
        path.push("/usr/bin:/bin".to_string());
        host.trial()
            .with("claude")
            .with("bedrock")
            .search_path(path.join(":"))
    }

    /// The `[tool.<name>]` table of `generated`.
    pub fn tool(generated: &Trialed, name: &str) -> toml::Value {
        let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
        file["tool"]
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("a [tool.{name}] in\n{}", generated.box_toml()))
    }

    /// The string items of a TOML list, or none when `value` is not a list.
    pub fn strings(value: &toml::Value) -> Vec<String> {
        value
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `path` as text.
    pub fn text(path: &Path) -> String {
        path.display().to_string()
    }

    /// Write the operator's pack `name` under the fake home.
    pub fn pack(host: &FakeHost, name: &str, body: &str) {
        write(
            &host
                .home()
                .join(".strands/box/packs")
                .join(name)
                .join("pack.toml"),
            &format!(
                "[pack]\nname = \"{name}\"\nversion = 1\n{}{body}",
                crate::lang::test_kind_line(body)
            ),
        );
    }

    /// A cargo trial on macOS whose `xcode-select -p` reports `developer`.
    pub fn macos_cargo(host: &FakeHost, developer: &Path) -> Trialed {
        host.trial()
            .with("claude")
            .with("bedrock")
            .os("macos")
            .command_output(&["/usr/bin/xcode-select", "-p"], &text(developer))
            .tools(["cargo"])
            .generate()
            .expect("a configuration")
    }

    /// The `box.toml` of `generated` as a table.
    pub fn box_toml(generated: &Trialed) -> toml::Table {
        toml::from_str(generated.box_toml()).expect("TOML")
    }

    /// The run's directory: the folder that holds its box folder.
    pub fn run_folder(generated: &Trialed) -> PathBuf {
        let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
        Path::new(file["box_dir"].as_str().expect("a box folder"))
            .parent()
            .expect("the run's directory")
            .to_path_buf()
    }
}
#[cfg(all(
    any(test, feature = "test-support"),
    any(target_os = "macos", target_os = "linux")
))]
pub use shared::*;
