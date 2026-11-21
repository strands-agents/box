#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::test_support::{
    Trees, Trial, Trialed, binary, box_toml, link, macos_cargo, pack, run_folder, script_with,
    strings, text, tool, trial, write,
};
use crate::{Error, FakeHost};

#[test]
fn package_hosts_permit_connections_on_443_and_http_requests() {
    let host = FakeHost::new();
    pack(
        &host,
        "registry",
        "include = [\"@box/npm\"]\n[tool.npm]\n\
         hosts = [\"registry.npmjs.org\", \"registry.npmjs.org\"]",
    );
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .with("registry")
        .tools(["cargo", "npm"])
        .generate()
        .expect("a configuration");
    let rules: Vec<&str> = generated
        .policy()
        .lines()
        .filter(|line| line.starts_with("@id(\"package_hosts"))
        .collect();
    assert_eq!(
        rules,
        [
            r#"@id("package_hosts_connect") permit (principal, action == Box::Action::"net:connect", resource) when { (context.input.host == "index.crates.io" || context.input.host == "static.crates.io" || context.input.host == "static.rust-lang.org" || context.input.host == "registry.npmjs.org") && context.input.port == 443 };"#,
            r#"@id("package_hosts_request") permit (principal, action == Box::Action::"http:request", resource) when { context.input.host == "index.crates.io" || context.input.host == "static.crates.io" || context.input.host == "static.rust-lang.org" || context.input.host == "registry.npmjs.org" };"#,
        ]
    );
}

#[test]
fn box_core_checks_the_package_hosts_rules_of_many_hosts() {
    let host = FakeHost::new();
    let hosts = (1..=60)
        .map(|index| format!("\"h{index}.example.com\""))
        .collect::<Vec<_>>()
        .join(", ");
    pack(
        &host,
        "registry",
        &format!("include = [\"@box/npm\"]\n[tool.npm]\nhosts = [{hosts}]"),
    );
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .with("registry")
        .tools(["npm"])
        .generate()
        .expect("a configuration");
    assert!(generated.policy().contains("package_hosts_connect"));
    let config = host.scratch().join("box.toml");
    crate::test_support::write(&config, generated.box_toml());
    crate::test_support::write(&host.scratch().join("policy.dw"), generated.policy());
    let checked = strands_box::check_policy(config).expect("a policy check");
    assert!(checked.errors().is_empty(), "{:?}", checked.errors());
}

#[test]
fn box_core_checks_the_box_home_forbids_of_many_storage_folders() {
    let host = FakeHost::new();
    let folders = (1..=40)
        .map(|index| format!("\"d{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    pack(
        &host,
        "folders",
        &format!("[storage]\ndirectories = [{folders}]"),
    );
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .with("folders")
        .generate()
        .expect("a configuration");
    assert!(generated.policy().contains("box_home_write"));
    let config = host.scratch().join("box.toml");
    crate::test_support::write(&config, generated.box_toml());
    crate::test_support::write(&host.scratch().join("policy.dw"), generated.policy());
    let checked = strands_box::check_policy(config).expect("a policy check");
    assert!(checked.errors().is_empty(), "{:?}", checked.errors());
}

#[test]
fn a_run_with_no_tool_that_upgrades_a_host_writes_no_gateway() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .tools(["node"])
        .generate()
        .expect("a configuration");
    assert!(box_toml(&generated).get("gateway").is_none());
}

#[test]
fn a_tool_upgrades_only_a_host_it_reaches() {
    let host = FakeHost::new();
    pack(
        &host,
        "registry",
        "include = [\"@box/npm\"]\n[tool.npm]\nupgrade_http = [\"example.com\"]",
    );
    pack(
        &host,
        "no-toolchains",
        "include = [\"@box/cargo\"]\n[tool.cargo]\n\
         hosts = [\"index.crates.io\", \"static.crates.io\"]",
    );
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .with("registry")
        .with("no-toolchains")
        .tools(["cargo", "npm"])
        .generate()
        .expect("a configuration");
    assert!(
        box_toml(&generated).get("gateway").is_none(),
        "{}",
        generated.box_toml()
    );
}

#[test]
fn tools_without_hosts_add_no_package_host_permits() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .tools(["node"])
        .generate()
        .expect("a configuration");
    assert!(
        !generated.policy().contains("package_hosts"),
        "{}",
        generated.policy()
    );
}

#[test]
fn a_dnf_install_reads_named_folders_of_usr_and_npm_runs_the_node_its_line_names() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let bin = trees.dnf();
    let generated = trial(&host, &[&bin])
        .os("linux")
        .tools(["git", "npm"])
        .generate()
        .expect("a configuration");
    let project = text(generated.project());
    let scratch = |tool: &str| text(&run_folder(&generated).join("tool-tmp").join(tool));
    let git = tool(&generated, "git");
    assert_eq!(strings(&git["command"]), [text(&bin.join("git"))]);
    assert_eq!(
        strings(&git["filesystem"]["read"]),
        [
            project.clone(),
            text(&trees.path("usr/libexec/git-core")),
            text(&trees.path("usr/share/git-core")),
            scratch("git"),
        ]
    );
    let node = tool(&generated, "node");
    assert_eq!(strings(&node["command"]), [text(&bin.join("node-20"))]);
    assert_eq!(
        strings(&node["filesystem"]["read"]),
        [
            project.clone(),
            text(&trees.path("usr/bin")),
            text(&trees.path("usr/share/node-20")),
            scratch("node")
        ],
        "node reads its own folder, and `share/node-*` matches the version folder"
    );
    let npm = tool(&generated, "npm");
    let script = trees.path("usr/lib/nodejs20/lib/node_modules/npm/bin/npm-cli.js");
    assert_eq!(strings(&npm["command"]), [text(&script)]);
    assert_eq!(
        strings(&npm["filesystem"]["read"]),
        [
            project,
            text(&trees.path("usr/lib/nodejs20/lib/node_modules")),
            scratch("npm"),
            text(&bin),
            text(&trees.path("usr/share/node-20")),
        ]
    );
    assert_eq!(
        npm["env"]["PATH"].as_str(),
        Some(format!("{}:/usr/bin:/bin", bin.display()).as_str())
    );
    for (name, path) in [
        ("git", bin.join("git")),
        ("node", bin.join("node-20")),
        ("npm", script),
    ] {
        assert!(
            generated.policy().contains(&format!(
                "context.input.program_path == {:?} && context.input.program == {name:?}",
                text(&path)
            )),
            "{name}: {}",
            generated.policy()
        );
    }
    assert!(
        generated
            .policy()
            .contains(r#"context.input.host == "registry.npmjs.org""#)
    );
}

#[test]
fn a_homebrew_install_reads_its_keg_and_its_dependencies_configuration() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let brew = trees.homebrew();
    let generated = trial(&host, &[&brew.join("bin")])
        .os("macos")
        .variable("HOMEBREW_PREFIX", text(&brew))
        .tools(["git", "npm"])
        .generate()
        .expect("a configuration");
    let git = tool(&generated, "git");
    assert_eq!(
        strings(&git["command"]),
        [text(&brew.join("Cellar/git/2.56.0_1/bin/git"))]
    );
    assert!(
        strings(&git["filesystem"]["read"]).contains(&text(&brew.join("Cellar"))),
        "{git}"
    );
    let node = tool(&generated, "node");
    assert!(
        strings(&node["filesystem"]["read"]).contains(&text(&brew.join("etc/openssl@3"))),
        "{node}"
    );
    let npm = tool(&generated, "npm");
    assert!(
        strings(&npm["filesystem"]["read"]).contains(&text(&brew.join("etc/openssl@3"))),
        "npm inherits node's reads: {npm}"
    );
    assert!(
        npm["env"]["PATH"]
            .as_str()
            .is_some_and(|path| path.starts_with(&text(&brew.join("Cellar/node/26.10.0_1/bin")))),
        "{npm}"
    );
}

#[test]
fn homebrew_support_follows_the_executable_and_needs_no_prefix_input() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let brew = trees.homebrew();
    let generated = trial(&host, &[&brew.join("bin")])
        .os("macos")
        .variable("HOMEBREW_PREFIX", "/irrelevant")
        .tools(["node"])
        .generate()
        .expect("a configuration");
    assert!(
        generated
            .inputs()
            .iter()
            .all(|(name, _, _)| name != "homebrew.prefix")
    );
    let node = tool(&generated, "node");
    assert_eq!(
        strings(&node["filesystem"]["read"]),
        [
            text(&host.project()),
            text(&brew.join("Cellar/node/26.10.0_1")),
            text(&brew.join("Cellar/openssl@3/3.0")),
            text(&brew.join("etc/openssl@3")),
            text(&run_folder(&generated).join("tool-tmp/node")),
        ],
        "{node}"
    );
    let hosts: Vec<String> = Path::new("/private/etc/hosts")
        .canonicalize()
        .ok()
        .iter()
        .map(|path| text(path))
        .collect();
    assert_eq!(
        node["filesystem"]
            .get("read_file")
            .map(strings)
            .unwrap_or_default(),
        hosts
    );
    assert_eq!(
        strings(&node["filesystem"]["list"]),
        [text(&brew.join("bin")), text(&brew.join("opt"))]
    );
    assert!(
        generated
            .box_toml()
            .contains("# installation tool.node homebrew: ")
    );
}

mod installation_grants {
    use super::*;
    use crate::reference::Sources;
    use strands_box::{ForbiddenClass, GrantRefusal};

    struct Host {
        programs: BTreeMap<String, PathBuf>,
        grants: BTreeMap<PathBuf, Result<bool, (GrantRefusal, String)>>,
    }

    impl Sources for Host {
        fn env(&self, _: &str) -> Option<String> {
            None
        }

        fn env_with_prefix(&self, _: &str) -> Vec<(String, String)> {
            Vec::new()
        }

        fn program(&mut self, name: &str) -> Option<PathBuf> {
            self.search(name)
        }

        fn search(&self, name: &str) -> Option<PathBuf> {
            self.programs.get(name).cloned()
        }

        fn developer_dir(&mut self) -> Result<String, String> {
            Err("no developer directory".into())
        }

        fn read_grant(&self, path: &Path) -> Result<bool, (GrantRefusal, String)> {
            self.grants.get(path).cloned().unwrap_or_else(|| {
                strands_box::check_read_grant(path)
                    .map_err(|error| (error.kind(), error.to_string()))
            })
        }
    }

    fn resolve(host: &FakeHost, sources: &mut Host, tools: &str) -> crate::profile::Resolved {
        resolve_text(
            host,
            sources,
            &format!("[project]\naccess = \"write\"\n[agent]\ncommand = [\"/bin/sh\"]\n{tools}"),
        )
    }

    /// Resolve the whole profile `text`.
    fn resolve_text(host: &FakeHost, sources: &mut Host, text: &str) -> crate::profile::Resolved {
        let home = host.home();
        let project = host.project();
        let profile = home.join(".strands/box/profiles/test/profile.toml");
        let box_dir = home.join(".strands/box/r/test/box");
        let storage = home.join(".strands/box/storage/test");
        crate::profile::Profile::parse(text, &profile, crate::VERSION)
            .expect("a profile")
            .resolve(
                None,
                &crate::lang::Lookup {
                    vendored: None,
                    operator: home.join(".strands/box/packs"),
                    collections: Vec::new(),
                    version: crate::VERSION,
                },
                sources,
                &crate::lang::Inputs {
                    home: &home,
                    box_home: &home.join(".strands/box"),
                    workspace: &project,
                    profile: &profile,
                    profile_file: &profile.join("profile.toml"),
                    box_dir: &box_dir,
                    storage: &storage,
                    os: "macos",
                    tool_cache: None,
                    packs: None,
                },
            )
            .expect("a resolved profile")
    }

    /// **A tool that the profile declares is not hidden by `extend`.** app extends git, which would
    /// hide git. The profile sets `[tool.git] program` itself, so git stays a tool of its own, and
    /// app still gets git's variable.
    #[test]
    fn a_tool_that_the_profile_declares_is_not_hidden_by_extend() {
        let host = FakeHost::new();
        let trees = Trees::new();
        binary(&trees.path("git/bin/git"));
        binary(&trees.path("app/bin/app"));
        tool_pack(&host, "git", &[], "[env]\nB = \"git\"");
        tool_pack(&host, "app", &["git"], "");
        let mut sources = Host {
            programs: BTreeMap::from([
                ("app".into(), trees.path("app/bin/app")),
                ("git".into(), trees.path("git/bin/git")),
            ]),
            grants: BTreeMap::new(),
        };
        let base = "packs = [\"app\"]\n[project]\naccess = \"write\"\n\
                    [agent]\ncommand = [\"/bin/sh\"]\n";
        let hidden = resolve_text(&host, &mut sources, base);
        assert!(!hidden.tool.contains_key("git"), "{:?}", hidden.tool.keys());
        let declared = resolve_text(
            &host,
            &mut sources,
            &format!("{base}[tool.git]\nprogram = \"git\"\n"),
        );
        assert!(
            declared.tool.contains_key("git"),
            "{:?}",
            declared.tool.keys()
        );
        assert_eq!(
            declared.tool["app"].env.get("B").map(String::as_str),
            Some("git")
        );
    }

    #[test]
    fn core_system_trees_are_dropped_from_selected_and_helper_installations() {
        for declaration in [
            "[tool.app]\nprogram = \"node\"\ninstallation = [\"homebrew\"]",
            "[tool.app]\nprogram = \"app\"\nhelpers = [\"node\"]",
        ] {
            let host = FakeHost::new();
            let trees = Trees::new();
            let brew = trees.homebrew();
            binary(&trees.path("app/app"));
            let mut sources = Host {
                programs: BTreeMap::from([
                    ("app".into(), trees.path("app/app")),
                    ("node".into(), brew.join("bin/node")),
                ]),
                grants: ["Cellar/node/26.10.0_1", "bin", "opt"]
                    .into_iter()
                    .map(|path| {
                        (
                            brew.join(path),
                            Err((
                                GrantRefusal::Forbidden(ForbiddenClass::SystemTree),
                                "Core system tree".into(),
                            )),
                        )
                    })
                    .collect(),
            };
            let resolved = resolve(&host, &mut sources, declaration);
            assert!(
                resolved.tools.skipped.is_empty(),
                "{:?}",
                resolved.tools.skipped
            );
            let process = &resolved.tool["app"];
            let mut expected = vec![
                text(&host.project()),
                text(&brew.join("Cellar/openssl@3/3.0")),
                text(&brew.join("etc/openssl@3")),
                text(&host.home().join(".strands/box/r/test/tool-tmp/app")),
            ];
            if declaration.contains("helpers") {
                // The helper is granted by the name `PATH` finds, a link Core shows the file at.
                expected.push(text(&brew.join("bin/node")));
            }
            assert_eq!(process.filesystem.read, expected, "{declaration}");
            assert_eq!(process.filesystem.read_file, Vec::<String>::new());
            assert_eq!(process.filesystem.list, Vec::<String>::new());
        }
    }

    #[test]
    fn core_system_trees_are_dropped_from_interpreter_installations() {
        let host = FakeHost::new();
        let trees = Trees::new();
        let brew = trees.homebrew();
        let node = brew.join("Cellar/node/26.10.0_1/bin/node");
        script_with(&trees.path("app/app"), &format!("#!{}\n", node.display()));
        let mut sources = Host {
            programs: BTreeMap::from([
                ("app".into(), trees.path("app/app")),
                ("node".into(), node.clone()),
            ]),
            grants: ["Cellar/node/26.10.0_1", "bin", "opt"]
                .into_iter()
                .map(|path| {
                    (
                        brew.join(path),
                        Err((
                            GrantRefusal::Forbidden(ForbiddenClass::SystemTree),
                            "Core system tree".into(),
                        )),
                    )
                })
                .collect(),
        };
        let resolved = resolve(
            &host,
            &mut sources,
            "[tool.node]\nprogram = \"node\"\n[tool.app]\nprogram = \"app\"",
        );
        assert!(
            resolved.tools.skipped.is_empty(),
            "{:?}",
            resolved.tools.skipped
        );
        let process = &resolved.tool["app"];
        assert_eq!(
            process.filesystem.read,
            [
                text(&host.project()),
                text(&host.home().join(".strands/box/r/test/tool-tmp/app")),
                text(&node),
                text(&brew.join("Cellar/openssl@3/3.0")),
                text(&brew.join("etc/openssl@3")),
            ]
        );
        assert_eq!(process.filesystem.read_file, Vec::<String>::new());
        assert_eq!(process.filesystem.list, Vec::<String>::new());
    }

    #[test]
    fn an_installation_directory_that_core_permits_is_preserved() {
        let host = FakeHost::new();
        let shell = PathBuf::from(crate::test_support::shell());
        let directory = shell.parent().expect("a shell directory");
        let mut sources = Host {
            programs: BTreeMap::from([("sh".into(), shell.clone())]),
            grants: BTreeMap::from([(directory.to_path_buf(), Ok(false))]),
        };
        let resolved = resolve(
            &host,
            &mut sources,
            "[tool.sh]\nprogram = \"sh\"\ninstallation = [\"directory\"]",
        );
        assert!(
            resolved.tools.skipped.is_empty(),
            "{:?}",
            resolved.tools.skipped
        );
        assert_eq!(
            resolved.tool["sh"].filesystem.read,
            [
                text(&host.project()),
                text(directory),
                text(&host.home().join(".strands/box/r/test/tool-tmp/sh")),
            ]
        );
    }

    #[test]
    fn a_helper_python_that_a_read_covers_gets_no_read_file() {
        let host = FakeHost::new();
        let trees = Trees::new();
        binary(&trees.path("app/app"));
        let bin = trees.folder("python/bin");
        let python = bin.join("python3.12");
        binary(&python);
        trees.folder("python/lib");
        link("python3.12", &bin.join("python3"));
        let helper = "[tool.app]\nprogram = \"app\"\nhelpers = [\"python3\"]";
        for declaration in [
            helper.to_string(),
            format!(
                "{helper}\n[tool.app.filesystem]\nread = [\"{}\"]",
                bin.display()
            ),
            format!(
                "{helper}\n[tool.app.filesystem]\nread_file = [{:?}]",
                bin.join("python3")
            ),
        ] {
            let mut sources = Host {
                programs: BTreeMap::from([
                    ("app".into(), trees.path("app/app")),
                    ("python3".into(), bin.join("python3")),
                ]),
                grants: BTreeMap::new(),
            };
            let resolved = resolve(&host, &mut sources, &declaration);
            assert!(
                resolved.tools.skipped.is_empty(),
                "{:?}",
                resolved.tools.skipped
            );
            let filesystem = &resolved.tool["app"].filesystem;
            assert!(
                filesystem
                    .read
                    .iter()
                    .any(|root| bin.join("python3").starts_with(root)),
                "{declaration}: {:?}",
                filesystem.read
            );
            assert!(
                filesystem.read.contains(&text(&trees.path("python/lib"))),
                "{declaration}: {:?}",
                filesystem.read
            );
            assert_eq!(filesystem.read_file, Vec::<String>::new(), "{declaration}");
        }
    }

    /// **A helper is granted by the name `PATH` finds it by, in that name's real folder.**
    /// `cc`, `ld` and `as` are links on most Linux hosts, and a folder on `PATH` such as `/bin`
    /// can itself be a link. The real file is never granted alone, and nothing on the way is.
    #[test]
    fn a_helper_is_granted_by_its_path_name_in_its_real_folder() {
        let host = FakeHost::new();
        let trees = Trees::new();
        binary(&trees.path("app/app"));
        let bin = trees.folder("usr/bin");
        binary(&bin.join("gcc"));
        link("gcc", &bin.join("cc"));
        binary(&bin.join("ld.bfd"));
        link("../../etc/alternatives/ld", &bin.join("ld"));
        link(
            &text(&bin.join("ld.bfd")),
            &trees.path("etc/alternatives/ld"),
        );
        binary(&bin.join("as"));
        let linked = trees.path("bin");
        std::os::unix::fs::symlink(&bin, &linked).expect("a linked folder");
        let mut sources = Host {
            programs: ["cc", "ld", "as"]
                .into_iter()
                .map(|name| (name.to_string(), linked.join(name)))
                .chain([("app".to_string(), trees.path("app/app"))])
                .collect(),
            grants: BTreeMap::from([(
                bin.clone(),
                Err((
                    GrantRefusal::Forbidden(ForbiddenClass::SystemTree),
                    "Core system tree".into(),
                )),
            )]),
        };
        let resolved = resolve(
            &host,
            &mut sources,
            "[tool.app]\nprogram = \"app\"\nhelpers = [\"cc\", \"ld\", \"as\"]",
        );
        let filesystem = &resolved.tool["app"].filesystem;
        for name in ["cc", "ld", "as"] {
            assert!(
                filesystem.read.contains(&text(&bin.join(name))),
                "{name}: {:?}",
                filesystem.read
            );
        }
        for granted in filesystem.read.iter().chain(&filesystem.read_file) {
            assert!(!granted.contains("alternatives"), "{granted}");
            assert_ne!(
                granted,
                &text(&bin.join("gcc")),
                "only the name, not the file alone"
            );
            assert_ne!(
                granted,
                &text(&bin.join("ld.bfd")),
                "only the name, not the file alone"
            );
            assert!(!granted.starts_with(&text(&linked)), "{granted}");
        }
    }
}

#[test]
fn a_git_table_that_reads_no_developer_folder_keeps_the_stub() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let (bin, developer) = trees.apple();
    pack(&host, "mygit", "[tool.mygit]\nprogram = \"git\"");
    let generated = trial(&host, &[&bin])
        .os("macos")
        .apple_stubs(&bin)
        .with("mygit")
        .command_output(&["/usr/bin/xcode-select", "-p"], &text(&developer))
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    assert_eq!(
        strings(&tool(&generated, "mygit")["command"]),
        [text(&bin.join("git"))]
    );
}

#[test]
fn on_linux_no_macos_entry_applies_and_xcode_select_never_runs() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let bin = trees.dnf();
    let generated = Trial::for_project(host.project())
        .home(host.home())
        .resources(crate::resources::source_tree())
        .with("claude")
        .with("bedrock")
        .search_path(format!("{}:/usr/bin:/bin", bin.display()))
        .os("linux")
        .tools(["git", "cargo"])
        .generate()
        .expect("a configuration with no answer for xcode-select");
    assert!(
        tool(&generated, "git")["env"]
            .get("DEVELOPER_DIR")
            .is_none()
    );
    assert!(
        !generated
            .inputs()
            .iter()
            .any(|(name, _, _)| name == "macos.developer_dir"),
        "{:?}",
        generated.inputs()
    );
}

#[test]
fn a_program_in_or_through_a_place_a_box_writes_is_skipped() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let planted = host.project().join("tools/node");
    binary(&planted);
    link(&text(&planted), &trees.path("links/node"));
    let box_home = host.home().join(".strands/box/bin/git");
    binary(&box_home);
    let generated = trial(
        &host,
        &[&trees.path("links"), &host.home().join(".strands/box/bin")],
    )
    .tools(["git", "node"])
    .generate()
    .expect("a configuration");
    let skipped = generated.skipped();
    let why = |label: &str| {
        skipped
            .iter()
            .find(|(name, _)| name == label)
            .map(|(_, why)| why.clone())
            .unwrap_or_else(|| panic!("{label} is skipped: {skipped:?}"))
    };
    assert!(
        why("node (@box/node)").contains("lies in the workspace"),
        "{skipped:?}"
    );
    assert!(
        why("git (@box/git)").contains("lies in the box home"),
        "{skipped:?}"
    );
    assert!(!generated.policy().contains("spawn_node"));
}

#[test]
fn a_script_inherits_its_interpreters_reads_with_the_deny_that_narrows_them() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let runtime = trees.folder("runtime");
    trees.folder("runtime/private");
    let listed = trees.folder("listing");
    binary(&trees.path("rt/bin/rt"));
    script_with(&trees.path("app/bin/app"), "#!/usr/bin/env rt\n");
    pack(
        &host,
        "rt",
        &format!(
            "[tool.rt]\nprogram = \"rt\"\n[tool.rt.filesystem]\nread = [{:?}]\nlist = [{:?}]\ndeny = [{:?}]\n\
             [tool.rt.env]\nRT_ONLY = \"1\"",
            text(&runtime),
            text(&listed),
            text(&runtime.join("private"))
        ),
    );
    pack(
        &host,
        "app",
        "extend = [\"rt\"]\n[tool.app]\nprogram = \"app\"\nhosts = [\"example.com\"]",
    );
    let generated = trial(&host, &[&trees.path("rt/bin"), &trees.path("app/bin")])
        .with("app")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    let app = tool(&generated, "app");
    assert!(
        strings(&app["filesystem"]["read"]).contains(&text(&runtime)),
        "{app}"
    );
    assert!(
        strings(&app["filesystem"]["read"])
            .iter()
            .any(|grant| trees.path("rt/bin/rt").starts_with(grant)),
        "an interpreter without read_file still receives an executable read: {app}"
    );
    assert!(
        strings(&app["filesystem"]["deny"]).contains(&text(&runtime.join("private"))),
        "the deny travels with the read: {app}"
    );
    let env = std::fs::canonicalize("/usr/bin/env").expect("env");
    assert!(
        strings(&app["filesystem"]["read"]).contains(&text(&env)),
        "the #! line runs through env, so the script reads env's real file: {app}"
    );
    assert!(
        strings(&app["filesystem"]["list"]).contains(&text(&listed)),
        "interpreter listings travel with its reads: {app}"
    );
    assert!(
        app["env"].get("RT_ONLY").is_none(),
        "no env is inherited: {app}"
    );
    assert!(
        generated.policy().contains(r#"@id("spawn_app") permit"#)
            && generated
                .policy()
                .contains(r#"context.input.host == "example.com""#),
        "{}",
        generated.policy()
    );
}

#[test]
fn a_script_reads_its_interpreter_file_once() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let interpreter = trees.path("rt/bin/rt");
    binary(&interpreter);
    let data = trees.path("rt/data");
    write(&data, "data");
    let alias = trees.path("app/data");
    link(&text(&data), &alias);
    script_with(&trees.path("app/bin/app"), "#!/usr/bin/env rt\n");
    pack(
        &host,
        "app",
        &format!(
            "[tool.rt]\nprogram = \"rt\"\n[tool.rt.filesystem]\nread_file = [{data:?}]\n\
             [tool.app]\nprogram = \"app\"\n\
             [tool.app.filesystem]\nread_file = [{interpreter:?}, {alias:?}]"
        ),
    );
    let generated = trial(&host, &[&trees.path("rt/bin"), &trees.path("app/bin")])
        .with("app")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    let app = tool(&generated, "app");
    assert_eq!(strings(&app["filesystem"]["read_file"]), [text(&alias)]);
    assert!(
        strings(&app["filesystem"]["read"]).contains(&text(&trees.path("rt/bin"))),
        "{app}"
    );
}

#[test]
fn a_tool_keeps_a_read_file_link_and_resolves_other_grants() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("app/bin/app"));
    let readable = trees.folder("readable");
    let real_file = trees.path("outside/data");
    write(&real_file, "data");
    let file = readable.join("file");
    let second = readable.join("second");
    link(&text(&real_file), &file);
    link(&text(&real_file), &second);
    link(&text(&readable), &trees.path("parent"));
    let directory = trees.folder("outside/directory");
    link(&text(&directory), &readable.join("directory"));
    let writable = trees.folder("outside/writable");
    link(&text(&writable), &readable.join("writable"));
    let state = writable.join("state");
    write(&state, "state");
    link(&text(&state), &readable.join("state"));

    for (input, covered) in [
        (&file, false),
        (&trees.path("parent/file"), false),
        (&file, true),
    ] {
        if covered {
            let local = readable.join("data");
            write(&local, "data");
            std::fs::remove_file(&file).expect("remove the outside link");
            link(&text(&local), &file);
        }
        pack(
            &host,
            "app",
            &format!(
                "[tool.app]\nprogram = \"app\"\n[tool.app.filesystem]\n\
                 read = [{readable:?}, {directory:?}, {real_file:?}]\n\
                 read_file = [{real_file:?}, {input:?}, {second:?}]\nexec = [{directory:?}]\n\
                 write = [{writable:?}]\nwrite_file = [{state:?}]",
                directory = readable.join("directory"),
                writable = readable.join("writable"),
                state = readable.join("state"),
            ),
        );
        let generated = trial(&host, &[&trees.path("app/bin")])
            .with("app")
            .tools(Vec::<String>::new())
            .generate()
            .expect("a configuration");
        let app = tool(&generated, "app");
        let expected = if covered {
            vec![text(&second)]
        } else {
            vec![text(&file), text(&second)]
        };
        assert_eq!(strings(&app["filesystem"]["read_file"]), expected, "{app}");
        let read = strings(&app["filesystem"]["read"]);
        assert!(read.contains(&text(&readable)), "{app}");
        assert!(read.contains(&text(&directory)), "{app}");
        assert!(!read.contains(&text(&real_file)), "{app}");
        assert!(!read.contains(&text(&readable.join("directory"))), "{app}");
        assert_eq!(strings(&app["filesystem"]["exec"]), [text(&directory)]);
        let write = strings(&app["filesystem"]["write"]);
        assert!(write.contains(&text(&writable)), "{app}");
        assert!(!write.contains(&text(&readable.join("writable"))), "{app}");
        assert_eq!(strings(&app["filesystem"]["write_file"]), [text(&state)]);
    }
}

#[test]
fn a_script_preserves_its_own_exact_interpreter_read() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let interpreter = trees.path("python/bin/python3.12");
    binary(&interpreter);
    trees.folder("python/lib");
    script_with(&trees.path("app/bin/app"), "#!/usr/bin/env python3.12\n");
    pack(
        &host,
        "app",
        &format!(
            "[tool.python]\nprogram = \"python3.12\"\n[tool.app]\nprogram = \"app\"\n\
             [tool.app.filesystem]\nread_file = [{:?}]",
            text(&interpreter)
        ),
    );
    let generated = trial(&host, &[&trees.path("python/bin"), &trees.path("app/bin")])
        .with("app")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    let app = tool(&generated, "app");
    assert_eq!(
        strings(&app["filesystem"]["read_file"]),
        [text(&interpreter)]
    );
    let read = strings(&app["filesystem"]["read"]);
    assert!(read.contains(&text(&trees.path("python/lib"))), "{app}");
    assert!(
        !read
            .iter()
            .any(|root| interpreter.starts_with(Path::new(root))),
        "{app}"
    );
}

#[test]
fn a_script_whose_interpreter_has_no_tool_table_is_skipped() {
    let host = FakeHost::new();
    let trees = Trees::new();
    script_with(&trees.path("bin/wrapper"), "#!/bin/sh\nexit 0\n");
    script_with(&trees.path("bin/viaenv"), "#!/usr/bin/env python3\n");
    pack(
        &host,
        "wrappers",
        "[tool.wrapper]\nprogram = \"wrapper\"\n[tool.viaenv]\nprogram = \"viaenv\"",
    );
    let generated = trial(&host, &[&trees.path("bin")])
        .with("wrappers")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    let skipped = generated.skipped();
    assert!(
        skipped
            .iter()
            .any(|(name, why)| name == "wrapper (wrappers)"
                && why.contains("is the command of no tool table")),
        "{skipped:?}"
    );
    assert!(
        skipped.iter().any(|(name, why)| name == "viaenv (wrappers)"
            && why.contains("no tool table in the profile has `program = \"python3\"`")),
        "{skipped:?}"
    );
}

#[test]
fn a_missing_tool_a_skipped_interpreter_and_a_missing_path_each_leave_the_run_going() {
    let host = FakeHost::new();
    std::fs::remove_file(host.brew().join("bin/node")).expect("remove node");
    std::fs::remove_dir_all(host.home().join(".rustup")).expect("remove rustup's home");
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .tools(["cargo", "git", "node", "npm"])
        .search_path(host.own_search_path())
        .generate()
        .expect("a configuration");
    let skipped: Vec<&str> = generated
        .skipped()
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(skipped, ["node (@box/node)", "npm (@box/npm)"]);
    assert!(
        generated
            .dropped()
            .contains(&("cargo".to_string(), text(&host.home().join(".rustup")))),
        "{:?}",
        generated.dropped()
    );
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    let tools: Vec<&str> = file["tool"]
        .as_table()
        .expect("tools")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(tools, ["cargo", "git"]);
    assert!(
        !generated.policy().contains("registry.npmjs.org"),
        "{}",
        generated.policy()
    );
}

#[test]
fn the_profile_preview_lists_each_skipped_tool_and_each_dropped_path() {
    let host = FakeHost::new();
    std::fs::remove_file(host.brew().join("bin/node")).expect("remove node");
    host.profile()
        .with("claude")
        .with("bedrock")
        .search_path(host.own_search_path())
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let preview = host
        .launcher()
        .search_path(host.own_search_path())
        .preview("claude", &host.project())
        .expect("a preview");
    assert!(
        preview.skipped.contains(&(
            "node (@box/node)".to_string(),
            "node is not on PATH".to_string()
        )),
        "{:?}",
        preview.skipped
    );
    assert!(
        preview
            .dropped
            .iter()
            .any(|(tool, path)| tool == "git" && path.ends_with("git/share/git-core")),
        "{:?}",
        preview.dropped
    );
}

#[test]
fn a_star_matches_within_one_name_and_any_text() {
    use crate::lang::fits;
    for (name, pieces, expected) in [
        ("node-20", &["node-", ""][..], true),
        ("libfoo.dylib", &["lib", ".dylib"][..], true),
        ("libfoo.so", &["lib", ".dylib"][..], false),
        ("a-x-b-y-c", &["a", "b", "c"][..], true),
        ("a-x-c", &["a", "b", "c"][..], false),
        ("ab", &["ab", "b"][..], false),
        ("a\u{20ac}", &["a", "bc"][..], false),
        ("\u{20ac}x", &["", "x"][..], true),
    ] {
        assert_eq!(fits(name, pieces), expected, "{name} {pieces:?}");
    }
}

#[test]
fn a_tool_under_a_write_grant_of_the_run_is_skipped() {
    let host = FakeHost::new();
    let local = host.home().join("tools/bin");
    binary(&local.join("git"));
    pack(
        &host,
        "writes",
        &format!("[agent.filesystem]\nwrite = [{:?}]", text(&local)),
    );
    let generated = trial(&host, &[&local])
        .with("writes")
        .tools(["git"])
        .generate()
        .expect("a configuration");
    let (_, why) = generated
        .skipped()
        .iter()
        .find(|(name, _)| name == "git (@box/git)")
        .expect("git is skipped");
    assert!(why.contains("lies under the write grant"), "{why}");
    assert!(!generated.policy().contains("spawn_git"));
}

#[test]
fn a_tool_table_that_names_a_program_has_a_plain_name() {
    let host = FakeHost::new();
    pack(&host, "odd", "[tool.\"a b\"]\nprogram = \"git\"");
    let error = trial(&host, &[])
        .with("odd")
        .tools(Vec::<String>::new())
        .generate()
        .expect_err("a name with a space");
    assert!(error.to_string().contains("letters, digits"), "{error}");
}

#[test]
fn a_cc_that_is_not_an_executable_file_is_passed_over() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let developer = trees.folder("Xcode.app/Contents/Developer");
    write(
        &developer.join("Toolchains/XcodeDefault.xctoolchain/usr/bin/cc"),
        "not a program",
    );
    binary(&developer.join("usr/bin/cc"));
    std::fs::create_dir_all(developer.join("SDKs/MacOSX.sdk")).expect("an SDK");
    let generated = macos_cargo(&host, &developer);
    assert_eq!(
        tool(&generated, "cargo")["env"]["CC_aarch64_apple_darwin"].as_str(),
        Some(text(&developer.join("usr/bin/cc")).as_str())
    );
}

#[test]
fn a_script_whose_interpreter_lies_under_a_write_grant_is_skipped() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("writable/rt"));
    script_with(&trees.path("clean/app"), "#!/usr/bin/env rt\n");
    pack(&host, "rt", "[tool.rt]\nprogram = \"rt\"");
    pack(
        &host,
        "app",
        &format!(
            "extend = [\"rt\"]\n[tool.app]\nprogram = \"app\"\n[agent.filesystem]\nwrite_file = [{:?}]",
            text(&trees.path("writable/rt"))
        ),
    );
    let generated = trial(&host, &[&trees.path("writable"), &trees.path("clean")])
        .with("app")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    let skipped: Vec<&str> = generated
        .skipped()
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(skipped.contains(&"rt (rt)"), "{skipped:?}");
    assert!(skipped.contains(&"app (app)"), "{skipped:?}");
    assert!(
        !generated.policy().contains("spawn_app"),
        "{}",
        generated.policy()
    );
}

#[test]
fn a_script_whose_env_lies_under_a_write_grant_is_skipped() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("rt/rt"));
    binary(&trees.path("writable/env"));
    script_with(
        &trees.path("clean/app"),
        &format!("#!{} rt\n", text(&trees.path("writable/env"))),
    );
    pack(&host, "rt", "[tool.rt]\nprogram = \"rt\"");
    pack(
        &host,
        "app",
        &format!(
            "extend = [\"rt\"]\n[tool.app]\nprogram = \"app\"\n[agent.filesystem]\nwrite_file = [{:?}]",
            text(&trees.path("writable/env"))
        ),
    );
    let generated = trial(&host, &[&trees.path("rt"), &trees.path("clean")])
        .with("app")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    let skipped: Vec<&str> = generated
        .skipped()
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(skipped, vec!["app (app)"], "the env a box can write");
}

#[test]
fn a_script_reads_each_program_of_its_interpreters_own_line() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("rt/rt"));
    let runtime = trees.folder("runtime");
    trees.folder("runtime/private");
    script_with(&trees.path("mid/mid"), "#!/usr/bin/env rt\n");
    script_with(&trees.path("app/app"), "#!/usr/bin/env mid\n");
    pack(
        &host,
        "rt",
        &format!(
            "[tool.rt]\nprogram = \"rt\"\n[tool.rt.filesystem]\nread = [{:?}]\ndeny = [{:?}]",
            text(&runtime),
            text(&runtime.join("private"))
        ),
    );
    pack(
        &host,
        "mid",
        "extend = [\"rt\"]\n[tool.mid]\nprogram = \"mid\"",
    );
    pack(
        &host,
        "app",
        "extend = [\"mid\"]\n[tool.app]\nprogram = \"app\"",
    );
    let generated = trial(
        &host,
        &[&trees.path("rt"), &trees.path("mid"), &trees.path("app")],
    )
    .with("app")
    .tools(Vec::<String>::new())
    .generate()
    .expect("a configuration");
    let app = tool(&generated, "app");
    let read = strings(&app["filesystem"]["read"]);
    let env = std::fs::canonicalize("/usr/bin/env").expect("env");
    for file in [env, trees.path("mid"), trees.path("rt"), runtime.clone()] {
        assert!(read.contains(&text(&file)), "{} in {app}", file.display());
    }
    assert_eq!(
        strings(&app["filesystem"]["deny"])
            .into_iter()
            .filter(|entry| entry.starts_with(&text(&runtime)))
            .collect::<Vec<_>>(),
        vec![text(&runtime.join("private"))],
        "the deeper hop's deny travels with its read: {app}"
    );
    let path: Vec<String> = app["env"]["PATH"]
        .as_str()
        .expect("a PATH")
        .split(':')
        .map(str::to_string)
        .collect();
    assert_eq!(
        path[..2],
        [text(&trees.path("mid")), text(&trees.path("rt"))],
        "mid's line finds rt on the script's PATH: {app}"
    );
}

#[test]
fn the_developer_folder_is_asked_for_only_when_a_kept_entry_names_it() {
    let host = FakeHost::new();
    let generated = Trial::for_project(host.project())
        .home(host.home())
        .resources(crate::resources::source_tree())
        .with("claude")
        .with("bedrock")
        .os("macos")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration with no answer for xcode-select");
    assert!(
        !generated
            .inputs()
            .iter()
            .any(|(name, _, _)| name == "macos.developer_dir"),
        "{:?}",
        generated.inputs()
    );
}

#[test]
fn the_developer_folder_outside_a_macos_when_is_refused() {
    let host = FakeHost::new();
    for entry in [
        "read = [\"${{ macos.developer_dir }}\"]",
        "read = [{ path = \"${{ macos.developer_dir }}\", when = \"linux\" }]",
        "read = [\"${{ macos.toolchain }}\"]",
        "read = [\"${{ macos.sdk_root }}\"]",
    ] {
        pack(
            &host,
            "unguarded",
            &format!("[tool.git]\nprogram = \"git\"\n[tool.git.filesystem]\n{entry}"),
        );
        let error = trial(&host, &[])
            .os("macos")
            .with("unguarded")
            .tools(Vec::<String>::new())
            .generate()
            .expect_err("no when = \"macos\"");
        assert!(
            error
                .to_string()
                .contains("valid only under `when = \"macos\"`"),
            "{entry}: {error}"
        );
    }
}

#[test]
fn root_is_the_folder_of_the_real_file_and_each_step_climbs_from_it() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("opt/rt/1.0/bin/rt"));
    binary(&trees.path("flat/1.0/flat"));
    let steps = "[env]\nROOT = \"${{ root }}\"\nUP = \"${{ root.parent }}\"\n\
                 UP2 = \"${{ root.parent.parent }}\"";
    pack(
        &host,
        "rt",
        &format!(
            "kind = \"tool\"\n{steps}\n[inputs.rt.path]\ntype = \"program\"\n\
                                program = \"rt\"\nsearch = [{{ env = \"PATH\" }}]\n[run]\n\
                                command = [\"${{{{ inputs.rt.path }}}}\"]"
        ),
    );
    pack(
        &host,
        "flat",
        &format!(
            "kind = \"tool\"\n{steps}\n[inputs.flat.path]\ntype = \"program\"\n\
                  program = \"flat\"\nsearch = [{{ env = \"PATH\" }}]\n[run]\n\
                  command = [\"${{{{ inputs.flat.path }}}}\"]"
        ),
    );
    let generated = trial(
        &host,
        &[&trees.path("opt/rt/1.0/bin"), &trees.path("flat/1.0")],
    )
    .with("rt")
    .with("flat")
    .tools(Vec::<String>::new())
    .generate()
    .expect("a configuration");
    for (name, root, up, up2) in [
        ("rt", "opt/rt/1.0/bin", "opt/rt/1.0", "opt/rt"),
        ("flat", "flat/1.0", "flat", ""),
    ] {
        let at = |relative: &str| match relative {
            "" => text(&trees.root),
            _ => text(&trees.path(relative)),
        };
        let env = &tool(&generated, name)["env"];
        assert_eq!(env["ROOT"].as_str(), Some(at(root).as_str()), "{name}");
        assert_eq!(env["UP"].as_str(), Some(at(up).as_str()), "{name}");
        assert_eq!(env["UP2"].as_str(), Some(at(up2).as_str()), "{name}");
    }
}

#[test]
fn a_root_step_that_is_not_parent_is_refused() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("rt/bin/rt"));
    pack(
        &host,
        "rt",
        "kind = \"tool\"\n[inputs.rt.path]\ntype = \"program\"\nprogram = \"rt\"\n\
         search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.rt.path }}\"]\n[env]\n\
         X = \"${{ root.up }}\"",
    );
    let error = trial(&host, &[&trees.path("rt/bin")])
        .with("rt")
        .tools(Vec::<String>::new())
        .generate()
        .expect_err("an unknown step");
    assert!(
        error
            .to_string()
            .contains("`up` is not a step of `root`; use `parent`"),
        "{error}"
    );
}

#[test]
fn an_env_line_with_flags_names_its_interpreter() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("rt/bin/rt"));
    script_with(&trees.path("app/bin/app"), "#!/usr/bin/env -S rt --flag\n");
    script_with(&trees.path("app/bin/empty"), "#!/usr/bin/env -S\n");
    pack(
        &host,
        "rt",
        "kind = \"tool\"\n[inputs.rt.path]\ntype = \"program\"\nprogram = \"rt\"\n\
                       search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.rt.path }}\"]",
    );
    pack(
        &host,
        "app",
        "kind = \"tool\"\nextend = [\"rt\"]\n[inputs.app.path]\n\
                        type = \"program\"\nprogram = \"app\"\nsearch = [{ env = \"PATH\" }]\n\
                        [run]\ncommand = [\"${{ inputs.app.path }}\"]",
    );
    pack(
        &host,
        "empty",
        "kind = \"tool\"\n[inputs.empty.path]\ntype = \"program\"\n\
                          program = \"empty\"\nsearch = [{ env = \"PATH\" }]\n[run]\n\
                          command = [\"${{ inputs.empty.path }}\"]",
    );
    let generated = trial(&host, &[&trees.path("rt/bin"), &trees.path("app/bin")])
        .with("app")
        .with("empty")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    let app = tool(&generated, "app");
    assert!(
        strings(&app["filesystem"]["read"]).contains(&text(&trees.path("rt/bin"))),
        "`env -S rt` runs the rt table: {app}"
    );
    assert!(
        generated
            .skipped()
            .iter()
            .any(|(name, why)| name == "empty (empty)"
                && why.contains("its #! line `/usr/bin/env -S` names no program after env")),
        "{:?}",
        generated.skipped()
    );
}

/// A `pm` whose real file is `pm/lib/pm/bin/pm`, found through a link in `global/bin`, where
/// `PATH` names `global` as `spelled` (a link to it when `spelled` is not `global`).
fn linked_program(trees: &Trees, spelled: &str) -> PathBuf {
    binary(&trees.path("pm/lib/pm/bin/pm"));
    std::fs::create_dir_all(trees.path("global/bin")).expect("a folder");
    std::os::unix::fs::symlink(trees.path("pm/lib/pm/bin/pm"), trees.path("global/bin/pm"))
        .expect("a link");
    if spelled != "global" {
        std::os::unix::fs::symlink(trees.path("global"), trees.path(spelled)).expect("a link");
    }
    trees.path(spelled).join("bin")
}

#[test]
fn a_program_found_through_a_link_has_the_links_folder_last_on_its_path_and_no_new_grant() {
    for (os, spelled) in [
        ("macos", "global"),
        ("macos", "profile"),
        ("linux", "global"),
    ] {
        let host = FakeHost::new();
        let trees = Trees::new();
        let search = linked_program(&trees, spelled);
        pack(
            &host,
            "pm",
            "kind = \"tool\"\n[inputs.pm.path]\ntype = \"program\"\n\
                           program = \"pm\"\nsearch = [{ env = \"PATH\" }]\n[run]\n\
                           command = [\"${{ inputs.pm.path }}\"]",
        );
        let generate = |folder: &Path| {
            trial(&host, &[folder])
                .os(os)
                .with("pm")
                .tools(Vec::<String>::new())
                .generate()
                .expect("a configuration")
        };
        let linked = generate(&search);
        let pm = tool(&linked, "pm");
        assert_eq!(
            pm["env"]["PATH"].as_str(),
            Some(format!("/usr/bin:/bin:{}", text(&search)).as_str()),
            "a package script that runs `pm` by name finds it as PATH spells it: {pm}"
        );
        let direct = generate(&trees.path("pm/lib/pm/bin"));
        assert_eq!(
            pm["filesystem"],
            tool(&direct, "pm")["filesystem"],
            "{os}, {spelled}: the link adds no grant"
        );
    }
}

#[test]
fn a_linked_programs_folder_that_a_profile_writes_into_is_not_added() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let search = linked_program(&trees, "global");
    pack(
        &host,
        "pm",
        "kind = \"tool\"\n[inputs.pm.path]\ntype = \"program\"\nprogram = \"pm\"\n\
                       search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.pm.path }}\"]",
    );
    pack(
        &host,
        "writer",
        &format!(
            "[agent.filesystem]\nwrite_file = [{:?}]",
            text(&trees.path("global/bin/other"))
        ),
    );
    let generated = trial(&host, &[&search])
        .os("macos")
        .with("pm")
        .with("writer")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    let pm = tool(&generated, "pm");
    assert_eq!(pm["env"]["PATH"].as_str(), Some("/usr/bin:/bin"), "{pm}");
    assert!(pm["filesystem"].get("list").is_none(), "{pm}");
}

#[test]
fn a_program_found_where_it_is_installed_adds_no_folder() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("pm/bin/pm"));
    pack(
        &host,
        "pm",
        "kind = \"tool\"\n[inputs.pm.path]\ntype = \"program\"\nprogram = \"pm\"\n\
                       search = [{ env = \"PATH\" }]\n[run]\ncommand = [\"${{ inputs.pm.path }}\"]",
    );
    let generated = trial(&host, &[&trees.path("pm/bin")])
        .with("pm")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    let pm = tool(&generated, "pm");
    assert_eq!(pm["env"]["PATH"].as_str(), Some("/usr/bin:/bin"), "{pm}");
    assert!(pm["filesystem"].get("list").is_none(), "{pm}");
}

#[test]
fn a_tool_pack_script_inherits_its_interpreter_and_runs_it_first_on_path() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let runtime = trees.folder("runtime");
    trees.folder("rt/lib");
    binary(&trees.path("rt/bin/rt"));
    script_with(&trees.path("app/bin/app"), "#!/usr/bin/env rt\n");
    pack(
        &host,
        "rt",
        &format!(
            "kind = \"tool\"\n[inputs.rt.path]\ntype = \"program\"\nprogram = \"rt\"\n\
             search = [{{ env = \"PATH\" }}]\n[run]\ncommand = [\"${{{{ inputs.rt.path }}}}\"]\n\
             [filesystem]\nread = [{:?}, \"${{{{ root.parent }}}}/lib\"]\n[env]\nRT_ONLY = \"1\"",
            text(&runtime)
        ),
    );
    pack(
        &host,
        "app",
        "kind = \"tool\"\nextend = [\"rt\"]\ninclude = [\"rt\"]\n[inputs.app.path]\ntype = \"program\"\n\
         program = \"app\"\nsearch = [{ env = \"PATH\" }]\n[run]\n\
         command = [\"${{ inputs.app.path }}\"]\nhosts = [\"example.com\"]",
    );
    let generated = trial(&host, &[&trees.path("rt/bin"), &trees.path("app/bin")])
        .with("app")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    let rt = tool(&generated, "rt");
    assert!(
        strings(&rt["filesystem"]["read"]).contains(&text(&trees.path("rt/lib"))),
        "`root.parent` is the folder above rt's folder: {rt}"
    );
    let app = tool(&generated, "app");
    let read = strings(&app["filesystem"]["read"]);
    assert!(read.contains(&text(&runtime)), "{app}");
    assert!(
        read.contains(&text(&trees.path("rt/bin"))),
        "the interpreter installation is readable: {app}"
    );
    assert_eq!(
        app["env"]["RT_ONLY"].as_str(),
        Some("1"),
        "app's pack extends rt, so app gets rt's variables: {app}"
    );
    assert_eq!(
        app["env"]["PATH"].as_str(),
        Some(format!("{}:/usr/bin:/bin", text(&trees.path("rt/bin"))).as_str()),
        "the interpreter's folder comes before the base PATH"
    );
    assert_eq!(
        app["env"]["TMPDIR"].as_str(),
        Some(text(&run_folder(&generated).join("tool-tmp/app")).as_str())
    );
    assert!(generated.skipped().is_empty(), "{:?}", generated.skipped());
}

#[test]
fn a_tool_that_names_an_unknown_installation_layout_is_refused() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("rt/bin/rt"));
    pack(
        &host,
        "rt",
        "[tool.rt]\nprogram = \"rt\"\ninstallation = [\"conda\"]",
    );
    let error = trial(&host, &[&trees.path("rt/bin")])
        .with("rt")
        .tools(Vec::<String>::new())
        .generate()
        .expect_err("an unknown layout");
    assert!(
        error
            .to_string()
            .contains(r#"names "conda", which is not a layout"#),
        "{error}"
    );
}

#[test]
fn launcher_packs_import_as_tools_only_when_selected() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let bin = trees.folder("launchers/bin");
    for name in ["npx", "uvx", "pnpx", "bunx", "node", "python3"] {
        binary(&bin.join(name));
    }
    let default = trial(&host, &[&bin]).generate().expect("default profile");
    let config: toml::Value = toml::from_str(default.box_toml()).expect("TOML");
    for launcher in ["npx", "uvx", "pnpx", "bunx"] {
        assert!(
            config["tool"].get(launcher).is_none(),
            "{launcher} is opt-in"
        );
        let generated = trial(&host, &[&bin])
            .with(launcher)
            .generate()
            .expect("ordinary tool pack");
        let declared = tool(&generated, launcher);
        let reads = strings(&declared["filesystem"]["read"]);
        if launcher != "uvx" {
            assert!(
                reads.contains(&text(&trees.path("launchers"))),
                "{launcher} can read its installation outside bin: {reads:?}"
            );
        }
        let env = declared["env"].to_string();
        assert!(env.contains(&format!(".cache/{launcher}")), "{env}");
        assert!(!env.contains("mcp-cache"), "{env}");
    }
}

#[test]
fn a_launcher_helper_reads_its_installed_python_runtime() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let bin = trees.folder("launchers/bin");
    let python = trees.folder("uv/python/cpython-3.11/bin");
    trees.folder("uv/python/cpython-3.11/lib");
    binary(&bin.join("uvx"));
    binary(&python.join("python3"));
    let generated = trial(&host, &[&bin, &python])
        .with("uvx")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a launcher tool");
    let declared = tool(&generated, "uvx");
    let read = strings(&declared["filesystem"]["read"]);
    assert!(
        read.contains(&text(&trees.path("uv/python/cpython-3.11"))),
        "{declared}"
    );
}

#[test]
fn mcp_launcher_path_keeps_the_selected_runtime_before_the_launcher_directory() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let runtime = trees.folder("runtime/bin");
    let launchers = trees.folder("launchers/bin");
    binary(&runtime.join("node"));
    binary(&launchers.join("node"));
    script_with(&launchers.join("npx"), "#!/usr/bin/env node\n");
    write(
        &host.home().join(".claude.json"),
        r#"{"mcpServers":{"memory":{"command":"npx"}}}"#,
    );
    let generated = trial(&host, &[&runtime, &launchers])
        .option("claude.import-mcp", "true")
        .tools(Vec::<String>::new())
        .generate()
        .expect("profile");
    let config: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    let path = config["mcp"]["memory"]["env"]["PATH"]
        .as_str()
        .expect("MCP PATH");
    let folders: Vec<_> = path.split(':').collect();
    assert_eq!(folders[0], text(&runtime));
    assert_eq!(folders[1], text(&launchers));
    assert!(
        config
            .get("tool")
            .and_then(|tools| tools.get("npx"))
            .is_none(),
        "MCP alone does not expose the launcher as a tool"
    );
}

/// A grammar for the `greet` test program: one action and one effect.
const GREET_GRAMMAR: &str = r#"
format = 1
version = 1
name = "greet"
program = "greet"

[effects]
loud = "Shouts the greeting"

[shell.hello]
usage = "greet hello [options] [<name>]"
options.loud = { flag = ["--loud"], adds = ["loud"] }
"#;

/// The operator's tool pack `greet`, with `extra` in its `pack.toml` and `grammar` beside it, and
/// the folder that holds the `greet` program when `installed`.
fn greet(
    host: &FakeHost,
    trees: &Trees,
    extra: &str,
    grammar: Option<&str>,
    installed: bool,
) -> PathBuf {
    pack(
        host,
        "greet",
        &format!(
            "kind = \"tool\"\n[inputs.greet.path]\ntype = \"program\"\nprogram = \"greet\"\n\
                  search = [{{ env = \"PATH\" }}]\n[run]\n\
                  command = [\"${{{{ inputs.greet.path }}}}\"]\n{extra}"
        ),
    );
    if let Some(grammar) = grammar {
        write(
            &host.home().join(".strands/box/packs/greet/grammar.toml"),
            grammar,
        );
    }
    let bin = trees.folder("greet/bin");
    if installed {
        binary(&bin.join("greet"));
    }
    bin
}

/// The trial of `host` with the operator's `greet` pack and no optional tool pack, on Linux.
fn greet_trial(host: &FakeHost, bin: &Path) -> Result<Trialed, Error> {
    trial(host, &[bin])
        .os("linux")
        .tools(Vec::<String>::new())
        .with("greet")
        .generate()
}

#[test]
fn a_packs_grammar_reaches_box_toml_unchanged_and_turns_on_tool_grammars() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let bin = greet(&host, &trees, "", Some(GREET_GRAMMAR), true);
    let generated = greet_trial(&host, &bin).expect("a configuration");
    let written: toml::Table = toml::from_str(GREET_GRAMMAR).expect("TOML");
    assert_eq!(
        tool(&generated, "greet")["grammar"],
        toml::Value::Table(written)
    );
    assert_eq!(
        box_toml(&generated)["experimental-features"],
        toml::from_str::<toml::Value>("tool-grammars = true").expect("TOML"),
        "{}",
        generated.box_toml()
    );
}

#[test]
fn a_grammar_keeps_its_when_value_and_placeholder_text_as_written() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let grammar = r#"
format = 1
version = 1
name = "greet"
program = "greet"

[effects]
note = "Names ${{ root }} and $${{ home }} as text"

[shell.hello]
usage = "greet hello [options]"
options.loud = { flag = ["--loud"], value = "optional", adds = ["note"], when = [{ like = "false", removes = ["note"] }] }
options.only = { value = "required", when = "linux" }
"#;
    let bin = greet(&host, &trees, "", Some(grammar), true);
    let generated = greet_trial(&host, &bin).expect("a configuration");
    let written: toml::Table = toml::from_str(grammar).expect("TOML");
    assert_eq!(
        tool(&generated, "greet")["grammar"],
        toml::Value::Table(written),
        "{}",
        generated.box_toml()
    );
}

#[test]
fn a_tool_with_a_grammar_keeps_its_spawn_permit_and_gets_every_action_of_its_grammar() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let bin = greet(&host, &trees, "", Some(GREET_GRAMMAR), true);
    let generated = greet_trial(&host, &bin).expect("a configuration");
    let rules: Vec<&str> = generated
        .policy()
        .lines()
        .filter(|line| {
            line.starts_with("@id(\"spawn_greet\"") || line.starts_with("@id(\"tool_greet\"")
        })
        .collect();
    assert_eq!(
        rules,
        [
            format!(
                r#"@id("spawn_greet") permit (principal, action == Box::Action::"shell:spawn", resource) when {{ context.input.program_path == {:?} && context.input.program == "greet" }};"#,
                text(&bin.join("greet"))
            ),
            r#"@id("tool_greet") permit (principal, action in [Tool::greet::Action::"*", Tool::greet::Action::"unmodeled"], resource);"#.to_string(),
        ]
    );
    assert!(
        generated
            .generated_ids()
            .contains(&"tool_greet".to_string())
    );
}

#[test]
fn a_box_with_no_grammar_writes_no_experimental_features() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let bin = greet(&host, &trees, "", None, true);
    let generated = greet_trial(&host, &bin).expect("a configuration");
    assert!(tool(&generated, "greet").get("grammar").is_none());
    assert!(
        !box_toml(&generated).contains_key("experimental-features"),
        "{}",
        generated.box_toml()
    );
    assert!(
        !generated.policy().contains("Tool::"),
        "{}",
        generated.policy()
    );
}

/// Assert that `generated` holds no `greet` tool, no switch, and no grammar permit.
fn assert_no_greet(generated: &Trialed) {
    let file = box_toml(generated);
    assert!(
        file.get("tool")
            .and_then(|tools| tools.get("greet"))
            .is_none(),
        "{}",
        generated.box_toml()
    );
    assert!(!file.contains_key("experimental-features"));
    assert!(!generated.policy().contains("tool_greet"));
}

#[test]
fn a_skipped_tool_takes_its_grammar_with_it() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let bin = greet(&host, &trees, "", Some(GREET_GRAMMAR), false);
    let generated = greet_trial(&host, &bin).expect("a configuration");
    assert!(
        generated
            .skipped()
            .iter()
            .any(|(name, _)| name.starts_with("greet")),
        "{:?}",
        generated.skipped()
    );
    assert_no_greet(&generated);
}

#[test]
fn a_tool_that_its_when_turns_off_takes_its_grammar_with_it() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let bin = greet(&host, &trees, "when = \"macos\"", Some(GREET_GRAMMAR), true);
    let generated = greet_trial(&host, &bin).expect("a configuration");
    assert_no_greet(&generated);
}

#[test]
fn a_host_name_is_lowercase_labels_that_box_core_can_match() {
    let longest_label = "a".repeat(63);
    let label = |length: usize| "a".repeat(length);
    let longest_name = format!("{0}.{0}.{0}.{1}", label(63), label(61));
    let too_long_name = format!("{0}.{0}.{0}.{1}", label(63), label(62));
    assert_eq!((longest_name.len(), too_long_name.len()), (253, 254));
    for name in [
        "example.com",
        "a-b.example.com",
        "127.0.0.1",
        "xn--bcher-kva.example",
        longest_label.as_str(),
        longest_name.as_str(),
    ] {
        assert!(crate::tool::is_host_name(name), "{name}");
    }
    let long_label = "a".repeat(64);
    let long_name = format!("{}com", "a.".repeat(130));
    for name in [
        "",
        "EXAMPLE.COM",
        "example.com.",
        ".example.com",
        "a..b",
        "-a.example.com",
        "a-.example.com",
        "a b",
        "a_b.example.com",
        "*.example.com",
        long_label.as_str(),
        long_name.as_str(),
        too_long_name.as_str(),
    ] {
        assert!(!crate::tool::is_host_name(name), "{name:?}");
    }
}

/// Write the operator's tool pack `name` for the program `name`, with `extra` after its `[run]`
/// and `extend` naming the packs it extends.
fn tool_pack(host: &FakeHost, name: &str, extends: &[&str], extra: &str) {
    let extends = if extends.is_empty() {
        String::new()
    } else {
        format!("extend = {extends:?}\n")
    };
    pack(
        host,
        name,
        &format!(
            "kind = \"tool\"\n{extends}[inputs.{name}.path]\ntype = \"program\"\nprogram = \"{name}\"\n\
             search = [{{ env = \"PATH\" }}]\n[run]\ncommand = [\"${{{{ inputs.{name}.path }}}}\"]\n{extra}"
        ),
    );
}

/// **A tool pack that extends another tool pack gets that pack's tool, writes too.** app extends
/// git, so `[tool.app]` gets `[tool.git]`'s variables and its whole filesystem, and git's folder on
/// its `PATH`, so app can start git without naming it as a helper. app's own variable wins, and
/// `[tool.git]` keeps its own.
#[test]
fn a_tool_pack_that_extends_a_tool_pack_inherits_its_tool() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("git/bin/git"));
    binary(&trees.path("app/bin/app"));
    let core = trees.folder("git/libexec/git-core");
    let state = trees.folder("git-state");
    tool_pack(
        &host,
        "git",
        &[],
        &format!(
            "[env]\nA = \"git\"\nB = \"git\"\n[filesystem]\nread = [{:?}]\nwrite = [{:?}]",
            text(&core),
            text(&state)
        ),
    );
    tool_pack(&host, "app", &["git"], "[env]\nA = \"app\"");
    let generated = trial(&host, &[&trees.path("git/bin"), &trees.path("app/bin")])
        .with("app")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    let app = tool(&generated, "app");
    assert_eq!(app["env"]["A"].as_str(), Some("app"), "{app}");
    assert_eq!(app["env"]["B"].as_str(), Some("git"), "{app}");
    assert!(
        strings(&app["filesystem"]["read"]).contains(&text(&core)),
        "{app}"
    );
    assert!(
        strings(&app["filesystem"]["write"]).contains(&text(&state)),
        "{app}"
    );
    let path = app["env"]["PATH"].as_str().unwrap_or_default();
    assert!(
        path.split(':')
            .any(|part| part == text(&trees.path("git/bin"))),
        "{app}"
    );
    assert!(
        box_toml(&generated)["tool"].get("git").is_none(),
        "git is merged into app and is not a tool of its own: {}",
        generated.box_toml()
    );
    assert!(
        !generated.policy().contains(r#"@id("spawn_git")"#),
        "{}",
        generated.policy()
    );
}

/// **A hidden base's package hosts stay in the box, on the tool that extends it.**
#[test]
fn the_hosts_of_a_tool_that_only_extend_brings_in_stay_in_the_box() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("git/bin/git"));
    binary(&trees.path("app/bin/app"));
    tool_pack(&host, "git", &[], "hosts = [\"git.example.com\"]");
    tool_pack(&host, "app", &["git"], "");
    let generated = trial(&host, &[&trees.path("git/bin"), &trees.path("app/bin")])
        .with("app")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    assert!(box_toml(&generated)["tool"].get("git").is_none());
    assert!(
        generated
            .policy()
            .contains(r#"context.input.host == "git.example.com""#),
        "{}",
        generated.policy()
    );
}

/// **`include` loads a tool pack as a tool of its own, beside the one that extends it.**
#[test]
fn an_included_tool_pack_stays_a_tool_of_its_own() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("git/bin/git"));
    binary(&trees.path("app/bin/app"));
    tool_pack(&host, "git", &[], "[env]\nA = \"git\"\nB = \"git\"");
    tool_pack(&host, "app", &["git"], "[env]\nA = \"app\"");
    let body = std::fs::read_to_string(host.home().join(".strands/box/packs/app/pack.toml"))
        .expect("the app pack");
    write(
        &host.home().join(".strands/box/packs/app/pack.toml"),
        &body.replace(
            "extend = [\"git\"]\n",
            "extend = [\"git\"]\ninclude = [\"git\"]\n",
        ),
    );
    let generated = trial(&host, &[&trees.path("git/bin"), &trees.path("app/bin")])
        .with("app")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    let app = tool(&generated, "app");
    assert_eq!(app["env"]["B"].as_str(), Some("git"), "{app}");
    let git = tool(&generated, "git");
    assert_eq!(git["env"]["A"].as_str(), Some("git"), "{git}");
    assert_ne!(app["env"]["TMPDIR"], git["env"]["TMPDIR"]);
}

/// **A dependency on a tool that only `extend` brings in stops the load.**
#[test]
fn a_dependency_on_a_tool_that_only_extend_brings_in_is_refused() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("git/bin/git"));
    binary(&trees.path("app/bin/app"));
    tool_pack(&host, "git", &[], "");
    tool_pack(&host, "app", &["git"], "");
    pack(&host, "needs", "[agent]\ndependency = [\"tool.git\"]");
    let error = trial(&host, &[&trees.path("git/bin"), &trees.path("app/bin")])
        .with("app")
        .with("needs")
        .tools(Vec::<String>::new())
        .generate()
        .expect_err("a dependency on a hidden tool");
    assert!(
        error
            .to_string()
            .contains("names tool.git, but only a tool pack's `extend` brings in that tool"),
        "{error}"
    );
}

/// **A tool inherits through the whole chain of tool packs, the nearest first.**
#[test]
fn a_tool_inherits_through_a_chain_of_tool_packs() {
    let host = FakeHost::new();
    let trees = Trees::new();
    for name in ["base", "mid", "top"] {
        binary(&trees.path(&format!("{name}/bin/{name}")));
    }
    tool_pack(&host, "base", &[], "[env]\nB = \"base\"\nM = \"base\"");
    tool_pack(&host, "mid", &["base"], "[env]\nM = \"mid\"");
    tool_pack(&host, "top", &["mid"], "");
    let generated = trial(
        &host,
        &[
            &trees.path("base/bin"),
            &trees.path("mid/bin"),
            &trees.path("top/bin"),
        ],
    )
    .with("top")
    .tools(Vec::<String>::new())
    .generate()
    .expect("a configuration");
    let top = tool(&generated, "top");
    assert_eq!(top["env"]["B"].as_str(), Some("base"), "{top}");
    assert_eq!(top["env"]["M"].as_str(), Some("mid"), "{top}");
}

/// **A skipped base gives nothing, and the tool that extends it is kept.** The host has no
/// `nogit`, so `[tool.nogit]` is skipped, and app is not skipped for its reason.
#[test]
fn a_tool_is_kept_when_the_tool_pack_it_extends_is_skipped() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("app/bin/app"));
    tool_pack(&host, "nogit", &[], "[env]\nB = \"git\"");
    tool_pack(&host, "app", &["nogit"], "");
    let generated = trial(&host, &[&trees.path("app/bin")])
        .with("app")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    assert!(
        generated
            .skipped()
            .iter()
            .any(|(name, _)| name.starts_with("nogit")),
        "{:?}",
        generated.skipped()
    );
    let app = tool(&generated, "app");
    assert!(app["env"].get("B").is_none(), "{app}");
}

/// **A later pack that sets `[tool.git] program` again does not take git from go.** go's base is
/// the tool that @box/git, the pack go extends, writes. So a pack listed after go that sets
/// `[tool.git] program` again, such as an operator's own git pack, leaves go's inheritance as it is.
#[test]
fn a_later_pack_that_redeclares_the_base_tool_keeps_the_inheritance() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("git/bin/base-git"));
    binary(&trees.path("app/bin/app"));
    let core = trees.folder("git/libexec/git-core");
    tool_pack(
        &host,
        "base-git",
        &[],
        &format!(
            "[env]\nB = \"git\"\n[filesystem]\nread = [{:?}]",
            text(&core)
        ),
    );
    tool_pack(&host, "app", &["base-git"], "");
    pack(
        &host,
        "late",
        "[tool.base-git]\nprogram = \"base-git\"\n[tool.base-git.env]\nL = \"late\"",
    );
    let generated = trial(&host, &[&trees.path("git/bin"), &trees.path("app/bin")])
        .with("app")
        .with("late")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    let app = tool(&generated, "app");
    assert_eq!(app["env"]["B"].as_str(), Some("git"), "{app}");
    assert_eq!(app["env"]["L"].as_str(), Some("late"), "{app}");
    assert!(
        strings(&app["filesystem"]["read"]).contains(&text(&core)),
        "{app}"
    );
}

/// **A tool that a support pack declares stays a tool of its own, even when a tool pack extends
/// its pack.** app extends git, which would hide `[tool.git]`. But mygit, a pack that is not a
/// tool pack, sets `[tool.git] program`, so git keeps its own table and its `spawn_git` permit.
#[test]
fn a_tool_that_a_support_pack_declares_is_not_hidden_by_extend() {
    let host = FakeHost::new();
    let trees = Trees::new();
    binary(&trees.path("git/bin/git"));
    binary(&trees.path("app/bin/app"));
    tool_pack(&host, "git", &[], "[env]\nB = \"git\"");
    tool_pack(&host, "app", &["git"], "");
    pack(&host, "mygit", "[tool.git]\nprogram = \"git\"");
    let generated = trial(&host, &[&trees.path("git/bin"), &trees.path("app/bin")])
        .with("app")
        .with("mygit")
        .tools(Vec::<String>::new())
        .generate()
        .expect("a configuration");
    assert_eq!(tool(&generated, "app")["env"]["B"].as_str(), Some("git"));
    assert_eq!(tool(&generated, "git")["env"]["B"].as_str(), Some("git"));
    assert!(
        generated.policy().contains(r#"@id("spawn_git")"#),
        "{}",
        generated.policy()
    );
}
