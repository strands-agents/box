use crate::support::*;

#[test]
fn homebrew_git_reads_the_opt_links_and_rewrites_github_ssh_remotes() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let brew = trees.homebrew();
    let generated = trial(&host, &[&brew.join("bin")])
        .os("macos")
        .variable("HOMEBREW_PREFIX", text(&brew))
        .tools(["git"])
        .generate()
        .expect("a configuration");
    let git = tool(&generated, "git");
    let scratch = text(&run_folder(&generated).join("tool-tmp/git"));
    assert_eq!(
        strings(&git["filesystem"]["read"]),
        [
            text(&host.project()),
            text(&host.developer()),
            text(&brew.join("Cellar")),
            text(&brew.join("opt")),
            scratch.clone(),
        ],
        "{git}"
    );
    let env: toml::Table = toml::from_str(&format!(
        r#"
PATH = "/usr/bin:/bin:{bin}"
TMPDIR = "{scratch}"
GIT_CONFIG_NOSYSTEM = "1"
GIT_CONFIG_GLOBAL = "/dev/null"
GIT_CONFIG_COUNT = "2"
GIT_CONFIG_KEY_0 = "url.https://github.com/.insteadOf"
GIT_CONFIG_VALUE_0 = "git@github.com:"
GIT_CONFIG_KEY_1 = "url.https://github.com/.insteadOf"
GIT_CONFIG_VALUE_1 = "ssh://git@github.com/"
GIT_AUTHOR_NAME = "Box Workload"
GIT_AUTHOR_EMAIL = "workload@example.invalid"
GIT_COMMITTER_NAME = "Box Workload"
GIT_COMMITTER_EMAIL = "workload@example.invalid"
GIT_EDITOR = "/usr/bin/true"
GIT_SEQUENCE_EDITOR = "/usr/bin/true"
"#,
        bin = text(&brew.join("bin")),
    ))
    .expect("an env table");
    assert_eq!(git["env"].as_table(), Some(&env), "{git}");
}

#[test]
fn homebrew_git_with_homebrew_prefix_unset_reads_its_keg_and_the_default_prefix() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let brew = trees.homebrew();
    let generated = trial(&host, &[&brew.join("bin")])
        .os("macos")
        .tools(["git"])
        .generate()
        .expect("a configuration");
    let git = tool(&generated, "git");
    let default = Path::new("/opt/homebrew");
    let mut expected = vec![
        text(&host.project()),
        text(&brew.join("Cellar/git/2.56.0_1/libexec/git-core")),
        text(&host.developer()),
    ];
    expected.extend(
        ["Cellar", "opt"]
            .iter()
            .map(|folder| default.join(folder))
            .filter(|folder| folder.exists())
            .map(|folder| text(&folder)),
    );
    expected.push(text(&run_folder(&generated).join("tool-tmp/git")));
    assert_eq!(strings(&git["filesystem"]["read"]), expected, "{git}");
}

#[test]
fn an_apple_stub_git_runs_the_git_of_the_folder_xcode_select_reports() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let (bin, developer) = trees.apple();
    let generated = trial(&host, &[&bin])
        .os("macos")
        .apple_stubs(&bin)
        .command_output(&["/usr/bin/xcode-select", "-p"], &text(&developer))
        .tools(["git"])
        .generate()
        .expect("a configuration");
    let git = tool(&generated, "git");
    assert_eq!(
        strings(&git["command"]),
        [text(&developer.join("usr/bin/git"))]
    );
    assert!(
        generated.policy().contains(&format!(
            "program_path == {:?}",
            text(&developer.join("usr/bin/git"))
        )),
        "{}",
        generated.policy()
    );
    assert!(git["env"].get("DEVELOPER_DIR").is_none(), "{git}");
    assert!(
        strings(&git["filesystem"]["read"]).contains(&text(&developer)),
        "{git}"
    );
    assert!(
        generated.inputs().contains(&(
            "macos.developer_dir".to_string(),
            text(&developer),
            "xcode-select -p".to_string()
        )),
        "{:?}",
        generated.inputs()
    );
    assert!(
        generated.dropped().contains(&(
            "git".to_string(),
            text(&developer.join("usr/libexec/git-core"))
        )),
        "{:?}",
        generated.dropped()
    );
}

#[test]
fn git_runs_as_path_finds_it_outside_the_stub_folder_or_off_macos() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let (bin, developer) = trees.apple();
    for (os, stubs) in [("macos", trees.path("elsewhere")), ("linux", bin.clone())] {
        let generated = trial(&host, &[&bin])
            .os(os)
            .apple_stubs(&stubs)
            .command_output(&["/usr/bin/xcode-select", "-p"], &text(&developer))
            .tools(["git"])
            .generate()
            .expect("a configuration");
        assert_eq!(
            strings(&tool(&generated, "git")["command"]),
            [text(&bin.join("git"))],
            "{os}"
        );
    }
}

#[test]
fn a_developer_folder_without_git_skips_git_with_the_reason() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let (bin, _) = trees.apple();
    let developer = trees.folder("Xcode.app/Contents/Developer");
    let generated = trial(&host, &[&bin])
        .os("macos")
        .apple_stubs(&bin)
        .command_output(&["/usr/bin/xcode-select", "-p"], &text(&developer))
        .tools(["git"])
        .generate()
        .expect("a configuration without git");
    assert!(
        generated.skipped().contains(&(
            "git (@box/git)".to_string(),
            format!(
                "the developer folder {} holds no usr/bin/git",
                text(&developer)
            )
        )),
        "{:?}",
        generated.skipped()
    );
}

#[test]
fn a_developer_folder_git_in_the_box_home_skips_git() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let (bin, _) = trees.apple();
    let developer = host.home().join(".strands/box/Developer");
    binary(&developer.join("usr/bin/git"));
    let generated = trial(&host, &[&bin])
        .os("macos")
        .apple_stubs(&bin)
        .command_output(&["/usr/bin/xcode-select", "-p"], &text(&developer))
        .tools(["git"])
        .generate()
        .expect("a configuration without git");
    assert!(
        generated
            .skipped()
            .iter()
            .any(|(name, why)| name == "git (@box/git)" && why.contains("lies in")),
        "{:?}",
        generated.skipped()
    );
}

#[test]
fn without_the_command_line_tools_the_apple_stub_git_is_skipped() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let (bin, _) = trees.apple();
    let generated = Trial::for_project(host.project())
        .home(host.home())
        .resources(resources())
        .with("claude")
        .with("bedrock")
        .search_path(format!("{}:/usr/bin:/bin", bin.display()))
        .os("macos")
        .apple_stubs(&bin)
        .command_output(&["/usr/bin/xcode-select", "-p"], "")
        .tools(["git"])
        .generate()
        .expect("a configuration without git");
    assert!(
        generated
            .skipped()
            .iter()
            .any(|(name, why)| name == "git (@box/git)" && why.contains("xcode-select")),
        "{:?}",
        generated.skipped()
    );
}
