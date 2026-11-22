use crate::support::*;

/// A Homebrew ripgrep keg that links pcre2, on the `bin` folder of a fresh prefix.
fn homebrew_rg(trees: &Trees) -> PathBuf {
    let brew = trees.path("brew");
    let keg = brew.join("Cellar/ripgrep/15.1.0");
    binary(&keg.join("bin/rg"));
    write(
        &keg.join("INSTALL_RECEIPT.json"),
        r#"{"runtime_dependencies":[{"full_name":"pcre2"}]}"#,
    );
    link("../Cellar/ripgrep/15.1.0/bin/rg", &brew.join("bin/rg"));
    let pcre2 = brew.join("Cellar/pcre2/10.46");
    std::fs::create_dir_all(pcre2.join("lib")).expect("a library folder");
    write(
        &pcre2.join("INSTALL_RECEIPT.json"),
        r#"{"runtime_dependencies":[]}"#,
    );
    link("../Cellar/pcre2/10.46", &brew.join("opt/pcre2"));
    brew
}

#[test]
fn homebrew_rg_reads_its_keg_and_pcre2_and_cannot_change_the_project() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let brew = homebrew_rg(&trees);
    let generated = trial(&host, &[&brew.join("bin")])
        .os("macos")
        .variable("HOMEBREW_PREFIX", text(&brew))
        .tools(["rg"])
        .generate()
        .expect("a configuration");
    let rg = tool(&generated, "rg");
    assert_eq!(
        strings(&rg["command"]),
        [text(&brew.join("Cellar/ripgrep/15.1.0/bin/rg"))]
    );
    let read = strings(&rg["filesystem"]["read"]);
    assert_eq!(read.first(), Some(&text(&host.project())), "{rg}");
    assert!(
        read.contains(&text(&brew.join("Cellar/pcre2/10.46"))),
        "{rg}"
    );
    let scratch = text(&run_folder(&generated).join("tool-tmp/rg"));
    assert_eq!(
        strings(&rg["filesystem"]["write"]),
        [text(&host.project()), scratch],
        "{rg}"
    );
    assert_eq!(
        strings(&rg["filesystem"]["deny_write"]),
        [text(&host.project())],
        "{rg}"
    );
}

#[test]
fn rg_names_no_package_host() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let brew = homebrew_rg(&trees);
    let without = trial(&host, &[]).generate().expect("a configuration");
    let with = trial(&host, &[&brew.join("bin")])
        .tools(["rg"])
        .generate()
        .expect("a configuration");
    let network = |generated: &Trialed| -> Vec<String> {
        generated
            .policy()
            .lines()
            .filter(|line| line.contains("net:") || line.contains("http:"))
            .map(str::to_string)
            .collect()
    };
    assert_eq!(network(&with), network(&without));
    assert_eq!(
        box_toml(&with).get("egress"),
        box_toml(&without).get("egress")
    );
}

#[test]
fn a_codex_box_runs_the_rg_that_the_path_finds() {
    let host = FakeHost::new();
    let bin = host.home().join(".cargo/bin");
    binary(&bin.join("rg"));
    let generated = host
        .trial()
        .with("codex")
        .with("bedrock-mantle")
        .generate()
        .expect("a configuration");
    assert_eq!(
        strings(&tool(&generated, "rg")["command"]),
        [text(&bin.join("rg"))]
    );
}

#[test]
fn a_codex_box_without_rg_skips_the_tool_and_still_runs() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("codex")
        .with("bedrock-mantle")
        .search_path(host.own_search_path())
        .generate()
        .expect("a configuration without rg");
    assert!(
        box_toml(&generated)
            .get("tool")
            .and_then(|tools| tools.get("rg"))
            .is_none(),
        "{}",
        generated.box_toml()
    );
    assert!(
        generated
            .skipped()
            .contains(&("rg (@box/rg)".to_string(), "rg is not on PATH".to_string())),
        "{:?}",
        generated.skipped()
    );
}
