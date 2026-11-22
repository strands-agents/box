use crate::support::*;

#[test]
fn npm_is_keyed_on_its_script_and_finds_node_through_its_own_path() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .generate()
        .expect("a configuration");
    let npm = resolution(&generated, "npm");
    assert_eq!(
        npm.identity,
        host.brew().join("lib/node_modules/npm/bin/npm-cli.js")
    );
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    let path = file["tool"]["npm"]["env"]["PATH"].as_str().expect("a PATH");
    assert!(path.starts_with(&format!(
        "{}:",
        host.brew().join("Cellar/node/26.9.0/bin").display()
    )));
}

#[test]
fn an_npm_outside_a_package_reads_only_its_own_root() {
    let host = FakeHost::new();
    let tools = host.home().join("tools");
    strands_box_cli_profile::fixtures::npm_script(&tools.join("npm"));
    strands_box_cli_profile::fixtures::link("../npm/bin/npm-cli.js", &tools.join("bin/npm"));
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .search_path(format!(
            "{}:{}",
            tools.join("bin").display(),
            host.search_path()
        ))
        .generate()
        .expect("a configuration");
    let npm = resolution(&generated, "npm");
    assert!(npm.read.contains(&tools.join("npm")), "{:?}", npm.read);
    assert!(!npm.read.contains(&host.home()), "{:?}", npm.read);
}

#[test]
fn an_nvm_npm_runs_nvm_node_first_on_its_path() {
    let host = FakeHost::alternate();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .tools(["npm"])
        .generate()
        .expect("a configuration");
    let nvm = host.home().join(".nvm/versions/node/v22.0.0");
    let npm = tool(&generated, "npm");
    assert_eq!(
        npm["env"]["PATH"].as_str(),
        Some(format!("{}:/usr/bin:/bin", nvm.join("bin").display()).as_str())
    );
    assert!(
        strings(&npm["filesystem"]["read"]).contains(&text(&nvm.join("bin"))),
        "{npm}"
    );
}

#[test]
fn an_npm_whose_line_names_another_node_than_the_node_table_is_skipped() {
    let host = FakeHost::alternate();
    let trees = Trees::new();
    let bin = trees.dnf();
    std::fs::remove_file(bin.join("node")).expect("remove dnf node from PATH");
    let nvm = host.home().join(".nvm/versions/node/v22.0.0/bin");
    std::fs::remove_file(nvm.join("npm")).expect("remove nvm npm from PATH");
    let generated = trial(&host, &[&nvm, &bin])
        .tools(["npm"])
        .generate()
        .expect("a configuration");
    let (_, why) = generated
        .skipped()
        .iter()
        .find(|(name, _)| name == "npm (@box/npm)")
        .expect("npm is skipped");
    assert!(
        why.contains("which is the command of no tool table"),
        "{why}"
    );
    assert!(tool(&generated, "node")["command"].as_array().is_some());
}

#[test]
fn tools_name_shipped_packs_and_npm_brings_node() {
    let host = FakeHost::new();
    let created = host
        .profile()
        .with("claude")
        .with("bedrock")
        .tools(["npm"])
        .create()
        .expect("a profile");
    assert_eq!(
        created.profile().packs(),
        ["@box/claude", "@box/bedrock", "@box/npm"]
    );
    let names: Vec<String> = created
        .resolutions()
        .into_iter()
        .map(|tool| tool.name)
        .collect();
    assert_eq!(names, ["node", "npm"]);
    let error = host
        .profile()
        .with("claude")
        .tools(["base"])
        .create()
        .expect_err("base is no tool pack");
    assert!(
        matches!(&error, Error::UnknownTool { known, .. } if known == "bunx, cargo, gh, git, go, node, npm, npx, pnpm, pnpx, uv, uvx, yarn"),
        "{error}"
    );
}
