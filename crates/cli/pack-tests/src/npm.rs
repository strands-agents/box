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
        matches!(&error, Error::UnknownTool { known, .. } if known == "bunx, cargo, gh, git, go, node, npm, npx, pnpm, pnpx, rg, uv, uvx, yarn"),
        "{error}"
    );
}

#[test]
fn npms_cache_is_in_its_own_storage_outside_the_project() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .tools(["npm"])
        .generate()
        .expect("a configuration");
    let npm = tool(&generated, "npm");
    let cache = npm["env"]["npm_config_cache"].as_str().expect("a cache");
    assert_in_tool_storage(&generated, &host, cache, "/tool/npm/cache");
}

#[test]
fn npm_runs_its_scripts_with_sh_and_reads_it() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .tools(["npm"])
        .generate()
        .expect("a configuration");
    let npm = tool(&generated, "npm");
    assert_eq!(
        npm["env"]["npm_config_script_shell"].as_str(),
        Some("/bin/sh")
    );
    assert!(
        strings(&npm["filesystem"]["read_file"]).contains(&script_shell()),
        "{npm}"
    );
}

#[test]
/// Each pack that extends `@box/node` gets its script shell and the grant to read it, once.
fn every_node_pack_runs_scripts_with_sh_as_a_tool_and_npx_as_an_mcp_launcher() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let bin = trees.folder("launchers/bin");
    binary(&bin.join("node"));
    for program in ["npx", "pnpx", "bunx", "yarn", "pnpm"] {
        script_with(&bin.join(program), "#!/usr/bin/env node\n");
    }
    write(
        &host.home().join(".claude.json"),
        r#"{"mcpServers":{"memory":{"command":"npx"}}}"#,
    );
    let search = format!("{}:{}", bin.display(), host.search_path());
    host.profile()
        .with("claude")
        .with("bedrock")
        .with("npx")
        .with("pnpx")
        .with("bunx")
        .with("yarn")
        .with("pnpm")
        .with("npm")
        .option("claude.import-mcp", "true")
        .tools(Vec::<String>::new())
        .search_path(&search)
        .create()
        .expect("a profile")
        .write(false)
        .expect("a profile on disk");
    let launch = host
        .launcher()
        .search_path(&search)
        .prepare("claude", &host.project(), None)
        .expect("a prepared run");
    let config: toml::Value =
        toml::from_str(&std::fs::read_to_string(launch.config()).expect("config")).expect("TOML");
    let mut processes: Vec<(String, &toml::Value)> = ["npm", "npx", "pnpx", "bunx", "yarn", "pnpm"]
        .iter()
        .map(|name| (format!("the {name} tool"), &config["tool"][*name]))
        .collect();
    processes.push(("the npx server".to_string(), &config["mcp"]["memory"]));
    for (label, process) in processes {
        assert_eq!(
            process["env"]["npm_config_script_shell"].as_str(),
            Some("/bin/sh"),
            "{label}: {process}"
        );
        let read_file = strings(&process["filesystem"]["read_file"]);
        assert_eq!(
            read_file
                .iter()
                .filter(|path| **path == script_shell())
                .count(),
            1,
            "{label} reads /bin/sh once: {read_file:?}"
        );
    }
}

/// `/bin/sh` as `box` grants it, with the folders above it resolved.
fn script_shell() -> String {
    let folder = std::fs::canonicalize("/bin").expect("the /bin folder");
    text(&folder.join("sh"))
}
