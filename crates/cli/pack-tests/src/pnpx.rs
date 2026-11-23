use crate::support::*;

#[test]
fn pnpx_has_a_prepared_temporary_directory_before_its_workspace_cache_exists() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let bin = trees.folder("launchers/bin");
    binary(&bin.join("node"));
    script_with(&bin.join("pnpx"), "#!/usr/bin/env node\n");
    write(
        &host.home().join(".claude.json"),
        r#"{"mcpServers":{"memory":{"command":"pnpx"}}}"#,
    );
    let search = format!("{}:{}", bin.display(), host.search_path());
    host.profile()
        .with("claude")
        .with("bedrock")
        .with("pnpx")
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
    let temporary = Path::new(
        config["tool"]["pnpx"]["env"]["TMPDIR"]
            .as_str()
            .expect("tool TMPDIR"),
    );
    assert!(
        temporary.is_dir(),
        "pnpm resolves TMPDIR before it creates its cache: {}",
        temporary.display()
    );
    assert_eq!(
        temporary,
        launch.config().parent().unwrap().join("tool-tmp/pnpx")
    );
    assert!(
        !host.project().join(".cache").exists(),
        "run preparation leaves workspace cache creation to the tool"
    );
    let cache = host
        .home()
        .join(".strands/box/storage/claude/default/mcp-cache/pnpx");
    assert_eq!(
        config["mcp"]["memory"]["env"]["TMPDIR"].as_str(),
        Some(text(&cache).as_str()),
        "MCP temporary files stay in the prepared server cache"
    );
    assert!(cache.is_dir(), "{}", cache.display());
}
