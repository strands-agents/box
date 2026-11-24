use crate::support::*;

#[test]
fn gos_module_and_build_caches_are_in_its_own_storage_outside_the_project() {
    let host = FakeHost::new();
    let go = host.home().join("sdk/go/bin");
    binary(&go.join("go"));
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .search_path(format!("{}:{}", go.display(), host.search_path()))
        .tools(["go"])
        .generate()
        .expect("a configuration");
    let env = &tool(&generated, "go")["env"];
    let gopath = env["GOPATH"].as_str().expect("a GOPATH");
    let cache = gopath
        .strip_suffix("/path")
        .expect("GOPATH below the cache");
    assert_in_tool_storage(&generated, &host, cache, "/tool/go/cache");
    assert_eq!(
        env["GOMODCACHE"].as_str(),
        Some(format!("{cache}/mod").as_str())
    );
    assert_eq!(
        env["GOCACHE"].as_str(),
        Some(format!("{cache}/build").as_str())
    );
}
