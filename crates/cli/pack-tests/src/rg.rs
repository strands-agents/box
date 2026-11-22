use crate::support::*;

#[test]
fn rg_cannot_change_the_project_that_it_reads() {
    let host = FakeHost::new();
    binary(&host.home().join(".cargo/bin/rg"));
    let generated = host
        .trial()
        .with("claude")
        .with("bedrock")
        .tools(["rg"])
        .generate()
        .expect("a configuration");
    let rg = tool(&generated, "rg");
    let project = text(&host.project());
    assert!(
        strings(&rg["filesystem"]["write"]).contains(&project),
        "{rg}"
    );
    assert_eq!(strings(&rg["filesystem"]["deny_write"]), [project], "{rg}");
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
