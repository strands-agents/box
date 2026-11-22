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
fn a_codex_profile_lists_rg_and_runs_without_it() {
    let host = FakeHost::new();
    let created = host
        .profile()
        .with("codex")
        .with("bedrock-mantle")
        .search_path(host.own_search_path())
        .policy("open")
        .answer(None)
        .expect("answers")
        .create()
        .expect("a profile");
    assert!(
        created
            .profile()
            .packs()
            .iter()
            .any(|pack| pack == "@box/rg"),
        "{:?}",
        created.profile().packs()
    );
    created.write(false).expect("a write");
    let prepared = host
        .launcher()
        .search_path(host.own_search_path())
        .prepare("codex", &host.project(), None)
        .expect("a run without rg");
    assert!(
        prepared
            .skipped()
            .contains(&("rg (@box/rg)".to_string(), "rg is not on PATH".to_string())),
        "{:?}",
        prepared.skipped()
    );
}
