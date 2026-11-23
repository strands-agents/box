use crate::support::*;

#[test]
fn homebrew_node_through_opt_runs_its_keg_and_reads_its_dependency_configuration() {
    let host = FakeHost::new();
    let trees = Trees::new();
    let brew = trees.homebrew();
    let generated = trial(&host, &[&brew.join("opt/node@22/bin")])
        .os("macos")
        .variable("HOMEBREW_PREFIX", text(&brew))
        .tools(["node"])
        .generate()
        .expect("a configuration");
    let node = tool(&generated, "node");
    assert_eq!(
        strings(&node["command"]),
        [text(&brew.join("Cellar/node@22/22.1.0/bin/node"))]
    );
    assert!(
        strings(&node["filesystem"]["read"]).contains(&text(&brew.join("etc/openssl@3"))),
        "{node}"
    );
}
