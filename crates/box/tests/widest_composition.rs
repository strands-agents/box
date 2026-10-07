//! A box at its widest composition still contains a workload.
//!
//! Each declared MCP server costs one alias on the agent's `PATH` and one `process-exec` literal in
//! the profile. Nothing bounds the count, so this runs a deliberately wide one: arithmetic agreeing
//! is not the same claim as a box that starts.

#[path = "support/fixture.rs"]
mod fixture;

/// How many MCP servers this test declares.
///
/// Chosen, not derived: the box carries no cap, so a count has to be picked, and a wide one is what
/// exercises the widest profile a box renders. A test declaring two would pass on a profile that
/// cannot express twenty.
const WIDE: usize = 20;

/// A box declaring many MCP servers still contains a workload.
#[test]
fn a_box_declaring_many_mcp_servers_still_runs() {
    // **Skips rather than fails where a box cannot be built at all.** A build container can refuse
    // `mount("proc")` inside a fresh PID namespace, so the Linux launcher cannot construct
    // its view and this test reported `Operation not permitted` there while passing on every host
    // that runs a box. The repository's rule is that an environment-dependent test skips with a
    // printed reason, and the arithmetic this test backs is already pinned at build time by
    // `layout.rs`'s `grant_counts` and above by `the_mirrored_ceilings_match_containments_own`.
    if !fixture::namespace_launcher_is_usable() {
        return;
    }

    // The programs are named rather than real. An entry is identity, and a server starts
    // only when the agent asks for it, so nothing here has to exist on the host.
    let declarations: String = (0..WIDE)
        .map(|index| {
            format!("[mcp.server-{index}]\ntype = \"stdio\"\ncommand = [\"program-{index}\"]\n")
        })
        .collect();

    let configured = fixture::Request::with_config(
        "mcp-ceiling",
        "permit(principal, action == Box::Action::\"shell:exec\", resource);\n",
        &declarations,
    )
    .expect();

    assert!(
        configured.bash("zsh -c 'true'").status.success(),
        "a box declaring {WIDE} MCP servers must still contain a workload; if this fails at \
         profile render, one of the grants it renders is no longer expressible"
    );

    let bin = configured.root().join("bin");
    for index in 0..WIDE {
        let alias = bin.join(format!("program-{index}"));
        assert!(
            alias.is_file(),
            "every declared server needs its alias on the agent's PATH; {} is missing",
            alias.display()
        );
    }
}
