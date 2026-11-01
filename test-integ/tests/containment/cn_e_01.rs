use strands_det_harness::det_case;

// Containment CN-E (a tool executes build output from an exec tree)
//
// The fixture declares `[tool.built]`, whose command is a binary under the workspace's `out/` tree
// (compiled by `rustc` when the fixture is prepared) and whose filesystem grants that tree exec. The Shell resolves the path, which it does not implement, policy permits the spawn,
// selection matches the tool's command, and the tool runs in its own boundary with the tree
// executable, so its output returns through the Shell.
det_case! {
    name: cn_e_01,
    id:   "CN-E-01",
    desc: "Exec tree: a declared tool runs a binary from its exec tree and its output returns",
    run: |b| {
        b.apply_policy(
            r#"@id("spawn_built") permit (principal, action == Box::Action::"shell:spawn", resource);"#,
        );
        let tool = b.built_tool();
        let r = b.run_sh(&format!("zsh -c '{} from-the-agent'", tool.display()));
        r.assert_contains("BUILD_OUTPUT_RAN from-the-agent");
        r.assert_allow();
    }
}
