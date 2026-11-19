use strands_det_harness::det_case;

// The operator installs build output outside the workspace before declaring it as a tool.
det_case! {
    name: cn_e_01,
    id:   "CN-E-01",
    desc: "A declared tool runs installed build output and returns its output",
    run: |b| {
        b.apply_policy(
            r#"@id("spawn_built") permit (principal, action == Box::Action::"shell:spawn", resource);"#,
        );
        let tool = b.configured_tool();
        let r = b.run_sh(&format!("zsh -c '{} from-the-agent'", tool.display()));
        r.assert_contains("BUILD_OUTPUT_RAN from-the-agent");
        r.assert_allow();
    }
}
