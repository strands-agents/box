use strands_det_harness::det_case;

// The configured script and its interpreter run outside the writable workspace.
det_case! {
    name: cn_e_02,
    id:   "CN-E-02",
    desc: "A declared tool runs an installed `#!/usr/bin/env sh` script and returns its output",
    run: |b| {
        b.apply_policy(
            r#"@id("spawn_built") permit (principal, action == Box::Action::"shell:spawn", resource);"#,
        );
        let script = b.configured_script();
        let r = b.run_sh(&format!("zsh -c '{}'", script.display()));
        r.assert_contains("SCRIPT_OUTPUT_RAN");
        r.assert_allow();
    }
}
