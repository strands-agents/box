use strands_det_harness::det_case;

// Containment CN-E (a tool executes build output from an exec tree), second half:
// a script whose shebang is `#!/usr/bin/env sh`. The kernel runs `env`, and `env` runs the shell,
// so the tool's boundary must grant both along with the exec tree.
det_case! {
    name: cn_e_02,
    id:   "CN-E-02",
    desc: "Exec tree: a declared tool runs a `#!/usr/bin/env sh` script from its exec tree and its output returns",
    run: |b| {
        b.apply_policy(
            r#"@id("spawn_built") permit (principal, action == Box::Action::"shell:spawn", resource);"#,
        );
        let script = b.built_script();
        let r = b.run_sh(&format!("zsh -c '{}'", script.display()));
        r.assert_contains("SCRIPT_OUTPUT_RAN");
        r.assert_allow();
    }
}
