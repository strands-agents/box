use strands_det_harness::det_case;

// Containment CN-F1 (a program under the agent's own `exec` entry runs with no table)
//
// A binary the workload builds under one of the agent's own `exec` entries runs through the hosted
// Shell with no per-binary `[tool.*]` table, under a `shell:spawn` permit, in the agent's own
// boundary. The box's own suite pins the selection step
// (`hosted.rs::a_program_under_the_callers_exec_grant_runs_in_the_callers_boundary`); this is the
// end-to-end check.
//
// Needs the box at c7d0f41d or later. On 864df453 no table names the program, the spawn is refused
// by name, and this case reads FAIL with that reason, not ERROR: the expected verdict there.
det_case! {
    name: cn_f1_01,
    id:   "CN-F1-01",
    desc: "Follow-up F1: a program under the agent's own exec entry runs in the agent's boundary with no table",
    run: |b| {
        b.apply_policy(
            r#"@id("workspace_spawn") permit (principal, action == Box::Action::"shell:spawn", resource);"#,
        );
        // A binary no table names, built beside the declared tool by the same compiler, so only the
        // agent's own `exec` entry can carry it. Canonical, because a grant names the identity the
        // kernel checks.
        let out = b
            .built_tool()
            .parent()
            .expect("DET_ERROR: the built tool sits in the exec tree")
            .canonicalize()
            .expect("DET_ERROR: resolve the exec tree");
        let free = out.join("free-hello");
        let compiled = std::process::Command::new("rustc")
            .arg("-o")
            .arg(&free)
            .arg(out.join("hello.rs"))
            .output()
            .expect("DET_ERROR: rustc is on PATH");
        assert!(
            compiled.status.success(),
            "DET_ERROR: rustc failed on the free binary: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let exec_entry = serde_json::to_string(&out.to_string_lossy()).unwrap();
        let r = b.run_sh_with_config(
            move |text| text.replacen("read_file = [", &format!("exec = [{exec_entry}]\nread_file = ["), 1),
            &format!("zsh -c '{} from-the-agent'", free.display()),
        );
        assert!(
            r.out.contains("BUILD_OUTPUT_RAN from-the-agent"),
            "F1 needs the box at c7d0f41d or later: a program under the agent's own exec entry must \
             run with no [tool.*] table; out=[{}]",
            r.snippet()
        );
        r.assert_allow();
    }
}
