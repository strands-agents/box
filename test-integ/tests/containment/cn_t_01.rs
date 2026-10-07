use crate::phase3 as support;
use strands_det_harness::det_case;

det_case! {
    name: cn_t_01,
    id: "CN-T-01",
    desc: "A named tool reads its own grant and cannot inherit the agent's file grant",
    run: |b| {
        let probe = support::compile(b);
        let root = b.workspace().parent().unwrap();
        let agent = root.join("agent-only.txt");
        let tool = root.join("tool-only.txt");
        let tool_work = root.join("tool-work");
        std::fs::create_dir(&tool_work).expect("DET_ERROR: tool work directory");
        let witness = tool_work.join("witness");
        std::fs::write(&agent, "AGENT_PRIVATE_P3").expect("DET_ERROR: agent fixture");
        std::fs::write(&tool, "TOOL_PRIVATE_P3").expect("DET_ERROR: tool fixture");
        let quoted = |p: &std::path::Path| serde_json::to_string(&p.to_string_lossy()).unwrap();
        let edit = |text: String| {
            let text = text.replacen(
                "read_file = [",
                &format!("read_file = [{}, ", quoted(&agent)), 1
            );
            format!("{text}\n[tool.phase3]\ncommand = [{}]\nworkspace = {}\n\
                [tool.phase3.filesystem]\nread_file = [{}]\nwrite = [{}]\n",
                quoted(&probe), quoted(&tool_work), quoted(&tool), quoted(&tool_work))
        };
        let control = b.run_sh_with_config(edit, &format!(
            "IFS= read -r data < {}; printf 'AGENT_CONTROL %s\\n' \"$data\"", support::q(&agent)));
        support::native_ok(&control, "AGENT_CONTROL AGENT_PRIVATE_P3");
        b.apply_policy(r#"permit (principal, action == Box::Action::"shell:spawn", resource);"#);
        let r = b.run_mediated_with_config(edit, &format!("{} files {} {} {}",
            support::q(&probe), support::q(&tool), support::q(&agent), support::q(&witness)));
        r.assert_mediated_permitted("shell:spawn", "phase3-probe");
        assert!(!r.out.contains("DET_ERROR:"), "DET_ERROR: tool probe setup: {}", r.out);
        assert!(r.out.lines().any(|line| line == "FILES_ENTERED"),
            "DET_ERROR: intended tool probe never entered: {}", r.out);
        r.assert_contains("FILES_ENTERED");
        r.assert_contains("OWN_CONTENT TOOL_PRIVATE_P3");
        assert_eq!(r.rc, 0, "tool did not finish: {}", r.out);
        support::require_refusal(&r.out, "OTHER", &[1, 2, 13]);
        r.assert_absent("AGENT_PRIVATE_P3");
        let observed = std::fs::read_to_string(&witness).expect("DET_ERROR: tool witness missing");
        assert!(observed.starts_with("TOOL_WITNESS\nOWN_CONTENT TOOL_PRIVATE_P3\n"));
        support::require_refusal(&observed, "OTHER", &[1, 2, 13]);
        assert_eq!(std::fs::read_to_string(&agent).unwrap(), "AGENT_PRIVATE_P3");
        assert_eq!(std::fs::read_to_string(&tool).unwrap(), "TOOL_PRIVATE_P3");
    }
}
