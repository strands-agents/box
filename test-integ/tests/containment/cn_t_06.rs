use strands_det_harness::{det_case, sh_quote};

// A tool leaf's environment is composed from its own `[tool.<name>.env]` table: it holds TOOL_V, and
// neither the agent's `[agent.env]` AGENT_V nor a variable set in the environment of
// `strands-box run` itself. The control is the agent, which sees its own AGENT_V.
const PROBE: &str = include_str!("../probes/leaf_probe.rs");

det_case! {
    name: cn_t_06,
    id:   "CN-T-06",
    desc: "A tool leaf's environment holds its [tool.x.env] TOOL_V, and not the agent's [agent.env] AGENT_V nor a host variable set on strands-box run; the agent sees AGENT_V",
    run: |b| {
        let probe = b.compile_probe("leafprobe-t06", PROBE);
        let quoted = |p: &std::path::Path| serde_json::to_string(&p.to_string_lossy()).unwrap();
        let host_secret = format!("DET_HOST_SECRET_T06_{}", std::process::id());
        let agent_value = "DET_AGENT_VALUE_T06";
        let edit = |text: String| format!(
            "{text}\n[agent.env]\nAGENT_V = \"{agent_value}\"\n\n\
             [tool.t06]\ncommand = [{}]\n\n[tool.t06.env]\nTOOL_V = \"1\"\n",
            quoted(&probe)
        );
        b.apply_policy(r#"permit (principal, action == Box::Action::"shell:spawn", resource);"#);

        // The control: the agent's own environment carries its declared AGENT_V.
        let agent = b.run_sh_with_config(edit, "printf 'AGENT_SEES=%s\\n' \"$AGENT_V\"");
        agent.assert_contains(&format!("AGENT_SEES={agent_value}"));

        let r = b.run_mediated_with_config_env(
            edit,
            &format!("{} env TOOL_V AGENT_V DET_HOST_SECRET", sh_quote(&probe.to_string_lossy())),
            &[("DET_HOST_SECRET", host_secret.as_str())],
        );
        r.assert_mediated_permitted("shell:spawn", "leafprobe-t06");
        assert!(
            r.out.lines().any(|l| l == "ENV_SET \"TOOL_V\" value=1"),
            "the tool leaf does not hold its own TOOL_V=1; out=[{}]", r.snippet()
        );
        assert!(
            r.out.lines().any(|l| l == "ENV_UNSET \"AGENT_V\""),
            "the tool leaf holds the agent's AGENT_V; out=[{}]", r.snippet()
        );
        assert!(
            r.out.lines().any(|l| l == "ENV_UNSET \"DET_HOST_SECRET\""),
            "the tool leaf inherited DET_HOST_SECRET from strands-box run; out=[{}]", r.snippet()
        );
        let names = r.out.lines().find_map(|l| l.strip_prefix("ENV_NAMES ")).unwrap_or_else(|| {
            panic!("DET_ERROR: the tool leaf printed no ENV_NAMES line; out=[{}]", r.snippet())
        });
        let names: Vec<&str> = names.split(',').collect();
        assert!(names.contains(&"TOOL_V"), "ENV_NAMES lacks TOOL_V: {names:?}");
        for absent in ["AGENT_V", "DET_HOST_SECRET"] {
            assert!(!names.contains(&absent), "the tool leaf environment names {absent}: {names:?}");
        }
        r.assert_absent_secret(&host_secret, "CN-T-06 host variable");
        r.assert_absent(agent_value);
    }
}
