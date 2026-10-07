use strands_det_harness::{det_case, user_home};

// The hosted Shell's environment is exactly HOME, PATH, PWD and USER. A variable set on the box
// process, and a variable the agent exports, are both absent.
det_case! {
    name: sh_env,
    id:   "SH-ENV",
    desc: "Composed environment: the hosted Shell's env is exactly HOME, PATH, PWD and USER; host and agent variables are absent",
    run: |b| {
        b.reset_policy();
        let r = b.run_sh_with_host_env(
            "export DET_AGENT_VAR=det-agent-value-7; zsh -lc 'echo DET_MEDIATED; env; echo DET_ENV_END'",
            &[("DET_HOST_SECRET", "det-host-value-9")],
        );
        r.assert_entered();
        let mut lines: Vec<&str> = r
            .out
            .lines()
            .skip_while(|line| *line != "DET_MEDIATED")
            .skip(1)
            .take_while(|line| *line != "DET_ENV_END")
            .collect();
        lines.sort_unstable();
        let expected = [
            format!("HOME={}", user_home().display()),
            "PATH=/usr/bin:/bin".to_string(),
            format!("PWD={}", b.workspace().display()),
            "USER=strands-box".to_string(),
        ];
        assert_eq!(
            lines,
            expected.iter().map(String::as_str).collect::<Vec<_>>(),
            "the Shell's environment must be exactly the composed set"
        );
        r.assert_absent("det-host-value-9");
        r.assert_absent("det-agent-value-7");
    }
}
