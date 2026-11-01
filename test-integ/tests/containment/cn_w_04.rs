use strands_det_harness::{det_case, user_home};

// Containment CN-W (Linux workload, act 4)
//
// The environment is composed, never inherited: HOME is the operator's, PATH starts with the alias
// directory, and an unusual TERM exported on the host is absent inside the box.
det_case! {
    name: cn_w_04,
    id:   "CN-W-04",
    desc: "Workload act 4: HOME is the operator's, PATH starts with the alias directory, the host's TERM is absent",
    run: |b| {
        b.reset_policy();
        let r = b.run_sh_with_host_env(
            "printf 'HOME=%s\\nPATH=%s\\nTERM=%s\\n' \"$HOME\" \"$PATH\" \"${TERM-unset}\"",
            &[("TERM", "xterm-det-unusual-4")],
        );
        // The operator's HOME as spelled: the box hands the agent `$HOME` itself, not its canonical
        // form, so on the macOS instances this is /var/tmp/det-home, a link into /private.
        r.assert_contains(&format!("HOME={}", user_home().display()));
        r.assert_absent("xterm-det-unusual-4");
        let path_line = r
            .out
            .lines()
            .find(|line| line.starts_with("PATH="))
            .unwrap_or_default();
        assert!(
            path_line.contains("/state/bin:"),
            "PATH must start with the box's alias directory: {path_line}"
        );
        r.assert_allow();
    }
}
