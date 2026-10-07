use strands_det_harness::{det_case, Route};

// Routing regression (2026-09-22). The two routes into the box must stay distinguishable, or
// every enforcement-point assertion in this suite is reading the wrong thing:
//
// - `run_sh` is the NATIVE contained bash: `[agent] command = ["bash"]` resolves on the declared
//   search path to the host bash, its builtins are the agent's own syscalls, and nothing it does
//   reaches the broker — so a native run journals no decision at all. The box puts its alias
//   directory (`<box_dir>/bin`) first on that bash's PATH, which is the only way in to the Shell.
// - `run_mediated` is that bash invoking the `zsh -lc` alias, whose commands are the hosted
//   Shell's and are journaled as `shell:exec`; a program the Shell does not implement is a
//   `shell:spawn` the gate judges.
//
// If the alias directory ever left the PATH, or `bash` itself became an alias, the sentinels and
// journal shapes below change and this case fails before any other case can misattribute.
det_case! {
    name: cn_r_01,
    id:   "CN-R-01",
    desc: "Routing: run_sh is the native bash (alias dir first on PATH, no journal); run_mediated reaches the hosted Shell (journaled shell:exec, no spawn for a Shell command)",
    run: |b| {
        b.reset_policy();
        let native = b.run_sh("command -v zsh; command -v python3; type read; printf 'NATIVE_OK\\n'");
        assert_eq!(native.route, Route::Native);
        native.assert_contains("NATIVE_OK");
        native.assert_contains("/state/bin/zsh");
        native.assert_contains("/state/bin/python3");
        native.assert_contains("read is a shell builtin");
        assert!(
            native.decisions.is_empty(),
            "a native bash run must journal nothing; it journaled: {:?}",
            native.decisions
        );

        let mediated = b.run_mediated("echo MEDIATED_OK");
        assert_eq!(mediated.route, Route::Mediated);
        mediated.assert_contains("MEDIATED_OK");
        assert!(
            mediated.decisions.iter().any(|d| d.is_action("shell:exec") && d.resource == "echo" && d.permitted()),
            "the Shell's echo must be journaled as a permitted shell:exec; decisions: {:?}",
            mediated.decisions
        );
        assert!(
            !mediated.decisions.iter().any(|d| d.is_action("shell:spawn")),
            "a Shell-implemented command must not become a spawn; decisions: {:?}",
            mediated.decisions
        );
    }
}
