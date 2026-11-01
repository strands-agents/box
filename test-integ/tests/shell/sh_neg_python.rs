use strands_det_harness::det_case;

// One scenario: the Shell's `python` refuses a bad invocation loudly, before any Monty run, as a
// usage error rather than a policy denial or a hang. Two script files is `only one script file`
// (exit 2); a bare invocation (a REPL/pipe/heredoc) is `no REPL` (exit 2) — the alias sends
// StdinEof, so bare `python` returns the refusal at once.
// Measured green on macOS 2026-09-22 (cargo test --test shell): `only one script file`/`RC=2` and
// `no REPL`/`RC=2`, no `effect denied`.
det_case! {
    name: sh_neg_python,
    id:   "SH-NEG-PY",
    desc: "Negative: python bad invocations (two files, bare REPL) are usage errors, not policy denials",
    run: |b| {
        b.reset_policy();
        let two_files = b.run_mediated("python a.py b.py 2>&1; echo RC=$?");
        two_files.assert_entered();
        two_files.assert_contains("only one script file");
        two_files.assert_contains("RC=2\n");
        two_files.assert_absent("effect denied");
        assert!(
            !two_files.decisions.iter().any(|d| !d.permitted()),
            "a python usage error must journal no deny decision; decisions: {:?}",
            two_files.decisions
        );
        let repl = b.run_mediated("python 2>&1; echo RC=$?");
        repl.assert_entered();
        repl.assert_contains("no REPL");
        repl.assert_contains("RC=2\n");
        repl.assert_absent("effect denied");
        assert!(
            !repl.decisions.iter().any(|d| !d.permitted()),
            "a python usage error must journal no deny decision; decisions: {:?}",
            repl.decisions
        );
    }
}
