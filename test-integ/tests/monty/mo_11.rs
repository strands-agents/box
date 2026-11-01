use strands_det_harness::det_case;

// `subprocess` is not part of Monty, so the import is rejected when the script is compiled —
// before its first statement runs, so the entry sentinel is never printed and Monty's own footer
// on the exception is the proof the script reached Monty (measured on the native Linux run:
// `ModuleNotFoundError: No module named 'subprocess'` then the footer, no sentinel). The identity
// control runs first through the hosted Shell. No process is ever asked for: a host CPython (which
// has `subprocess`) would either run `id` or fail some other way, and neither passes here.
det_case! {
    name: mo_11,
    id:   "MO-11",
    desc: "Monty sandbox: 'import subprocess' is unavailable in Monty (ModuleNotFoundError), so nothing is spawned",
    run: |b| {
        b.reset_policy();
        b.assert_python_is_monty();
        let r = b.run_py("import subprocess\nsubprocess.run(['id'])\nprint('SPAWNED')");
        r.assert_monty();
        r.assert_contains("ModuleNotFoundError: No module named 'subprocess'");
        r.assert_absent("SPAWNED");
        r.assert_absent("uid=");
        assert!(
            !r.decisions.iter().any(|d| d.is_action("shell:spawn")),
            "the import must fail inside Monty before any spawn reaches the broker; decisions: {:?}",
            r.decisions
        );
    }
}
