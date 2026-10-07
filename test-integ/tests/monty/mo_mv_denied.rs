use strands_det_harness::det_case;

// The baseline names no `fs:move`, so a rename is default-denied and moves nothing.
det_case! {
    name: mo_mv_denied,
    id:   "MO-MV-DENIED",
    desc: "Rename refusal: Path.rename with no fs:move permit is default-denied; the source stays and no destination appears",
    run: |b| {
        b.reset_policy();
        b.assert_python_is_monty();
        let r = b.run_py(
            "from pathlib import Path\nPath('x.txt').write_text('data')\ntry:\n    Path('x.txt').rename('y.txt')\n    print('MOVED')\nexcept Exception as e:\n    print('ERR=' + type(e).__name__)\nprint('STATE=' + str(Path('x.txt').exists()) + ',' + str(Path('y.txt').exists()))",
        );
        r.assert_monty();
        let rule = r.assert_mediated_denied("fs:move", "y.txt");
        assert!(
            rule.contains("default-deny"),
            "the rename must be refused by default-deny, not a rule of the case's own: {rule}"
        );
        r.assert_contains("ERR=PermissionError");
        r.assert_contains("STATE=True,False");
        r.assert_absent("MOVED");
    }
}
