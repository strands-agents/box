use strands_det_harness::det_case;

// Under an `fs:move` permit, a rename onto a new name performs, and a rename onto an existing file is
// refused by the baseline's `no_deletes` forbid.
det_case! {
    name: mo_mv_replace,
    id:   "MO-MV-REPLACE",
    desc: "Replacing rename: under an fs:move permit, Path.rename to a new name performs and onto an existing file is refused by no_deletes; both files keep their content",
    run: |b| {
        b.apply_policy(r#"@id("mv") permit (principal, action == Box::Action::"fs:move", resource);"#);
        b.assert_python_is_monty();
        let r = b.run_py(
            "from pathlib import Path\nPath('a.txt').write_text('new')\nPath('b.txt').write_text('old')\nPath('n.txt').write_text('n')\nPath('n.txt').rename('fresh.txt')\nprint('FRESH=' + Path('fresh.txt').read_text())\ntry:\n    Path('a.txt').rename('b.txt')\n    print('REPLACED')\nexcept Exception as e:\n    print('ERR=' + type(e).__name__)\nprint('STATE=' + Path('a.txt').read_text() + ',' + Path('b.txt').read_text())",
        );
        r.assert_monty();
        r.assert_mediated_permitted("fs:move", "fresh.txt");
        r.assert_contains("FRESH=n");
        assert!(
            r.decisions
                .iter()
                .any(|d| d.denied() && d.resource.ends_with("/b.txt") && d.forbidden_by("no_deletes")),
            "the move onto b.txt must be refused by no_deletes; out=[{}]",
            r.snippet()
        );
        r.assert_contains("ERR=PermissionError");
        r.assert_contains("STATE=new,old");
        r.assert_absent("REPLACED");
    }
}
