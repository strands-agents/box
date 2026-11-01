use strands_det_harness::det_case;

// A rename under an `fs:move` permit moves the file within the workspace.
det_case! {
    name: mo_mv,
    id:   "MO-MV",
    desc: "Rename: Path.rename under an fs:move permit moves the file, and the move is judged",
    run: |b| {
        b.apply_policy(r#"@id("mv") permit (principal, action == Box::Action::"fs:move", resource);"#);
        b.assert_python_is_monty();
        let r = b.run_py(
            "from pathlib import Path\nPath('a.txt').write_text('hi')\nPath('a.txt').rename('r.txt')\nprint('MV=' + str(Path('a.txt').exists()) + ',' + str(Path('r.txt').exists()))",
        );
        r.assert_monty();
        r.assert_mediated_permitted("fs:move", "r.txt");
        r.assert_contains("MV=False,True");
    }
}
