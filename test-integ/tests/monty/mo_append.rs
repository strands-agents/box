use strands_det_harness::det_case;

// An append is an `fs:write` of its own that keeps the existing content.
det_case! {
    name: mo_append,
    id:   "MO-APPEND",
    desc: "Append: open(..., 'a') adds to a file without truncating it, and the append is a second judged fs:write",
    run: |b| {
        b.reset_policy();
        b.assert_python_is_monty();
        let r = b.run_py(
            "from pathlib import Path\nPath('log.txt').write_text('one\\n')\nf = open('log.txt', 'a')\nf.write('two\\n')\nf.close()\nprint('AP=' + Path('log.txt').read_text().replace('\\n', '|'))",
        );
        r.assert_monty();
        let writes = r
            .decisions
            .iter()
            .filter(|d| d.is_action("fs:write") && d.resource.ends_with("/log.txt") && d.permitted())
            .count();
        assert!(writes >= 2, "the write and the append must each be a judged fs:write; saw {writes}; out=[{}]", r.snippet());
        r.assert_contains("AP=one|two|");
    }
}
