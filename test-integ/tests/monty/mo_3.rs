use strands_det_harness::det_case;

// A Monty script's filesystem effects arrive as suspensions the host answers
// (docs/design/decisions.md#monty-is-judged-at-the-effect-level-alone), each
// judged as an `fs:*` the baseline permits under the box home: a write, a read-back, and a mkdir
// all perform and journal their permits. The script surface is pathlib (Monty exposes no `os.mkdir`
// / `os.unlink` — see MO-DEL). Delete is not exercised here: the baseline forbids `fs:delete`, so
// the delete bound is its own case (MO-DEL).
// Measured green on macOS 2026-09-22 (cargo test --test monty): journaled fs:write+fs:read on
// `f.txt`, `READ=MONTY_FS` and `MKDIR_OK` returned.
det_case! {
    name: mo_3,
    id:   "MO-3",
    desc: "Governed fs effect: a Monty script writes, reads back, and mkdirs under the box home, each judged",
    run: |b| {
        b.reset_policy();
        b.assert_python_is_monty();
        let r = b.run_py(
            "from pathlib import Path\nPath('f.txt').write_text('MONTY_FS')\nprint('READ='+Path('f.txt').read_text())\nPath('d').mkdir()\nprint('MKDIR_OK')",
        );
        r.assert_monty();
        r.assert_mediated_permitted("fs:write", "f.txt");
        r.assert_mediated_permitted("fs:read", "f.txt");
        r.assert_contains("READ=MONTY_FS");
        r.assert_contains("MKDIR_OK");
    }
}
