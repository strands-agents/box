use strands_det_harness::det_case;

// The box's own `unlink_and_rmdir_delete_within_the_home` pins that a delete PERFORMS under an
// `fs:delete` grant, but at the adapter (`OsFunctionCall::Unlink`) level. Through a real Monty
// script the delete surface is pathlib `Path.unlink()` (os.unlink is not exposed — os has no
// `unlink`). This is the bound: the baseline forbids `fs:delete`, so the delete on a file the
// script just wrote is refused by policy and journaled — the write succeeds (baseline permits
// `fs:write`), the delete does not, and `DELETED` never prints.
// Measured green on macOS 2026-09-22: the write performed, Path.unlink raised a PermissionError
// carrying the engine text, and `DELETED` was absent.
det_case! {
    name: mo_del,
    id:   "MO-DEL",
    desc: "Monty delete refusal: os.unlink with no fs:delete permit is refused by policy; the file is not removed",
    run: |b| {
        b.reset_policy();
        b.assert_python_is_monty();
        let r = b.run_py("from pathlib import Path\nPath('victim.txt').write_text('x')\nPath('victim.txt').unlink()\nprint('DELETED')");
        r.assert_monty();
        r.assert_mediated_denied("fs:delete", "victim.txt");
        r.assert_contains("PermissionError");
        r.assert_absent("DELETED");
    }
}
