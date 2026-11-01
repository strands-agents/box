use strands_det_harness::det_case;

// An enumeration returns each entry under the path the script named, and no host path.
det_case! {
    name: mo_iter,
    id:   "MO-ITER",
    desc: "Enumeration: Path.iterdir returns entries under the named path and no absolute host path, and the listing is judged",
    run: |b| {
        b.reset_policy();
        b.assert_python_is_monty();
        let r = b.run_py(
            "from pathlib import Path\nPath('sub').mkdir()\nPath('sub/a.txt').write_text('x')\nnames = [str(p) for p in Path('sub').iterdir()]\nprint('LS=' + ','.join(names))\nprint('ABS=' + str(any(n.startswith('/') for n in names)))",
        );
        r.assert_monty();
        r.assert_mediated_permitted("fs:read", "sub");
        r.assert_contains("LS=sub/a.txt\nABS=False");
    }
}
