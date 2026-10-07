use strands_det_harness::det_case;

// Path.resolve and Path.absolute are refused as unsupported calls and return no path.
det_case! {
    name: mo_resolve,
    id:   "MO-RESOLVE",
    desc: "No path leak: Path.resolve and Path.absolute raise RuntimeError as unsupported and return no host path",
    run: |b| {
        b.reset_policy();
        b.assert_python_is_monty();
        let r = b.run_py(
            "from pathlib import Path\nPath('a.txt').write_text('x')\ntry:\n    print('LEAK=' + str(Path('a.txt').resolve()))\nexcept RuntimeError as e:\n    print('REFUSED=' + str(e))\ntry:\n    print('LEAK=' + str(Path('a.txt').absolute()))\nexcept RuntimeError as e:\n    print('REFUSED=' + str(e))",
        );
        r.assert_monty();
        r.assert_contains("REFUSED=Path.resolve: not supported by this box's Python (Monty)");
        r.assert_contains("REFUSED=Path.absolute: not supported by this box's Python (Monty)");
        r.assert_absent("LEAK=");
    }
}
