use strands_det_harness::det_case;

// A predicate of a missing path answers False and spends a `read_metadata` budget, as `stat()` does.
const PROBE_BUDGET: &str = r#"permit (principal, action == Box::Action::"fs:read", resource);
@id("probe_budget") forbid (principal, action == Box::Action::"fs:read", resource)
when { context.input.operation == Box::FsReadOperation::"read_content" }
when temporal {
  exists (spent: Long). (
    (count for (t: Timepoint). where (
      formerly within 1h (
        Box::Action::"fs:read"::response{ input.path: _, input.operation: Box::FsReadOperation::"read_metadata" } && tp(t)
      )
    )) == spent
    && spent >= 4
  )
};"#;

det_case! {
    name: mo_probe_predicates,
    id:   "MO-PROBE-PREDICATES",
    desc: "Metadata budget: exists, is_file, is_dir and is_symlink of a missing path each answer False and spend a read_metadata budget of four, so the next read is refused",
    run: |b| {
        b.apply_policy(PROBE_BUDGET);
        std::fs::write(b.workspace().join("ok.txt"), "kept").expect("plant the file");
        b.assert_python_is_monty();
        let r = b.run_py(
            "from pathlib import Path\np = Path('absent.txt')\nprint('ANSWERS=' + str(p.exists()) + ',' + str(p.is_file()) + ',' + str(p.is_dir()) + ',' + str(p.is_symlink()))\nprint('READ=' + Path('ok.txt').read_text())",
        );
        r.assert_monty();
        r.assert_contains("ANSWERS=False,False,False,False");
        r.assert_forbidden_by("fs:read", "ok.txt", "probe_budget");
        r.assert_absent("READ=kept");
    }
}
