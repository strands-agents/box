use strands_det_harness::det_case;

// One `read_metadata` budget of two is spent by a Shell `test -e` and a Python `stat()` of missing
// paths, because both routes record an answered "no" the same way.
const PROBE_BUDGET: &str = r#"permit (principal, action == Box::Action::"shell:exec", resource);
permit (principal, action == Box::Action::"fs:read", resource);
@id("probe_budget") forbid (principal, action == Box::Action::"fs:read", resource)
when { context.input.operation == Box::FsReadOperation::"read_content" }
when temporal {
  exists (spent: Long). (
    (count for (t: Timepoint). where (
      formerly within 1h (
        Box::Action::"fs:read"::response{ input.path: _, input.operation: Box::FsReadOperation::"read_metadata" } && tp(t)
      )
    )) == spent
    && spent >= 2
  )
};"#;

det_case! {
    name: sh_probe_shared,
    id:   "SH-PROBE-SHARED",
    desc: "Shared metadata budget: a Shell test -e and a Python stat of missing paths each spend a read_metadata budget of two, so the next read is refused",
    run: |b| {
        b.apply_policy(PROBE_BUDGET);
        std::fs::write(b.workspace().join("ok.txt"), "kept").expect("plant the file");
        b.assert_python_is_monty();
        let r = b.run_mediated(
            "test -e absent-shell.txt; echo RC=$?; python3 -c \"from pathlib import Path\ntry:\n    Path('absent-py.txt').stat()\nexcept OSError:\n    print('PY_MISSING')\"; cat ok.txt; echo CAT=$?",
        );
        r.assert_entered();
        r.assert_contains("RC=1");
        r.assert_contains("PY_MISSING");
        r.assert_forbidden_by("fs:read", "ok.txt", "probe_budget");
        r.assert_absent("CAT=0");
    }
}
