use strands_det_harness::det_case;

// One `create_dir` budget of two is spent by the hosted Shell and by Monty within one run, and the
// spend carries into the next run of the same box.
const MKDIR_BUDGET: &str = r#"@id("mkdir_budget") forbid (principal, action == Box::Action::"fs:write", resource)
when { context.input.operation == Box::FsWriteOperation::"create_dir" }
when temporal {
  exists (spent: Long). (
    (count for (t: Timepoint). where (
      formerly within 1h (
        Box::Action::"fs:write"::response{ input.path: _, input.operation: Box::FsWriteOperation::"create_dir" } && tp(t)
      )
    )) == spent
    && spent >= 2
  )
};"#;

det_case! {
    name: sh_temporal_shared,
    id:   "SH-TEMPORAL-SHARED",
    desc: "Shared budget: in one run, a Shell mkdir and a Monty mkdir spend a create_dir budget of two and the next Shell mkdir is refused; a Monty mkdir in the next run is refused too",
    run: |b| {
        b.apply_policy(MKDIR_BUDGET);
        b.assert_python_is_monty();
        let one = b.run_mediated(
            "mkdir d1; echo RC1=$?; python3 -c \"from pathlib import Path; Path('d2').mkdir(); print('D2_OK')\"; mkdir d3 2>&1; echo RC3=$?",
        );
        one.assert_entered();
        one.assert_mediated_permitted("fs:write", "/d1");
        one.assert_contains("RC1=0");
        one.assert_mediated_permitted("fs:write", "/d2");
        one.assert_contains("D2_OK");
        one.assert_forbidden_by("fs:write", "/d3", "mkdir_budget");
        one.assert_absent("RC3=0");
        let next = b.run_py("from pathlib import Path\nPath('d4').mkdir()\nprint('D4_OK')");
        next.assert_monty();
        next.assert_forbidden_by("fs:write", "/d4", "mkdir_budget");
        next.assert_absent("D4_OK");
        assert!(
            b.workspace().join("d1").is_dir() && b.workspace().join("d2").is_dir(),
            "the two permitted mkdirs must create their directories"
        );
        assert!(
            !b.workspace().join("d3").exists() && !b.workspace().join("d4").exists(),
            "a refused mkdir created its directory"
        );
    }
}
