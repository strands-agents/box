use strands_det_harness::det_case;

// A `read_metadata` budget of three counts each `test -e` under a missing folder, so the third one spends it.
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
    && spent >= 3
  )
};"#;

det_case! {
    name: sh_probe_folder,
    id:   "SH-PROBE-FOLDER",
    desc: "Metadata budget: each Shell test -e under a missing folder is answered and spends a read_metadata budget of three; after two a read is permitted, after the third it is refused",
    run: |b| {
        b.apply_policy(PROBE_BUDGET);
        std::fs::write(b.workspace().join("ok.txt"), "kept").expect("plant the file");
        let two = b.run_mediated(
            "test -e absent-dir/1.txt; echo RC=$?; test -e absent-dir/deeper/2.txt; echo RC=$?; cat ok.txt; echo CAT=$?",
        );
        two.assert_entered();
        two.assert_contains("RC=1");
        two.assert_absent("RC=0");
        two.assert_contains("CAT=0");
        let three = b.run_mediated("test -e absent-dir/3.txt; echo RC=$?; cat ok.txt; echo CAT=$?");
        three.assert_entered();
        three.assert_contains("RC=1");
        three.assert_forbidden_by("fs:read", "ok.txt", "probe_budget");
        three.assert_absent("CAT=0");
    }
}
