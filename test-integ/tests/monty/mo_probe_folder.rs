use strands_det_harness::det_case;

// A `read_metadata` budget of three counts each `stat()` under a missing folder, so the third one spends it.
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
    name: mo_probe_folder,
    id:   "MO-PROBE-FOLDER",
    desc: "Metadata budget: each Python stat under a missing folder is answered and spends a read_metadata budget of three; after two a read is permitted, after the third it is refused",
    run: |b| {
        b.apply_policy(PROBE_BUDGET);
        std::fs::write(b.workspace().join("ok.txt"), "kept").expect("plant the file");
        b.assert_python_is_monty();
        let two = b.run_py(
            "from pathlib import Path\nfor name in ['absent-dir/1.txt', 'absent-dir/deeper/2.txt']:\n    try:\n        Path(name).stat()\n        print('FOUND')\n    except OSError:\n        print('MISSING')\nprint('READ=' + Path('ok.txt').read_text())",
        );
        two.assert_monty();
        two.assert_contains("MISSING");
        two.assert_absent("FOUND");
        two.assert_contains("READ=kept");
        let three = b.run_py(
            "from pathlib import Path\ntry:\n    Path('absent-dir/3.txt').stat()\nexcept OSError:\n    print('MISSING')\nprint('READ=' + Path('ok.txt').read_text())",
        );
        three.assert_monty();
        three.assert_contains("MISSING");
        three.assert_forbidden_by("fs:read", "ok.txt", "probe_budget");
        three.assert_absent("READ=kept");
    }
}
