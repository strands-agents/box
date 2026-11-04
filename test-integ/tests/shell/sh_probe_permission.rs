use std::os::unix::fs::PermissionsExt as _;

use strands_det_harness::det_case;

// A check that the host refuses for permission is an answer in the Shell and in Python, so each
// spends one `read_metadata` budget of two.
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
    name: sh_probe_permission,
    id:   "SH-PROBE-PERMISSION",
    desc: "Shared metadata budget: a Shell test -e and a Python exists() under a folder the host will not search are both answered, so they spend a read_metadata budget of two and the next read is refused",
    run: |b| {
        b.apply_policy(PROBE_BUDGET);
        std::fs::write(b.workspace().join("ok.txt"), "kept").expect("plant the file");
        let locked = b.workspace().join("locked");
        std::fs::create_dir(&locked).expect("plant the folder");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("lock the folder");
        b.assert_python_is_monty();
        let r = b.run_mediated(
            "test -e locked/f.txt; echo RC=$?; python3 -c \"from pathlib import Path\ntry:\n    print('PY=' + str(Path('locked/f.txt').exists()))\nexcept OSError:\n    print('PY=refused')\"; cat ok.txt; echo CAT=$?",
        );
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
            .expect("unlock the folder");
        r.assert_entered();
        r.assert_contains("RC=1");
        r.assert_contains("PY=");
        r.assert_absent("PY=True");
        r.assert_forbidden_by("fs:read", "ok.txt", "probe_budget");
        r.assert_absent("CAT=0");
    }
}
