#![cfg(unix)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::Command;
use strands_det_harness::{BoxFixture, run_case, user_home, verdict};

const NOTE: &str = "CHARACTERIZATION host=input-refused contained=input-injected";
const CHILD: &str = "DET_CASE_NOTES_CHILD";

fn control(b: &BoxFixture) {
    b.run_sh("printf 'NOTE_CONTROL\\n'")
        .assert_contains("NOTE_CONTROL");
}

fn failure(id: &str, body: impl FnOnce(&BoxFixture)) {
    assert!(catch_unwind(AssertUnwindSafe(|| run_case(id, "note regression", body))).is_err());
}

fn exercise_case_notes() {
    run_case("NOTE-PASS", "note regression", |b| {
        control(b);
        b.record_note(NOTE.into());
    });
    run_case("NOTE-EMPTY", "note regression", control);
    failure("NOTE-FAIL", |b| {
        control(b);
        b.record_note("must not hide failure".into());
        panic!("original assertion failure");
    });
    failure("NOTE-ERROR", |b| {
        control(b);
        b.record_note("must not hide setup failure".into());
        panic!("DET_ERROR: original setup failure");
    });
    failure("NOTE-NO-LAUNCH", |b| {
        b.record_note("note is not a launch".into())
    });
    failure("NOTE-NO-ASSERT", |b| {
        b.record_note("note is not an assertion".into());
        let _ = b.run_sh("true");
    });
    run_case("NOTE-AFTER-FAILURES", "note regression", control);
}

#[test]
fn case_notes_are_scoped_and_preserve_failures_under_normal_capture() {
    if std::env::var_os(CHILD).is_some() {
        exercise_case_notes();
        return;
    }
    let fixture = tempfile::tempdir().expect("note fixture");
    let operator = fixture.path().join("operator");
    let bin = fixture.path().join("bin");
    let results = fixture.path().join("results");
    std::fs::create_dir_all(&operator).unwrap();
    std::fs::create_dir(&bin).unwrap();
    let shim = bin.join("strands-box");
    std::fs::write(
        &shim,
        "#!/bin/sh\n\
         if [ \"$5\" = DET_PREFLIGHT_OK ]; then exec /bin/echo DET_PREFLIGHT_OK; fi\n\
         shift 4\n\
         exec /bin/bash \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    let old_path = std::env::var_os("PATH").expect("toolchain PATH");
    let path =
        std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(&old_path))).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "case_notes_are_scoped_and_preserve_failures_under_normal_capture",
        ])
        .env(CHILD, "1")
        .env("HOME", &operator)
        .env("PATH", path)
        .env(
            "RUSTUP_HOME",
            std::env::var_os("RUSTUP_HOME").unwrap_or_else(|| user_home().join(".rustup").into()),
        )
        .env(
            "CARGO_HOME",
            std::env::var_os("CARGO_HOME").unwrap_or_else(|| user_home().join(".cargo").into()),
        )
        .env("DET_RESULTS_DIR", &results)
        .env_remove("DET_BOX_ROOT")
        .env_remove("RUST_TEST_NOCAPTURE")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(NOTE));
    let loaded = verdict::read_rows(&results);
    assert!(loaded.malformed.is_empty(), "{:?}", loaded.malformed);
    let rows: BTreeMap<_, _> = loaded.rows.into_iter().map(|r| (r.id.clone(), r)).collect();
    assert_eq!(rows.len(), 7);
    assert_eq!(rows["NOTE-PASS"].result, "PASS");
    assert_eq!(rows["NOTE-PASS"].note, NOTE);
    for id in ["NOTE-EMPTY", "NOTE-AFTER-FAILURES"] {
        assert_eq!(rows[id].result, "PASS");
        assert_eq!(rows[id].note, "");
    }
    assert_eq!(rows["NOTE-FAIL"].result, "FAIL");
    assert_eq!(rows["NOTE-FAIL"].note, "original assertion failure");
    assert_eq!(rows["NOTE-ERROR"].result, "ERROR");
    assert_eq!(rows["NOTE-ERROR"].note, "original setup failure");
    for (id, reason) in [
        ("NOTE-NO-LAUNCH", "the case launched no workload"),
        ("NOTE-NO-ASSERT", "the case made no RunResult assertion"),
    ] {
        assert_eq!(rows[id].result, "ERROR");
        assert!(rows[id].note.contains(reason), "{:?}", rows[id]);
    }
}
