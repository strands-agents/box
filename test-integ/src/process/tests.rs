use super::*;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::time::Duration;

unsafe extern "C" {
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
}

fn fixture(root: &Path, script: &str) -> BoxFixture {
    let script_path = root.join("run");
    let box_bin = std::path::PathBuf::from("/bin/sh");
    std::fs::write(
        &script_path,
        format!("#!/bin/sh\nprintf '%s' $$ > child.pid\n{script}\n"),
    )
    .unwrap();
    let config = root.join("box.toml");
    std::fs::write(&config, "original").unwrap();
    BoxFixture {
        box_bin,
        ws: root.into(),
        config,
        policy_base: root.join("policy.dw"),
        template: "command = {command}\n".into(),
        state: root.join("state"),
        note: std::sync::Mutex::new(String::new()),
    }
}

fn assert_child_reaped(root: &Path) {
    let pid: i32 = std::fs::read_to_string(root.join("child.pid"))
        .unwrap()
        .parse()
        .unwrap();
    let mut status = 0;
    let observed = unsafe { waitpid(pid, &mut status, 1) };
    if observed == 0 {
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
        unsafe { waitpid(pid, &mut status, 0) };
    }
    assert_eq!(
        observed, -1,
        "the helper must stop and reap its child before returning or unwinding"
    );
}

#[test]
fn when_the_callback_panics_then_the_child_is_stopped_and_reaped() {
    let tmp = tempfile::tempdir().unwrap();
    let b = fixture(tmp.path(), ": > .det-ready\nexec /bin/sleep 60");
    let result = catch_unwind(AssertUnwindSafe(|| {
        b.spawn_meanwhile_with_timeouts(
            "unused",
            &[],
            || panic!("callback failed"),
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
    }));
    assert_eq!(
        super::super::panic_message(&result.unwrap_err()),
        "callback failed"
    );
    assert_child_reaped(tmp.path());
}

#[test]
fn when_readiness_times_out_then_the_child_is_stopped_and_reaped() {
    let tmp = tempfile::tempdir().unwrap();
    let b = fixture(tmp.path(), "exec /bin/sleep 60");
    let result = catch_unwind(AssertUnwindSafe(|| {
        b.spawn_meanwhile_with_timeouts(
            "unused",
            &[],
            || panic!("callback must not run"),
            Duration::from_millis(200),
            Duration::from_secs(5),
        );
    }));
    let message = super::super::panic_message(&result.unwrap_err());
    assert!(
        message.contains("never touched the ready marker"),
        "{message}"
    );
    assert_child_reaped(tmp.path());
}

#[test]
fn when_the_child_exits_before_ready_then_the_callback_never_runs_and_output_is_kept() {
    let tmp = tempfile::tempdir().unwrap();
    let b = fixture(
        tmp.path(),
        "printf 'early-out\\n'; printf 'early-err\\n' >&2; exit 7",
    );
    let called = Cell::new(false);
    let result = b.spawn_meanwhile_with_timeouts(
        "unused",
        &[],
        || called.set(true),
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    assert!(!called.get());
    assert_eq!(result.rc, 7, "{}", result.out);
    assert!(
        result
            .out
            .contains("workload exited before the ready marker")
    );
    assert!(result.out.contains("early-out"));
    assert!(result.out.contains("early-err"));
    assert!(!b.go_marker().exists());
    assert_child_reaped(tmp.path());
}

#[test]
fn when_the_child_never_exits_then_timeout_stops_it_and_preserves_output() {
    let tmp = tempfile::tempdir().unwrap();
    let b = fixture(
        tmp.path(),
        "printf 'before-timeout\\n'; : > .det-ready\nexec /bin/sleep 60",
    );
    let called = Cell::new(false);
    let result = b.spawn_meanwhile_with_timeouts(
        "unused",
        &[],
        || called.set(true),
        Duration::from_secs(5),
        Duration::from_millis(100),
    );
    assert!(called.get());
    assert_ne!(result.rc, 0);
    assert!(result.out.contains("box did not exit"));
    assert!(result.out.contains("before-timeout"));
    assert_child_reaped(tmp.path());
}

#[test]
fn when_the_callback_succeeds_then_the_workload_continues_and_both_pipes_are_captured() {
    let tmp = tempfile::tempdir().unwrap();
    let b = fixture(
        tmp.path(),
        ": > .det-ready\nwhile [ ! -e .det-go ]; do sleep 0.01; done\nprintf 'finished-out\\n'; printf 'finished-err\\n' >&2",
    );
    let called = Cell::new(false);
    let result = b.spawn_meanwhile_with_timeouts(
        "unused",
        &[],
        || called.set(true),
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    assert!(called.get());
    assert_eq!(result.rc, 0);
    assert!(result.out.contains("finished-out"));
    assert!(result.out.contains("finished-err"));
    assert_child_reaped(tmp.path());
}

#[test]
fn when_a_configured_callback_panics_then_the_baseline_command_is_restored() {
    let tmp = tempfile::tempdir().unwrap();
    let b = fixture(tmp.path(), ": > .det-ready\nexec /bin/sleep 60");
    let result = catch_unwind(AssertUnwindSafe(|| {
        b.run_sh_with_config_meanwhile(
            |_| "temporary configuration".into(),
            "unused",
            || panic!("callback failed"),
        );
    }));
    assert_eq!(
        super::super::panic_message(&result.unwrap_err()),
        "callback failed"
    );
    let restored = std::fs::read_to_string(&b.config).unwrap();
    assert_child_reaped(tmp.path());
    assert_eq!(restored, "command = [\"bash\"]\n");
}

#[test]
fn when_an_environment_callback_panics_then_the_baseline_command_is_restored() {
    let tmp = tempfile::tempdir().unwrap();
    let b = fixture(tmp.path(), ": > .det-ready\nexec /bin/sleep 60");
    let result = catch_unwind(AssertUnwindSafe(|| {
        b.run_sh_with_config_meanwhile_env(
            |_| "temporary configuration".into(),
            "unused",
            &[("DET_FIXTURE", "value")],
            || panic!("callback failed"),
        );
    }));
    assert_eq!(
        super::super::panic_message(&result.unwrap_err()),
        "callback failed"
    );
    let restored = std::fs::read_to_string(&b.config).unwrap();
    assert_child_reaped(tmp.path());
    assert_eq!(restored, "command = [\"bash\"]\n");
}
