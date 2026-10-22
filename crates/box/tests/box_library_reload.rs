//! `run_with_handle` hands a caller the authority the running box decides against, and a box that
//! fails to open hands out no handle.
//!
//! **One process per probe.** `strands_box::run` and `strands_box::run_with_handle` share a
//! process-wide one-run guard, so each case below re-executes this binary rather than calling a
//! second run in the same process. `box_library.rs` pins the guard itself.

#[path = "support/fixture.rs"]
mod fixture;

use std::process::ExitCode;
use std::sync::mpsc;

use fixture::{Request, box_binary, no_op_program};

/// No `fs:write` rule, so the authority the box opens with denies a write.
const READ_ONLY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
"#;

/// The same policy with a write rule added, authored as a caller would author it.
const READ_AND_WRITE: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
"#;

/// Names an action the schema does not declare, which the engine refuses rather than ignores.
const UNDECLARED_ACTION: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"no:such", resource);
"#;

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--probe-live-handle") => a_handle_reloads_the_running_boxs_own_authority(),
        Some("--probe-no-handle") => a_box_that_fails_to_open_hands_out_no_handle(),
        _ => {
            // The live-handle case opens a real box, which the namespace backend serves on aarch64
            // alone. A case that cannot construct a box measures nothing, so it skips loudly.
            if fixture::namespace_launcher_is_usable() {
                probe("--probe-live-handle");
            } else {
                eprintln!(
                    "skipping: this host cannot run the namespace launcher, so no box opens here"
                );
            }
            // Needs no box: the configuration is absent, so the run fails before one opens.
            probe("--probe-no-handle");
        }
    }
}

/// Run one case in its own process, from beside the box binary.
///
/// A box resolves `strands-box-contain-trampoline` and `strands-box-sock-alias` from the directory
/// of the running image, and a test binary lives in `deps/`, where neither sibling is. So each case
/// runs from a copy of this binary placed beside them. A symlink does not work: the box requires an
/// executable regular file.
fn probe(case: &str) {
    let beside_the_box = box_binary()
        .parent()
        .expect("the box binary sits in a directory")
        .join(format!(
            "box-library-reload-{}",
            case.trim_start_matches('-')
        ));
    std::fs::copy(
        std::env::current_exe().expect("test executable"),
        &beside_the_box,
    )
    .expect("place the probe beside the box binary");

    let output = std::process::Command::new(&beside_the_box)
        .arg(case)
        .output()
        .expect("run the probe");
    let _ = std::fs::remove_file(&beside_the_box);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{case} failed: {stderr}");
}

/// The handle reaches the engine this box is already deciding against, not a fresh copy of it.
///
/// A reload naming an undeclared action is refused, and one authored against the box's real schema
/// applies. Both outcomes come from the running box's own authority: a handle built over a new
/// engine would carry neither this box's schema nor its history.
fn a_handle_reloads_the_running_boxs_own_authority() {
    let configured = Request::with_policy("lib-reload-live", READ_ONLY).expect();
    configured.write_command(no_op_program());
    let config = configured.config().to_path_buf();
    let origin = config.with_file_name("policy.dw");

    // The callback runs on the box's own task, so it reports through a channel and the assertions
    // run here. A panic on that task would unwind the supervision path instead of failing a test.
    let (outcomes, reported) = mpsc::channel();
    let exit = strands_box::run_with_handle(config, Vec::new(), move |handle| {
        let refused = handle.reload(&[strands_box::Policy {
            origin: origin.clone(),
            text: UNDECLARED_ACTION.to_string(),
        }]);
        let applied = handle.reload(&[strands_box::Policy {
            origin,
            text: READ_AND_WRITE.to_string(),
        }]);
        let _ = outcomes.send((
            refused.map_err(|refusal| refusal.to_string()),
            applied.map_err(|refusal| refusal.to_string()),
        ));
    });

    let (refused, applied) = reported
        .try_recv()
        .expect("the box opened, so on_open ran and reported");

    assert!(
        refused.is_err(),
        "a rule naming an undeclared action must be refused, got {refused:?}"
    );
    assert_eq!(
        applied,
        Ok(()),
        "a policy authored against this box's schema must apply to its live authority"
    );
    assert!(
        matches!(exit, ExitCode::SUCCESS),
        "the no-op workload exits zero, so the run does too"
    );
}

/// A run that never opens a box calls `on_open` for no one.
///
/// The configuration does not exist, so the run fails before any authority exists to hand out. A
/// caller that received a handle here would hold one over a box that is not running.
fn a_box_that_fails_to_open_hands_out_no_handle() {
    let directory = tempfile::tempdir().expect("create test directory");
    let missing = directory.path().join("absent.toml");

    let (handles, received) = mpsc::channel();
    let exit = strands_box::run_with_handle(missing, Vec::new(), move |_handle| {
        let _ = handles.send(());
    });

    assert!(
        matches!(exit, ExitCode::FAILURE),
        "a missing configuration fails the run"
    );
    assert!(
        received.try_recv().is_err(),
        "on_open must not run for a box that failed to open"
    );
}
