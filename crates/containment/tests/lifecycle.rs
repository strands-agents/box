//! Facade apply-pipeline tests using the feature-gated mock backend.

use containment::test_support::{MockContainment, RecordedCall};
use containment::{
    ContainmentConfig, ContainmentError, IpcMode, Network, Operation, ProcessInfoMode, Scope,
    SignalMode,
};

#[test]
fn successful_apply_records_apply() {
    let containment = MockContainment::macos_seatbelt();

    containment
        .apply(&ContainmentConfig::new())
        .expect("mock apply");

    assert_eq!(containment.calls(), vec![RecordedCall::Apply]);
}

#[test]
fn apply_failure_is_propagated() {
    let containment = MockContainment::macos_seatbelt();
    containment.fail_apply("simulated enforcement failure");

    let error = containment
        .apply(&ContainmentConfig::new())
        .expect_err("apply must fail");

    assert!(matches!(
        error,
        ContainmentError::ApplyFailed { ref backend, ref reason }
            if backend == "seatbelt" && reason.contains("simulated")
    ));
    assert_eq!(containment.calls(), vec![RecordedCall::Apply]);
}

/// However much a request carries — grants, socket scopes, every reach mode —
/// it is enforced by one irreversible `apply`. There is no second entry point a
/// caller could reach for, and no mode that splits the pipeline in two.
#[test]
fn every_control_travels_through_the_one_irreversible_apply() {
    let directory = tempfile::tempdir().expect("tempdir");
    // The exec and connect grants sit OUTSIDE the write root. They used to sit inside it, which the
    // write-xor-exec floor now refuses — a fixture that was legal only because that floor lived in the
    // Seatbelt renderer and the mock backend never reached it.
    let state = directory.path().join("state");
    std::fs::create_dir(&state).expect("write root fixture");
    let file = directory.path().join("file");
    std::fs::write(&file, "fixture").expect("fixture");
    let containment = MockContainment::macos_seatbelt();
    let config = ContainmentConfig::new()
        .allow(&state, Operation::Read, Scope::Root)
        .expect("directory grant")
        .allow(&state, Operation::Write, Scope::Root)
        .expect("directory grant")
        .allow(&file, Operation::Exec, Scope::File)
        .expect("execute-only grant")
        .allow(&file, Operation::Connect, Scope::File)
        .expect("socket grant")
        .set_network(Network::localhost().connect(8443))
        .expect("proxy port")
        .set_signal_mode(SignalMode::AllowAll)
        .set_process_info_mode(ProcessInfoMode::AllowAll)
        .set_ipc_mode(IpcMode::Full);

    containment.apply(&config).expect("mock apply");

    assert_eq!(containment.calls(), vec![RecordedCall::Apply]);
}

#[cfg(unix)]
#[test]
fn path_identity_drift_is_rejected_before_backend_apply() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let authorized = root.path().join("authorized");
    let replacement = root.path().join("replacement");
    let requested = root.path().join("requested");
    std::fs::create_dir(&authorized).unwrap();
    std::fs::create_dir(&replacement).unwrap();
    symlink(&authorized, &requested).unwrap();

    let prepared = ContainmentConfig::prepare_filesystem_path(&requested).unwrap();
    let config = ContainmentConfig::new()
        .allow_prepared(prepared, Operation::Read, Scope::Root)
        .expect("read tree");
    std::fs::remove_file(&requested).unwrap();
    symlink(&replacement, &requested).unwrap();

    let containment = MockContainment::macos_seatbelt();
    let error = containment
        .apply(&config)
        .expect_err("changed path identity must be refused before apply");

    assert!(matches!(error, ContainmentError::ConfigValidation(_)));
    assert!(
        containment.calls().is_empty(),
        "the backend must not run after path identity drift"
    );
}

/// **The floors run beneath the backend, not inside it.**
///
/// The mock backend accepts anything, so it is the one place this can be shown: it records no call at
/// all, which means the refusal happened before it was consulted.
#[test]
fn a_system_root_is_refused_before_any_backend_is_consulted() {
    for root in ["/", "/etc", "/usr"] {
        if !std::path::Path::new(root).is_dir() {
            continue;
        }
        let containment = MockContainment::macos_seatbelt();
        let config = ContainmentConfig::new()
            .allow(root, Operation::Read, Scope::Root)
            .expect("the vocabulary accepts a well-formed grant on any directory");

        let error = containment
            .apply(&config)
            .expect_err("a system root is never a grantable tree");
        assert!(
            error.to_string().contains("never a grantable tree"),
            "unexpected error for {root}: {error}"
        );
        assert!(
            containment.calls().is_empty(),
            "the floor must refuse before the backend is consulted: {:?}",
            containment.calls()
        );
    }

    // A file INSIDE a system root stays grantable, because the check is path equality.
    let containment = MockContainment::macos_seatbelt();
    let config = ContainmentConfig::new()
        .allow("/etc/hosts", Operation::Read, Scope::File)
        .expect("a file inside a system root is well-formed");
    containment
        .apply(&config)
        .expect("path equality, not a prefix: a file inside /etc is grantable");
}

/// **Write-plus-exec applies beneath every backend, and the caller is warned.**
///
/// The floor once refused the pair before any backend was consulted. It clears now, and the
/// warning is the caller's to disclose, so the mock backend — which accepts anything — is reached.
#[test]
fn an_exec_grant_inside_a_write_root_warns_and_applies_beneath_every_backend() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical");
    let program = root.join("agent");
    std::fs::write(&program, "agent").expect("program fixture");

    let containment = MockContainment::macos_seatbelt();
    let config = ContainmentConfig::new()
        .allow(&root, Operation::Write, Scope::Root)
        .expect("write root")
        .allow(&program, Operation::Exec, Scope::File)
        .expect("exec inside it is well-formed on its own");

    containment
        .apply(&config)
        .expect("a path that is both writable and executable applies, with a warning");
    assert_eq!(
        containment.calls(),
        vec![RecordedCall::Apply],
        "the floor lets the pair reach the backend"
    );
    let warnings = config.warnings();
    assert_eq!(warnings.len(), 1, "one pair, one warning: {warnings:?}");
    assert!(
        warnings[0]
            .to_string()
            .contains("both writable and executable"),
        "the warning names the pair: {}",
        warnings[0]
    );
}
