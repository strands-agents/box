use super::*;
use crate::{
    Decision, Delivery, DenyReason, GovernedBox, Outcome, Policy, PolicyEngine, Principal, Request,
};
use serde_json::{Value, json};
use std::{
    fs,
    fs::OpenOptions,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[path = "../../../tests/support/captured_migration.rs"]
mod captured_migration;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const POLICY: &str = include_str!("../../../tests/fixtures/dogwood_1_0_0/reversible.dw");

fn helper() -> PathBuf {
    std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("strands-box-dogwood-1-0-migrate")
}
fn open(path: &Path) -> Result<File> {
    Ok(OpenOptions::new().read(true).write(true).open(path)?)
}
fn private(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}
fn original_inputs(path: &Path) -> Result<MigrationInput> {
    let log = DurableLog::open(path)?;
    let bytes = log
        .get_meta(PROVENANCE_KEY)?
        .ok_or("original migration missing")?;
    let record: MigrationRecord = serde_json::from_slice(&bytes)?;
    drop(log);
    Ok(MigrationInput::new(
        open(path)?,
        record
            .original_sources
            .into_iter()
            .map(|source| Policy {
                origin: PathBuf::from(source.origin),
                text: source.text,
            })
            .collect(),
    )
    .with_legacy_validator(File::open(helper())?))
}
fn convert(path: &Path, target: MigrationTarget, label: &str) -> Result<bool> {
    let migration = PolicyMigration::prepare_for(original_inputs(path)?, target)?;
    let completed = migration.summary().already_completed;
    migration.apply(
        private(&path.with_extension(format!("{label}-prepare")))?,
        private(&path.with_extension(format!("{label}-validate")))?,
    )?;
    Ok(completed)
}
fn raw(path: &Path) -> Result<Value> {
    let log = DurableLog::open(path)?;
    let captured = capture_store(&log, &storage::MigrationLimits::default())?;
    let mut archives = Vec::new();
    for generation in 1..=4 {
        archives.push(log.get_meta(&archive_key(generation))?);
    }
    Ok(
        json!({"captured": {"base":captured.base,"next":captured.next,"records":captured.records,"metadata":captured.metadata,"snapshot":captured.snapshot.map(|saved|json!({"up_to":saved.up_to,"payload":saved.payload}))}, "archives": archives, "sentinel": log.get_meta("test.unknown.metadata")?}),
    )
}
fn request(path: &Path, bytes: Option<usize>) -> Result {
    let sources = vec![Policy {
        origin: "reversible.dw".into(),
        text: POLICY.to_owned(),
    }];
    let engine = PolicyEngine::open(sources, path)?;
    let governed = GovernedBox::assigned("directional-interruption");
    let route = if bytes.is_some() {
        "/health"
    } else {
        "/v1/upload"
    };
    let method = if bytes.is_some() { "GET" } else { "POST" };
    let request = Request::Http {
        host: "api.example.com",
        port: 443,
        method,
        path: route,
        body_bytes: bytes.unwrap_or(0),
        intercepted: true,
    };
    let (decision, id) = engine.decide(&governed, &Principal::agent(), &request);
    if let Some(bytes) = bytes {
        assert!(matches!(decision, Decision::Allow { .. }), "{decision:?}");
        engine.record(
            &governed,
            &Principal::agent(),
            &id.ok_or("missing request identity")?,
            &Outcome::Http {
                host: "api.example.com",
                port: 443,
                method,
                path: route,
                delivery: Delivery::Completed { bytes },
                status: Some(200),
                intercepted: true,
            },
        )?;
    } else {
        assert!(
            matches!(
                decision,
                Decision::Deny {
                    reason: DenyReason::NoMatch,
                    ..
                }
            ),
            "exhausted history must deny, got {decision:?}"
        );
    }
    Ok(())
}
fn fixture(root: &Path, target: MigrationTarget) -> Result<PathBuf> {
    let path = root.join("history.redb");
    captured_migration::write_fixture(&path, "reversible")?;
    let log = DurableLog::open(&path)?;
    log.commit(&[Write::Meta {
        key: "test.unknown.metadata",
        value: &[1, 2, 3, 4],
    }])?;
    drop(log);
    let source = vec![Policy {
        origin: "reversible.dw".into(),
        text: POLICY.to_owned(),
    }];
    PolicyMigration::prepare_for(
        MigrationInput::new(open(&path)?, source).with_legacy_validator(File::open(helper())?),
        MigrationTarget::Dogwood1_1_2,
    )?
    .apply(
        private(&root.join("initial-prepare"))?,
        private(&root.join("initial-validate"))?,
    )?;
    request(&path, Some(70))?;
    request(&path, None)?;
    let mut engine = dogwood_local_engine::DurableTemporalEngine::open(&path, 0)
        .map_err(|error| error.to_string())?;
    engine.checkpoint().map_err(|error| error.to_string())?;
    drop(engine);
    let log = DurableLog::open(&path)?;
    assert!(
        log.base_offset() > 0,
        "fault fixture must require saved accumulated state"
    );
    assert_eq!(log.get_snapshot()?.unwrap().up_to_offset, log.next_offset());
    drop(log);
    if target == MigrationTarget::Dogwood1_1_2 {
        assert!(!convert(&path, MigrationTarget::Dogwood1_0_0, "make-old")?);
    }
    fs::write(root.join("before.json"), serde_json::to_vec(&raw(&path)?)?)?;
    Ok(path)
}
fn target() -> MigrationTarget {
    match std::env::var("DIRECTIONAL_TARGET").unwrap().as_str() {
        "1.0.0" => MigrationTarget::Dogwood1_0_0,
        "1.1.2" => MigrationTarget::Dogwood1_1_2,
        value => panic!("unknown target {value}"),
    }
}
fn child_command(root: &Path, target: MigrationTarget, mode: &str, name: &str) -> Command {
    let test_name = format!("{}::{name}", module_path!().split_once("::").unwrap().1);
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", &test_name, "--ignored", "--nocapture"])
        .env("DIRECTIONAL_DIR", root)
        .env("DIRECTIONAL_TARGET", target.version())
        .env("DIRECTIONAL_MODE", mode);
    command
}
fn verify_retry(
    root: &Path,
    target: MigrationTarget,
    expected_completed: Option<bool>,
) -> Result<Value> {
    let path = root.join("history.redb");
    let before: Value = serde_json::from_slice(&fs::read(root.join("before.json"))?)?;
    let after = raw(&path)?;
    for key in ["base", "next", "records"] {
        assert_eq!(
            before["captured"][key], after["captured"][key],
            "conversion changed {key}"
        );
    }
    assert_eq!(before["sentinel"], after["sentinel"]);
    let check = PolicyMigration::prepare_for(original_inputs(&path)?, target)?;
    let completed = check.summary().already_completed;
    if let Some(expected) = expected_completed {
        assert_eq!(completed, expected);
    }
    if !completed {
        assert_eq!(
            before, after,
            "uncommitted conversion must retain all original state"
        );
    }
    drop(check);
    let saved_after_fault = path.with_extension("after-fault.redb");
    fs::copy(&path, &saved_after_fault)?;
    let applied_before = convert(&path, target, "retry")?;
    assert_eq!(applied_before, completed);
    let stable = raw(&path)?;
    assert!(convert(&path, target, "repeat")?);
    assert_eq!(raw(&path)?, stable, "same-target retry must not write");
    if target == MigrationTarget::Dogwood1_0_0 {
        let output = Command::new(helper())
            .arg("validate")
            .stdin(Stdio::from(open(&path)?))
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!convert(
            &path,
            MigrationTarget::Dogwood1_1_2,
            "return-current"
        )?);
    }
    request(&path, None)?;
    request(&path, Some(1))?;
    Ok(
        json!({"completed_at_crash":completed,"retry_preserved_records":true,"repeat_apply_unchanged":true,"current_budget_verdict":"NoMatch","health_verdict":"Allow","saved_after_fault":saved_after_fault}),
    )
}
fn interruption_case(target: MigrationTarget, mode: &str, code: i32, committed: bool) -> Result {
    let root = tempfile::tempdir()?;
    fixture(root.path(), target)?;
    let output = child_command(root.path(), target, mode, "conversion_child").output()?;
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(root.path().join("boundary"))?,
        if committed { "after" } else { "before" }
    );
    verify_retry(root.path(), target, Some(committed))?;
    Ok(())
}
#[test]
fn process_exit_before_downgrade_commit_preserves_history() -> Result {
    interruption_case(MigrationTarget::Dogwood1_0_0, "exit-before", 91, false)
}
#[test]
fn process_exit_after_downgrade_commit_preserves_history() -> Result {
    interruption_case(MigrationTarget::Dogwood1_0_0, "exit-after", 92, true)
}
#[test]
fn process_exit_before_return_upgrade_commit_preserves_history() -> Result {
    interruption_case(MigrationTarget::Dogwood1_1_2, "exit-before", 91, false)
}
#[test]
fn process_exit_after_return_upgrade_commit_preserves_history() -> Result {
    interruption_case(MigrationTarget::Dogwood1_1_2, "exit-after", 92, true)
}

#[cfg(target_os = "linux")]
fn arm_io_fault(fd: i32, mode: &str, trace: i32) {
    use std::ffi::{CString, c_char, c_void};
    #[link(name = "dl")]
    unsafe extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    }
    let symbol = c"arm_conversion_fault_fd";
    let mode = CString::new(mode).unwrap();
    // Only the isolated test child can load this evidence-only I/O controller.
    unsafe {
        let address = dlsym(std::ptr::null_mut(), symbol.as_ptr());
        assert!(
            !address.is_null(),
            "the requested fault controller was not loaded"
        );
        let arm: unsafe extern "C" fn(i32, *const c_char, i32) = std::mem::transmute(address);
        arm(fd, mode.as_ptr(), trace);
    }
}

#[test]
#[ignore]
fn conversion_child() -> Result {
    let root = PathBuf::from(std::env::var("DIRECTIONAL_DIR")?);
    let path = root.join("history.redb");
    let mode = std::env::var("DIRECTIONAL_MODE")?;
    let mut migration = PolicyMigration::prepare_for(original_inputs(&path)?, target())?;
    let Some(PreparedPlan::Transition(plan)) = migration.plan.as_ref() else {
        panic!("child requires a pending directional transition")
    };
    let a = private(&root.join("child-prepare"))?;
    let b = private(&root.join("child-validate"))?;
    #[cfg(target_os = "linux")]
    let trace = private(&root.join("io-trace"))?;
    #[cfg(target_os = "linux")]
    let fd = migration.input.history.as_raw_fd();
    let result = apply_observed(
        &mut migration.log,
        &migration.input,
        plan,
        &a,
        &b,
        &migration.limits,
        |boundary| match boundary {
            CommitBoundary::Before => {
                fs::write(root.join("boundary"), "before").unwrap();
                if mode == "exit-before" {
                    std::process::exit(91);
                }
                if mode != "exit-after" {
                    #[cfg(target_os = "linux")]
                    arm_io_fault(fd, &mode, trace.as_raw_fd());
                    #[cfg(not(target_os = "linux"))]
                    panic!("I/O controller requires Linux");
                }
            }
            CommitBoundary::After => {
                fs::write(root.join("boundary"), "after").unwrap();
                if mode == "exit-after" {
                    std::process::exit(92);
                }
                #[cfg(target_os = "linux")]
                arm_io_fault(fd, "complete", trace.as_raw_fd());
            }
        },
    );
    drop(migration);
    let value = json!({"ok":result.is_ok(),"error":result.as_ref().err().map(ToString::to_string)});
    fs::write(root.join("child-result.json"), serde_json::to_vec(&value)?)?;
    if mode.starts_with("fail-") {
        let error = result.unwrap_err().to_string();
        assert!(error.contains("commit may have completed"), "{error}");
    } else {
        result?;
    }
    Ok(())
}
#[test]
#[ignore]
fn external_fixture() -> Result {
    let root = PathBuf::from(std::env::var("DIRECTIONAL_DIR")?);
    fixture(&root, target())?;
    Ok(())
}
#[test]
#[ignore]
fn external_recovery() -> Result {
    let root = PathBuf::from(std::env::var("DIRECTIONAL_DIR")?);
    let result = verify_retry(&root, target(), None)?;
    fs::write(root.join("recovery.json"), serde_json::to_vec(&result)?)?;
    Ok(())
}
