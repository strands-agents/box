use super::*;
use dogwood_language::{Event, EventBuilder, Value};
use dogwood_local_engine::{Clock, Outcome};
use std::{fs, fs::OpenOptions, os::unix::fs::OpenOptionsExt, path::Path};
use tempfile::TempDir;
const APP_KEY: &str = "box.dogwood.migration.v1";
const NOW: i64 = 1_800_000_000_000_000_000;
struct FixedClock;
impl Clock for FixedClock {
    fn now_nanos(&self) -> i64 {
        NOW
    }
}
fn fixture_config() -> DurableConfig {
    DurableConfig::new(0).with_clock(Box::new(FixedClock))
}

fn migrate_fixture(
    original: &mut DurableLog,
    verified_original: &File,
    scratch_prepare: &File,
    scratch_validate: &File,
    approved: &MigrationPlan,
    limits: &MigrationLimits,
) -> Result<MigrationReport> {
    migrate_observed(
        original,
        verified_original,
        scratch_prepare,
        scratch_validate,
        approved,
        limits,
        (|_| {}, fixture_config),
    )
}

struct Fixture {
    dir: TempDir,
    file: File,
    log: DurableLog,
    a: File,
    b: File,
    plan: MigrationPlan,
}
fn private(path: &Path) -> File {
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap()
}
fn plan(log: &DurableLog) -> MigrationPlan {
    let captured = capture_plan_input(log, APP_KEY, &MigrationLimits::default()).unwrap();
    let old = captured
        .historical_statements()
        .unwrap()
        .into_iter()
        .find(|s| s.contains("has \"input\".user"))
        .unwrap();
    let mut expected_policies = if let Some(snapshot) = &captured.snapshot {
        SnapshotPayload::decode(&snapshot.payload)
            .unwrap()
            .bundle
            .policies
            .entries()
            .cloned()
            .collect::<Vec<_>>()
    } else {
        captured
            .records
            .iter()
            .filter_map(|(_, bytes)| match Record::decode(bytes).unwrap() {
                Record::Add {
                    ts,
                    id,
                    token,
                    statement,
                } => Some(PolicyEntry {
                    id,
                    token,
                    created: ts,
                    updated: ts,
                    statement,
                }),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    for e in &mut expected_policies {
        e.statement = e.statement.replace("has \"input\".user", "has input.user");
    }
    MigrationPlan {
        migration_id: "fixture-explicit-upgrade".into(),
        from_version: "1.0.0".into(),
        to_version: "1.1.2".into(),
        provenance:
            "exact static has-path translation approved by the fixture; temporal source unchanged"
                .into(),
        expected_policies,
        translations: vec![StatementTranslation {
            replacement: old.replace("has \"input\".user", "has input.user"),
            old,
        }],
        application_metadata_key: APP_KEY.into(),
        application_metadata_value: br#"{"format_version":1,"fixture":"old-count-two"}"#.to_vec(),
    }
}
fn fixture(form: &str) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("original.redb");
    let file = private(&path);
    let bytes: &[u8] = match form {
        "complete" => include_bytes!("fixtures/old-complete.redb"),
        "pruned" => include_bytes!("fixtures/old-pruned.redb"),
        _ => panic!("unsupported fixture form: {form}"),
    };
    file.write_all_at(bytes, 0).unwrap();
    file.sync_all().unwrap();
    let log = DurableLog::open(fd_path(&file)).unwrap();
    let plan = plan(&log);
    let a = private(&dir.path().join("prepare.redb"));
    let b = private(&dir.path().join("validate.redb"));
    Fixture {
        dir,
        file,
        log,
        a,
        b,
        plan,
    }
}
fn event(action: &str, kind: &str) -> EventBuilder {
    Event::builder(action, kind)
        .principal("Drupe::OAuthUser::\"alice\"")
        .resource("Drupe::Gateway::\"gw1\"")
        .field("input", "user", Value::String("alice".into()))
        .request_context("input", "user", Value::String("alice".into()))
}
fn read(engine: &mut DurableTemporalEngine, threshold: i64) -> bool {
    let result = engine
        .submit(
            event("Drupe::Action::Read", "request")
                .field("input", "threshold", Value::Int(threshold))
                .request_context("input", "threshold", Value::Int(threshold)),
        )
        .unwrap();
    match result.outcome {
        Outcome::Decision(d) => d.allowed(),
        Outcome::Recorded => panic!("Read produced no decision"),
    }
}
fn open_engine(log: DurableLog, file: &File) -> DurableTemporalEngine {
    DurableTemporalEngine::open_with_log_config(log, fd_path(file), fixture_config()).unwrap()
}
fn preserve_counts(form: &str) {
    let mut f = fixture(form);
    let before = capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap();
    let report = migrate_fixture(
        &mut f.log,
        &f.file,
        &f.a,
        &f.b,
        &f.plan,
        &MigrationLimits::default(),
    )
    .unwrap();
    assert_eq!(report.disposition, Disposition::Applied);
    assert!(report.translated_occurrences > 0);
    let after = capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap();
    assert_eq!(before.records, after.records);
    assert_eq!((before.base, before.next), (after.base, after.next));
    assert_eq!(
        after.metadata[APP_KEY].as_ref().unwrap(),
        &f.plan.application_metadata_value
    );
    let snapshot = after.snapshot.unwrap();
    assert_eq!(snapshot.up_to, before.next);
    let expected = f.plan.expected_policies.clone();
    assert_eq!(
        SnapshotPayload::decode(&snapshot.payload)
            .unwrap()
            .bundle
            .policies
            .entries()
            .cloned()
            .collect::<Vec<_>>(),
        expected
    );
    let mut engine = open_engine(f.log, &f.file);
    assert_eq!(engine.list(), expected);
    assert!(!read(&mut engine, 2));
    assert!(read(&mut engine, 3));
    assert!(matches!(
        engine
            .submit(event("Drupe::Action::Login", "response"))
            .unwrap()
            .outcome,
        Outcome::Recorded
    ));
    assert!(!read(&mut engine, 3));
    assert!(read(&mut engine, 4));
    engine.checkpoint().unwrap();
    drop(engine);
    let mut engine = open_engine(DurableLog::open(fd_path(&f.file)).unwrap(), &f.file);
    assert_eq!(engine.list(), expected);
    assert!(!read(&mut engine, 3));
    assert!(read(&mut engine, 4));
}
#[test]
fn complete_old_history_and_new_event_survive() {
    preserve_counts("complete");
}
#[test]
fn pruned_old_history_and_new_event_survive() {
    preserve_counts("pruned");
}
#[test]
fn exact_retry_is_idempotent_after_new_checkpoint() {
    let mut f = fixture("pruned");
    migrate_fixture(
        &mut f.log,
        &f.file,
        &f.a,
        &f.b,
        &f.plan,
        &MigrationLimits::default(),
    )
    .unwrap();
    let mut engine = open_engine(f.log, &f.file);
    assert!(!read(&mut engine, 2));
    engine.checkpoint().unwrap();
    drop(engine);
    f.log = DurableLog::open(fd_path(&f.file)).unwrap();
    let before = capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap();
    let image = image_hash(&f.file, u64::MAX).unwrap();
    let result = migrate_fixture(
        &mut f.log,
        &f.file,
        &f.a,
        &f.b,
        &f.plan,
        &MigrationLimits::default(),
    )
    .unwrap();
    assert_eq!(result.disposition, Disposition::AlreadyApplied);
    assert_eq!(
        capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap(),
        before
    );
    assert_eq!(image_hash(&f.file, u64::MAX).unwrap(), image);
}
#[test]
fn changed_plan_cannot_reuse_committed_migration() {
    let mut f = fixture("complete");
    migrate_fixture(
        &mut f.log,
        &f.file,
        &f.a,
        &f.b,
        &f.plan,
        &MigrationLimits::default(),
    )
    .unwrap();
    f.plan.provenance.push_str(" different approval");
    let before = capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap();
    assert_eq!(
        migrate_fixture(
            &mut f.log,
            &f.file,
            &f.a,
            &f.b,
            &f.plan,
            &MigrationLimits::default()
        )
        .unwrap_err()
        .stage,
        "idempotency"
    );
    assert_eq!(
        capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap(),
        before
    );
}
#[test]
fn incompatible_translation_leaves_original_unchanged() {
    for form in ["complete", "pruned"] {
        let mut f = fixture(form);
        let before = capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap();
        let image = image_hash(&f.file, u64::MAX).unwrap();
        f.plan.translations[0].replacement = "not a valid policy".into();
        let e = migrate_fixture(
            &mut f.log,
            &f.file,
            &f.a,
            &f.b,
            &f.plan,
            &MigrationLimits::default(),
        )
        .unwrap_err();
        assert!(!e.commit_may_have_happened);
        assert_eq!(
            capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap(),
            before
        );
        assert_eq!(image_hash(&f.file, u64::MAX).unwrap(), image);
    }
}
#[test]
fn temporal_fingerprint_change_is_rejected_for_pruned_store() {
    let mut f = fixture("pruned");
    f.plan.translations[0].replacement = f.plan.translations[0]
        .replacement
        .replace("within 1h", "within 2h");
    let before = capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap();
    assert!(
        migrate_fixture(
            &mut f.log,
            &f.file,
            &f.a,
            &f.b,
            &f.plan,
            &MigrationLimits::default()
        )
        .is_err()
    );
    assert_eq!(
        capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap(),
        before
    );
}
#[test]
fn absent_approved_statement_is_rejected() {
    let mut f = fixture("complete");
    f.plan.translations.push(StatementTranslation {
        old: "absent".into(),
        replacement: "also absent".into(),
    });
    let before = capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap();
    assert_eq!(
        migrate_fixture(
            &mut f.log,
            &f.file,
            &f.a,
            &f.b,
            &f.plan,
            &MigrationLimits::default()
        )
        .unwrap_err()
        .stage,
        "plan coverage"
    );
    assert_eq!(
        capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap(),
        before
    );
}
#[test]
fn incompatible_pruned_suffix_is_refused() {
    let mut f = fixture("pruned");
    let payload = SnapshotPayload::decode(&f.log.get_snapshot().unwrap().unwrap().payload).unwrap();
    let e = payload
        .bundle
        .policies
        .entries()
        .find(|e| e.statement == f.plan.translations[0].old)
        .unwrap();
    f.log
        .append(
            &Record::Update {
                ts: NOW + 10,
                id: e.id,
                statement: e.statement.clone(),
            }
            .encode(),
        )
        .unwrap();
    let before = capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap();
    assert_eq!(
        migrate_fixture(
            &mut f.log,
            &f.file,
            &f.a,
            &f.b,
            &f.plan,
            &MigrationLimits::default()
        )
        .unwrap_err()
        .stage,
        "unsupported pruned suffix"
    );
    assert_eq!(
        capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap(),
        before
    );
}
#[test]
fn corrupt_record_is_refused_before_copy() {
    let mut f = fixture("complete");
    f.log.append(b"invalid record").unwrap();
    let image = image_hash(&f.file, u64::MAX).unwrap();
    assert_eq!(
        migrate_fixture(
            &mut f.log,
            &f.file,
            &f.a,
            &f.b,
            &f.plan,
            &MigrationLimits::default()
        )
        .unwrap_err()
        .stage,
        "capture"
    );
    assert_eq!(image_hash(&f.file, u64::MAX).unwrap(), image);
    assert_eq!(f.a.metadata().unwrap().len(), 0);
}
#[test]
fn corrupt_snapshot_is_refused_even_with_complete_log() {
    let mut f = fixture("complete");
    f.log
        .commit(&[Write::Snapshot(&Snapshot {
            up_to_offset: f.log.next_offset(),
            payload: b"bad".to_vec(),
        })])
        .unwrap();
    let image = image_hash(&f.file, u64::MAX).unwrap();
    assert_eq!(
        migrate_fixture(
            &mut f.log,
            &f.file,
            &f.a,
            &f.b,
            &f.plan,
            &MigrationLimits::default()
        )
        .unwrap_err()
        .stage,
        "decode snapshot"
    );
    assert_eq!(image_hash(&f.file, u64::MAX).unwrap(), image);
}
#[test]
fn pruned_without_snapshot_is_refused() {
    let mut f = fixture("complete");
    f.log.prune_below(f.log.next_offset(), usize::MAX).unwrap();
    let image = image_hash(&f.file, u64::MAX).unwrap();
    assert_eq!(
        migrate_fixture(
            &mut f.log,
            &f.file,
            &f.a,
            &f.b,
            &f.plan,
            &MigrationLimits::default()
        )
        .unwrap_err()
        .stage,
        "capture"
    );
    assert_eq!(image_hash(&f.file, u64::MAX).unwrap(), image);
}
#[test]
fn hardlinked_scratch_cannot_truncate_original() {
    let mut f = fixture("complete");
    let same = f.file.try_clone().unwrap();
    let image = image_hash(&f.file, u64::MAX).unwrap();
    assert_eq!(
        migrate_fixture(
            &mut f.log,
            &f.file,
            &same,
            &f.b,
            &f.plan,
            &MigrationLimits::default()
        )
        .unwrap_err()
        .stage,
        "scratch files"
    );
    assert_eq!(image_hash(&f.file, u64::MAX).unwrap(), image);
}
#[test]
fn descriptor_path_swap_still_migrates_verified_inode() {
    let mut f = fixture("pruned");
    let path = f.dir.path().join("original.redb");
    fs::rename(&path, f.dir.path().join("retained.redb")).unwrap();
    fs::write(&path, b"decoy must not change").unwrap();
    let id = identity(&f.file).unwrap();
    let report = migrate_fixture(
        &mut f.log,
        &f.file,
        &f.a,
        &f.b,
        &f.plan,
        &MigrationLimits::default(),
    )
    .unwrap();
    assert_eq!((report.source_device, report.source_inode), id);
    assert_eq!(fs::read(path).unwrap(), b"decoy must not change");
    let mut engine = open_engine(f.log, &f.file);
    assert!(!read(&mut engine, 2));
}
#[test]
fn mismatched_source_descriptor_is_rejected() {
    let mut f = fixture("complete");
    let other = fixture("pruned");
    let image = image_hash(&f.file, u64::MAX).unwrap();
    assert_eq!(
        migrate_fixture(
            &mut f.log,
            &other.file,
            &f.a,
            &f.b,
            &f.plan,
            &MigrationLimits::default()
        )
        .unwrap_err()
        .stage,
        "verify copied source"
    );
    assert_eq!(image_hash(&f.file, u64::MAX).unwrap(), image);
}
#[test]
fn reserved_application_keys_are_rejected() {
    for key in [
        "snapshot",
        "next_offset",
        "base_offset",
        RECEIPT_KEY,
        ENGINE_KEYS[0],
        ENGINE_KEYS[1],
    ] {
        let mut f = fixture("complete");
        f.plan.application_metadata_key = key.into();
        let image = image_hash(&f.file, u64::MAX).unwrap();
        assert_eq!(
            migrate_fixture(
                &mut f.log,
                &f.file,
                &f.a,
                &f.b,
                &f.plan,
                &MigrationLimits::default()
            )
            .unwrap_err()
            .stage,
            "plan"
        );
        assert_eq!(image_hash(&f.file, u64::MAX).unwrap(), image);
    }
}
#[test]
fn unmatched_application_marker_is_not_overwritten() {
    let mut f = fixture("complete");
    f.log
        .commit(&[Write::Meta {
            key: APP_KEY,
            value: b"unmatched",
        }])
        .unwrap();
    assert_eq!(
        migrate_fixture(
            &mut f.log,
            &f.file,
            &f.a,
            &f.b,
            &f.plan,
            &MigrationLimits::default()
        )
        .unwrap_err()
        .stage,
        "idempotency"
    );
    assert_eq!(f.log.get_meta(APP_KEY).unwrap().unwrap(), b"unmatched");
}
#[test]
fn image_bound_failure_preserves_source() {
    let mut f = fixture("complete");
    let limits = MigrationLimits {
        max_image_bytes: 1,
        ..MigrationLimits::default()
    };
    let image = image_hash(&f.file, u64::MAX).unwrap();
    assert!(migrate_fixture(&mut f.log, &f.file, &f.a, &f.b, &f.plan, &limits).is_err());
    assert_eq!(image_hash(&f.file, u64::MAX).unwrap(), image);
}
#[test]
fn unknown_original_metadata_survives() {
    let mut f = fixture("complete");
    f.log
        .commit(&[Write::Meta {
            key: "unrelated.application.key",
            value: b"opaque original value",
        }])
        .unwrap();
    migrate_fixture(
        &mut f.log,
        &f.file,
        &f.a,
        &f.b,
        &f.plan,
        &MigrationLimits::default(),
    )
    .unwrap();
    assert_eq!(
        f.log
            .get_meta("unrelated.application.key")
            .unwrap()
            .unwrap(),
        b"opaque original value"
    );
}

// These are process exits at the call boundary, not faults inside redb's commit.
#[test]
#[ignore]
fn interruption_child() {
    let root = std::env::var("MIGRATION_CHILD_DIR").unwrap();
    let mode = std::env::var("MIGRATION_CHILD_MODE").unwrap();
    let path = Path::new(&root);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path.join("original.redb"))
        .unwrap();
    let mut log = DurableLog::open(fd_path(&file)).unwrap();
    let plan = plan(&log);
    let a = private(&path.join("child-prepare.redb"));
    let b = private(&path.join("child-validate.redb"));
    migrate_observed(
        &mut log,
        &file,
        &a,
        &b,
        &plan,
        &MigrationLimits::default(),
        (
            |point| {
                if matches!(
                    (mode.as_str(), point),
                    ("before", CommitBoundary::Before) | ("after", CommitBoundary::After)
                ) {
                    std::process::exit(91);
                }
            },
            fixture_config,
        ),
    )
    .unwrap();
    panic!("interrupt boundary was not reached");
}
#[test]
fn process_exit_before_commit_preserves_original_and_allows_retry() {
    interrupt_case("before");
}
#[test]
fn process_exit_after_commit_has_atomic_markers_and_idempotent_retry() {
    interrupt_case("after");
}
fn interrupt_case(mode: &str) {
    let f = fixture("pruned");
    let before = capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap();
    let plan = f.plan.clone();
    let dir = f.dir;
    let file = f.file;
    drop(f.log);
    drop(f.a);
    drop(f.b);
    let test_module = module_path!().split_once("::").unwrap().1;
    let child_name = format!("{test_module}::interruption_child");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", child_name.as_str(), "--ignored", "--nocapture"])
        .env("MIGRATION_CHILD_DIR", dir.path())
        .env("MIGRATION_CHILD_MODE", mode)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(91));
    let mut log = DurableLog::open(fd_path(&file)).unwrap();
    if mode == "before" {
        assert_eq!(
            capture(&log, &plan, &MigrationLimits::default()).unwrap(),
            before
        );
        assert!(log.get_meta(RECEIPT_KEY).unwrap().is_none());
        assert!(log.get_meta(APP_KEY).unwrap().is_none());
    } else {
        assert!(log.get_meta(RECEIPT_KEY).unwrap().is_some());
        assert_eq!(
            log.get_meta(APP_KEY).unwrap().unwrap(),
            plan.application_metadata_value
        );
        assert_eq!(
            log.get_snapshot().unwrap().unwrap().up_to_offset,
            before.next
        );
    }
    let a = private(&dir.path().join("retry-prepare.redb"));
    let b = private(&dir.path().join("retry-validate.redb"));
    let report =
        migrate_fixture(&mut log, &file, &a, &b, &plan, &MigrationLimits::default()).unwrap();
    assert_eq!(
        report.disposition,
        if mode == "before" {
            Disposition::Applied
        } else {
            Disposition::AlreadyApplied
        }
    );
    let mut engine = open_engine(log, &file);
    assert!(!read(&mut engine, 2));
    assert!(read(&mut engine, 3));
}

#[test]
fn expected_identity_mismatch_cannot_publish() {
    let mut f = fixture("complete");
    f.plan.expected_policies[0].created += 1;
    let before = capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap();
    assert_eq!(
        migrate_fixture(
            &mut f.log,
            &f.file,
            &f.a,
            &f.b,
            &f.plan,
            &MigrationLimits::default()
        )
        .unwrap_err()
        .stage,
        "approved policy identity"
    );
    assert_eq!(
        capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap(),
        before
    );
}
#[test]
fn translated_output_expansion_is_bounded_before_original_write() {
    let mut f = fixture("complete");
    let captured = capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap();
    let input_bytes = captured.records.iter().map(|(_, b)| b.len()).sum::<usize>();
    f.plan.translations[0]
        .replacement
        .push_str(&format!("\n//{}", "x".repeat(512)));
    let limits = MigrationLimits {
        max_record_bytes: input_bytes + 1,
        ..MigrationLimits::default()
    };
    assert_eq!(
        migrate_fixture(&mut f.log, &f.file, &f.a, &f.b, &f.plan, &limits)
            .unwrap_err()
            .stage,
        "translated output bound"
    );
    assert_eq!(
        capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap(),
        captured
    );
}
#[test]
fn retry_rejects_snapshot_behind_prune_boundary() {
    let mut f = fixture("pruned");
    migrate_fixture(
        &mut f.log,
        &f.file,
        &f.a,
        &f.b,
        &f.plan,
        &MigrationLimits::default(),
    )
    .unwrap();
    f.log
        .append(
            &Record::Reset {
                ts: NOW + 20,
                id: f.plan.expected_policies[2].id,
            }
            .encode(),
        )
        .unwrap();
    f.log.prune_below(f.log.next_offset(), usize::MAX).unwrap();
    assert_eq!(
        migrate_fixture(
            &mut f.log,
            &f.file,
            &f.a,
            &f.b,
            &f.plan,
            &MigrationLimits::default()
        )
        .unwrap_err()
        .stage,
        "receipt verification"
    );
}
#[test]
fn retry_rejects_changed_same_boundary_monitor_payload() {
    let mut f = fixture("pruned");
    migrate_fixture(
        &mut f.log,
        &f.file,
        &f.a,
        &f.b,
        &f.plan,
        &MigrationLimits::default(),
    )
    .unwrap();
    let mut snapshot = f.log.get_snapshot().unwrap().unwrap();
    let mut payload = SnapshotPayload::decode(&snapshot.payload).unwrap();
    payload.engine.push(0);
    snapshot.payload = payload.encode().unwrap();
    f.log.commit(&[Write::Snapshot(&snapshot)]).unwrap();
    assert_eq!(
        verify_application_receipt(&f.log, APP_KEY, &f.plan.application_metadata_value)
            .unwrap_err()
            .stage,
        "receipt verification"
    );
    assert_eq!(
        migrate_fixture(
            &mut f.log,
            &f.file,
            &f.a,
            &f.b,
            &f.plan,
            &MigrationLimits::default()
        )
        .unwrap_err()
        .stage,
        "receipt verification"
    );
}
#[test]
fn retry_checks_current_time_unit_and_bounds() {
    let mut f = fixture("pruned");
    migrate_fixture(
        &mut f.log,
        &f.file,
        &f.a,
        &f.b,
        &f.plan,
        &MigrationLimits::default(),
    )
    .unwrap();
    let small = MigrationLimits {
        max_snapshot_bytes: 1,
        ..MigrationLimits::default()
    };
    assert_eq!(
        migrate_fixture(&mut f.log, &f.file, &f.a, &f.b, &f.plan, &small)
            .unwrap_err()
            .stage,
        "capture"
    );
    f.log
        .commit(&[Write::Meta {
            key: ENGINE_KEYS[0],
            value: b"wrong-unit",
        }])
        .unwrap();
    assert_eq!(
        migrate_fixture(
            &mut f.log,
            &f.file,
            &f.a,
            &f.b,
            &f.plan,
            &MigrationLimits::default()
        )
        .unwrap_err()
        .stage,
        "capture"
    );
}
#[test]
fn marker_without_receipt_is_not_migration_evidence() {
    let f = fixture("complete");
    f.log
        .commit(&[Write::Meta {
            key: APP_KEY,
            value: &f.plan.application_metadata_value,
        }])
        .unwrap();
    assert!(
        verify_application_receipt(&f.log, APP_KEY, &f.plan.application_metadata_value).is_err()
    );
}
#[test]
fn covered_records_after_partial_prune_do_not_need_translation() {
    let mut f = fixture("complete");
    let donor = fixture("pruned");
    let mut payload =
        SnapshotPayload::decode(&donor.log.get_snapshot().unwrap().unwrap().payload).unwrap();
    // Both real 1.0 fixtures have the same event timeline and monitor state. Bind
    // the snapshot carrier to this complete fixture's recorded policy tokens.
    let captured = capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap();
    let entries = captured
        .records
        .iter()
        .filter_map(|(_, b)| match Record::decode(b).unwrap() {
            Record::Add {
                ts,
                id,
                token,
                statement,
            } => Some(PolicyEntry {
                id,
                token,
                created: ts,
                updated: ts,
                statement,
            }),
            _ => None,
        })
        .collect::<Vec<_>>();
    let cursor = payload.bundle.policies.next_id();
    payload.bundle.policies = dogwood_local_engine::PolicySet::from_recorded(entries, cursor);
    let snapshot = Snapshot {
        up_to_offset: f.log.next_offset(),
        payload: payload.encode().unwrap(),
    };
    f.log.commit(&[Write::Snapshot(&snapshot)]).unwrap();
    f.log.prune_below(2, usize::MAX).unwrap();
    assert!(f.log.base_offset() < snapshot.up_to_offset);
    let before = capture(&f.log, &f.plan, &MigrationLimits::default()).unwrap();
    migrate_fixture(
        &mut f.log,
        &f.file,
        &f.a,
        &f.b,
        &f.plan,
        &MigrationLimits::default(),
    )
    .unwrap();
    assert_eq!(
        capture(&f.log, &f.plan, &MigrationLimits::default())
            .unwrap()
            .records,
        before.records
    );
    let mut engine = open_engine(f.log, &f.file);
    assert!(!read(&mut engine, 2));
    assert!(read(&mut engine, 3));
}
#[test]
fn logically_identical_copy_does_not_prove_descriptor_log_association() {
    let mut f = fixture("complete");
    let other = private(&f.dir.path().join("logical-copy.redb"));
    copy_image(&f.file, &other, &MigrationLimits::default()).unwrap();
    assert_ne!(identity(&f.file).unwrap(), identity(&other).unwrap());
    // Deliberately violate the private caller invariant to document its boundary.
    // Logical equality alone cannot prove that the supplied FD opened this log.
    let report = migrate_fixture(
        &mut f.log,
        &other,
        &f.a,
        &f.b,
        &f.plan,
        &MigrationLimits::default(),
    )
    .unwrap();
    assert_eq!(report.source_inode, identity(&other).unwrap().1);
    assert!(f.log.get_meta(RECEIPT_KEY).unwrap().is_some());
    let copy = DurableLog::open(fd_path(&other)).unwrap();
    assert!(copy.get_meta(RECEIPT_KEY).unwrap().is_none());
}
