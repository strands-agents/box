//! Explicit conversions preserve captured old records and all three activity periods.

use dogwood_local_engine::{
    DurableLog, DurableTemporalEngine, PolicyEntry, Record, SnapshotPayload, Write,
};
use policy::{
    Decision, Delivery, DenyReason, GovernedBox, MigrationInput, MigrationTarget, Outcome, Policy,
    PolicyEngine, PolicyMigration, Principal, Request,
};
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[path = "support/captured_migration.rs"]
mod captured_migration;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const POLICY: &str = include_str!("fixtures/dogwood_1_0_0/reversible.dw");
const DUPLICATE: &str = include_str!("fixtures/dogwood_1_0_0/reversible-duplicates.dw");
const STREAM: &str = include_str!("fixtures/dogwood_1_0_0/reversible.jsonl");
const PHASE: &str = "box.dogwood.transition.v1";

fn helper() -> PathBuf {
    std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("strands-box-dogwood-1-0-migrate")
}
fn sources(text: &str) -> Vec<Policy> {
    vec![Policy {
        origin: PathBuf::from("reversible.dw"),
        text: text.to_owned(),
    }]
}
fn opened(path: &Path) -> Result<File> {
    Ok(OpenOptions::new().read(true).write(true).open(path)?)
}
fn legacy(path: &Path, mode: &str) -> Result<Value> {
    let output = Command::new(helper())
        .arg(mode)
        .stdin(Stdio::from(opened(path)?))
        .output()?;
    assert!(
        output.status.success(),
        "legacy {mode}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
fn input(path: &Path, text: &str) -> Result<MigrationInput> {
    Ok(MigrationInput::new(opened(path)?, sources(text))
        .with_legacy_validator(File::open(helper())?))
}
fn scratch(directory: &Path, name: &str) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(name))?)
}
fn convert(path: &Path, text: &str, target: MigrationTarget, label: &str) -> Result {
    let before = raw(path)?;
    let migration = PolicyMigration::prepare_for(input(path, text)?, target)?;
    assert_eq!(migration.summary().to_version, target.version());
    let summary = migration.apply(
        scratch(path.parent().unwrap(), &format!("{label}-prepare"))?,
        scratch(path.parent().unwrap(), &format!("{label}-validate"))?,
    )?;
    assert!(!summary.already_completed);
    let after = raw(path)?;
    assert_eq!(
        before["records"], after["records"],
        "conversion rewrote original records"
    );
    assert_eq!(
        before["base"], after["base"],
        "conversion pruned original history"
    );
    assert_eq!(
        before["next"], after["next"],
        "conversion appended management operations"
    );
    assert_eq!(after["sentinel"], json!([1, 2, 3, 4]));
    Ok(())
}
fn raw(path: &Path) -> Result<Value> {
    let log = DurableLog::open(path)?;
    let mut records = Vec::new();
    log.scan_from(log.base_offset(), |offset, bytes| {
        records.push(json!([offset, bytes]))
    })?;
    Ok(
        json!({"base":log.base_offset(),"next":log.next_offset(),"records":records,
        "snapshot":log.get_snapshot()?.map(|s|json!([s.up_to_offset,s.payload])),
        "phase":log.get_meta(PHASE)?,"sentinel":log.get_meta("test.unknown.metadata")?}),
    )
}
fn entries(path: &Path) -> Result<Vec<PolicyEntry>> {
    let log = DurableLog::open(path)?;
    let saved = log.get_snapshot()?.ok_or("no checkpoint")?;
    Ok(SnapshotPayload::decode(&saved.payload)?
        .bundle
        .policies
        .entries()
        .cloned()
        .collect())
}
fn current(path: &Path, text: &str, route: &str, bytes: Option<usize>, expected: &str) -> Result {
    let before = entries(path)?;
    let before_log = raw(path)?;
    let engine = PolicyEngine::open(sources(text), path)?;
    let governed = GovernedBox::assigned("history-conversion-test");
    let method = if route == "/health" { "GET" } else { "POST" };
    let request = Request::Http {
        host: "api.example.com",
        port: 443,
        method,
        path: route,
        body_bytes: bytes.unwrap_or(0),
        intercepted: true,
    };
    let (decision, id) = engine.decide(&governed, &Principal::agent(), &request);
    let actual = match decision {
        Decision::Allow { .. } => "Allow",
        Decision::Deny {
            reason: DenyReason::NoMatch,
            ..
        } => "NoMatch",
        Decision::Deny {
            reason: DenyReason::Forbidden,
            ..
        } => "Forbidden",
        other => panic!("unexpected verdict {other:?}"),
    };
    assert_eq!(actual, expected);
    if let Some(bytes) = bytes {
        assert_eq!(actual, "Allow");
        engine.record(
            &governed,
            &Principal::agent(),
            &id.ok_or("request ID missing")?,
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
    }
    drop(engine);
    let inspected = DurableTemporalEngine::open(path, 0).map_err(|error| error.to_string())?;
    assert_eq!(
        inspected.list(),
        before,
        "unchanged source replaced a recorded identity"
    );
    drop(inspected);
    let after_log = raw(path)?;
    let old = before_log["records"].as_array().unwrap();
    let new = after_log["records"].as_array().unwrap();
    assert!(
        new.starts_with(old),
        "unchanged open changed the existing record prefix"
    );
    for record in &new[old.len()..] {
        let bytes: Vec<u8> = serde_json::from_value(record[1].clone())?;
        assert!(
            matches!(Record::decode(&bytes)?, Record::Event(_)),
            "unchanged open appended policy management"
        );
    }
    Ok(())
}
fn checkpoint_current(path: &Path) -> Result {
    let mut engine = DurableTemporalEngine::open(path, 0).map_err(|e| e.to_string())?;
    engine.checkpoint().map_err(|e| e.to_string())?;
    Ok(())
}

// The old engine consumes a paired observation encoded exactly like the captured
// old Box request/response. The sealed prototype separately exercised old Box;
// these product tests exercise the pinned old-engine helper and current Box APIs.
fn append_old_activity(path: &Path, bytes: u64) -> Result {
    let log = DurableLog::open(path)?;
    let request_id = log.next_offset().to_string();
    let start = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
    let templates: Vec<Value> = STREAM
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    let pair = &templates[templates.len() - 2..];
    let mut encoded = Vec::new();
    for (index, template) in pair.iter().enumerate() {
        let mut value = template.clone();
        value["ts"] = json!(start + index as i64);
        value["event"]["logged"]["requestId"] = json!(["s", request_id]);
        for section in ["logged", "context"] {
            let fields = &mut value["event"][section]["input"][1];
            fields["body_bytes"] = json!(["i", bytes]);
            fields["method"] = json!(["s", "GET"]);
            fields["path"] = json!(["s", "/health"]);
        }
        let bytes = serde_json::to_vec(&value)?;
        let decoded = Record::decode(&bytes)?;
        assert_eq!(serde_json::from_slice::<Value>(&decoded.encode())?, value);
        encoded.push(decoded.encode());
    }
    let offsets = log.commit(
        &encoded
            .iter()
            .map(|record| Write::Append(record))
            .collect::<Vec<_>>(),
    )?;
    assert_eq!(offsets.len(), 2);
    Ok(())
}

fn matrix(duplicate: bool, pruned: bool, under_limit: bool) -> Result {
    assert!(
        helper().is_file(),
        "build the separately resolved legacy helper beside this test executable"
    );
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("history.redb");
    let text = if duplicate { DUPLICATE } else { POLICY };
    captured_migration::write_fixture(
        &path,
        if duplicate {
            "reversible-duplicates"
        } else {
            "reversible"
        },
    )?;
    {
        let log = DurableLog::open(&path)?;
        log.commit(&[Write::Meta {
            key: "test.unknown.metadata",
            value: &[1, 2, 3, 4],
        }])?;
    }
    if pruned {
        legacy(&path, "checkpoint")?;
    }
    convert(&path, text, MigrationTarget::Dogwood1_1_2, "first")?;
    let first = entries(&path)?;
    current(&path, text, "/v1/upload", None, "Allow")?;
    if pruned {
        checkpoint_current(&path)?;
    }
    current(
        &path,
        text,
        "/health",
        Some(if under_limit { 40 } else { 70 }),
        "Allow",
    )?;
    let before_reverse = if under_limit { "Allow" } else { "NoMatch" };
    current(&path, text, "/v1/upload", None, before_reverse)?;
    current(&path, text, "/blocked", None, "Forbidden")?;
    if pruned {
        let log = DurableLog::open(&path)?;
        assert!(log.base_offset() > 0);
        assert!(
            log.get_snapshot()?.unwrap().up_to_offset < log.next_offset(),
            "source needs a nonempty suffix"
        );
    }
    convert(&path, text, MigrationTarget::Dogwood1_0_0, "reverse")?;
    let old = entries(&path)?;
    assert_eq!(old.len(), first.len());
    for (a, b) in first.iter().zip(&old) {
        assert_eq!(
            (a.id, &a.token, a.created, a.updated),
            (b.id, &b.token, b.created, b.updated)
        );
    }
    assert!(
        old.iter()
            .any(|entry| entry.statement.contains("has \"input\".host"))
    );
    legacy(&path, "checkpoint")?;
    let validated = legacy(&path, "validate")?;
    assert_eq!(validated["policies"], serde_json::to_value(&old)?);
    append_old_activity(&path, if under_limit { 30 } else { 20 })?;
    let unchanged = raw(&path)?;
    let refusal =
        PolicyMigration::prepare(MigrationInput::new(opened(&path)?, sources(text))).unwrap_err();
    assert!(
        refusal
            .to_string()
            .contains("directional history requires prepare_for")
    );
    assert_eq!(
        raw(&path)?,
        unchanged,
        "default prepare must not write or claim the historical forward receipt"
    );
    convert(&path, text, MigrationTarget::Dogwood1_1_2, "again")?;
    assert_eq!(entries(&path)?, first);
    current(&path, text, "/v1/upload", None, "NoMatch")?;
    current(&path, text, "/blocked", None, "Forbidden")?;
    let already = PolicyMigration::prepare_for(input(&path, text)?, MigrationTarget::Dogwood1_1_2)?;
    assert!(already.summary().already_completed);
    assert_eq!(already.summary().generation, 2);
    drop(already);
    Ok(())
}

#[test]
fn complete_history_survives_forward_reverse_forward() -> Result {
    matrix(false, false, false)
}
#[test]
fn pruned_history_with_a_suffix_survives_both_directions() -> Result {
    matrix(false, true, false)
}
#[test]
fn duplicate_rule_identities_survive_both_directions() -> Result {
    matrix(true, false, false)
}
#[test]
fn forty_old_forty_new_and_thirty_downgraded_bytes_all_remain_counted() -> Result {
    matrix(false, true, true)
}

#[test]
fn edited_policies_and_corrupt_directional_receipts_refuse_without_writing() -> Result {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("history.redb");
    captured_migration::write_fixture(&path, "reversible")?;
    {
        let log = DurableLog::open(&path)?;
        log.commit(&[Write::Meta {
            key: "test.unknown.metadata",
            value: &[1, 2, 3, 4],
        }])?;
    }
    convert(&path, POLICY, MigrationTarget::Dogwood1_1_2, "first")?;
    let changed = POLICY.replace("total < 100", "total < 200");
    let engine = PolicyEngine::open(sources(&changed), &path)?;
    drop(engine);
    let unchanged = raw(&path)?;
    assert!(
        PolicyMigration::prepare_for(input(&path, &changed)?, MigrationTarget::Dogwood1_0_0)
            .is_err()
    );
    assert_eq!(raw(&path)?, unchanged);
    let engine = PolicyEngine::open(sources(POLICY), &path)?;
    drop(engine);
    let unchanged = raw(&path)?;
    assert!(
        PolicyMigration::prepare_for(input(&path, POLICY)?, MigrationTarget::Dogwood1_0_0).is_err()
    );
    assert_eq!(
        raw(&path)?,
        unchanged,
        "edit-away/back must not revive old bindings"
    );
    {
        let log = DurableLog::open(&path)?;
        log.commit(&[Write::Meta {
            key: PHASE,
            value: b"{}",
        }])?;
    }
    let unchanged = raw(&path)?;
    assert!(
        PolicyMigration::prepare_for(input(&path, POLICY)?, MigrationTarget::Dogwood1_0_0).is_err()
    );
    assert!(PolicyEngine::open(sources(POLICY), &path).is_err());
    assert_eq!(raw(&path)?, unchanged);
    Ok(())
}
