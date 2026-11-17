//! The installed command converts a stopped, already configured Box history.
//!
//! Captured 1.0.0 streams use the policy crate's reversible timestamp-only loader.
//! The fixture writes the existing version-21 committed-record format; it never
//! launches a workload or uses `run` to initialize a new current-version history.

use dogwood_local_engine::{DurableLog, PolicyEntry, SnapshotPayload, Write};
use policy::{
    Decision, Delivery, DenyReason, GovernedBox, Outcome, Policy, PolicyEngine, Principal, Request,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

#[path = "../../policy/tests/support/captured_migration.rs"]
mod captured_migration;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const ORIGINAL: &str = include_str!("../../policy/tests/fixtures/dogwood_1_0_0/reversible.dw");
const DUPLICATES: &str =
    include_str!("../../policy/tests/fixtures/dogwood_1_0_0/reversible-duplicates.dw");
const HELPER: &str = "strands-box-dogwood-1-0-migrate";
const BOX_ID: &str = "box-0123456789abcdef";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_strands-box"))
}
fn helper() -> PathBuf {
    binary().parent().unwrap().join(HELPER)
}
fn opened(path: &Path) -> Result<File> {
    Ok(OpenOptions::new().read(true).write(true).open(path)?)
}
fn write_private(path: &Path, bytes: impl AsRef<[u8]>) -> Result {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
fn succeeded(output: Output) -> Output {
    assert!(
        output.status.success(),
        "command refused: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn summary(output: &Output) -> Value {
    serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Value>()
        .next()
        .expect("command reports a summary")
        .expect("summary is JSON")
}

struct Fixture {
    _temporary: tempfile::TempDir,
    config: PathBuf,
    policy: PathBuf,
    private: PathBuf,
    history: PathBuf,
    text: &'static str,
}
impl Fixture {
    fn new(duplicates: bool) -> Result<Self> {
        let temporary = tempfile::tempdir()?;
        let parent = temporary.path().canonicalize()?;
        let directory = parent.join("state");
        let private = directory.join("private");
        fs::create_dir(&directory)?;
        fs::create_dir(&private)?;
        for path in [&directory, &private] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let text = if duplicates { DUPLICATES } else { ORIGINAL };
        let policy = parent.join("policy.dw");
        write_private(&policy, text)?;
        let config = parent.join("box.toml");
        let selected = format!(
            "name = \"migration\"\nbox_dir = {:?}\npolicy = {:?}\n",
            directory.display().to_string(),
            policy.display().to_string()
        );
        write_private(&config, &selected)?;
        let record = format!("version = 21\nbox_id = \"{BOX_ID}\"\n{selected}");
        write_private(&private.join("box.toml"), &record)?;
        write_private(
            &private.join("configured"),
            format!(
                "{BOX_ID} sha256:{}\n",
                Sha256::digest(record.as_bytes())
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ),
        )?;
        write_private(&private.join("policy.dw"), text)?;
        write_private(&private.join(".lock"), [])?;
        let history = private.join("dogwood.redb");
        captured_migration::write_fixture(
            &history,
            if duplicates {
                "reversible-duplicates"
            } else {
                "reversible"
            },
        )?;
        fs::set_permissions(&history, fs::Permissions::from_mode(0o600))?;
        let log = DurableLog::open(&history)?;
        log.commit(&[Write::Meta {
            key: "test.unknown.metadata",
            value: &[9, 8, 7],
        }])?;
        drop(log);
        Ok(Self {
            _temporary: temporary,
            config,
            policy,
            private,
            history,
            text,
        })
    }

    fn command(&self, executable: &Path, to: &str, apply: bool) -> Result<Output> {
        let mut command = Command::new(executable);
        command
            .env("EXPERIMENTAL_X86_SUPPORT", "TRUE")
            .args(["policy", "migrate-history", "--config"])
            .arg(&self.config)
            .args(["--to", to]);
        if apply {
            command.arg("--apply");
        }
        Ok(command.output()?)
    }

    fn convert(&self, to: &str) -> Result {
        let before = raw(&self.history)?;
        let authority: Vec<_> = [
            self.private.join("box.toml"),
            self.private.join("configured"),
            self.private.join("policy.dw"),
            self.config.clone(),
            self.policy.clone(),
        ]
        .into_iter()
        .map(|p| Ok((p.clone(), fs::read(p)?)))
        .collect::<Result<_>>()?;
        let prepared = succeeded(self.command(&binary(), to, false)?);
        assert_eq!(summary(&prepared)["to_version"], to);
        assert!(!summary(&prepared)["already_completed"].as_bool().unwrap());
        assert_eq!(
            before,
            raw(&self.history)?,
            "prepare changed stored history"
        );
        assert!(String::from_utf8_lossy(&prepared.stdout).contains("repeat with --apply"));
        let applied = succeeded(self.command(&binary(), to, true)?);
        assert!(String::from_utf8_lossy(&applied.stdout).contains("History conversion complete"));
        let after = raw(&self.history)?;
        for field in ["base", "next", "records", "sentinel"] {
            assert_eq!(before[field], after[field], "apply changed {field}");
        }
        for (path, bytes) in authority {
            assert_eq!(fs::read(path)?, bytes);
        }
        let repeated = succeeded(self.command(&binary(), to, true)?);
        assert!(summary(&repeated)["already_completed"].as_bool().unwrap());
        assert!(String::from_utf8_lossy(&repeated.stdout).contains("No conversion is needed"));
        assert_eq!(after, raw(&self.history)?, "repeated apply changed history");
        Ok(())
    }

    fn current_decision(&self, bytes: Option<usize>, expected: &str) -> Result {
        let engine = PolicyEngine::open(
            vec![Policy {
                origin: self.policy.clone(),
                text: self.text.to_owned(),
            }],
            &self.history,
        )?;
        let governed = GovernedBox::assigned(BOX_ID);
        let request = Request::Http {
            host: "api.example.com",
            port: 443,
            method: "POST",
            path: "/v1/upload",
            body_bytes: bytes.unwrap_or(0),
            intercepted: true,
        };
        let (decision, id) = engine.decide(&governed, &Principal::agent(), &request);
        let found = match decision {
            Decision::Allow { .. } => "Allow",
            Decision::Deny {
                reason: DenyReason::NoMatch,
                ..
            } => "NoMatch",
            other => panic!("unexpected verdict {other:?}"),
        };
        assert_eq!(found, expected);
        if let Some(bytes) = bytes {
            assert_eq!(found, "Allow");
            engine.record(
                &governed,
                &Principal::agent(),
                &id.ok_or("missing request ID")?,
                &Outcome::Http {
                    host: "api.example.com",
                    port: 443,
                    method: "POST",
                    path: "/v1/upload",
                    delivery: Delivery::Completed { bytes },
                    status: Some(200),
                    intercepted: true,
                },
            )?;
        }
        Ok(())
    }
}

fn raw(path: &Path) -> Result<Value> {
    let log = DurableLog::open(path)?;
    let mut records = Vec::new();
    log.scan_from(log.base_offset(), |offset, bytes| {
        records.push(json!([offset, bytes]))
    })?;
    Ok(json!({
        "base":log.base_offset(), "next":log.next_offset(), "records":records,
        "snapshot":log.get_snapshot()?.map(|s|json!([s.up_to_offset,s.payload])),
        "migration":log.get_meta("box.dogwood.migration.v1")?,
        "transition":log.get_meta("box.dogwood.transition.v1")?,
        "sentinel":log.get_meta("test.unknown.metadata")?,
    }))
}
fn entries(path: &Path) -> Result<Vec<PolicyEntry>> {
    let log = DurableLog::open(path)?;
    let snapshot = log
        .get_snapshot()?
        .ok_or("migration did not save a snapshot")?;
    Ok(SnapshotPayload::decode(&snapshot.payload)?
        .bundle
        .policies
        .entries()
        .cloned()
        .collect())
}
fn legacy_checkpoint(path: &Path) -> Result<Value> {
    let output = succeeded(
        Command::new(helper())
            .arg("checkpoint")
            .stdin(Stdio::from(opened(path)?))
            .output()?,
    );
    let result: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(result["protocol"], 1);
    assert_eq!(result["engine_version"], "1.0.0");
    assert_eq!(result["language_version"], "1.0.0");
    let log = DurableLog::open(path)?;
    assert_eq!(log.base_offset(), log.next_offset());
    assert_eq!(log.get_snapshot()?.unwrap().up_to_offset, log.next_offset());
    Ok(result)
}

fn round_trip(duplicates: bool, pruned: bool) -> Result {
    assert!(
        helper().is_file(),
        "build the bundled legacy helper beside strands-box before testing"
    );
    let fixture = Fixture::new(duplicates)?;
    if pruned {
        legacy_checkpoint(&fixture.history)?;
    }
    fixture.convert("1.1.2")?;
    let first = entries(&fixture.history)?;
    assert_eq!(first.len(), if duplicates { 4 } else { 3 });
    // Neither the captured 40 bytes nor the later 70 bytes alone reaches 100.
    fixture.current_decision(Some(70), "Allow")?;
    fixture.current_decision(None, "NoMatch")?;
    fixture.convert("1.0.0")?;
    let reversed = entries(&fixture.history)?;
    assert_eq!(first.len(), reversed.len());
    for (current, old) in first.iter().zip(&reversed) {
        assert_eq!(
            (current.id, &current.token, current.created, current.updated),
            (old.id, &old.token, old.created, old.updated)
        );
    }
    let old = legacy_checkpoint(&fixture.history)?;
    assert_eq!(old["policies"], serde_json::to_value(&reversed)?);
    fixture.convert("1.1.2")?;
    assert_eq!(entries(&fixture.history)?, first);
    fixture.current_decision(None, "NoMatch")?;
    Ok(())
}

#[test]
fn command_preserves_complete_old_history_and_later_activity_in_both_directions() -> Result {
    round_trip(false, false)
}
#[test]
fn command_preserves_pruned_old_history_and_duplicate_rule_identities() -> Result {
    round_trip(true, true)
}
#[test]
fn missing_or_wrong_installed_helper_refuses_before_history_changes() -> Result {
    let fixture = Fixture::new(false)?;
    let installation = fixture.config.parent().unwrap().join("installation");
    fs::create_dir(&installation)?;
    let executable = installation.join("strands-box");
    fs::copy(binary(), &executable)?;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
    let history = fs::read(&fixture.history)?;
    let missing = fixture.command(&executable, "1.1.2", true)?;
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("migration helper"));
    assert_eq!(fs::read(&fixture.history)?, history);
    // A native executable with no migration protocol must never qualify by its magic alone.
    fs::copy("/usr/bin/true", installation.join(HELPER))?;
    fs::set_permissions(installation.join(HELPER), fs::Permissions::from_mode(0o700))?;
    let wrong = fixture.command(&executable, "1.1.2", true)?;
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("validator"));
    assert_eq!(fs::read(&fixture.history)?, history);
    Ok(())
}
