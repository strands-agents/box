//! Explicit migration preserves captured Dogwood 1.0.0 history and later edit semantics.
//!
//! These fixtures contain captured 1.0.0 records and metadata. The fixture loader
//! shifts only record timestamps into the recent past and replays the complete
//! stream. It uses the production clock and does not manufacture a legacy snapshot.

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use dogwood_local_engine::{DurableLog, DurableTemporalEngine, Record};
use policy::{
    Decision, Delivery, DenyReason, GovernedBox, MigrationInput, Operator, Outcome, Policy,
    PolicyEngine, PolicyMigration, Principal, Request, RequestId, SchemaStage,
};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ORIGINAL: &str = include_str!("fixtures/dogwood_1_0_0/original.dw");
const LEGACY: &str = include_str!("fixtures/dogwood_1_0_0/physical-legacy.dw");
const CHANGED: &str = include_str!("fixtures/dogwood_1_0_0/changed-original.dw");
const STAGED: &str = include_str!("fixtures/dogwood_1_0_0/staged-forbid.dw");
const TOOLS: &str = include_str!("fixtures/dogwood_1_0_0/tools-list.json");
const ORIGINAL_TOOL_SCHEMA: &str =
    include_str!("fixtures/dogwood_1_0_0/alpha-original.cedarschema");

fn sources(text: &str) -> Vec<Policy> {
    vec![Policy {
        origin: PathBuf::from("compatibility-budget.dw"),
        text: text.to_owned(),
    }]
}

#[path = "support/captured_migration.rs"]
mod captured_migration;

struct Case {
    _storage: tempfile::TempDir,
    directory: PathBuf,
    history: PathBuf,
    next_scratch: usize,
}
impl Case {
    fn new(name: &str, staged: bool) -> TestResult<Self> {
        Self::from_seed(
            name,
            if staged {
                "staged-forbid-1.0.0.redb"
            } else {
                "collision-1.0.0.redb"
            },
        )
    }
    fn from_seed(name: &str, seed: &str) -> TestResult<Self> {
        let storage = tempfile::Builder::new().prefix(name).tempdir()?;
        let directory = storage.path().to_path_buf();
        let history = directory.join("history.redb");
        captured_migration::write_fixture(&history, seed)?;
        Ok(Self {
            _storage: storage,
            directory,
            history,
            next_scratch: 0,
        })
    }
    fn file(&self) -> TestResult<File> {
        Ok(OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.history)?)
    }
    fn scratch(&mut self) -> TestResult<File> {
        self.next_scratch += 1;
        let path = self
            .directory
            .join(format!("scratch-{}.redb", self.next_scratch));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        Ok(options.open(path)?)
    }
    fn trace(&self, label: &str, value: Value) -> TestResult {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.directory.join("trace.jsonl"))?;
        serde_json::to_writer(&mut file, &json!({"label":label,"value":value}))?;
        writeln!(file)?;
        Ok(())
    }
    fn migrate(
        &mut self,
        text: &str,
        mcp_schemas: Vec<String>,
        expected_rules: usize,
    ) -> TestResult {
        let before_state = raw_state(&self.history)?;
        let before_bytes = fs::read(&self.history)?;
        let migration = PolicyMigration::prepare(
            MigrationInput::new(self.file()?, sources(text))
                .with_grammar_schemas(Vec::new())
                .with_mcp_schemas(mcp_schemas.clone()),
        )?;
        self.trace(
            "prepared",
            json!({
                "preserved_rules":migration.summary().preserved_rules,
                "converted_statements":migration.summary().converted_statements,
                "already_completed":migration.summary().already_completed,
            }),
        )?;
        assert_eq!(migration.summary().preserved_rules, expected_rules);
        assert_eq!(
            migration.summary().converted_statements,
            0,
            "binder-only fixture needs no static conversion"
        );
        assert!(!migration.summary().already_completed);
        drop(migration);
        let after_state = raw_state(&self.history)?;
        self.trace(
            "prepare-dropped",
            json!({"logical_state_unchanged":before_state == after_state,
            "physical_bytes_unchanged":before_bytes == fs::read(&self.history)?}),
        )?;
        assert!(
            before_state == after_state,
            "prepare changed records, snapshot, offsets, or migration metadata"
        );
        // Reprepare the same inputs after demonstrating the review-only boundary.
        let migration = PolicyMigration::prepare(
            MigrationInput::new(self.file()?, sources(text))
                .with_grammar_schemas(Vec::new())
                .with_mcp_schemas(mcp_schemas),
        )?;
        let applied = migration.apply(self.scratch()?, self.scratch()?)?;
        self.trace("applied", json!({"preserved_rules":applied.preserved_rules,
            "converted_statements":applied.converted_statements,"already_completed":applied.already_completed}))?;
        assert_eq!(applied.preserved_rules, expected_rules);
        Ok(())
    }
    fn refusal(&self, candidate: Vec<Policy>, schemas: Vec<String>) -> TestResult {
        let before_state = raw_state(&self.history)?;
        let before_bytes = fs::read(&self.history)?;
        let result = PolicyMigration::prepare(
            MigrationInput::new(self.file()?, candidate)
                .with_grammar_schemas(Vec::new())
                .with_mcp_schemas(schemas),
        );
        let error = match result {
            Err(error) => error.to_string(),
            Ok(_) => {
                panic!("migration accepted a changed, missing, duplicate, or incomplete input")
            }
        };
        let after_state = raw_state(&self.history)?;
        let unchanged = before_state == after_state;
        self.trace(
            "refused",
            json!({"error":error,"logical_state_unchanged":unchanged,
            "physical_bytes_unchanged":before_bytes == fs::read(&self.history)?}),
        )?;
        assert!(
            unchanged,
            "refused prepare changed records, snapshot, offsets, or migration metadata"
        );
        Ok(())
    }
}

fn raw_state(history: &Path) -> TestResult<Value> {
    let log = DurableLog::open(history)?;
    let mut records = Vec::new();
    log.scan_from(0, |offset, bytes| {
        records.push(json!({"offset":offset,"bytes":bytes.iter().map(|v|format!("{v:02x}")).collect::<String>()}));
    })?;
    let snapshot = log.get_snapshot()?.map(|snapshot| {
        json!({"up_to_offset":snapshot.up_to_offset,
        "payload":snapshot.payload.iter().map(|v|format!("{v:02x}")).collect::<String>()})
    });
    // These keys are read-only observations of the current private format. They
    // are not a public migration API or a way to write provenance from the test.
    let provenance = log.get_meta("box.dogwood.migration.v1")?;
    let service = log.get_meta("dogwood_server_service_schema")?;
    Ok(
        json!({"records":records,"snapshot":snapshot,"base_offset":log.base_offset(),
        "next_offset":log.next_offset(),"provenance":provenance,"service":service}),
    )
}

fn inspect(history: &Path) -> TestResult<Value> {
    let engine = DurableTemporalEngine::open(history, 10_000).map_err(|error| error.to_string())?;
    let rules: Vec<_> = engine.list().into_iter().map(|entry| json!({
        "id":format!("{:?}", entry.id), "token":entry.token.to_string(), "statement":entry.statement,
    })).collect();
    let offset = engine.log_offset();
    drop(engine);
    let log = DurableLog::open(history)?;
    let snapshot = log.get_snapshot()?.map(|snapshot| snapshot.up_to_offset);
    let mut records = Vec::new();
    let mut events = Vec::new();
    let mut decode_error = None;
    log.scan_from(0, |offset, bytes| {
        records.push(json!({"offset":offset,"bytes":bytes.iter().map(|v|format!("{v:02x}")).collect::<String>()}));
        match Record::decode(bytes) {
            Ok(Record::Event(event)) => events.push(json!({"offset":offset,"timestamp":event.timestamp(),
                "kind":event.kind(),"event":dogwood_local_engine::event_to_json(&event)})),
            Ok(_) => (),
            Err(error) => decode_error = Some(error.to_string()),
        }
    })?;
    if let Some(error) = decode_error {
        return Err(error.into());
    }
    Ok(json!({"rules":rules,"offset":offset,"snapshot":snapshot,"records":records,"events":events}))
}
fn assert_prefix(before: &Value, after: &Value) {
    let old = before["records"].as_array().expect("old records");
    let current = after["records"].as_array().expect("new records");
    assert!(
        current.starts_with(old),
        "migration or reload discarded/rewrote the prior record prefix"
    );
}
fn one_token(state: &Value) -> &str {
    assert_eq!(state["rules"].as_array().unwrap().len(), 1);
    state["rules"][0]["token"].as_str().unwrap()
}
fn request() -> Request<'static> {
    Request::Http {
        host: "api.example.com",
        port: 443,
        method: "POST",
        path: "/v1/upload",
        body_bytes: 150,
        intercepted: true,
    }
}
fn decide(engine: &PolicyEngine) -> (Decision, Option<RequestId>) {
    engine.decide(
        &GovernedBox::assigned("dependency-compatibility-probe"),
        &Principal::agent(),
        &request(),
    )
}
fn is_exhausted(decision: &Decision) -> bool {
    matches!(
        decision,
        Decision::Deny {
            reason: DenyReason::NoMatch,
            ..
        }
    )
}

fn record_upload(engine: &PolicyEngine, request_id: &RequestId) -> TestResult {
    engine.record(
        &GovernedBox::assigned("dependency-compatibility-probe"),
        &Principal::agent(),
        request_id,
        &Outcome::Http {
            host: "api.example.com",
            port: 443,
            method: "POST",
            path: "/v1/upload",
            delivery: Delivery::Completed { bytes: 150 },
            status: Some(200),
            intercepted: true,
        },
    )?;
    Ok(())
}

#[test]
fn explicit_upgrade_preserves_denial_across_two_opens_and_unchanged_reload() -> TestResult {
    let mut case = Case::new("upgrade-reopen-reload", false)?;
    let before = inspect(&case.history)?;
    case.trace("before", before.clone())?;
    case.migrate(ORIGINAL, Vec::new(), 1)?;
    for opening in 0..2 {
        let engine = PolicyEngine::open(sources(ORIGINAL), &case.history)?;
        let (decision, id) = decide(&engine);
        assert!(
            is_exhausted(&decision),
            "migration reset the exhausted budget"
        );
        let id = id.ok_or("denied decision has no logged request id")?;
        assert!(id.as_str().parse::<u64>()? >= before["offset"].as_u64().unwrap());
        drop(engine);
        let engine =
            PolicyEngine::open_staged(&Operator::unanchored(), sources(ORIGINAL), &case.history)?;
        assert!(
            is_exhausted(&decide(&engine).0),
            "staged reopen reset the budget"
        );
        engine.reload(&sources(ORIGINAL))?;
        assert!(
            is_exhausted(&decide(&engine).0),
            "unchanged reload reset the exhausted budget"
        );
        drop(engine);
        let after = inspect(&case.history)?;
        assert_eq!(
            before["rules"], after["rules"],
            "unchanged source replaced an installed identity"
        );
        assert_prefix(&before, &after);
        case.trace(&format!("open-{opening}"), after)?;
    }
    Ok(())
}

#[test]
fn completed_migration_is_idempotent() -> TestResult {
    let mut case = Case::new("already-completed", false)?;
    case.migrate(ORIGINAL, Vec::new(), 1)?;
    let before_state = raw_state(&case.history)?;
    let before_bytes = fs::read(&case.history)?;
    let migration = PolicyMigration::prepare(MigrationInput::new(case.file()?, sources(ORIGINAL)))?;
    assert!(migration.summary().already_completed);
    assert_eq!(migration.summary().preserved_rules, 1);
    let summary = migration.apply(case.scratch()?, case.scratch()?)?;
    assert!(summary.already_completed);
    let same = before_state == raw_state(&case.history)?;
    let same_bytes = before_bytes == fs::read(&case.history)?;
    case.trace(
        "idempotent",
        json!({"already_completed":summary.already_completed,"logical_state_unchanged":same,"physical_bytes_unchanged":same_bytes}),
    )?;
    assert!(
        same,
        "reapplying a completed migration changed logical history"
    );
    Ok(())
}

#[test]
fn editing_to_physical_legacy_text_and_back_starts_new_budgets() -> TestResult {
    let mut case = Case::new("logical-edit-physical-edit-back", false)?;
    let original_state = inspect(&case.history)?;
    let original_token = one_token(&original_state).to_owned();
    case.migrate(ORIGINAL, Vec::new(), 1)?;
    let engine =
        PolicyEngine::open_staged(&Operator::unanchored(), sources(ORIGINAL), &case.history)?;
    assert!(is_exhausted(&decide(&engine).0));
    engine.reload(&sources(LEGACY))?;
    assert!(
        decide(&engine).0.is_allow(),
        "C-to-physical-L edit retained C's exhausted history"
    );
    drop(engine);
    let legacy_state = inspect(&case.history)?;
    assert_ne!(one_token(&legacy_state), original_token);
    assert_prefix(&original_state, &legacy_state);
    case.trace("edited-to-physical-legacy", legacy_state.clone())?;
    let legacy_token = one_token(&legacy_state).to_owned();
    let engine =
        PolicyEngine::open_staged(&Operator::unanchored(), sources(LEGACY), &case.history)?;
    engine.reload(&sources(ORIGINAL))?;
    let (decision, id) = decide(&engine);
    assert!(
        decision.is_allow(),
        "editing back resurrected the old exhausted mapping"
    );
    record_upload(
        &engine,
        &id.ok_or("allowed edit-back request has no identifier")?,
    )?;
    assert!(
        is_exhausted(&decide(&engine).0),
        "the edit-back rule did not record its new outcome"
    );
    drop(engine);
    let after = inspect(&case.history)?;
    assert_ne!(one_token(&after), original_token);
    assert_ne!(one_token(&after), legacy_token);
    assert_prefix(&original_state, &after);
    case.trace("edited-back-and-spent", after.clone())?;
    let engine = PolicyEngine::open(sources(ORIGINAL), &case.history)?;
    assert!(
        is_exhausted(&decide(&engine).0),
        "new edit-back history failed on reopen"
    );
    drop(engine);
    assert_eq!(after["rules"], inspect(&case.history)?["rules"]);
    Ok(())
}

#[test]
fn missing_original_refuses_without_live_mutation() -> TestResult {
    Case::new("missing-original", false)?.refusal(Vec::new(), Vec::new())
}
#[test]
fn changed_original_refuses_without_live_mutation() -> TestResult {
    Case::new("changed-original", false)?.refusal(sources(CHANGED), Vec::new())
}
#[test]
fn duplicate_source_correspondence_refuses_without_live_mutation() -> TestResult {
    let mut duplicate = sources(ORIGINAL);
    duplicate.extend(sources(ORIGINAL));
    Case::new("duplicate-source", false)?.refusal(duplicate, Vec::new())
}
#[test]
fn duplicate_authored_rule_ids_refuse_without_live_mutation() -> TestResult {
    Case::new("duplicate-rule-id", false)?.refusal(
        sources(include_str!("fixtures/dogwood_1_0_0/duplicate-id.dw")),
        Vec::new(),
    )
}

fn tool(engine: &PolicyEngine, path: &str) -> Decision {
    engine
        .refine_tool_call(
            &GovernedBox::assigned("dependency-compatibility-probe"),
            &Principal::agent(),
            "alpha",
            "read",
            &json!({"path":path}),
        )
        .0
}
#[test]
fn staged_tool_discovery_keeps_migrated_history_and_typed_constraints() -> TestResult {
    let mut case = Case::new("staged-tools", true)?;
    let before = inspect(&case.history)?;
    let fragment = policy::generate_mcp_schema("alpha", TOOLS)?;
    // Migration needs the captured schema; discovery uses the current generator.
    case.refusal(sources(STAGED), vec![fragment.clone()])?;
    case.migrate(STAGED, vec![ORIGINAL_TOOL_SCHEMA.to_owned()], 3)?;
    let engine =
        PolicyEngine::open_staged(&Operator::unanchored(), sources(STAGED), &case.history)?;
    assert!(
        is_exhausted(&decide(&engine).0),
        "staging reset the known HTTP rule"
    );
    assert!(
        matches!(
            tool(&engine, "/workspace/input"),
            Decision::Deny {
                reason: DenyReason::PolicyPending,
                ..
            }
        ),
        "typed tool ran before its schema staged"
    );
    assert!(
        matches!(
            engine.stage_mcp_schema("alpha", fragment)?,
            SchemaStage::Accepted {
                authority_ready: true
            }
        ),
        "typed schema did not complete authority"
    );
    assert!(engine.finish_mcp_discovery()?.is_empty());
    assert!(tool(&engine, "/workspace/input").is_allow());
    assert!(
        matches!(
            tool(&engine, "/workspace/other"),
            Decision::Deny {
                reason: DenyReason::Forbidden,
                ..
            }
        ),
        "typed path constraint was bypassed"
    );
    assert!(
        is_exhausted(&decide(&engine).0),
        "tool discovery reset HTTP history"
    );
    engine.reload(&sources(STAGED))?;
    assert!(
        is_exhausted(&decide(&engine).0),
        "unchanged staged reload reset HTTP history"
    );
    drop(engine);
    let after = inspect(&case.history)?;
    assert_eq!(
        before["rules"], after["rules"],
        "discovery changed migrated rule identities"
    );
    assert_prefix(&before, &after);
    case.trace("after-discovery-and-reload", after)?;
    Ok(())
}
#[test]
fn missing_typed_schema_refuses_without_live_mutation() -> TestResult {
    Case::new("missing-typed-schema", true)?.refusal(sources(STAGED), Vec::new())
}

#[test]
fn installed_duplicates_keep_distinct_ordered_identities() -> TestResult {
    const DUPLICATES: &str = include_str!("fixtures/dogwood_1_0_0/installed-duplicates.dw");
    let mut case = Case::from_seed("installed-duplicates", "installed-duplicates-1.0.0.redb")?;
    let before = inspect(&case.history)?;
    let rules = before["rules"]
        .as_array()
        .ok_or("missing installed rules")?;
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[1]["statement"], rules[2]["statement"]);
    assert_ne!(rules[1]["token"], rules[2]["token"]);
    case.migrate(DUPLICATES, Vec::new(), 3)?;
    for reopening in 0..2 {
        let engine =
            PolicyEngine::open_staged(&Operator::unanchored(), sources(DUPLICATES), &case.history)?;
        assert!(is_exhausted(&decide(&engine).0));
        engine.reload(&sources(DUPLICATES))?;
        assert!(is_exhausted(&decide(&engine).0));
        drop(engine);
        let after = inspect(&case.history)?;
        assert_eq!(
            before["rules"], after["rules"],
            "duplicate rules changed identity or order"
        );
        assert_prefix(&before, &after);
        case.trace(&format!("duplicate-reopen-{reopening}"), after)?;
    }
    Ok(())
}
