//! Convert the latest saved state between explicitly approved Dogwood versions.

use dogwood_local_engine::{
    DurableConfig, DurableLog, PolicyEntry, PolicySet, Snapshot, SnapshotPayload, Write,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs::File};

use super::preparation::{
    MigrationInput, MigrationSummary, MigrationTarget, PolicyMigration, PreparedPlan,
};
use super::{
    ENGINE_VERSION, LEGACY_VERSION, MigrationRecord, OriginalSource, PROVENANCE_KEY, capture,
    legacy, storage, validator,
};
use crate::{Operator, PolicyError};

pub(super) const PHASE_KEY: &str = "box.dogwood.transition.v1";
const ARCHIVE_PREFIX: &str = "box.dogwood.transition.receipt.v1.";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    format_version: u32,
    generation: u64,
    from_version: String,
    to_version: String,
    previous_receipt_sha256: String,
    original_migration_sha256: String,
    source_capture_sha256: String,
    source_image_sha256: String,
    helper_sha256: String,
    source_base: u64,
    offset: u64,
    snapshot_sha256: String,
    engine_sha256: String,
    next_id: u64,
    last_ts: i64,
    action_schema: String,
    source_policies: Vec<PolicyEntry>,
    target_policies: Vec<PolicyEntry>,
    original: MigrationRecord,
}

pub(super) struct TransitionPlan {
    source_capture: String,
    predecessor: String,
    original_bytes: Vec<u8>,
    original: MigrationRecord,
    source_version: String,
    target: MigrationTarget,
    generation: u64,
    helper_sha256: String,
    source_policies: Vec<PolicyEntry>,
    target_policies: Vec<PolicyEntry>,
    next_id: u64,
    action_schema: String,
}

fn fail(error: impl std::fmt::Display) -> PolicyError {
    PolicyError::Evaluation(format!("Dogwood version conversion refused: {error}"))
}

fn require(condition: bool, message: &str) -> Result<(), PolicyError> {
    if condition {
        Ok(())
    } else {
        Err(fail(message))
    }
}

fn capture_store(
    log: &DurableLog,
    limits: &storage::MigrationLimits,
) -> Result<storage::CapturedStore, PolicyError> {
    let mut captured = storage::capture_plan_input(log, PROVENANCE_KEY, limits).map_err(fail)?;
    captured
        .metadata
        .insert(PHASE_KEY.to_owned(), log.get_meta(PHASE_KEY).map_err(fail)?);
    Ok(captured)
}

fn same_identity(a: &PolicyEntry, b: &PolicyEntry) -> bool {
    a.id == b.id && a.token == b.token && a.created == b.created && a.updated == b.updated
}

fn archive_key(generation: u64) -> String {
    format!("{ARCHIVE_PREFIX}{generation}")
}

fn decode_receipt(bytes: &[u8], limit: usize) -> Result<Receipt, PolicyError> {
    require(
        bytes.len() <= limit,
        "saved directional receipt exceeds 8 MiB",
    )?;
    let receipt: Receipt = serde_json::from_slice(bytes).map_err(fail)?;
    receipt.original.validate().map_err(fail)?;
    require(
        receipt.original.migrated_from.as_deref() == Some(LEGACY_VERSION),
        "directional receipt has no completed original migration",
    )?;
    for digest in [
        &receipt.previous_receipt_sha256,
        &receipt.original_migration_sha256,
        &receipt.source_capture_sha256,
        &receipt.source_image_sha256,
        &receipt.helper_sha256,
        &receipt.snapshot_sha256,
        &receipt.engine_sha256,
    ] {
        require(
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "directional receipt contains an invalid digest",
        )?;
    }

    require(
        receipt.format_version == 1 && receipt.generation > 0,
        "unsupported directional receipt format",
    )?;
    require(
        matches!(
            (receipt.from_version.as_str(), receipt.to_version.as_str()),
            (ENGINE_VERSION, LEGACY_VERSION) | (LEGACY_VERSION, ENGINE_VERSION)
        ),
        "invalid recorded conversion direction",
    )?;
    require(
        receipt.source_base <= receipt.offset,
        "invalid recorded conversion offsets",
    )?;
    require(
        receipt.source_policies.len() == receipt.target_policies.len()
            && !receipt.target_policies.is_empty(),
        "invalid recorded policy counts",
    )?;
    let mut ids = BTreeSet::new();
    let mut tokens = BTreeSet::new();
    for (source, target) in receipt.source_policies.iter().zip(&receipt.target_policies) {
        require(
            same_identity(source, target)
                && ids.insert(target.id)
                && tokens.insert(target.token.clone())
                && target.id.0 < receipt.next_id
                && !target.statement.trim().is_empty(),
            "invalid recorded target policy identity",
        )?;
    }
    Ok(receipt)
}

fn verify_receipt(log: &DurableLog, bytes: &[u8]) -> Result<Receipt, PolicyError> {
    let receipt = decode_receipt(bytes, storage::MigrationLimits::default().max_plan_bytes)?;
    require(
        log.get_meta(&archive_key(receipt.generation))
            .map_err(fail)?
            .as_deref()
            == Some(bytes),
        "active phase differs from its archived conversion receipt",
    )?;
    if receipt.generation == 1 {
        require(
            receipt.from_version == ENGINE_VERSION,
            "first directional receipt must start from the original completed upgrade",
        )?;
    }
    let predecessor = if receipt.generation == 1 {
        log.get_meta(storage::RECEIPT_KEY).map_err(fail)?
    } else {
        log.get_meta(&archive_key(receipt.generation - 1))
            .map_err(fail)?
    }
    .ok_or_else(|| fail("conversion predecessor receipt is missing"))?;
    require(
        storage::hash(&predecessor) == receipt.previous_receipt_sha256,
        "conversion predecessor receipt differs",
    )?;
    if receipt.generation > 1 {
        let previous = decode_receipt(
            &predecessor,
            storage::MigrationLimits::default().max_plan_bytes,
        )?;
        require(
            previous.generation + 1 == receipt.generation
                && previous.to_version == receipt.from_version
                && previous.original == receipt.original,
            "conversion predecessor phase differs",
        )?;
    }
    let original = log
        .get_meta(PROVENANCE_KEY)
        .map_err(fail)?
        .ok_or_else(|| fail("original migration record is missing"))?;
    require(
        storage::hash(&original) == receipt.original_migration_sha256,
        "original migration provenance differs",
    )?;
    require(
        serde_json::from_slice::<MigrationRecord>(&original).map_err(fail)? == receipt.original,
        "directional and original migration provenance differ",
    )?;
    let snapshot = log
        .get_snapshot()
        .map_err(fail)?
        .ok_or_else(|| fail("converted history has no saved state"))?;
    require(
        receipt.offset <= snapshot.up_to_offset && snapshot.up_to_offset <= log.next_offset(),
        "saved state does not cover the completed conversion",
    )?;
    SnapshotPayload::decode(&snapshot.payload).map_err(fail)?;
    if snapshot.up_to_offset == receipt.offset {
        require(
            storage::SavedSnapshot {
                up_to: snapshot.up_to_offset,
                payload: snapshot.payload,
            }
            .sha()
                == receipt.snapshot_sha256,
            "saved state at the conversion boundary differs from its receipt",
        )?;
    }
    Ok(receipt)
}

pub(super) fn runtime_record(log: &DurableLog) -> Result<Option<MigrationRecord>, PolicyError> {
    let Some(bytes) = log.get_meta(PHASE_KEY).map_err(fail)? else {
        return Ok(None);
    };
    let receipt = verify_receipt(log, &bytes)?;
    require(
        receipt.to_version == ENGINE_VERSION,
        "history was explicitly prepared for Dogwood 1.0.0; run an explicit conversion to 1.1.2 before opening it with this Box",
    )?;
    Ok(Some(receipt.original))
}

pub(super) fn prepare(
    mut input: MigrationInput,
    log: DurableLog,
    target: MigrationTarget,
) -> Result<PolicyMigration, PolicyError> {
    let limits = storage::MigrationLimits::default();
    let original_bytes = log.get_meta(PROVENANCE_KEY).map_err(fail)?.ok_or_else(|| {
        fail("reverse conversion requires a completed, recorded original migration")
    })?;
    require(
        original_bytes.len() <= limits.max_plan_bytes,
        "original migration record exceeds 8 MiB",
    )?;
    let original: MigrationRecord = serde_json::from_slice(&original_bytes).map_err(fail)?;
    original.validate().map_err(fail)?;
    require(
        original.migrated_from.as_deref() == Some(LEGACY_VERSION),
        "this history has no approved 1.0.0 source; new or edited 1.1.2 policies require a separate compatibility review",
    )?;
    let (source_version, generation, predecessor) = match log.get_meta(PHASE_KEY).map_err(fail)? {
        Some(bytes) => {
            let receipt = verify_receipt(&log, &bytes)?;
            require(
                receipt.original == original,
                "original conversion input differs",
            )?;
            (
                receipt.to_version,
                receipt.generation,
                storage::hash(&bytes),
            )
        }
        None => {
            storage::verify_application_receipt(&log, PROVENANCE_KEY, &original_bytes)
                .map_err(fail)?;
            let receipt = log
                .get_meta(storage::RECEIPT_KEY)
                .map_err(fail)?
                .ok_or_else(|| fail("original storage receipt is missing"))?;
            (ENGINE_VERSION.to_owned(), 0, storage::hash(&receipt))
        }
    };
    let supplied: Vec<_> = input
        .policies
        .iter()
        .map(|source| OriginalSource {
            origin: source.origin.display().to_string(),
            text: source.text.clone(),
        })
        .collect();
    if input.mcp_schemas.is_empty() {
        input.mcp_schemas = original.mcp_schemas.clone();
    }
    require(
        supplied == original.original_sources
            && input.grammar_schemas == original.grammar_schemas
            && input.mcp_schemas == original.mcp_schemas,
        "authored policies or schemas changed; explicit version conversion does not reverse legitimate edits",
    )?;
    let captured = capture_store(&log, &limits)?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Service {
        event_schema: Option<String>,
        macros: Option<String>,
    }
    let service_bytes = captured
        .metadata
        .get("dogwood_server_service_schema")
        .and_then(Option::as_deref)
        .ok_or_else(|| fail("saved event schema is missing"))?;
    let service: Service = serde_json::from_slice(service_bytes).map_err(fail)?;
    require(
        service.event_schema.as_deref() == Some(crate::dogwood::event_schema_source())
            && service.macros.is_none(),
        "saved event schema or custom macro library differs from the supported original inputs",
    )?;
    let installed = capture::installed(&captured)?;
    let source = crate::policy::authored(&input.policies);
    let (current, schema, _) = crate::dogwood::check_and_expand(
        &source,
        &input.grammar_schemas,
        &input.mcp_schemas,
        &Operator::unanchored(),
        true,
        &[],
    )
    .map_err(|error| error.into_error())?;
    require(
        schema.source == installed.action_schema,
        "installed action schema differs from the approved original schema",
    )?;
    require(
        current.len() == original.bindings.len()
            && current
                .iter()
                .zip(&original.bindings)
                .all(|(statement, binding)| statement == &binding.current_statement),
        "current authored expansion differs from the approved original migration",
    )?;
    let helper = input
        .legacy_validator
        .as_ref()
        .ok_or_else(|| fail("the installed legacy validator is required"))?;
    let helper_sha256 = validator::describe(helper)?;
    let old = validator::compile(
        helper,
        &source,
        crate::dogwood::event_schema_source(),
        &schema.source,
    )?;
    require(
        old.len() == original.bindings.len(),
        "old compiler produced a different rule count",
    )?;
    let service = crate::dogwood::service_schema()?;
    let mut current_entries = Vec::new();
    let mut old_entries = Vec::new();
    for (old_statement, binding) in old.into_iter().zip(&original.bindings) {
        require(
            legacy::convert_saved_statement(&old_statement, &service)
                .map_err(fail)?
                .statement
                == binding.retained.statement,
            "old compiler output does not equal the approved retained rule after the supported static syntax correction",
        )?;
        let mut old_entry = binding.retained.clone();
        old_entry.statement = old_statement;
        old_entries.push(old_entry);
        current_entries.push(binding.retained.clone());
    }
    current_entries.sort_by_key(|entry| entry.id);
    old_entries.sort_by_key(|entry| entry.id);
    let expected_source = if source_version == LEGACY_VERSION {
        &old_entries
    } else {
        &current_entries
    };
    let actual: Vec<_> = installed.policies.entries().cloned().collect();
    require(
        &actual == expected_source,
        "installed rule identities changed, including edits or delete/re-add; history was not converted",
    )?;
    let expected_target = if target == MigrationTarget::Dogwood1_0_0 {
        old_entries
    } else {
        current_entries
    };
    let next_generation = if source_version == target.version() {
        generation
    } else {
        generation
            .checked_add(1)
            .ok_or_else(|| fail("conversion generation exhausted"))?
    };
    let summary = MigrationSummary {
        from_version: source_version.clone(),
        to_version: target.version().to_owned(),
        generation: next_generation,
        preserved_rules: actual.len(),
        converted_statements: actual
            .iter()
            .zip(&expected_target)
            .filter(|(a, b)| a.statement != b.statement)
            .count(),
        history_records: captured.records.len(),
        already_completed: source_version == target.version(),
    };
    let source_capture = captured.sha();
    let plan = if summary.already_completed {
        None
    } else {
        Some(PreparedPlan::Transition(TransitionPlan {
            source_capture: source_capture.clone(),
            predecessor,
            original_bytes,
            original,
            source_version,
            target,
            generation: next_generation,
            helper_sha256,
            source_policies: actual,
            target_policies: expected_target,
            next_id: installed.policies.next_id(),
            action_schema: installed.action_schema,
        }))
    };
    Ok(PolicyMigration {
        input,
        log,
        source_capture,
        plan,
        summary,
        limits,
    })
}

fn latest_snapshot(
    file: &File,
    expected_offset: u64,
    limits: &storage::MigrationLimits,
) -> Result<Snapshot, PolicyError> {
    let log = storage::scratch_log(file).map_err(fail)?;
    require(
        log.next_offset() == expected_offset,
        "scratch recovery changed the log end",
    )?;
    let snapshot = log
        .get_snapshot()
        .map_err(fail)?
        .ok_or_else(|| fail("scratch recovery produced no saved state"))?;
    require(
        snapshot.up_to_offset == expected_offset
            && snapshot.payload.len() <= limits.max_snapshot_bytes,
        "scratch saved state does not exactly cover the source log end or exceeds 64 MiB",
    )?;
    require(
        file.metadata().map_err(fail)?.len() <= limits.max_image_bytes,
        "scratch image exceeds 1 GiB",
    )?;
    Ok(snapshot)
}

fn check_helper_state(
    state: &validator::State,
    snapshot: &SnapshotPayload,
    offset: u64,
) -> Result<(), PolicyError> {
    require(
        state.offset == offset
            && state.next_id == snapshot.bundle.policies.next_id()
            && state.policies
                == snapshot
                    .bundle
                    .policies
                    .entries()
                    .cloned()
                    .collect::<Vec<_>>()
            && state.action_schema == snapshot.bundle.action_schema
            && state.last_ts == snapshot.last_ts
            && state.engine_sha256 == storage::hash(&snapshot.engine),
        "legacy recovery result differs from its exact saved state",
    )
}

pub(super) fn apply(
    original: &mut DurableLog,
    input: &MigrationInput,
    plan: &TransitionPlan,
    scratch_prepare: &File,
    scratch_validate: &File,
    limits: &storage::MigrationLimits,
) -> Result<(), PolicyError> {
    apply_observed(
        original,
        input,
        plan,
        scratch_prepare,
        scratch_validate,
        limits,
        |_| {},
    )
}

#[derive(Clone, Copy)]
enum CommitBoundary {
    Before,
    After,
}

fn apply_observed(
    original: &mut DurableLog,
    input: &MigrationInput,
    plan: &TransitionPlan,
    scratch_prepare: &File,
    scratch_validate: &File,
    limits: &storage::MigrationLimits,
    mut observe: impl FnMut(CommitBoundary),
) -> Result<(), PolicyError> {
    let source_id = storage::check_files(&input.history, scratch_prepare, scratch_validate, limits)
        .map_err(fail)?;
    let source = capture_store(original, limits)?;
    require(
        source.sha() == plan.source_capture,
        "history changed after conversion preparation",
    )?;
    let helper = input
        .legacy_validator
        .as_ref()
        .ok_or_else(|| fail("the installed legacy validator is missing"))?;
    require(
        validator::describe(helper)? == plan.helper_sha256,
        "installed helper changed after preparation",
    )?;
    let image = storage::copy_image(&input.history, scratch_prepare, limits).map_err(fail)?;
    let copied = storage::scratch_log(scratch_prepare).map_err(fail)?;
    require(
        capture_store(&copied, limits)? == source,
        "source descriptor image does not match the held database",
    )?;
    drop(copied);
    let old_state = if plan.source_version == LEGACY_VERSION {
        Some(validator::recover(helper, scratch_prepare, true)?)
    } else {
        let log = storage::scratch_log(scratch_prepare).map_err(fail)?;
        let mut engine =
            storage::recovered(log, scratch_prepare, DurableConfig::new(0)).map_err(fail)?;
        require(
            engine.has_policy() && engine.list() == plan.source_policies,
            "source recovery changed the approved policy identities",
        )?;
        require(
            engine.checkpoint().map_err(fail)? == source.next,
            "source checkpoint advanced the log",
        )?;
        drop(engine);
        None
    };
    let source_snapshot = latest_snapshot(scratch_prepare, source.next, limits)?;
    let mut payload = SnapshotPayload::decode(&source_snapshot.payload).map_err(fail)?;
    if let Some(state) = old_state.as_ref() {
        check_helper_state(state, &payload, source.next)?;
    }
    require(
        payload
            .bundle
            .policies
            .entries()
            .cloned()
            .collect::<Vec<_>>()
            == plan.source_policies
            && payload.bundle.policies.next_id() == plan.next_id
            && payload.bundle.action_schema == plan.action_schema,
        "latest source checkpoint differs from the approved complete policy set",
    )?;
    let engine = payload.engine.clone();
    let last_ts = payload.last_ts;
    payload.bundle.policies = PolicySet::from_recorded(plan.target_policies.clone(), plan.next_id);
    require(
        payload.engine == engine
            && payload.last_ts == last_ts
            && payload.bundle.action_schema == plan.action_schema,
        "statement conversion changed temporal state",
    )?;
    let target_snapshot = Snapshot {
        up_to_offset: source.next,
        payload: payload.encode().map_err(fail)?,
    };
    require(
        target_snapshot.payload.len() <= limits.max_snapshot_bytes,
        "converted saved state exceeds 64 MiB",
    )?;
    require(
        storage::copy_image(&input.history, scratch_validate, limits).map_err(fail)? == image,
        "source image changed before target validation",
    )?;
    let validation = storage::scratch_log(scratch_validate).map_err(fail)?;
    require(
        capture_store(&validation, limits)? == source,
        "validation descriptor does not match the held source",
    )?;
    validation
        .commit(&[Write::Snapshot(&target_snapshot)])
        .map_err(fail)?;
    while !validation
        .prune_below(source.next, 4096)
        .map_err(fail)?
        .done
    {}
    require(
        validation.base_offset() == source.next && validation.next_offset() == source.next,
        "target validation must recover from the snapshot alone",
    )?;
    drop(validation);
    if plan.target == MigrationTarget::Dogwood1_0_0 {
        let state = validator::recover(helper, scratch_validate, false)?;
        check_helper_state(&state, &payload, source.next)?;
    } else {
        let log = storage::scratch_log(scratch_validate).map_err(fail)?;
        let check =
            storage::recovered(log, scratch_validate, DurableConfig::new(0)).map_err(fail)?;
        require(
            check.has_policy()
                && check.list() == plan.target_policies
                && check.log_offset() == source.next,
            "target snapshot recovery changed the approved state or rule identities",
        )?;
        drop(check);
    }
    let validated = latest_snapshot(scratch_validate, source.next, limits)?;
    require(
        validated.payload == target_snapshot.payload,
        "target validation changed the proposed saved state",
    )?;
    require(
        capture_store(original, limits)? == source
            && storage::identity(&input.history).map_err(fail)? == source_id
            && storage::image_hash(&input.history, limits.max_image_bytes)
                .map_err(fail)?
                .0
                == image,
        "original history changed before publication",
    )?;
    require(
        validator::describe(helper)? == plan.helper_sha256,
        "installed helper changed before publication",
    )?;
    let receipt = Receipt {
        format_version: 1,
        generation: plan.generation,
        from_version: plan.source_version.clone(),
        to_version: plan.target.version().to_owned(),
        previous_receipt_sha256: plan.predecessor.clone(),
        original_migration_sha256: storage::hash(&plan.original_bytes),
        source_capture_sha256: source.sha(),
        source_image_sha256: image,
        helper_sha256: plan.helper_sha256.clone(),
        source_base: source.base,
        offset: source.next,
        snapshot_sha256: storage::SavedSnapshot {
            up_to: source.next,
            payload: target_snapshot.payload.clone(),
        }
        .sha(),
        engine_sha256: storage::hash(&engine),
        next_id: plan.next_id,
        last_ts,
        action_schema: plan.action_schema.clone(),
        source_policies: plan.source_policies.clone(),
        target_policies: plan.target_policies.clone(),
        original: plan.original.clone(),
    };
    let bytes = serde_json::to_vec(&receipt).map_err(fail)?;
    require(
        bytes.len() <= limits.max_plan_bytes,
        "directional receipt exceeds 8 MiB",
    )?;
    let archive = archive_key(plan.generation);
    require(
        original.get_meta(&archive).map_err(fail)?.is_none(),
        "conversion generation already exists",
    )?;
    observe(CommitBoundary::Before);
    original.commit(&[
        Write::Snapshot(&target_snapshot), Write::Meta { key: PHASE_KEY, value: &bytes },
        Write::Meta { key: &archive, value: &bytes },
    ]).map_err(|error| fail(format!("{error}; commit may have completed: retry the same explicit target and original inputs")))?;
    observe(CommitBoundary::After);
    verify_receipt(original, &bytes).map_err(|error| {
        fail(format!(
            "history conversion committed, but receipt verification failed: {error}; retry the same explicit target and original inputs"
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests;
