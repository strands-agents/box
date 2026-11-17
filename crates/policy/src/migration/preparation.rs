//! Explicit capture, review, and application of a supported legacy migration.

use std::collections::BTreeMap;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use dogwood_language::ParsedPolicySet;
use dogwood_local_engine::DurableLog;
use serde::Deserialize;

use super::{
    ENGINE_VERSION, FORMAT_VERSION, LEGACY_VERSION, MigrationRecord, OriginalSource,
    PROVENANCE_KEY, RuleBinding, capture, legacy, storage, transition, validator,
};
use crate::{Operator, Policy, PolicyError, ToolGrammars};

/// The stopped history file and its original authored policies and schemas.
///
/// Supply the unchanged files used by the 1.0.0 installation. The migration checks
/// every installed rule against these inputs; it cannot reconstruct missing intent.
/// The caller must stop Box and exclude other writers before opening this file.
pub struct MigrationInput {
    pub(super) history: File,
    pub(super) policies: Vec<Policy>,
    pub(super) grammar_schemas: Vec<String>,
    pub(super) mcp_schemas: Vec<String>,
    pub(super) legacy_validator: Option<File>,
}

impl MigrationInput {
    /// Capture original policy text and an already-open history file.
    pub fn new(history: File, policies: Vec<Policy>) -> Self {
        Self {
            history,
            policies,
            grammar_schemas: Vec::new(),
            mcp_schemas: Vec::new(),
            legacy_validator: None,
        }
    }

    /// Use the checked tool grammars from the stopped Box configuration.
    #[must_use]
    pub fn with_tool_grammars(mut self, grammars: ToolGrammars) -> Self {
        self.grammar_schemas = grammars.schemas();
        self
    }

    /// Hold the trusted, already-open legacy validator shipped with this Box installation.
    #[must_use]
    pub fn with_legacy_validator(mut self, executable: File) -> Self {
        self.legacy_validator = Some(executable);
        self
    }

    /// Include the original tool grammar action schemas, in their installed order.
    #[must_use]
    pub fn with_grammar_schemas(mut self, schemas: Vec<String>) -> Self {
        self.grammar_schemas = schemas;
        self
    }

    /// Include the original discovered MCP action schemas, in their installed order.
    #[must_use]
    pub fn with_mcp_schemas(mut self, schemas: Vec<String>) -> Self {
        self.mcp_schemas = schemas;
        self
    }
}

/// The published Dogwood version that an explicit conversion prepares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationTarget {
    /// Prepare history for the published Dogwood 1.0.0 engine and language.
    Dogwood1_0_0,
    /// Prepare history for the published Dogwood 1.1.2 engine and language.
    Dogwood1_1_2,
}

impl MigrationTarget {
    /// Return the exact published target version.
    pub const fn version(self) -> &'static str {
        match self {
            Self::Dogwood1_0_0 => LEGACY_VERSION,
            Self::Dogwood1_1_2 => ENGINE_VERSION,
        }
    }
}

/// Reviewable counts for the explicit Dogwood 1.0.0 to 1.1.2 migration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MigrationSummary {
    /// The exact source engine version.
    pub from_version: String,
    /// The exact engine version prepared for the next open.
    pub to_version: String,
    /// The directional receipt generation, or zero for the original upgrade.
    pub generation: u64,
    /// Rules selected for retention; after completion, the historical migration count.
    pub preserved_rules: usize,
    /// Distinct saved rule statements that require the supported static syntax correction.
    pub converted_statements: usize,
    /// Retained event and policy-management records in the reviewed source.
    pub history_records: usize,
    /// A matching completed migration was already recorded; apply performs no new write.
    pub already_completed: bool,
}

/// An explicit migration holding the original file and its exclusive database lock.
///
/// Preparing a migration returns no policy authority. Applying it validates private
/// copies and commits the replacement saved state and provenance together. Normal
/// policy opens never call this API or infer legacy equivalence.
pub struct PolicyMigration {
    pub(super) input: MigrationInput,
    pub(super) log: DurableLog,
    pub(super) source_capture: String,
    pub(super) plan: Option<PreparedPlan>,
    pub(super) summary: MigrationSummary,
    pub(super) limits: storage::MigrationLimits,
}

pub(super) enum PreparedPlan {
    Original(storage::MigrationPlan),
    Transition(transition::TransitionPlan),
}

impl std::fmt::Debug for PolicyMigration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PolicyMigration")
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

impl PolicyMigration {
    /// Review a stopped 1.0.0 history against its original policies and schemas.
    ///
    /// Original authored policies must parse and pass Box checks under 1.1.2.
    ///
    /// The database is opened through the retained file descriptor. Database opening
    /// can update its own metadata, but preparation changes no policy or event record.
    /// Refuses unsupported syntax, missing original rules, schema changes, and unsafe
    /// generated-name collisions. The lock remains held until this value is dropped.
    pub fn prepare(input: MigrationInput) -> Result<Self, PolicyError> {
        if !input.history.metadata().map_err(fail)?.is_file() {
            return Err(fail("history must be an already-open regular file"));
        }
        let log = DurableLog::open(descriptor(&input.history)).map_err(fail)?;
        Self::prepare_original(input, log)
    }

    /// Review an explicit version conversion while retaining the stopped history lock.
    pub fn prepare_for(
        input: MigrationInput,
        target: MigrationTarget,
    ) -> Result<Self, PolicyError> {
        if !input.history.metadata().map_err(fail)?.is_file() {
            return Err(fail("history must be an already-open regular file"));
        }
        let helper = input.legacy_validator.as_ref().ok_or_else(|| {
            fail(
                "the installed Dogwood 1.0.0 validator is required for explicit version conversion",
            )
        })?;
        validator::describe(helper)?;
        let log = DurableLog::open(descriptor(&input.history)).map_err(fail)?;
        if target == MigrationTarget::Dogwood1_1_2
            && log.get_meta(PROVENANCE_KEY).map_err(fail)?.is_none()
            && log.get_meta(transition::PHASE_KEY).map_err(fail)?.is_none()
        {
            return Self::prepare_original(input, log);
        }
        transition::prepare(input, log, target)
    }

    fn prepare_original(input: MigrationInput, log: DurableLog) -> Result<Self, PolicyError> {
        if log.get_meta(transition::PHASE_KEY).map_err(fail)?.is_some() {
            return Err(fail(
                "directional history requires prepare_for with its explicit target version",
            ));
        }
        let limits = storage::MigrationLimits::default();
        let originals: Vec<_> = input
            .policies
            .iter()
            .map(|source| OriginalSource {
                origin: source.origin.display().to_string(),
                text: source.text.clone(),
            })
            .collect();
        if let Some(bytes) = log.get_meta(PROVENANCE_KEY).map_err(fail)? {
            let record: MigrationRecord = serde_json::from_slice(&bytes).map_err(fail)?;
            record.validate().map_err(fail)?;
            if record.migrated_from.is_none() {
                return Err(fail(
                    "this history already uses Dogwood 1.1.2 and needs no legacy migration",
                ));
            }
            if record.original_sources != originals
                || record.grammar_schemas != input.grammar_schemas
                || record.mcp_schemas != input.mcp_schemas
            {
                return Err(fail(
                    "history was already migrated with different original inputs; do not repeat migration for a policy edit",
                ));
            }
            let receipt =
                storage::verify_application_receipt(&log, PROVENANCE_KEY, &bytes).map_err(fail)?;
            let summary = MigrationSummary {
                from_version: LEGACY_VERSION.to_owned(),
                to_version: ENGINE_VERSION.to_owned(),
                generation: 0,
                preserved_rules: record.bindings.len(),
                converted_statements: 0,
                history_records: receipt.record_count,
                already_completed: true,
            };
            return Ok(Self {
                input,
                log,
                source_capture: String::new(),
                plan: None,
                summary,
                limits,
            });
        }
        let captured = storage::capture_plan_input(&log, PROVENANCE_KEY, &limits).map_err(fail)?;
        let bundle = capture::installed(&captured)?;
        let service_bytes = captured
            .metadata
            .get("dogwood_server_service_schema")
            .and_then(Option::as_deref)
            .ok_or_else(|| fail("history has no saved event schema"))?;
        let service_config: StoredService = serde_json::from_slice(service_bytes).map_err(fail)?;
        if service_config.event_schema.as_deref() != Some(crate::dogwood::event_schema_source())
            || service_config.macros.is_some()
        {
            return Err(fail(
                "history uses an unsupported event schema or custom macro library",
            ));
        }
        let service = crate::dogwood::service_schema()?;
        let source = crate::policy::authored(&input.policies);
        let (current, effective_schema, _) = crate::dogwood::check_and_expand(
            &source,
            &input.grammar_schemas,
            &input.mcp_schemas,
            &Operator::unanchored(),
            true,
            &[],
        )
        .map_err(|refused| refused.into_error())?;
        if effective_schema.source != bundle.action_schema {
            if input.mcp_schemas.is_empty()
                && !crate::mcp_schema::mcp_schemas_in(
                    &bundle.action_schema,
                    &effective_schema.source,
                )
                .is_empty()
            {
                return Err(fail(
                    "missing original MCP action schemas; provide the original schemas without running discovery during migration",
                ));
            }
            return Err(fail(
                "supplied action schemas differ from the installed schemas; provide the original schema inputs",
            ));
        }
        let parsed = ParsedPolicySet::parse(&source, &service).map_err(fail)?;
        let policies: Vec<_> = parsed.policies().collect();
        if policies.len() != current.len() {
            return Err(fail("authored rule expansion is inconsistent"));
        }
        let old_compiled = input
            .legacy_validator
            .as_ref()
            .map(|helper| {
                validator::compile(
                    helper,
                    &source,
                    crate::dogwood::event_schema_source(),
                    &effective_schema.source,
                )
            })
            .transpose()?;
        if old_compiled
            .as_ref()
            .is_some_and(|statements| statements.len() != current.len())
        {
            return Err(fail(
                "old compiler produced a different authored rule count",
            ));
        }
        let mut converted = BTreeMap::new();
        let mut translations = Vec::new();
        for old in captured.historical_statements().map_err(fail)? {
            let result = legacy::convert_saved_statement(&old, &service).map_err(fail)?;
            if result.statement != old {
                translations.push(storage::StatementTranslation {
                    old: old.clone(),
                    replacement: result.statement.clone(),
                });
            }
            converted.insert(old, result.statement);
        }
        let installed: Vec<_> = bundle.policies.entries().collect();
        let mut used = vec![false; installed.len()];
        let mut bindings = Vec::new();
        for (index, policy) in policies.iter().enumerate() {
            let predicted = legacy::original_statement(
                policy,
                &current[index],
                old_compiled.as_ref().map(|old| old[index].as_str()),
                &service,
            )
            .map_err(fail)?;
            let stored_index = installed.iter().enumerate().find_map(|(stored_index, entry)| {
                (!used[stored_index]
                    && converted.get(&entry.statement).is_some_and(|statement| statement == &predicted))
                    .then_some(stored_index)
            }).ok_or_else(|| fail(format!(
                "original rule {} does not safely match an installed rule; history was not changed", index + 1
            )))?;
            used[stored_index] = true;
            let mut retained = installed[stored_index].clone();
            retained.statement = predicted;
            bindings.push(RuleBinding {
                current_statement: current[index].clone(),
                retained,
            });
        }
        if used.iter().any(|used| !used) {
            return Err(fail(
                "original policies omit installed rules; provide the complete unchanged original inputs before editing policies",
            ));
        }
        let expected_policies = installed
            .into_iter()
            .map(|entry| {
                let mut retained = entry.clone();
                retained.statement = converted[&entry.statement].clone();
                retained
            })
            .collect();
        let record = MigrationRecord {
            format_version: FORMAT_VERSION,
            engine_version: ENGINE_VERSION.to_owned(),
            migrated_from: Some(LEGACY_VERSION.to_owned()),
            original_sources: originals,
            grammar_schemas: input.grammar_schemas.clone(),
            mcp_schemas: input.mcp_schemas.clone(),
            bindings,
        };
        record.validate().map_err(fail)?;
        let bytes = serde_json::to_vec(&record).map_err(fail)?;
        let source_capture = captured.sha();
        let summary = MigrationSummary {
            from_version: LEGACY_VERSION.to_owned(),
            to_version: ENGINE_VERSION.to_owned(),
            generation: 0,
            preserved_rules: record.bindings.len(),
            converted_statements: translations.len(),
            history_records: captured.records.len(),
            already_completed: false,
        };
        let plan = storage::MigrationPlan {
            migration_id: format!("box-dogwood-112-{source_capture}"),
            from_version: LEGACY_VERSION.to_owned(),
            to_version: ENGINE_VERSION.to_owned(),
            provenance: format!(
                "Explicit migration of captured unchanged Box policies and schemas; source capture {source_capture}"
            ),
            translations,
            expected_policies,
            application_metadata_key: PROVENANCE_KEY.to_owned(),
            application_metadata_value: bytes,
        };
        Ok(Self {
            input,
            log,
            source_capture,
            plan: Some(PreparedPlan::Original(plan)),
            summary,
            limits,
        })
    }

    /// Return the reviewed counts. This does not activate the migrated history.
    pub fn summary(&self) -> &MigrationSummary {
        &self.summary
    }

    /// Validate two private copies and atomically activate the migrated history.
    ///
    /// Scratch files must be empty, regular, mode 0600 files with distinct identities
    /// and one hardlink each. Keep the originals stopped until this method returns.
    /// On an ambiguous storage error, retry with the same original inputs; do not
    /// restore an older backup over history that might contain newer activity.
    pub fn apply(
        mut self,
        scratch_prepare: File,
        scratch_validate: File,
    ) -> Result<MigrationSummary, PolicyError> {
        if let Some(PreparedPlan::Transition(plan)) = self.plan.as_ref() {
            transition::apply(
                &mut self.log,
                &self.input,
                plan,
                &scratch_prepare,
                &scratch_validate,
                &self.limits,
            )?;
            return Ok(self.summary);
        }
        let Some(PreparedPlan::Original(plan)) = self.plan.as_ref() else {
            return Ok(self.summary);
        };
        let current =
            storage::capture_plan_input(&self.log, PROVENANCE_KEY, &self.limits).map_err(fail)?;
        if current.sha() != self.source_capture {
            return Err(fail("history changed after migration preparation"));
        }
        storage::migrate(
            &mut self.log,
            &self.input.history,
            &scratch_prepare,
            &scratch_validate,
            plan,
            &self.limits,
        )
        .map_err(|error| {
            let suffix = if error.commit_may_have_happened {
                "; the commit may have completed: retry with the same original inputs"
            } else {
                ""
            };
            fail(format!("{error}{suffix}"))
        })?;
        Ok(self.summary)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredService {
    event_schema: Option<String>,
    macros: Option<String>,
}

fn descriptor(file: &File) -> PathBuf {
    PathBuf::from(format!("/dev/fd/{}", file.as_raw_fd()))
}
fn fail(error: impl std::fmt::Display) -> PolicyError {
    PolicyError::Evaluation(format!("Dogwood migration refused: {error}"))
}
