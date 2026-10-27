//! The Dogwood decision engine — history-dependent authorization.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
#[cfg(test)]
use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};
use std::time::Duration;

use dogwood_language::{
    Decision as DogwoodDecision, Event, EventBuilder, LoweredPolicySet, PolicySchema,
    ServiceSchema, Validator, Value,
};
#[cfg(test)]
use dogwood_local_engine::Clock as DurableClock;
use dogwood_local_engine::{
    DurableConfig, DurableError, DurableLog, DurableTemporalEngine, Outcome as DurableOutcome,
    PolicyToken, Verb,
};

use crate::error::{PolicyError, PolicyStagingError};
use crate::outcome::Delivery;
use crate::request::{Principal, Request};
use crate::schema::{
    AGENT_TYPE, ActionIdentity, ActionSchema, GovernedBox, RESOURCE_TYPE, SCHEMA_SRC,
    UNUSED_RESOURCE_ID, action, action_schema, attr,
};
use crate::spelling::{Operator, PolicyWarning};
use crate::{Decision, DenyReason, Outcome, PolicyAttribution, RuleId};

/// The policy engine and pinned language version.
pub(crate) const ENGINE_ID: &str = "dogwood-0.1.0";

/// The action type path for fixed-action outcome events.
const FIXED_ACTION_NAMESPACE: &[&str] = &["Box", "Action"];

/// The event kind that carries a verdict, from the default event schema.
const KIND_REQUEST: &str = "request";
/// The event kind that records an effect that happened or may have happened, and
/// carries no verdict.
const KIND_RESPONSE: &str = "response";
/// The event kind that records a failed effect; history-only, inputs only.
const KIND_ERROR: &str = "error";

impl ActionIdentity {
    fn event_builder(&self, kind: &str) -> EventBuilder {
        match self {
            Self::Fixed { id } => Event::builder_for(FIXED_ACTION_NAMESPACE, id, kind),
            Self::McpTool { namespace, tool } => {
                Event::builder_for(&[namespace, "Action"], tool, kind)
            }
        }
    }
}

/// The field group every input value is written under, matching the schema's
/// `context: { input: … }` shape.
const GROUP_INPUT: &str = "input";
/// The field group an output value is written under, matching `context.output`.
const GROUP_OUTPUT: &str = "output";

/// Events between durable monitor snapshots.
const SNAPSHOT_INTERVAL: u64 = 10_000;

/// One loaded Dogwood policy authority over a single temporal history.
pub(crate) struct DogwoodEngine {
    engine: Mutex<DurableTemporalEngine>,
    rule_ids: HashMap<PolicyToken, RuleId>,
    request_schema: cedar_policy::Schema,
    tool_actions: std::collections::HashSet<cedar_policy::EntityUid>,
    #[cfg(test)]
    fixed_clock: Option<Arc<AtomicI64>>,
}

#[cfg(test)]
const NANOS_PER_SECOND: i64 = 1_000_000_000;

/// A test clock advanced explicitly by [`DogwoodEngine::advance_clock`].
#[cfg(test)]
struct FixedClock {
    now: Arc<AtomicI64>,
}

#[cfg(test)]
impl DurableClock for FixedClock {
    fn now_nanos(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }
}

/// The box's own event-kind contract (`schema/events.dwschema`): the
/// `request`/`response`/`error` convention shared with upstream `dogwood-language`
/// and AgentCore, the default macro library, and no providers.
///
/// The box owns its contract in `schema/events.dwschema` rather than inheriting
/// `ServiceSchema::defaults()`, which insulates it from upstream default-convention
/// drift.
///
/// It declares no pin. A pin scopes temporal history by a context value, and this
/// box's scope is structural: one box, one engine, one history. A rule never names
/// a pin value, so a shared multi-box engine may add one without changing any
/// authored policy. The runtime supplies `Box::Resource::"unused"` for every event.
const EVENTS_DWSCHEMA: &str = include_str!("../schema/events.dwschema");

/// Open durable history at `path`.
fn open_history(path: &Path, config: DurableConfig) -> Result<DurableTemporalEngine, DurableError> {
    let log = DurableLog::open(path).map_err(|error| DurableError::Log(error.to_string()))?;
    recover_history(log, path.to_path_buf(), config, SNAPSHOT_INTERVAL)
}

/// Recover durable history, and checkpoint when the replayed records reach `interval`.
fn recover_history(
    log: DurableLog,
    label: PathBuf,
    config: DurableConfig,
    interval: u64,
) -> Result<DurableTemporalEngine, DurableError> {
    let summarized = log
        .get_snapshot()
        .map_err(|error| DurableError::Log(error.to_string()))?
        .map_or(0, |snapshot| snapshot.up_to_offset);
    let replayed = log.next_offset().saturating_sub(summarized);
    let mut engine = DurableTemporalEngine::open_with_log_config(log, label, config)?;
    if replayed >= interval {
        let _ = engine.checkpoint();
    }
    Ok(engine)
}

/// A path that names the open file itself, so no directory entry is resolved again.
fn opened_file_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/dev/fd/{}", file.as_raw_fd()))
}

fn durable_config() -> DurableConfig {
    DurableConfig::new(SNAPSHOT_INTERVAL).with_max_future_skew(Duration::MAX)
}

fn rule_ids(engine: &DurableTemporalEngine) -> HashMap<PolicyToken, RuleId> {
    engine
        .list()
        .into_iter()
        .enumerate()
        .map(|(index, entry)| (entry.token, RuleId::from_engine(format!("policy_{index}"))))
        .collect()
}

/// The embedded Dogwood event schema source.
pub fn event_schema_source() -> &'static str {
    EVENTS_DWSCHEMA
}

fn service_schema() -> Result<ServiceSchema, PolicyError> {
    ServiceSchema::builder()
        .event_schema_str(EVENTS_DWSCHEMA)
        .build()
        .map_err(|error| PolicyError::Schema(format!("dogwood event schema: {error}")))
}

impl DogwoodEngine {
    /// Open durable history and install authored sources against the shipped schema.
    #[cfg(test)]
    pub(crate) fn open(source: &str, history: &Path) -> Result<Self, PolicyError> {
        Self::open_with_mcp_schemas(source, &[], history, &Operator::unanchored())
            .map(|(engine, _)| engine)
    }

    /// Open durable history and install sources against canonical plus MCP schemas.
    pub(crate) fn open_with_mcp_schemas(
        source: &str,
        mcp_schemas: &[String],
        history: &Path,
        operator: &Operator,
    ) -> Result<(Self, Vec<PolicyWarning>), PolicyError> {
        let (canonical_policies, effective_schema, warnings) =
            validate_and_expand(source, mcp_schemas, operator)?;
        let mut engine = open_history(history, durable_config()).map_err(durable_history_error)?;
        reconcile_policy_set(
            &mut engine,
            &canonical_policies,
            mcp_schemas,
            &effective_schema.source,
        )?;

        Ok((
            Self {
                rule_ids: rule_ids(&engine),
                engine: Mutex::new(engine),
                request_schema: effective_schema.cedar,
                tool_actions: effective_schema.tool_actions,
                #[cfg(test)]
                fixed_clock: None,
            },
            warnings,
        ))
    }

    /// Open durable history without changing its installed authority.
    pub(crate) fn open_for_staging(history: &Path) -> Result<Self, PolicyStagingError> {
        let effective_schema = action_schema(&[])?;
        let engine = open_history(history, durable_config())
            .map_err(|error| PolicyStagingError::Durable(error.to_string()))?;
        Self::from_staging_engine(
            engine,
            effective_schema.cedar,
            effective_schema.tool_actions,
        )
    }

    pub(crate) fn open_for_staging_file(
        history: File,
        label: PathBuf,
    ) -> Result<Self, PolicyStagingError> {
        let effective_schema = action_schema(&[])?;
        let log = DurableLog::open(opened_file_path(&history))
            .map_err(|error| PolicyStagingError::Durable(error.to_string()))?;
        drop(history);
        let engine = recover_history(log, label, durable_config(), SNAPSHOT_INTERVAL)
            .map_err(|error| PolicyStagingError::Durable(error.to_string()))?;
        Self::from_staging_engine(
            engine,
            effective_schema.cedar,
            effective_schema.tool_actions,
        )
    }

    #[cfg(test)]
    pub(crate) fn open_for_staging_with_faults(
        history: &Path,
        faults: Arc<dogwood_local_engine::fault_injection::FaultInjector>,
    ) -> Result<Self, PolicyStagingError> {
        let effective_schema = action_schema(&[])?;
        let config = durable_config().with_fault_injector(faults);
        let engine = open_history(history, config)
            .map_err(|error| PolicyStagingError::Durable(error.to_string()))?;
        Self::from_staging_engine(
            engine,
            effective_schema.cedar,
            effective_schema.tool_actions,
        )
    }

    fn from_staging_engine(
        engine: DurableTemporalEngine,
        request_schema: cedar_policy::Schema,
        tool_actions: std::collections::HashSet<cedar_policy::EntityUid>,
    ) -> Result<Self, PolicyStagingError> {
        if engine.has_policy() && engine.event_schema().as_deref() != Some(EVENTS_DWSCHEMA) {
            return Err(PolicyStagingError::Durable(
                "dogwood history uses a different event schema".to_string(),
            ));
        }

        Ok(Self {
            rule_ids: rule_ids(&engine),
            engine: Mutex::new(engine),
            request_schema,
            tool_actions,
            #[cfg(test)]
            fixed_clock: None,
        })
    }

    pub(crate) fn declares_tool_action(&self, action: &cedar_policy::EntityUid) -> bool {
        self.tool_actions.contains(action)
    }

    /// Parse, lower, and strict-validate sources against canonical plus MCP schemas.
    pub(crate) fn validate_with_mcp_schemas(
        source: &str,
        mcp_schemas: &[String],
        operator: &Operator,
    ) -> Result<Vec<PolicyWarning>, PolicyError> {
        validate_and_expand(source, mcp_schemas, operator).map(|(_, _, warnings)| warnings)
    }

    /// Install a validated staged bundle and its request schema.
    pub(crate) fn commit_staged(
        &mut self,
        canonical_policies: &[String],
        effective_schema: ActionSchema,
    ) -> Result<(), DurableError> {
        let mut engine = self
            .engine
            .lock()
            .map_err(|_| DurableError::Log("dogwood durable engine lock poisoned".to_string()))?;
        reconcile_staged_policy_set(
            &mut engine,
            canonical_policies,
            effective_schema.source.as_str(),
        )?;
        self.rule_ids = rule_ids(&engine);
        drop(engine);
        self.request_schema = effective_schema.cedar;
        self.tool_actions = effective_schema.tool_actions;
        Ok(())
    }

    /// Open with a fault injector on the durable log, for tests that pause the store.
    #[cfg(test)]
    pub(crate) fn open_with_faults(
        source: &str,
        history: &Path,
        faults: Arc<dogwood_local_engine::fault_injection::FaultInjector>,
    ) -> Result<Self, PolicyError> {
        let (canonical_policies, effective_schema, _) =
            validate_and_expand(source, &[], &Operator::unanchored())?;
        let config = durable_config().with_fault_injector(faults);
        let mut engine = open_history(history, config).map_err(durable_history_error)?;
        reconcile_policy_set(
            &mut engine,
            &canonical_policies,
            &[],
            &effective_schema.source,
        )?;

        Ok(Self {
            rule_ids: rule_ids(&engine),
            engine: Mutex::new(engine),
            request_schema: effective_schema.cedar,
            tool_actions: effective_schema.tool_actions,
            fixed_clock: None,
        })
    }

    /// Open with a driven clock, for tests that need to cross a window boundary.
    #[cfg(test)]
    pub(crate) fn open_with_test_clock(
        source: &str,
        history: &Path,
        start_secs: i64,
    ) -> Result<Self, PolicyError> {
        let (canonical_policies, effective_schema, _) =
            validate_and_expand(source, &[], &Operator::unanchored())?;
        let now = Arc::new(AtomicI64::new(start_secs.saturating_mul(NANOS_PER_SECOND)));
        let config = durable_config().with_clock(Box::new(FixedClock {
            now: Arc::clone(&now),
        }));
        let mut engine = open_history(history, config).map_err(durable_history_error)?;
        reconcile_policy_set(
            &mut engine,
            &canonical_policies,
            &[],
            &effective_schema.source,
        )?;

        Ok(Self {
            rule_ids: rule_ids(&engine),
            engine: Mutex::new(engine),
            request_schema: effective_schema.cedar,
            tool_actions: effective_schema.tool_actions,
            fixed_clock: Some(now),
        })
    }

    /// Advance the driven clock by `seconds`.
    #[cfg(test)]
    pub(crate) fn advance_clock(&self, seconds: i64) {
        self.fixed_clock
            .as_ref()
            .expect("advance_clock requires a test clock")
            .fetch_add(seconds.saturating_mul(NANOS_PER_SECOND), Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn poison_scope_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.engine.lock().expect("scope is not yet poisoned");
            panic!("simulated Dogwood scope panic");
        }));
    }

    /// Decide one request at the current point in history.
    #[cfg(test)]
    pub(crate) fn decide(
        &self,
        governed: &GovernedBox,
        principal: &Principal,
        request: &Request<'_>,
    ) -> Decision {
        let identity = ActionIdentity::for_request(request);
        self.decide_with_identity(governed, principal, request, &identity)
    }

    pub(crate) fn decide_with_identity(
        &self,
        governed: &GovernedBox,
        principal: &Principal,
        request: &Request<'_>,
        identity: &ActionIdentity,
    ) -> Decision {
        // Validate the (principal, action, context) tuple against the shipped schema
        // BEFORE deciding.
        //
        // This is load-bearing, and its absence was a real fail-open caught by
        // `tests/engine_differential.rs`: the schema declares `fs:*` and `shell:exec`
        // for the one `Agent` principal, so an out-of-vocabulary request attempting an
        // `fs:*` action is
        // not a request the vocabulary permits. Without this gate a catch-all
        // `permit(principal, action, resource)` matched it and ALLOWED — 32 verdicts
        // where the stateless engine denied. Dogwood's own lowering validates the
        // *policy* against the schema but not the *request*, so the check belongs here.
        //
        // The schema is the single source of truth for both engines, which is why this
        // reuses the same request-construction gate rather than restating the
        // principal/action pairings.
        if let Err(error) =
            crate::schema::to_cedar_request(principal, request, identity, &self.request_schema)
        {
            eprintln!("policy: warn: {error}; denying");
            return Decision::internal_fault();
        }

        match self.submit(|| request_event(governed, principal, request, identity)) {
            Ok(Some(decision)) => decision,
            // A decision-kind event that produced no response, or a poisoned lock:
            // neither is a permit.
            Ok(None) => Decision::internal_fault(),
            Err(error) => {
                eprintln!("policy: warn: {error}; denying");
                Decision::internal_fault()
            }
        }
    }

    /// Submit one completed effect as history.
    pub(crate) fn observe_outcome(
        &self,
        governed: &GovernedBox,
        principal: &Principal,
        outcome: &Outcome<'_>,
    ) -> Result<(), PolicyError> {
        self.submit(|| outcome_event(governed, principal, outcome))
            .map(|_| ())
            .map_err(PolicyError::Evaluation)
    }

    /// Feed one event through the durable engine under the scope lock.
    fn submit(&self, build: impl FnOnce() -> EventBuilder) -> Result<Option<Decision>, String> {
        let mut engine = self
            .engine
            .lock()
            .map_err(|_| "dogwood durable engine lock poisoned".to_string())?;
        let submitted = engine.submit(build()).map_err(|error| error.to_string())?;

        let DurableOutcome::Decision(response) = submitted.outcome else {
            return Ok(None);
        };

        let attribution = response
            .diagnostics()
            .reason()
            .map(|reference| {
                let rule = self
                    .rule_ids
                    .get(&reference.token)
                    .cloned()
                    .ok_or_else(|| "dogwood determining policy is not installed".to_string())?;
                Ok(PolicyAttribution {
                    token: reference.token.to_string(),
                    rule,
                    annotation_id: reference.annotation_id().map(str::to_owned),
                    description: reference.description().map(str::to_owned),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        let mut errors = response.diagnostics().errors().peekable();
        if errors.peek().is_some() {
            let joined = errors.collect::<Vec<_>>().join("; ");
            eprintln!("policy: warn: dogwood evaluation failed: {joined}; denying");
            return Ok(Some(Decision::Deny {
                reason: DenyReason::InternalFault,
                rule: RuleId::default_deny(),
                attribution,
                resource: String::new(),
            }));
        }

        let rule = attribution
            .first()
            .map(|attribution| attribution.rule.clone())
            .unwrap_or_else(RuleId::default_deny);

        Ok(Some(match response.decision() {
            DogwoodDecision::Allow => Decision::Allow {
                rule,
                attribution,
                resource: String::new(),
            },
            DogwoodDecision::Deny => {
                let reason = if attribution.is_empty() {
                    DenyReason::NoMatch
                } else {
                    DenyReason::Forbidden
                };
                Decision::Deny {
                    reason,
                    rule,
                    attribution,
                    resource: String::new(),
                }
            }
        }))
    }

    #[cfg(test)]
    fn log_offset(&self) -> u64 {
        self.engine
            .lock()
            .expect("durable engine lock")
            .log_offset()
    }
}

/// Parse and macro-expand a source bundle without an action schema.
pub(crate) fn parse_policy_source(source: &str) -> Result<Vec<String>, PolicyError> {
    let service = service_schema()?;
    let parsed = dogwood_language::ParsedPolicySet::parse(source, &service)
        .map_err(|error| PolicyError::Parse(format!("dogwood parse: {error}")))?;

    if parsed.policies().any(|policy| policy.uses_providers()) {
        return Err(PolicyError::Parse(
            "dogwood: information providers are not enabled in this build".to_string(),
        ));
    }

    Ok(parsed
        .policies()
        .map(|policy| policy.expanded_source())
        .collect())
}

/// Strict-validate canonical policy statements against an ordered schema set.
pub(crate) fn validate_canonical_policy_set(
    canonical_policies: &[String],
    mcp_schemas: &[String],
    operator: &Operator,
) -> Result<(ActionSchema, Vec<PolicyWarning>), PolicyError> {
    let source = canonical_policies.join("\n");
    validate_and_expand(&source, mcp_schemas, operator)
        .map(|(_, schema, warnings)| (schema, warnings))
}

/// Parse and validate a bundle before the durable engine installs it.
fn validate_and_expand(
    source: &str,
    mcp_schemas: &[String],
    operator: &Operator,
) -> Result<(Vec<String>, crate::schema::ActionSchema, Vec<PolicyWarning>), PolicyError> {
    // Parse the Cedar-side schema here, not on the first decision. The request gate
    // caches it behind a `OnceLock`, so leaving it lazy charged the workload's *first*
    // filesystem call ~1.5ms of schema parsing. Startup is where blocking work
    // belongs; a parse fault also becomes a load error rather than a first-request
    // deny.
    let effective_schema = action_schema(mcp_schemas)?;

    let policy_schema = PolicySchema::from_cedarschema_str(&effective_schema.source)
        .map_err(|error| PolicyError::Schema(format!("dogwood action schema: {error}")))?;

    let service = service_schema()?;
    let parsed = dogwood_language::ParsedPolicySet::parse(source, &service)
        .map_err(|error| PolicyError::Parse(format!("dogwood parse: {error}")))?;

    // An information provider runs a sandboxed script on the decision path. We
    // ship none, and an erroring provider is documented upstream as undefined
    // behaviour, so a policy that uses one is refused at load rather than trusted
    // to fail closed.
    if parsed.policies().any(|policy| policy.uses_providers()) {
        return Err(PolicyError::Parse(
            "dogwood: information providers are not enabled in this build".to_string(),
        ));
    }
    let canonical_policies = parsed
        .policies()
        .map(|policy| policy.expanded_source())
        .collect::<Vec<_>>();
    let lowered: LoweredPolicySet = parsed
        .lower(&policy_schema)
        .map_err(|error| PolicyError::Schema(format!("dogwood lower: {error}")))?;
    refuse_shared_rule_ids(&lowered)?;
    refuse_reserved_action_rules(&lowered)?;
    let cap_warnings = crate::cap::judge(&parsed, &lowered)?;

    // Strict schema validation, and it is load-bearing: `lower` alone accepts a
    // typo'd action (`Box::Action::"fs:raed"`) and an undeclared context attribute, which
    // would then match nothing at decision time — a silent no-match that reads as
    // "the rule did not apply" instead of "the rule is wrong". Aborting here is what
    // keeps an authoring mistake from becoming a permanent hole.
    let validation = Validator::new().validate(&lowered);
    if !validation.validation_passed() {
        let errors = validation
            .validation_errors()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let joined = errors.join("; ");
        // An unrecognized action keeps its own variant. It is the single most likely
        // authoring mistake (a typo in a verb) and the one whose silent-no-match
        // failure mode this crate names explicitly, so a caller can report it as
        // "you named an action that does not exist" rather than a generic schema
        // fault.
        if errors
            .iter()
            .any(|error| error.contains("unrecognized action"))
        {
            return Err(PolicyError::UnknownAction(joined));
        }
        return Err(PolicyError::Schema(joined));
    }

    let warnings = crate::spelling::judge(lowered.as_cedar(), operator)?
        .into_iter()
        .chain(cap_warnings)
        .collect();

    Ok((canonical_policies, effective_schema, warnings))
}

/// Refuse a bundle in which two rules carry one non-blank `@id`.
fn refuse_shared_rule_ids(lowered: &LoweredPolicySet) -> Result<(), PolicyError> {
    let cedar = lowered.as_cedar();
    let mut rules_by_id: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for rule in lowered.rules() {
        let policy_id = rule
            .cedar_policy_id
            .parse::<cedar_policy::PolicyId>()
            .map_err(|error| PolicyError::Schema(format!("dogwood rule id: {error}")))?;
        match cedar.annotation(&policy_id, "id") {
            Some(id) if !id.trim().is_empty() => rules_by_id
                .entry(id)
                .or_default()
                .push(rule.rule_index.saturating_add(1)),
            _ => {}
        }
    }
    let shared: Vec<String> = rules_by_id
        .into_iter()
        .filter(|(_, rules)| rules.len() > 1)
        .map(|(id, rules)| {
            let positions = rules
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            format!("@id(\"{id}\") is on rules {positions}")
        })
        .collect();
    if shared.is_empty() {
        return Ok(());
    }
    Err(PolicyError::SharedRuleId(format!(
        "{}; a denial and a telemetry record name a rule by its @id, so give each rule its own @id",
        shared.join("; ")
    )))
}

/// Refuse a bundle in which a rule's scope is only the reserved `fs:other`.
fn refuse_reserved_action_rules(lowered: &LoweredPolicySet) -> Result<(), PolicyError> {
    let cedar = lowered.as_cedar();
    let mut inert = Vec::new();
    for rule in lowered.rules() {
        let policy_id = rule
            .cedar_policy_id
            .parse::<cedar_policy::PolicyId>()
            .map_err(|error| PolicyError::Schema(format!("dogwood rule id: {error}")))?;
        if let Some(policy) = cedar.policy(&policy_id)
            && crate::spelling::names_only_reserved_action(policy)
        {
            inert.push(format!(
                "{} (rule {}) names only the reserved action \"{}\"",
                crate::spelling::rule_name(policy),
                rule.rule_index.saturating_add(1),
                action::FS_OTHER
            ));
        }
    }
    if inert.is_empty() {
        return Ok(());
    }
    Err(PolicyError::ReservedAction(format!(
        "{}; no operation raises it, so the rule cannot match; name fs:read, fs:write, \
         fs:delete, or fs:move, alone or beside fs:other",
        inert.join("; ")
    )))
}

fn reconcile_staged_policy_set(
    engine: &mut DurableTemporalEngine,
    canonical_policies: &[String],
    effective_schema: &str,
) -> Result<(), DurableError> {
    let source = canonical_policies.join("\n");
    if !engine.has_policy() {
        engine
            .install(&source, effective_schema, Some(EVENTS_DWSCHEMA), None)
            .map(|_| ())?;
        return Ok(());
    }

    if engine.event_schema().as_deref() != Some(EVENTS_DWSCHEMA) {
        return Err(DurableError::Log(
            "dogwood history uses a different event schema".to_string(),
        ));
    }

    let (additions, mut changes) = policy_set_change_parts(engine, canonical_policies);
    if engine.action_schema().as_deref() != Some(effective_schema) {
        changes.push(Verb::SetActionSchema {
            action_schema: effective_schema.to_string(),
        });
    }
    changes.extend(additions);
    engine.batch(changes).map(|_| ())
}

/// The policy source a fresh store installs before the authored set is reconciled onto it.
const EMPTY_POLICY_SOURCE: &str = "";

fn reconcile_policy_set(
    engine: &mut DurableTemporalEngine,
    canonical_policies: &[String],
    mcp_schemas: &[String],
    effective_schema: &str,
) -> Result<(), PolicyError> {
    let installed = !engine.has_policy();
    if installed {
        engine
            .install(EMPTY_POLICY_SOURCE, SCHEMA_SRC, Some(EVENTS_DWSCHEMA), None)
            .map_err(durable_history_error)?;
    }

    if engine.event_schema().as_deref() != Some(EVENTS_DWSCHEMA) {
        return Err(PolicyError::Schema(
            "dogwood history uses a different event schema".to_string(),
        ));
    }

    let mut changes = Vec::new();
    if engine.action_schema().as_deref() != Some(effective_schema) {
        if !installed {
            changes.push(Verb::SetActionSchema {
                action_schema: SCHEMA_SRC.to_string(),
            });
        }
        changes.extend(
            mcp_schemas
                .iter()
                .cloned()
                .map(|fragment| Verb::AppendActionSchema { fragment }),
        );
    }
    changes.extend(policy_set_changes(engine, canonical_policies));
    if !changes.is_empty() {
        engine.batch(changes).map_err(durable_history_error)?;
    }

    Ok(())
}

fn policy_set_changes(engine: &DurableTemporalEngine, canonical_policies: &[String]) -> Vec<Verb> {
    let (mut additions, deletions) = policy_set_change_parts(engine, canonical_policies);
    additions.extend(deletions);
    additions
}

fn policy_set_change_parts(
    engine: &DurableTemporalEngine,
    canonical_policies: &[String],
) -> (Vec<Verb>, Vec<Verb>) {
    let existing = engine.list();
    let mut retained = vec![false; existing.len()];
    let mut additions = Vec::new();

    for policy in canonical_policies {
        match existing
            .iter()
            .enumerate()
            .find(|(index, entry)| !retained[*index] && entry.statement == *policy)
        {
            Some((index, _)) => retained[index] = true,
            None => additions.push(Verb::Add {
                policy: policy.clone(),
            }),
        }
    }

    let deletions = existing
        .into_iter()
        .enumerate()
        .filter(|(index, _)| !retained[*index])
        .map(|(_, entry)| Verb::Delete { id: entry.token })
        .collect();

    (additions, deletions)
}

fn durable_history_error(error: DurableError) -> PolicyError {
    PolicyError::Evaluation(error.to_string())
}

/// Build the decision-kind event for one request.
fn request_event(
    governed: &GovernedBox,
    principal: &Principal,
    request: &Request<'_>,
    identity: &ActionIdentity,
) -> EventBuilder {
    let builder = identity.event_builder(KIND_REQUEST);
    // A per-tool `tools/call` carries its raw JSON arguments. Type them into the `input`
    // group so a temporal rule can read `context.input.<arg>`; the typing mirrors the Cedar context
    // built in `schema::context_for`. Every other request uses the fixed-vocabulary fields.
    if let Request::McpCall {
        arguments: Some(arguments),
        ..
    } = request
    {
        return with_input(builder, json_value(arguments));
    }
    with_fields(builder, governed, principal, request_fields(request))
}

/// Set the principal/resource and write `input` to both bags, for a request whose context is a raw
/// JSON record rather than the fixed vocabulary.
fn with_input(mut builder: EventBuilder, input: Value) -> EventBuilder {
    builder = builder
        .principal_for(AGENT_TYPE, crate::request::DEFAULT_PRINCIPAL_ID)
        .resource_for(RESOURCE_TYPE, UNUSED_RESOURCE_ID);
    builder
        .logged_field(GROUP_INPUT, input.clone())
        .request_context_field(GROUP_INPUT, input)
}

/// A `serde_json::Value` as a dogwood `Value`, matching Cedar's JSON typing. An integer maps to
/// `Int`; a non-integer number keeps its text as a `Decimal`, since dogwood has no float.
fn json_value(value: &serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(value) => Value::Bool(*value),
        serde_json::Value::Number(value) => value
            .as_i64()
            .map_or_else(|| Value::Decimal(value.to_string()), Value::Int),
        serde_json::Value::String(value) => Value::String(value.clone()),
        serde_json::Value::Array(values) => Value::Array(values.iter().map(json_value).collect()),
        serde_json::Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(name, value)| (name.clone(), json_value(value)))
                .collect(),
        ),
    }
}

/// Build the history-kind event for one observed effect: a `response` when the
/// effect happened, an `error` when it did not.
fn outcome_event(
    governed: &GovernedBox,
    principal: &Principal,
    outcome: &Outcome<'_>,
) -> EventBuilder {
    let action = outcome_action_id(outcome);
    let builder = Event::builder_for(FIXED_ACTION_NAMESPACE, action, outcome_kind(outcome));
    let builder = with_fields(builder, governed, principal, outcome_fields(outcome));
    with_output_fields(builder, output_fields(outcome))
}

/// `response` when the effect happened or may have happened; `error` when it did
/// not. Counting the uncertain as a `response` keeps a rate limit sound on exactly
/// the error paths an attacker aims for; a rule counting certain completions
/// excludes the guess on `output.result` instead.
///
/// A non-zero exit status is still a `response`: the command ran, and its status is
/// the workload's outcome, not a mediation failure.
fn outcome_kind(outcome: &Outcome<'_>) -> &'static str {
    match outcome {
        Outcome::Connect { connected, .. } => {
            if *connected {
                KIND_RESPONSE
            } else {
                KIND_ERROR
            }
        }
        Outcome::Http { delivery, .. } => {
            if matches!(delivery, Delivery::Failed) {
                KIND_ERROR
            } else {
                KIND_RESPONSE
            }
        }
        Outcome::ShellRun { .. } | Outcome::ShellSpawn { .. } => KIND_RESPONSE,
        Outcome::Fs { result, .. } => {
            if result.response_result().is_some() {
                KIND_RESPONSE
            } else {
                KIND_ERROR
            }
        }
        // A completed call is a `response`, whatever the server replied — a JSON-RPC error is still
        // `::response`, exactly as `ShellRun` is always a `response` regardless of exit status and a
        // delivered `Http` request is a `response` regardless of a 500. A call that never completes
        // records nothing, so there is no MCP `::error` producer.
        Outcome::Mcp { .. } => KIND_RESPONSE,
    }
}

/// Attach every output field to both bags, under the `output` group.
fn with_output_fields(
    mut builder: EventBuilder,
    fields: Vec<(&'static str, Value)>,
) -> EventBuilder {
    for (name, value) in fields {
        builder = builder
            .field(GROUP_OUTPUT, name, value.clone())
            .request_context(GROUP_OUTPUT, name, value);
    }
    builder
}

/// Attach the fixed policy identities and every input field to both bags.
fn with_fields(
    mut builder: EventBuilder,
    _governed: &GovernedBox,
    _principal: &Principal,
    fields: Vec<(&'static str, Value)>,
) -> EventBuilder {
    builder = builder
        .principal_for(AGENT_TYPE, crate::request::DEFAULT_PRINCIPAL_ID)
        .resource_for(RESOURCE_TYPE, UNUSED_RESOURCE_ID);
    for (name, value) in fields {
        builder = builder
            .field(GROUP_INPUT, name, value.clone())
            .request_context(GROUP_INPUT, name, value);
    }
    builder
}

/// The action id whose `response` or `error` an outcome records — the same verb as
/// the request it completes, so a rule correlates the two by action.
fn outcome_action_id(outcome: &Outcome<'_>) -> &'static str {
    match outcome {
        Outcome::Connect { .. } => action::NET_CONNECT,
        Outcome::Http { .. } => action::HTTP_REQUEST,
        Outcome::ShellRun { .. } => action::SHELL_EXEC,
        Outcome::ShellSpawn { .. } => action::SHELL_SPAWN,
        // The response names the SAME coarse action as the request, so a rule joining
        // `mcp:call::request` to `mcp:call::response` cannot name two actions.
        Outcome::Mcp { .. } => action::MCP_CALL,
        // The same granular action as the request, via the one shared mapping, so a
        // `::request`/`::response` pair a rule joins on cannot name two actions.
        Outcome::Fs { operation, .. } => crate::schema::fs_action_id(*operation),
    }
}

/// The operation entity value for one kernel verb, mirroring the Cedar mapping's
/// `fs_operation_expr` so the two bags carry one representation.
fn fs_operation_value(operation: crate::request::FsOperation) -> Value {
    let (entity_type, verb) = crate::schema::fs_operation_entity(operation);
    Value::Entity {
        ty: entity_type.to_string(),
        id: verb.to_string(),
    }
}

/// The `input` fields of a request event. Same names and types the Cedar mapping
/// writes, since both are checked against one schema.
fn request_fields(request: &Request<'_>) -> Vec<(&'static str, Value)> {
    match request {
        Request::Fs {
            path, operation, ..
        } => {
            vec![
                (attr::PATH, Value::String(path.reported().into_owned())),
                (attr::OPERATION, fs_operation_value(*operation)),
            ]
        }
        Request::Connect { host, ip, port } => {
            let mut fields = vec![
                (attr::HOST, Value::String((*host).to_string())),
                (attr::PORT, Value::Int(i64::from(*port))),
            ];
            if let Some(ip) = ip {
                fields.push((attr::IP, Value::String(crate::address::canonical(*ip))));
            }
            fields
        }
        Request::Http {
            host,
            port,
            method,
            path,
            body_bytes,
            intercepted,
        } => vec![
            (attr::HOST, Value::String((*host).to_string())),
            (attr::PORT, Value::Int(i64::from(*port))),
            (attr::METHOD, Value::String((*method).to_string())),
            (attr::PATH, Value::String((*path).to_string())),
            (attr::BODY_BYTES, Value::Int(clamp(*body_bytes))),
            (attr::INTERCEPTED, Value::Bool(*intercepted)),
        ],
        Request::McpCall {
            server,
            method,
            tool,
            prompt,
            uri,
            ..
        } => {
            // The coarse `mcp:call` fields (`arguments: None`). A per-tool `tools/call`
            // (`arguments: Some`) is handled in `request_event` via the raw JSON input group.
            let mut fields = vec![
                (attr::SERVER, Value::String((*server).to_string())),
                (attr::METHOD, Value::String((*method).to_string())),
            ];
            for (name, value) in [(attr::TOOL, tool), (attr::PROMPT, prompt), (attr::URI, uri)] {
                if let Some(value) = value {
                    fields.push((name, Value::String((*value).to_string())));
                }
            }
            fields
        }
        Request::ShellExec {
            command,
            program,
            args,
            cwd,
        } => {
            let mut fields = vec![
                (attr::COMMAND, Value::String((*command).to_string())),
                (attr::PROGRAM, Value::String((*program).to_string())),
                (attr::CWD, Value::String((*cwd).to_string())),
            ];
            fields.extend(argument_fields(args));
            fields
        }
        Request::ShellSpawn {
            command,
            program,
            program_path,
            credential_reads,
            args,
            cwd,
        } => {
            let mut fields = vec![
                (attr::COMMAND, Value::String((*command).to_string())),
                (attr::PROGRAM, Value::String((*program).to_string())),
                (
                    attr::PROGRAM_PATH,
                    Value::String((*program_path).to_string()),
                ),
                (attr::CWD, Value::String((*cwd).to_string())),
            ];
            fields.extend(credential_read_fields(credential_reads));
            fields.extend(argument_fields(args));
            fields
        }
    }
}

/// The argument fields, mirroring [`crate::schema`]'s Cedar mapping exactly.
///
/// The two mappings are checked against one schema, so a field present in one and absent
/// from the other is a load error rather than a silent divergence — but the *optionality*
/// is not checked that way. `arg1` present here and absent there would leave a temporal
/// predicate matching where the stateless condition did not, so both sides push a
/// position only when the argument exists.
fn argument_fields(args: &[String]) -> Vec<(&'static str, Value)> {
    let mut fields = vec![(attr::ARG_COUNT, Value::Int(crate::request::arg_count(args)))];
    for (name, value) in [(attr::ARG1, args.first()), (attr::ARG2, args.get(1))] {
        if let Some(value) = value {
            fields.push((name, Value::String(value.clone())));
        }
    }
    fields
}

fn credential_read_fields(paths: &[String]) -> Vec<(&'static str, Value)> {
    if paths.is_empty() {
        Vec::new()
    } else {
        vec![(
            attr::CREDENTIAL_READS,
            Value::Array(paths.iter().cloned().map(Value::String).collect()),
        )]
    }
}

/// The `input` fields of a response or error event.
fn outcome_fields(outcome: &Outcome<'_>) -> Vec<(&'static str, Value)> {
    match outcome {
        // Only schema-declared fields may appear; a field the schema does not know is
        // a hard load error. Whether the socket opened is carried by the event KIND
        // (`response` vs `error`), so the fields record the attempt's identity.
        Outcome::Connect { host, port, .. } => vec![
            (attr::HOST, Value::String((*host).to_string())),
            (attr::PORT, Value::Int(i64::from(*port))),
        ],
        Outcome::Http {
            host,
            port,
            method,
            path,
            delivery,
            ..
        } => vec![
            (attr::HOST, Value::String((*host).to_string())),
            (attr::PORT, Value::Int(i64::from(*port))),
            (attr::METHOD, Value::String((*method).to_string())),
            (attr::PATH, Value::String((*path).to_string())),
            // The DELIVERED count, carried on the schema's `body_bytes`. A budget rule
            // sums this, so it must be what left the box, not what was offered.
            (
                attr::BODY_BYTES,
                Value::Int(clamp(delivery.accepted_bytes())),
            ),
            (attr::INTERCEPTED, Value::Bool(true)),
        ],
        Outcome::ShellRun {
            command,
            program,
            args,
            cwd,
            ..
        } => {
            let mut fields = vec![
                (attr::COMMAND, Value::String((*command).to_string())),
                (attr::PROGRAM, Value::String((*program).to_string())),
                (attr::CWD, Value::String((*cwd).to_string())),
            ];
            fields.extend(argument_fields(args));
            fields
        }
        Outcome::ShellSpawn {
            command,
            program,
            program_path,
            credential_reads,
            args,
            cwd,
            ..
        } => {
            let mut fields = vec![
                (attr::COMMAND, Value::String((*command).to_string())),
                (attr::PROGRAM, Value::String((*program).to_string())),
                (
                    attr::PROGRAM_PATH,
                    Value::String((*program_path).to_string()),
                ),
                (attr::CWD, Value::String((*cwd).to_string())),
            ];
            fields.extend(credential_read_fields(credential_reads));
            fields.extend(argument_fields(args));
            fields
        }
        Outcome::Fs {
            path, operation, ..
        } => vec![
            (
                attr::PATH,
                Value::String(path.to_string_lossy().into_owned()),
            ),
            (attr::OPERATION, fs_operation_value(*operation)),
        ],
        // The same `McpCallInput` fields the request carried (`server`/`method`, and the per-item
        // identity — `tool`/`prompt`/`uri` — when the method names one), so a temporal rule joins the
        // request and response legs on any of them, exactly as the request leg emits them.
        Outcome::Mcp {
            server,
            method,
            tool,
            prompt,
            uri,
            ..
        } => {
            let mut fields = vec![
                (attr::SERVER, Value::String((*server).to_string())),
                (attr::METHOD, Value::String((*method).to_string())),
            ];
            for (name, value) in [(attr::TOOL, tool), (attr::PROMPT, prompt), (attr::URI, uri)] {
                if let Some(value) = value {
                    fields.push((name, Value::String((*value).to_string())));
                }
            }
            fields
        }
    }
}

/// The `output` fields of a response event: `result` on every filesystem response,
/// `status` on an HTTP response whose reply arrived, and `status` on every shell response.
fn output_fields(outcome: &Outcome<'_>) -> Vec<(&'static str, Value)> {
    match outcome {
        Outcome::Fs { result, .. } => match result.response_result() {
            Some(id) => vec![(
                attr::RESULT,
                Value::Entity {
                    ty: crate::schema::FS_RESPONSE_RESULT_TYPE.to_string(),
                    id: id.to_string(),
                },
            )],
            None => Vec::new(),
        },
        Outcome::Http {
            status: Some(status),
            ..
        } => vec![(attr::STATUS, Value::Int(i64::from(*status)))],
        Outcome::ShellRun { status, .. } | Outcome::ShellSpawn { status, .. } => {
            vec![(attr::STATUS, Value::Int(i64::from(*status)))]
        }
        _ => Vec::new(),
    }
}

/// Narrow a byte count to Cedar's `Long`, saturating rather than wrapping.
fn clamp(bytes: usize) -> i64 {
    i64::try_from(bytes).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::ops::Deref;
    use std::time::Duration;

    use dogwood_local_engine::fault_injection::{FaultInjector, FaultPoint};
    use dogwood_local_engine::{DurableLog, Record};

    use super::*;

    const BUDGET: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
when temporal {
    exists (total: Long). (
        (sum b for (b: Long), (t: Timepoint). where (
            formerly within 60s (
                Box::Action::"http:request"::response{ input.host: _, input.body_bytes: b } && tp(t)
            )
        )) == total
        && total < 100
    )
};
"#;

    /// Integration metadata for the engine under test.
    fn governed() -> GovernedBox {
        GovernedBox::assigned("test-box")
    }

    struct EngineFixture {
        authority: DogwoodEngine,
        _history: tempfile::TempDir,
    }

    impl Deref for EngineFixture {
        type Target = DogwoodEngine;

        fn deref(&self) -> &Self::Target {
            &self.authority
        }
    }

    fn engine() -> EngineFixture {
        let history = tempfile::tempdir().expect("history directory");
        let authority = DogwoodEngine::open(BUDGET, &history.path().join("dogwood.redb"))
            .expect("policy loads");
        EngineFixture {
            authority,
            _history: history,
        }
    }

    #[test]
    fn staged_open_reports_an_incompatible_history_schema_as_durable() {
        let history = tempfile::tempdir().expect("history directory");
        let path = history.path().join("dogwood.redb");
        {
            let mut durable =
                DurableTemporalEngine::open(&path, SNAPSHOT_INTERVAL).expect("history opens");
            durable
                .install(
                    r#"permit(principal, action == Box::Action::"shell:exec", resource);"#,
                    SCHEMA_SRC,
                    None,
                    None,
                )
                .expect("history installs with the default event schema");
        }

        let error = match DogwoodEngine::open_for_staging(&path) {
            Ok(_) => panic!("staged open must reject the incompatible history schema"),
            Err(error) => error,
        };
        assert!(
            matches!(
                error,
                PolicyStagingError::Durable(ref reason)
                    if reason.contains("different event schema")
            ),
            "incompatible durable configuration must remain a durable error: {error:?}"
        );
    }

    fn engine_with_clock(start_secs: i64) -> EngineFixture {
        let history = tempfile::tempdir().expect("history directory");
        let authority = DogwoodEngine::open_with_test_clock(
            BUDGET,
            &history.path().join("dogwood.redb"),
            start_secs,
        )
        .expect("policy loads");
        EngineFixture {
            authority,
            _history: history,
        }
    }

    #[test]
    fn every_determining_policy_keeps_its_token_and_raw_annotations() {
        for effect in ["permit", "forbid"] {
            let history = tempfile::tempdir().expect("history directory");
            let source = format!(
                r#"
                @id("first") @description(" first\n\tline ")
                {effect}(principal, action, resource);
                @id("second") @description("second")
                {effect}(principal, action, resource);
                @id("") @description("")
                {effect}(principal, action, resource);
                {effect}(principal, action, resource);
                "#
            );
            let authority = DogwoodEngine::open(&source, &history.path().join("dogwood.redb"))
                .expect("policy loads");
            let tokens: Vec<_> = authority
                .engine
                .lock()
                .expect("engine")
                .list()
                .into_iter()
                .map(|entry| entry.token.to_string())
                .collect();
            let offset = authority.log_offset();
            let decision = authority.decide(&governed(), &Principal::agent(), &http());
            assert_eq!(authority.log_offset(), offset + 1);
            assert_eq!(decision.is_allow(), effect == "permit");
            let rule = match &decision {
                Decision::Allow { rule, .. } => rule,
                Decision::Deny { reason, rule, .. } => {
                    assert_eq!(*reason, DenyReason::Forbidden);
                    rule
                }
            };
            assert_eq!(rule, &decision.attribution()[0].rule);
            let mut attribution = decision.attribution().to_vec();
            attribution.sort_by(|left, right| left.rule.as_str().cmp(right.rule.as_str()));
            let expected: Vec<_> = [
                (Some("first"), Some(" first\n\tline ")),
                (Some("second"), Some("second")),
                (Some(""), Some("")),
                (None, None),
            ]
            .into_iter()
            .enumerate()
            .map(|(index, (id, description))| PolicyAttribution {
                token: tokens[index].clone(),
                rule: RuleId::from_engine(format!("policy_{index}")),
                annotation_id: id.map(str::to_owned),
                description: description.map(str::to_owned),
            })
            .collect();
            assert_eq!(attribution, expected);
        }
    }

    #[test]
    fn an_evaluation_fault_keeps_attribution_and_appends_once() {
        for effect in ["permit", "forbid", ""] {
            let history = tempfile::tempdir().expect("history directory");
            let determining = if effect.is_empty() {
                String::new()
            } else {
                format!(
                    r#"@id("context") @description("diagnostic")
                    {effect}(principal, action, resource);"#
                )
            };
            let source = format!(
                r#"{determining}
                forbid(principal, action, resource)
                when {{ 9223372036854775807 + 1 > 0 }};"#
            );
            let authority = DogwoodEngine::open(&source, &history.path().join("dogwood.redb"))
                .expect("policy loads");
            let offset = authority.log_offset();
            let decision = authority.decide(&governed(), &Principal::agent(), &http());
            assert_eq!(authority.log_offset(), offset + 1);
            assert!(matches!(
                decision,
                Decision::Deny {
                    reason: DenyReason::InternalFault,
                    ..
                }
            ));
            assert_eq!(
                format!("{decision:?}"),
                r#"Deny { reason: InternalFault, rule: RuleId("<default-deny>"), resource: "" }"#
            );
            assert_eq!(
                decision.attribution().len(),
                usize::from(!effect.is_empty())
            );
            if let Some(attribution) = decision.attribution().first() {
                assert_eq!(attribution.annotation_id.as_deref(), Some("context"));
                assert_eq!(attribution.description.as_deref(), Some("diagnostic"));
                assert_eq!(attribution.rule.as_str(), "policy_0");
            }
            authority.poison_scope_for_test();
            assert_eq!(
                authority.decide(&governed(), &Principal::agent(), &http()),
                Decision::internal_fault(),
            );
        }
    }

    #[test]
    fn determining_rule_ids_survive_staging_and_recovery() {
        let history = tempfile::tempdir().expect("history directory");
        let path = history.path().join("dogwood.redb");
        let permit = r#"@id("permit-http")
            permit(principal, action == Box::Action::"http:request", resource);"#;
        let forbid = r#"@id("forbid-http")
            forbid(principal, action == Box::Action::"http:request", resource);"#;
        let mut authority = DogwoodEngine::open_for_staging(&path).expect("staging opens");

        for (source, allow) in [
            (format!("{permit}\n{forbid}"), false),
            (forbid.to_string(), false),
            (permit.to_string(), true),
        ] {
            let (policies, schema, _) =
                validate_and_expand(&source, &[], &Operator::unanchored()).expect("valid policy");
            authority
                .commit_staged(&policies, schema)
                .expect("policy installs");
            let lowered = LoweredPolicySet::from_str(
                &source,
                &service_schema().expect("service schema"),
                &PolicySchema::from_cedarschema_str(SCHEMA_SRC).expect("action schema"),
            )
            .expect("policy lowers");
            let rule = RuleId::from_engine(lowered.rules().last().expect("rule").cedar_policy_id);
            let token = authority
                .rule_ids
                .iter()
                .find(|(_, id)| **id == rule)
                .expect("determining token")
                .0
                .to_string();
            let attribution = vec![PolicyAttribution {
                token,
                rule: rule.clone(),
                annotation_id: Some(if allow { "permit-http" } else { "forbid-http" }.to_string()),
                description: None,
            }];
            let expected = if allow {
                Decision::Allow {
                    rule,
                    attribution,
                    resource: String::new(),
                }
            } else {
                Decision::Deny {
                    reason: DenyReason::Forbidden,
                    rule,
                    attribution,
                    resource: String::new(),
                }
            };
            assert_eq!(
                authority.decide(&governed(), &Principal::agent(), &http()),
                expected
            );
            drop(authority);
            authority = DogwoodEngine::open_for_staging(&path).expect("history recovers");
            assert_eq!(
                authority.decide(&governed(), &Principal::agent(), &http()),
                expected
            );
        }
    }

    #[test]
    fn wall_clock_rollback_preserves_history_across_every_open_path() {
        let history = tempfile::tempdir().expect("history directory");
        let path = history.path().join("dogwood.redb");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs();
        let future = i64::try_from(now).expect("epoch fits") + 3_600;
        let authority = DogwoodEngine::open_with_test_clock(BUDGET, &path, future)
            .expect("policy installs before clock rollback");
        authority
            .observe_outcome(&governed(), &Principal::agent(), &delivered(101))
            .expect("budget consumption records");
        drop(authority);

        for mode in 0..4 {
            let authority = match mode {
                0 => DogwoodEngine::open(BUDGET, &path).expect("normal open"),
                1 => DogwoodEngine::open_for_staging(&path).expect("staged open"),
                2 => {
                    let file = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&path)
                        .expect("history file");
                    DogwoodEngine::open_for_staging_file(file, path.clone())
                        .expect("descriptor open")
                }
                _ => DogwoodEngine::open_for_staging_with_faults(
                    &path,
                    Arc::new(FaultInjector::new()),
                )
                .expect("fault-injection open"),
            };
            assert_eq!(
                authority.decide(&governed(), &Principal::agent(), &http()),
                Decision::Deny {
                    reason: DenyReason::NoMatch,
                    rule: RuleId::default_deny(),
                    attribution: Vec::new(),
                    resource: String::new(),
                },
                "open mode {mode} must retain the consumed budget after clock rollback"
            );
        }
    }

    #[test]
    fn recovery_checkpoints_a_backlog_that_reaches_the_interval() {
        let history = tempfile::tempdir().expect("history directory");
        let path = history.path().join("dogwood.redb");
        for _ in 0..3 {
            let engine = DogwoodEngine::open(BUDGET, &path).expect("policy loads");
            engine
                .observe_outcome(&governed(), &Principal::agent(), &delivered(10))
                .expect("history records");
        }
        let snapshot = || {
            DurableLog::open(&path)
                .expect("log opens")
                .get_snapshot()
                .expect("snapshot slot")
        };
        let recover = |interval| {
            let log = DurableLog::open(&path).expect("log opens");
            drop(recover_history(log, path.clone(), durable_config(), interval).expect("recovers"));
        };

        recover(u64::MAX);
        assert_eq!(
            snapshot(),
            None,
            "a backlog below the interval must not checkpoint"
        );

        recover(3);
        assert!(
            snapshot().is_some(),
            "a backlog at the interval must checkpoint on recovery"
        );
    }

    /// Two `count_within` calls in one rule, so expansion mints two gensyms.
    const TWO_MACRO_CALLS: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
when temporal {
    (exists (a: Long). ((count_within(60s, Box::Action::"http:request"::response{ input.host: _ })) == a && a < 10))
    && (exists (b: Long). ((count_within(120s, Box::Action::"http:request"::response{ input.host: _ })) == b && b < 20))
};
"#;

    /// The `Timepoint` binder names an expanded policy carries, in order.
    fn timepoint_binders(expanded: &str) -> Vec<String> {
        expanded
            .split('(')
            .filter_map(|segment| segment.split_once(": Timepoint)"))
            .map(|(name, _)| name.to_string())
            .collect()
    }

    #[test]
    #[ignore = "Dogwood 1.0.0 temporal gensyms are not stable: #59"]
    fn expansion_is_stable_under_whitespace_and_keeps_each_call_distinct() {
        let expanded = |source: &str| {
            parse_policy_source(source)
                .expect("the policy expands")
                .join("\n")
        };
        let spaced_source = TWO_MACRO_CALLS.replace("(count_within(120s", "(   count_within(120s");
        assert_ne!(
            spaced_source, TWO_MACRO_CALLS,
            "the edit must change the source"
        );

        let compact = expanded(TWO_MACRO_CALLS);
        assert_eq!(
            compact,
            expanded(&spaced_source),
            "whitespace before a macro call must not change expanded source"
        );

        let binders = timepoint_binders(&compact);
        assert_eq!(
            binders.len(),
            2,
            "two calls must mint two binders: {compact}"
        );
        assert_ne!(
            binders[0], binders[1],
            "separate calls must keep distinct binders: {compact}"
        );
    }

    #[test]
    #[ignore = "Dogwood 1.0.0 temporal gensyms are not stable: #59"]
    fn a_generated_binder_never_takes_an_authored_name() {
        for ordinal in 0..TWO_MACRO_CALLS.len() + 64 {
            let authored = format!("t_{ordinal}");
            let source = TWO_MACRO_CALLS
                .replace("(a: Long)", &format!("({authored}: Long)"))
                .replace("== a &&", &format!("== {authored} &&"))
                .replace("a < 10", &format!("{authored} < 10"));
            let expanded = parse_policy_source(&source)
                .expect("the policy expands")
                .join("\n");

            assert!(
                !timepoint_binders(&expanded).contains(&authored),
                "a generated binder must not take the authored `{authored}`: {expanded}"
            );
        }
    }

    #[test]
    fn a_descriptor_open_writes_the_opened_history_after_a_path_swap() {
        let history = tempfile::tempdir().expect("history directory");
        let path = history.path().join("dogwood.redb");
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .expect("history descriptor");

        // A valid history, so a reopen by path succeeds and the assertions decide.
        let decoy = history.path().join("decoy.redb");
        drop(DogwoodEngine::open(BUDGET, &decoy).expect("decoy history"));
        let decoy_bytes = std::fs::read(&decoy).expect("decoy reads");
        let moved = path.with_extension("moved");
        std::fs::rename(&path, &moved).expect("move the opened history");
        std::fs::rename(&decoy, &path).expect("swap a valid history into the path");

        let authority =
            DogwoodEngine::open_for_staging_file(opened, path.clone()).expect("descriptor open");
        drop(authority);

        assert!(
            !std::fs::read(&moved)
                .expect("opened history reads")
                .is_empty(),
            "the write must land on the opened file"
        );
        assert_eq!(
            std::fs::read(&path).expect("path reads"),
            decoy_bytes,
            "the file swapped into the path must stay untouched"
        );
    }

    fn delivered(bytes: usize) -> Outcome<'static> {
        Outcome::Http {
            host: "api.example.com",
            port: 443,
            method: "POST",
            path: "/v1",
            delivery: crate::Delivery::Completed { bytes },
            status: Some(200),
        }
    }

    fn http() -> Request<'static> {
        Request::Http {
            host: "api.example.com",
            port: 443,
            method: "POST",
            path: "/v1",
            body_bytes: 10,
            intercepted: true,
        }
    }

    #[test]
    fn a_poisoned_lock_denies_every_later_decision() {
        // The engine is a large body of vendored code behind a `Mutex`. A panic inside
        // it poisons the lock, and the only safe reading of a poisoned lock is that the
        // engine's state is untrustworthy — so every later decision must DENY.
        //
        // Recovering the guard with `into_inner()` and continuing would be a fail-open:
        // the temporal history could be torn mid-update, silently under-reporting the
        // very events a `forbid` depends on. Denying permanently is a liveness cost
        // (the box stops making outbound progress) taken deliberately over that.
        let engine = engine();
        assert!(
            engine
                .decide(&governed(), &Principal::agent(), &http())
                .is_allow()
        );

        // Poison the lock by panicking while holding it.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = engine.authority.engine.lock().expect("not yet poisoned");
            panic!("simulated engine panic");
        }));
        assert!(result.is_err(), "the panic happened");
        assert!(
            engine.authority.engine.is_poisoned(),
            "the lock is poisoned"
        );

        // Every subsequent verdict is a denial, not a permit.
        for _ in 0..3 {
            let verdict = engine.decide(&governed(), &Principal::agent(), &http());
            assert!(
                matches!(
                    verdict,
                    Decision::Deny {
                        reason: DenyReason::InternalFault,
                        ..
                    }
                ),
                "a poisoned lock must deny as an internal fault, got {verdict:?}"
            );
        }

        // And a history submission surfaces the failure rather than reporting success,
        // so a caller cannot mistake a lost event for a recorded one.
        assert!(
            engine
                .observe_outcome(
                    &governed(),
                    &Principal::agent(),
                    &Outcome::Http {
                        host: "api.example.com",
                        port: 443,
                        method: "POST",
                        path: "/v1",
                        delivery: crate::Delivery::Completed { bytes: 10 },
                        status: Some(200),
                    }
                )
                .is_err(),
            "recording into a poisoned engine must fail loudly"
        );
    }

    #[test]
    fn a_denied_request_cannot_age_out_a_budget() {
        // The defect this pins: with an event *counter* as the clock, `within 60s` meant
        // "the last 60 events", so a workload that spun cheap DENIED requests aged its own
        // budget out and egressed unboundedly — 57 denials reopened a 100-byte/60s budget
        // while delivering nothing. A window must advance with time, not with traffic.
        let engine = engine_with_clock(1_000);
        let egress = Principal::agent();

        // Exhaust the budget with real deliveries.
        for _ in 0..2 {
            assert!(engine.decide(&governed(), &egress, &http()).is_allow());
            engine
                .observe_outcome(&governed(), &egress, &delivered(60))
                .expect("records");
        }
        assert!(
            !engine.decide(&governed(), &egress, &http()).is_allow(),
            "budget closed"
        );

        // Now make noise: many denied requests, no clock movement, nothing delivered.
        for _ in 0..500 {
            assert!(
                !engine.decide(&governed(), &egress, &http()).is_allow(),
                "a denied request must not reopen the budget"
            );
        }
    }

    #[test]
    fn a_budget_reopens_only_after_the_window_really_elapses() {
        // The other half: the window must actually expire. If it never did, a single burst
        // would deny forever and the box would stop making progress.
        let engine = engine_with_clock(1_000);
        let egress = Principal::agent();

        for _ in 0..2 {
            assert!(engine.decide(&governed(), &egress, &http()).is_allow());
            engine
                .observe_outcome(&governed(), &egress, &delivered(60))
                .expect("records");
        }
        assert!(
            !engine.decide(&governed(), &egress, &http()).is_allow(),
            "budget closed"
        );

        // Still inside the 60s window.
        engine.advance_clock(59);
        assert!(
            !engine.decide(&governed(), &egress, &http()).is_allow(),
            "the window has not elapsed yet"
        );

        // Past it: the old deliveries fall out of the sum.
        engine.advance_clock(2);
        assert!(
            engine.decide(&governed(), &egress, &http()).is_allow(),
            "the budget must reopen once the window truly elapses"
        );
    }
    #[test]
    fn a_temporal_predicate_matches_the_action_namespace_it_is_written_with() {
        // Regression guard for a silent fail-open. A temporal predicate matches on
        // action AND kind AND namespace; the parser splits the policy's
        // `Box::Action::"http:request"` into namespace ["Box", "Action"]. An empty namespace here
        // compiles, loads, validates — and then matches nothing, so every temporal rule
        // silently permits. This asserts the budget actually trips, which it cannot do
        // unless the namespace agrees.
        let engine = engine();
        let outcome = Outcome::Http {
            host: "api.example.com",
            port: 443,
            method: "POST",
            path: "/v1",
            delivery: crate::Delivery::Completed { bytes: 150 },
            status: Some(200),
        };
        assert!(
            engine
                .decide(&governed(), &Principal::agent(), &http())
                .is_allow()
        );
        engine
            .observe_outcome(&governed(), &Principal::agent(), &outcome)
            .expect("records");
        assert!(
            !engine
                .decide(&governed(), &Principal::agent(), &http())
                .is_allow(),
            "a recorded 150-byte delivery must exhaust a 100-byte budget; if this \
             allows, the predicate is not matching the recorded event at all"
        );
    }

    fn counting_window(seconds: u64) -> String {
        format!(
            r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource)
when temporal {{
    exists (total: Long). (
        (count for (t: Timepoint). where (
            formerly within {seconds}s (
                Box::Action::"shell:exec"::request{{ input.program: _ }} && tp(t)
            )
        )) == total
        && total < 1000000000
    )
}};
"#
        )
    }

    fn exec() -> Request<'static> {
        Request::ShellExec {
            command: "printf ok",
            program: "printf",
            args: &[],
            cwd: "/",
        }
    }

    struct Growth {
        bytes_at_half: u64,
        bytes_at_end: u64,
        reopen_at_half: Duration,
        reopen_at_end: Duration,
        append_first_half: Duration,
        append_second_half: Duration,
    }

    fn ratio(treatment: Duration, control: Duration) -> f64 {
        treatment.as_secs_f64() / control.as_secs_f64().max(f64::EPSILON)
    }

    /// Append `events` one second apart under `policy`, reopening the store halfway and at the end.
    fn grow_history(policy: &str, events: usize) -> Growth {
        const START: i64 = 1_000_000;
        let history = tempfile::tempdir().expect("history directory");
        let path = history.path().join("dogwood.redb");
        let agent = Principal::agent();
        let append = |engine: &DogwoodEngine, count: usize| {
            let started = std::time::Instant::now();
            for _ in 0..count {
                engine.advance_clock(1);
                assert!(engine.decide(&governed(), &agent, &exec()).is_allow());
            }
            started.elapsed()
        };
        let reopen = |at: i64| {
            let mut timings = Vec::with_capacity(3);
            let mut engine = None;
            for _ in 0..3 {
                drop(engine.take());
                let started = std::time::Instant::now();
                engine = Some(
                    DogwoodEngine::open_with_test_clock(policy, &path, at)
                        .expect("history recovers"),
                );
                timings.push(started.elapsed());
            }
            timings.sort_unstable();
            (engine.expect("an engine"), timings[1])
        };
        let half = events / 2;
        let engine = DogwoodEngine::open_with_test_clock(policy, &path, START).expect("opens");
        let append_first_half = append(&engine, half);
        drop(engine);
        let bytes_at_half = std::fs::metadata(&path).expect("history file").len();
        let (engine, reopen_at_half) = reopen(START + half as i64);
        let append_second_half = append(&engine, events - half);
        drop(engine);
        let bytes_at_end = std::fs::metadata(&path).expect("history file").len();
        let (engine, reopen_at_end) = reopen(START + events as i64);
        drop(engine);
        Growth {
            bytes_at_half,
            bytes_at_end,
            reopen_at_half,
            reopen_at_end,
            append_first_half,
            append_second_half,
        }
    }

    #[test]
    #[ignore = "forty thousand durable appends, minutes long: run by hand with --ignored"]
    fn history_size_and_recovery_time_follow_the_deepest_window_and_not_the_event_count() {
        const EVENTS: usize = 20_000;
        const LARGEST_STEADY_GROWTH: f64 = 1.25;
        const LARGEST_REOPEN_GROWTH: f64 = 1.5;
        let minute = grow_history(&counting_window(60), EVENTS);
        let day = grow_history(&counting_window(24 * 3600), EVENTS);
        for (name, growth) in [("60 s window", &minute), ("24 h window", &day)] {
            let _ = writeln!(
                std::io::stderr().lock(),
                "NFR-06 {name}: {} bytes after {} events, {} bytes after {EVENTS}; reopen {:?} then \
                 {:?}; appends took {:?} then {:?}",
                growth.bytes_at_half,
                EVENTS / 2,
                growth.bytes_at_end,
                growth.reopen_at_half,
                growth.reopen_at_end,
                growth.append_first_half,
                growth.append_second_half
            );
        }
        let size_growth = minute.bytes_at_end as f64 / minute.bytes_at_half.max(1) as f64;
        let reopen_growth = ratio(minute.reopen_at_end, minute.reopen_at_half);
        assert!(
            size_growth <= LARGEST_STEADY_GROWTH,
            "under a 60 s window the history grew from {} to {} bytes between {} and {EVENTS} \
             events (ratio {size_growth:.2}, limit {LARGEST_STEADY_GROWTH}): history is not pruned \
             to the window",
            minute.bytes_at_half,
            minute.bytes_at_end,
            EVENTS / 2
        );
        assert!(
            reopen_growth <= LARGEST_REOPEN_GROWTH,
            "under a 60 s window reopening took {:?} after {EVENTS} events against {:?} after {} \
             (ratio {reopen_growth:.2}, limit {LARGEST_REOPEN_GROWTH}): recovery time follows the \
             event count",
            minute.reopen_at_end,
            minute.reopen_at_half,
            EVENTS / 2
        );
        let day_growth = day.bytes_at_end as i64 - day.bytes_at_half as i64;
        let minute_growth = minute.bytes_at_end as i64 - minute.bytes_at_half as i64;
        assert!(
            day_growth > minute_growth,
            "between {} and {EVENTS} events the 24 h window grew by {day_growth} bytes and the 60 s \
             window by {minute_growth}: the window is not what decides what history keeps",
            EVENTS / 2
        );
    }

    #[test]
    fn recorded_history_survives_reopening_the_store() {
        let history = tempfile::tempdir().expect("history directory");
        let path = history.path().join("dogwood.redb");
        let egress = Principal::agent();

        let offset_before_reopen = {
            let engine = DogwoodEngine::open(BUDGET, &path).expect("policy loads");
            assert!(engine.decide(&governed(), &egress, &http()).is_allow());
            engine
                .observe_outcome(&governed(), &egress, &delivered(150))
                .expect("history records");
            engine.log_offset()
        };

        let recovered = DogwoodEngine::open(BUDGET, &path).expect("history recovers");
        assert_eq!(
            recovered.log_offset(),
            offset_before_reopen,
            "reopening an unchanged policy must not append another install record"
        );
        assert!(
            !recovered.decide(&governed(), &egress, &http()).is_allow(),
            "the recovered delivery must keep the budget closed"
        );
    }

    #[test]
    fn policy_reconciliation_does_not_checkpoint() {
        let history = tempfile::tempdir().expect("history directory");
        let path = history.path().join("dogwood.redb");
        let (policies, schema, _) =
            validate_and_expand(BUDGET, &[], &Operator::unanchored()).expect("policy validates");
        let changed = format!(
            r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);

{BUDGET}
"#
        );
        let (changed_policies, changed_schema, _) =
            validate_and_expand(&changed, &[], &Operator::unanchored())
                .expect("changed policy validates");
        let faults = Arc::new(FaultInjector::new());
        let config = DurableConfig::new(SNAPSHOT_INTERVAL).with_fault_injector(Arc::clone(&faults));
        let mut engine =
            DurableTemporalEngine::open_with_config(&path, config).expect("history opens");

        faults.arm(FaultPoint::CheckpointBeforePrune);
        let worker = std::thread::spawn(move || {
            let result = reconcile_policy_set(&mut engine, &policies, &[], &schema.source)
                .and_then(|()| {
                    reconcile_policy_set(
                        &mut engine,
                        &changed_policies,
                        &[],
                        &changed_schema.source,
                    )
                })
                .and_then(|()| {
                    reconcile_policy_set(
                        &mut engine,
                        &changed_policies,
                        &[],
                        &changed_schema.source,
                    )
                });
            (result, engine)
        });
        let checkpointed_before_release = faults.wait_until_reached(Duration::from_millis(250));
        faults.release();
        let (result, _engine) = worker.join().expect("reconciliation exits");
        let checkpointed = checkpointed_before_release || faults.wait_until_reached(Duration::ZERO);

        result.expect("policies reconcile");
        assert!(!checkpointed, "policy reconciliation must not checkpoint");
    }

    #[test]
    fn boot_installs_canonical_schema_then_appends_mcp_fragments() {
        let history = tempfile::tempdir().expect("history directory");
        let path = history.path().join("dogwood.redb");
        let first = crate::mcp_schema::generate_mcp_schema(
            "issues-mcp",
            r#"{
                "result": {
                    "tools": [{
                        "name": "Search",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"query": {"type": "string"}},
                            "required": ["query"]
                        }
                    }]
                }
            }"#,
        )
        .expect("first MCP fragment");
        let second = crate::mcp_schema::generate_mcp_schema(
            "aws-mcp",
            r#"{
                "result": {
                    "tools": [{
                        "name": "Lookup",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"account": {"type": "string"}},
                            "required": ["account"]
                        }
                    }]
                }
            }"#,
        )
        .expect("second MCP fragment");
        let fragments = vec![first, second];
        let expected = action_schema(&fragments).expect("effective schema");

        let (authority, _) = DogwoodEngine::open_with_mcp_schemas(
            BUDGET,
            &fragments,
            &path,
            &Operator::unanchored(),
        )
        .expect("schema fragments install");
        let offset = authority.log_offset();
        assert_eq!(
            authority
                .engine
                .lock()
                .expect("engine is available")
                .action_schema()
                .as_deref(),
            Some(expected.source.as_str()),
            "the stored schema must be canonical followed by every MCP fragment"
        );
        drop(authority);

        let log = DurableLog::open(&path).expect("reopen durable log");
        let mut schema_changes = Vec::new();
        log.scan_from(0, |_, bytes| {
            match Record::decode(bytes).expect("record decodes") {
                Record::SetActionSchema { action_schema, .. } => {
                    schema_changes.push(("set", action_schema));
                }
                Record::AppendActionSchema { fragment, .. } => {
                    schema_changes.push(("append", fragment));
                }
                _ => {}
            }
        })
        .expect("scan schema changes");
        assert_eq!(
            schema_changes,
            vec![
                ("set", SCHEMA_SRC.to_string()),
                ("append", fragments[0].clone()),
                ("append", fragments[1].clone()),
            ],
            "the durable install must set the canonical schema before appending each fragment"
        );
        drop(log);

        let (reopened, _) = DogwoodEngine::open_with_mcp_schemas(
            BUDGET,
            &fragments,
            &path,
            &Operator::unanchored(),
        )
        .expect("the unchanged schema reopens");
        assert_eq!(
            reopened.log_offset(),
            offset,
            "an unchanged effective schema must not append the fragments again"
        );
    }

    /// The same budget as `BUDGET`, written with the shipped `sum_within` macro.
    const MACRO_BUDGET: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource)
when temporal {
    exists (total: Long). (
        (sum_within(b, 60s, Box::Action::"http:request"::response{ input.host: _, input.body_bytes: b })) == total
        && total < 100
    )
};
"#;

    #[test]
    #[ignore = "Dogwood 1.0.0 temporal gensyms are not stable: #59"]
    fn a_whitespace_only_edit_keeps_an_exhausted_macro_budget_closed() {
        let history = tempfile::tempdir().expect("history directory");
        let path = history.path().join("dogwood.redb");
        let egress = Principal::agent();

        {
            let engine = DogwoodEngine::open(MACRO_BUDGET, &path).expect("policy loads");
            assert!(engine.decide(&governed(), &egress, &http()).is_allow());
            engine
                .observe_outcome(&governed(), &egress, &delivered(150))
                .expect("history records");
            assert!(
                !engine.decide(&governed(), &egress, &http()).is_allow(),
                "a 150-byte delivery must exhaust a 100-byte budget"
            );
        }

        let reformatted = MACRO_BUDGET.replace("(sum_within(b,", "(   sum_within(b,");
        assert_ne!(reformatted, MACRO_BUDGET, "the edit must change the source");
        let recovered = DogwoodEngine::open(&reformatted, &path).expect("reformatted bundle loads");
        assert!(
            !recovered.decide(&governed(), &egress, &http()).is_allow(),
            "a whitespace-only edit must not reopen an exhausted budget"
        );
    }

    #[test]
    fn unchanged_statements_keep_their_history_when_the_bundle_changes() {
        let history = tempfile::tempdir().expect("history directory");
        let path = history.path().join("dogwood.redb");
        let egress = Principal::agent();

        {
            let engine = DogwoodEngine::open(BUDGET, &path).expect("policy loads");
            assert!(engine.decide(&governed(), &egress, &http()).is_allow());
            engine
                .observe_outcome(&governed(), &egress, &delivered(150))
                .expect("history records");
        }

        let changed = format!(
            r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);

{BUDGET}
"#
        );
        let recovered = DogwoodEngine::open(&changed, &path).expect("changed bundle loads");
        assert!(
            !recovered.decide(&governed(), &egress, &http()).is_allow(),
            "inserting an unrelated statement must not reset an unchanged budget"
        );
    }
}
