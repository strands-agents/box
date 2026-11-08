//! Coordinates policy proposal state and live-authority transitions.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::Path;
use std::str::FromStr;
use std::sync::Mutex;

use cedar_policy::EntityUid;
use dogwood_local_engine::DurableError;

use super::{Policy, SchemaStage, authored};
use crate::check::{Finding, Refused, RuleRef, annotated_id};
use crate::dogwood::{
    DogwoodEngine, check_canonical_policy_set, expand_policy_source,
    refuse_input_reads_before_discovery, rule_conditions, validate_canonical_policy_set,
};
use crate::request::ActionRequest;
use crate::schema::{
    ActionIdentity, GovernedBox, composed_action_schema, mcp_action_namespace, mcp_tool_action,
};
use crate::spelling::{Operator, PolicyWarning};
use crate::{Decision, Outcome, PolicyError, PolicyStagingError, Principal, Request, RequestId};

#[derive(Debug, Clone)]
struct CandidatePolicy {
    ordinal: usize,
    expanded_source: String,
    /// The per-tool actions the head names, decoded at parse time.
    head_tools: BTreeSet<(String, String)>,
}

#[derive(Debug, Clone)]
struct ProposalState {
    operator: Operator,
    candidates: Vec<CandidatePolicy>,
    grammar_schemas: Vec<String>,
    schemas: BTreeMap<String, String>,
    ready: BTreeSet<usize>,
    pending: BTreeMap<usize, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Readiness {
    /// Serving the committed schema-independent subset while typed schemas are still staging
    /// (docs/design/decisions.md#discovery-serves-the-schema-independent-subset). Tool calls
    /// whose typed action is still pending are held (`pending_tools`). A subset that cannot even
    /// validate makes `open_staged` return an error, so there is no deny-all state to reach at
    /// runtime.
    Discovering,
    Ready,
}

struct LiveAuthority {
    engine: DogwoodEngine,
    readiness: Readiness,
    /// The `(namespace, tool)` typed actions whose schema has not staged yet. While `Discovering`,
    /// a `tools/call` naming one of these is held with a transient `PolicyPending`. Empty
    /// when `Ready`.
    pending_tools: BTreeSet<(String, String)>,
    /// The `(namespace, tool)` typed actions that a rule still pending when discovery finished
    /// decides. A `tools/call` naming one is denied fail-closed in any state, so a hardcoded call
    /// cannot ride the coarse `mcp:call` permit with its argument constraint unenforced. Empty
    /// until `finish_mcp_discovery` degrades, and empty again once a complete bundle installs.
    degraded_tools: BTreeSet<(String, String)>,
}

pub(super) struct Authority {
    proposal: Mutex<Option<ProposalState>>,
    live: Mutex<LiveAuthority>,
    warnings: Vec<PolicyWarning>,
}

impl Authority {
    /// Opens a ready authority with a complete policy and schema set.
    pub(super) fn open_complete(
        sources: Vec<Policy>,
        mcp_schemas: &[String],
        history: &Path,
    ) -> Result<Self, PolicyError> {
        Self::open_complete_with_grammars(sources, &[], mcp_schemas, history)
    }

    /// Opens a ready authority with a complete policy set, tool grammar schemas, and MCP schemas.
    pub(super) fn open_complete_with_grammars(
        sources: Vec<Policy>,
        grammar_schemas: &[String],
        mcp_schemas: &[String],
        history: &Path,
    ) -> Result<Self, PolicyError> {
        let (engine, warnings) = DogwoodEngine::open_with_schemas(
            &authored(&sources),
            grammar_schemas,
            mcp_schemas,
            history,
            &Operator::unanchored(),
        )?;
        Ok(Self {
            proposal: Mutex::new(None),
            live: Mutex::new(LiveAuthority {
                engine,
                readiness: Readiness::Ready,
                pending_tools: BTreeSet::new(),
                degraded_tools: BTreeSet::new(),
            }),
            warnings,
        })
    }

    /// Opens an authority that can remain blocked until runtime schemas make its policy set valid.
    pub(super) fn open_staged(
        operator: &Operator,
        sources: Vec<Policy>,
        history: &Path,
    ) -> Result<Self, PolicyStagingError> {
        Self::open_staged_with_engine(
            operator,
            sources,
            Vec::new(),
            DogwoodEngine::open_for_staging(history)?,
        )
    }

    /// Opens a staging authority. Each schema set holds `grammar_schemas` below the MCP schemas.
    pub(super) fn open_staged_file(
        operator: &Operator,
        sources: Vec<Policy>,
        grammar_schemas: Vec<String>,
        history: File,
        label: std::path::PathBuf,
    ) -> Result<Self, PolicyStagingError> {
        Self::open_staged_with_engine(
            operator,
            sources,
            grammar_schemas,
            DogwoodEngine::open_for_staging_file(history, label)?,
        )
    }

    fn open_staged_with_engine(
        operator: &Operator,
        sources: Vec<Policy>,
        grammar_schemas: Vec<String>,
        mut engine: DogwoodEngine,
    ) -> Result<Self, PolicyStagingError> {
        let candidates = candidates(&authored(&sources)).map_err(Refused::into_error)?;
        let mut proposal = ProposalState {
            operator: operator.clone(),
            candidates,
            grammar_schemas,
            schemas: BTreeMap::new(),
            ready: BTreeSet::new(),
            pending: BTreeMap::new(),
        };
        let complete = proposal.complete_policy_set();
        refuse_input_reads_before_discovery(&complete).map_err(Refused::into_error)?;
        let (readiness, pending_tools, warnings) = match validate_canonical_policy_set(
            &complete,
            &proposal.grammar_schemas,
            &[],
            operator,
            &[],
        ) {
            Ok((effective_schema, warnings)) => {
                engine
                    .commit_staged(&complete, effective_schema)
                    .map_err(|error| PolicyStagingError::Durable(error.to_string()))?;
                proposal.mark_all_ready();
                (Readiness::Ready, BTreeSet::new(), warnings)
            }
            Err(inert) if is_inert(&inert) => {
                return Err(inert.into());
            }
            Err(_) => {
                proposal.classify(&[])?;
                // Serve the schema-independent subset while typed schemas stage
                // (`Discovering`), instead of denying every request. A per-tool rule that has
                // not validated is not refused here; `finish_mcp_discovery` degrades the
                // servers it waits for instead.
                let subset = proposal.ready_policy_set();
                let (effective_schema, warnings) = validate_canonical_policy_set(
                    &subset,
                    &proposal.grammar_schemas,
                    &[],
                    operator,
                    &proposal.ready_positions(),
                )?;
                engine
                    .commit_staged(&subset, effective_schema)
                    .map_err(|error| PolicyStagingError::Durable(error.to_string()))?;
                (
                    Readiness::Discovering,
                    pending_typed_tools(&proposal),
                    warnings,
                )
            }
        };

        Ok(Self {
            proposal: Mutex::new(Some(proposal)),
            live: Mutex::new(LiveAuthority {
                engine,
                readiness,
                pending_tools,
                degraded_tools: BTreeSet::new(),
            }),
            warnings,
        })
    }

    pub(super) fn warnings(&self) -> &[PolicyWarning] {
        &self.warnings
    }

    /// Re-install an authored policy set over the live engine, keeping this box's decision
    /// history and the MCP schemas this run already discovered.
    ///
    /// Validation runs before the live lock is taken, so text that does not validate costs no
    /// decision latency and leaves the previous authority serving every request. The authored
    /// set is replaced wholesale and refused wholesale: `open_staged` may install the
    /// schema-independent subset and open `Discovering`, because at startup the typed schemas
    /// have not arrived yet and a box that denied everything until they did would be useless.
    /// Reject the entire replacement if any rule fails validation, and keep the current policy.
    pub(super) fn reload(&self, sources: &[Policy]) -> Result<(), PolicyStagingError> {
        // Same order as `stage_mcp_schema`: proposal first, then live. A reload that took them
        // the other way round would deadlock against a schema staging mid-discovery.
        let mut proposal_guard = self
            .proposal
            .lock()
            .map_err(|_| PolicyStagingError::Durable("policy staging lock poisoned".to_string()))?;
        let Some(current) = proposal_guard.as_ref() else {
            return Err(PolicyStagingError::Durable(
                "the authority was not opened for runtime staging".to_string(),
            ));
        };
        let mut proposed = current.clone();
        // The operator and the discovered schemas carry over; only the authored rules change.
        proposed.candidates = candidates(&authored(sources)).map_err(Refused::into_error)?;
        proposed.ready = BTreeSet::new();
        proposed.pending = BTreeMap::new();

        let schemas = proposed.schema_sources();
        let complete = proposed.complete_policy_set();
        let (effective_schema, _) = validate_canonical_policy_set(
            &complete,
            &proposed.grammar_schemas,
            &schemas,
            &proposed.operator,
            &[],
        )?;

        let mut live = self.live.lock().map_err(|_| {
            PolicyStagingError::Durable("policy authority lock poisoned".to_string())
        })?;
        live.engine
            .commit_staged(&complete, effective_schema)
            .map_err(|error| PolicyStagingError::Durable(error.to_string()))?;
        proposed.mark_all_ready();
        live.readiness = Readiness::Ready;
        live.pending_tools = BTreeSet::new();
        live.degraded_tools.clear();
        drop(live);
        *proposal_guard = Some(proposed);
        Ok(())
    }

    /// Validates one schema proposal and commits only a valid complete policy set.
    pub(super) fn stage_mcp_schema(
        &self,
        server: &str,
        fragment: String,
    ) -> Result<SchemaStage, PolicyStagingError> {
        let mut proposal_guard = self
            .proposal
            .lock()
            .map_err(|_| PolicyStagingError::Durable("policy staging lock poisoned".to_string()))?;
        let Some(current) = proposal_guard.as_ref() else {
            return Ok(SchemaStage::Rejected {
                reason: "the authority was not opened for runtime staging".to_string(),
            });
        };
        let mut proposed = current.clone();
        proposed.schemas.insert(server.to_string(), fragment);
        let named_schemas = proposed.named_schemas();
        if let Err(error) = crate::mcp_schema::validate_mcp_schema_composition(&named_schemas) {
            return Ok(SchemaStage::Rejected {
                reason: error.to_string(),
            });
        }
        let schemas = proposed.schema_sources();
        let complete = proposed.complete_policy_set();

        match validate_canonical_policy_set(
            &complete,
            &proposed.grammar_schemas,
            &schemas,
            &proposed.operator,
            &[],
        ) {
            Ok((effective_schema, _)) => {
                let mut live = self.live.lock().map_err(|_| {
                    PolicyStagingError::Durable("policy authority lock poisoned".to_string())
                })?;
                match live.engine.commit_staged(&complete, effective_schema) {
                    Ok(()) => {
                        proposed.mark_all_ready();
                        *proposal_guard = Some(proposed);
                        live.readiness = Readiness::Ready;
                        live.pending_tools = BTreeSet::new();
                        live.degraded_tools.clear();
                        Ok(SchemaStage::Accepted {
                            authority_ready: true,
                        })
                    }
                    Err(DurableError::Rejected(reason)) => Ok(SchemaStage::Rejected { reason }),
                    Err(error) => Err(PolicyStagingError::Durable(error.to_string())),
                }
            }
            Err(complete_error) => {
                let live = self.live.lock().map_err(|_| {
                    PolicyStagingError::Durable("policy authority lock poisoned".to_string())
                })?;
                if live.readiness == Readiness::Ready {
                    return Ok(SchemaStage::Rejected {
                        reason: complete_error.to_string(),
                    });
                }
                drop(live);

                if let Err(error) = proposed.validate_ready(&schemas) {
                    return Ok(SchemaStage::Rejected {
                        reason: error.to_string(),
                    });
                }
                if let Err(error) = proposed.classify(&schemas) {
                    return Ok(SchemaStage::Rejected {
                        reason: error.to_string(),
                    });
                }
                // Re-commit the grown subset (this server's now-ready typed rules included)
                // so they enforce live, and refresh the held-tool set. Readiness stays `Discovering`
                // until the complete bundle validates.
                let subset = proposed.ready_policy_set();
                let (subset_schema, _) = validate_canonical_policy_set(
                    &subset,
                    &proposed.grammar_schemas,
                    &schemas,
                    &proposed.operator,
                    &proposed.ready_positions(),
                )?;
                let mut live = self.live.lock().map_err(|_| {
                    PolicyStagingError::Durable("policy authority lock poisoned".to_string())
                })?;
                live.engine
                    .commit_staged(&subset, subset_schema)
                    .map_err(|error| PolicyStagingError::Durable(error.to_string()))?;
                live.pending_tools = pending_typed_tools(&proposed);
                live.readiness = Readiness::Discovering;
                drop(live);
                *proposal_guard = Some(proposed);
                Ok(SchemaStage::Accepted {
                    authority_ready: false,
                })
            }
        }
    }

    /// Completes discovery, degrading any server whose per-tool rule never staged
    /// (docs/design/decisions.md#a-server-whose-discovery-a-policy-denies-degrades-alone).
    ///
    /// Every door has drained, so a candidate still pending has not validated against the schemas
    /// that arrived. Rather than fatally refuse the whole box, the still-pending typed tools
    /// become `degraded_tools` — denied fail-closed in `decide` — the committed subset becomes the
    /// final `Ready` authority, and the servers each pending rule waits for are returned so the
    /// caller can warn. Only a genuine durable fault is an `Err`.
    ///
    /// The tools held and the servers named answer different questions, so they come from different
    /// scans. A rule decides no call to a tool it only reads from history, and yet it still waits
    /// for that tool to be declared. `servers_a_pending_rule_waits_for` states which servers reach
    /// the warning.
    pub(super) fn finish_mcp_discovery(&self) -> Result<Vec<String>, PolicyStagingError> {
        let proposal = self
            .proposal
            .lock()
            .map_err(|_| PolicyStagingError::Durable("policy staging lock poisoned".to_string()))?;
        let mut live = self.live.lock().map_err(|_| {
            PolicyStagingError::Durable("policy authority lock poisoned".to_string())
        })?;
        if live.readiness == Readiness::Ready {
            return Ok(Vec::new());
        }
        // The still-pending typed rules have not validated, so the tools they decide are not
        // enforceable. Hold them fail-closed and finish `Ready`.
        let degraded = proposal
            .as_ref()
            .map(pending_typed_tools)
            .unwrap_or_default();
        live.degraded_tools = degraded;
        live.pending_tools = BTreeSet::new();
        live.readiness = Readiness::Ready;
        let servers = proposal
            .as_ref()
            .map(|proposal| servers_a_pending_rule_waits_for(proposal, &live.engine))
            .unwrap_or_default();
        Ok(servers.into_iter().collect())
    }

    /// Decides through a ready live authority and denies every other state.
    pub(super) fn decide(
        &self,
        governed: &GovernedBox,
        principal: &Principal,
        request: ActionRequest<'_>,
    ) -> (Decision, Option<RequestId>) {
        let identity = &request.identity();
        match self.live.lock() {
            Ok(live) => {
                // Fail-closed for a degraded tool: a rule that decides it has not validated, so
                // its argument constraint is not enforceable. Deny outright — in any state — rather
                // than let a hardcoded call ride the coarse `mcp:call` permit unconstrained.
                if let ActionIdentity::McpTool { namespace, tool } = identity
                    && live
                        .degraded_tools
                        .contains(&(namespace.clone(), tool.clone()))
                {
                    return (Decision::no_match(), None);
                }
                match live.readiness {
                    Readiness::Discovering => {
                        // Guard: hold a `tools/call` whose per-tool typed action has not staged
                        // yet — its arg constraint is not enforceable, so deny transiently rather than
                        // let it ride the coarse permit unconstrained. Everything else (the model, other
                        // tools, `tools/list`) is decided against the committed schema-independent subset.
                        if let ActionIdentity::McpTool { namespace, tool } = identity
                            && live
                                .pending_tools
                                .contains(&(namespace.clone(), tool.clone()))
                        {
                            return (Decision::policy_pending(), None);
                        }
                        live.engine.decide(governed, principal, request)
                    }
                    Readiness::Ready => live.engine.decide(governed, principal, request),
                }
            }
            Err(_) => (Decision::internal_fault(), None),
        }
    }

    /// Records one outcome. The live authority always serves decisions (`Discovering` or `Ready`),
    /// so no readiness state refuses a record.
    pub(super) fn record(
        &self,
        governed: &GovernedBox,
        principal: &Principal,
        request_id: &RequestId,
        outcome: &Outcome<'_>,
    ) -> Result<(), PolicyError> {
        let live = self
            .live
            .lock()
            .map_err(|_| PolicyError::Evaluation("policy authority lock poisoned".to_string()))?;
        live.engine
            .observe_outcome(governed, principal, request_id, outcome)
    }

    /// Records the `::response` of one completed action whose `input` is a JSON record.
    #[cfg_attr(
        not(any(test, feature = "shell-adapter")),
        expect(
            dead_code,
            reason = "only the shell adapter records a grammar response"
        )
    )]
    pub(super) fn record_response(
        &self,
        identity: &ActionIdentity,
        input: &serde_json::Value,
        request_id: &RequestId,
        status: i32,
    ) -> Result<(), PolicyError> {
        let live = self
            .live
            .lock()
            .map_err(|_| PolicyError::Evaluation("policy authority lock poisoned".to_string()))?;
        live.engine
            .observe_response(identity, input, request_id, status)
    }

    /// Decides one `tools/call` under a single live-lock read: a degraded tool is denied, a
    /// pending tool is held, and a tool that no per-tool rule matches rides the coarse allow.
    pub(super) fn refine_tool_call(
        &self,
        governed: &GovernedBox,
        principal: &Principal,
        request: &Request<'_>,
        identity: &ActionIdentity,
    ) -> Decision {
        let Ok(live) = self.live.lock() else {
            return Decision::internal_fault();
        };
        if let ActionIdentity::McpTool { namespace, tool } = identity {
            let key = (namespace.clone(), tool.clone());
            if live.degraded_tools.contains(&key) {
                return Decision::no_match();
            }
            if live.readiness == Readiness::Discovering && live.pending_tools.contains(&key) {
                return Decision::policy_pending();
            }
        }
        let Ok(action) = identity.cedar_uid() else {
            return Decision::internal_fault();
        };
        let decision = if live.engine.declares_tool_action(&action) {
            live.engine
                .decide(governed, principal, ActionRequest::Request(request))
                .0
        } else {
            Decision::no_match()
        };
        match decision {
            // No per-tool rule matched: ride the coarse `mcp:call` allow rather than default-denying.
            Decision::Deny {
                reason: crate::DenyReason::NoMatch,
                ..
            } => Decision::Allow {
                rule: crate::RuleId::default_deny(),
                attribution: Vec::new(),
                resource: String::new(),
            },
            // An explicit `forbid`, an internal fault, or an allow — enforce as decided.
            other => other,
        }
    }

    #[cfg(test)]
    /// Opens a ready authority with a fixed test clock.
    pub(super) fn open_with_test_clock(
        sources: Vec<Policy>,
        history: &Path,
        now_secs: i64,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            proposal: Mutex::new(None),
            live: Mutex::new(LiveAuthority {
                engine: DogwoodEngine::open_with_test_clock(
                    &authored(&sources),
                    history,
                    now_secs,
                )?,
                readiness: Readiness::Ready,
                pending_tools: BTreeSet::new(),
                degraded_tools: BTreeSet::new(),
            }),
            warnings: Vec::new(),
        })
    }

    #[cfg(test)]
    pub(super) fn open_with_faults(
        sources: Vec<Policy>,
        history: &Path,
        faults: std::sync::Arc<dogwood_local_engine::fault_injection::FaultInjector>,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            proposal: Mutex::new(None),
            live: Mutex::new(LiveAuthority {
                engine: DogwoodEngine::open_with_faults(&authored(&sources), history, faults)?,
                readiness: Readiness::Ready,
                pending_tools: BTreeSet::new(),
                degraded_tools: BTreeSet::new(),
            }),
            warnings: Vec::new(),
        })
    }

    #[cfg(test)]
    /// Poisons the durable engine's scope lock, the engine's terminal store state.
    pub(super) fn poison_scope_for_test(&self) {
        self.live
            .lock()
            .expect("live authority lock")
            .engine
            .poison_scope_for_test();
    }

    #[cfg(test)]
    /// Poisons the live-authority lock for fail-closed tests.
    pub(super) fn poison_live_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self
                .live
                .lock()
                .expect("live authority is not yet poisoned");
            panic!("simulated live-authority panic");
        }));
    }
}

impl ProposalState {
    fn complete_policy_set(&self) -> Vec<String> {
        self.candidates
            .iter()
            .map(|candidate| candidate.expanded_source.clone())
            .collect()
    }

    fn ready_policy_set(&self) -> Vec<String> {
        self.candidates
            .iter()
            .filter(|candidate| self.ready.contains(&candidate.ordinal))
            .map(|candidate| candidate.expanded_source.clone())
            .collect()
    }

    /// The authored index of each statement in `ready_policy_set`.
    fn ready_positions(&self) -> Vec<usize> {
        self.ready.iter().copied().collect()
    }

    /// The authored index of each statement in `candidate_policy_set(ordinal)`.
    fn candidate_positions(&self, ordinal: usize) -> Vec<usize> {
        let mut positions = self.ready_positions();
        if !self.ready.contains(&ordinal) {
            positions.push(ordinal);
            positions.sort_unstable();
        }
        positions
    }

    fn candidate_policy_set(&self, ordinal: usize) -> Vec<String> {
        self.candidates
            .iter()
            .filter(|candidate| {
                self.ready.contains(&candidate.ordinal) || candidate.ordinal == ordinal
            })
            .map(|candidate| candidate.expanded_source.clone())
            .collect()
    }

    fn validate_ready(&self, schemas: &[String]) -> Result<(), PolicyError> {
        validate_canonical_policy_set(
            &self.ready_policy_set(),
            &self.grammar_schemas,
            schemas,
            &self.operator,
            &self.ready_positions(),
        )
        .map(|_| ())
    }

    fn classify(&mut self, schemas: &[String]) -> Result<(), PolicyError> {
        self.classify_naming(schemas)
            .map_err(|(_, refused)| refused.into_error())
    }

    /// Classify each candidate, and name the candidate whose refusal stopped it.
    fn classify_naming(&mut self, schemas: &[String]) -> Result<(), (usize, Refused)> {
        loop {
            let mut changed = false;
            for ordinal in 0..self.candidates.len() {
                if self.ready.contains(&ordinal) {
                    continue;
                }
                let candidate = self.candidate_policy_set(ordinal);
                match check_canonical_policy_set(
                    &candidate,
                    &self.grammar_schemas,
                    schemas,
                    &self.operator,
                    &self.candidate_positions(ordinal),
                ) {
                    Ok(_) => {
                        self.ready.insert(ordinal);
                        self.pending.remove(&ordinal);
                        changed = true;
                    }
                    Err(refused) if is_inert(&refused.error) => {
                        return Err((ordinal, refused));
                    }
                    Err(refused) => {
                        if !self.names_a_typed_action(ordinal)
                            || self.names_an_undeclared_qualified_action(ordinal)
                        {
                            return Err((ordinal, refused));
                        }
                        self.pending.insert(ordinal, refused.error.to_string());
                    }
                }
            }
            if !changed {
                return Ok(());
            }
        }
    }

    /// Whether a candidate names a per-tool action. A rule over the fixed vocabulary alone cannot
    /// become valid when a tool schema stages, so its load error is a refusal and not a pending state.
    /// A history reference counts, because a rule that only reads one still waits for that schema.
    fn names_a_typed_action(&self, ordinal: usize) -> bool {
        let mut typed = BTreeSet::new();
        if let Some(candidate) = self.candidates.get(ordinal) {
            collect_typed_actions(
                &candidate.expanded_source,
                HistoryReferences::Named,
                &mut typed,
            );
        }
        !typed.is_empty()
    }

    /// Whether a candidate names a qualified action, such as `Tool::git::Action::"push"`, that no
    /// tool grammar schema declares. No MCP schema can declare one, so the rule cannot wait for it.
    fn names_an_undeclared_qualified_action(&self, ordinal: usize) -> bool {
        let Some(candidate) = self.candidates.get(ordinal) else {
            return false;
        };
        let named = qualified_actions(&candidate.expanded_source);
        if named.is_empty() {
            return false;
        }
        let Ok(schema) = composed_action_schema(&self.grammar_schemas, &[]) else {
            return true;
        };
        named
            .iter()
            .any(|action| !schema.cedar.actions().any(|declared| declared == action))
    }

    /// The rule that candidate `ordinal` stands for, with the `@id` its expanded source carries.
    fn rule(&self, ordinal: usize) -> RuleRef {
        let id = self
            .candidates
            .get(ordinal)
            .and_then(|candidate| annotated_id(&candidate.expanded_source));
        RuleRef::new(ordinal, id)
    }

    fn mark_all_ready(&mut self) {
        self.ready = self
            .candidates
            .iter()
            .map(|candidate| candidate.ordinal)
            .collect();
        self.pending.clear();
    }

    fn named_schemas(&self) -> Vec<(&str, &str)> {
        self.schemas
            .iter()
            .map(|(server, source)| (server.as_str(), source.as_str()))
            .collect()
    }

    fn schema_sources(&self) -> Vec<String> {
        self.schemas.values().cloned().collect()
    }
}

/// Parse and macro-expand an authored bundle into one candidate per rule.
fn candidates(source: &str) -> Result<Vec<CandidatePolicy>, Refused> {
    Ok(expand_policy_source(source)?
        .into_iter()
        .enumerate()
        .map(|(ordinal, policy)| CandidatePolicy {
            ordinal,
            expanded_source: policy.source,
            head_tools: policy.head_tools,
        })
        .collect())
}

/// The typed `(namespace, tool)` pairs whose calls a proposal holds back, from each pending rule's
/// decoded head, from a scan of its rendered text, and from the tool its conditions pin to
/// literals. A tool that a pending rule only reads from history is left out: that rule decides no
/// call to it, so holding it would refuse a healthy server's tool over another rule's mistake
/// (docs/design/decisions.md#a-server-whose-discovery-a-policy-denies-degrades-alone).
fn pending_typed_tools(proposal: &ProposalState) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for &ordinal in proposal.pending.keys() {
        if let Some(candidate) = proposal.candidates.get(ordinal) {
            out.extend(candidate.head_tools.iter().cloned());
            collect_typed_actions(
                &candidate.expanded_source,
                HistoryReferences::Skipped,
                &mut out,
            );
            out.extend(pinned_tool_action(candidate));
        }
    }
    out
}

/// The one `(namespace, tool)` a rule's conditions pin to literals, through `context.input.server`
/// and `context.input.tool`. Such a rule decides exactly that call, so the hold covers it. `None`
/// for a rule whose head already names a typed tool, because the head states that rule's whole
/// reach and a pin beside it can only contradict it. `None` too unless one server and one tool
/// survive, because any other count leaves the set of calls the rule decides wider than the pins
/// state.
fn pinned_tool_action(candidate: &CandidatePolicy) -> Option<(String, String)> {
    if !candidate.head_tools.is_empty() {
        return None;
    }
    let mut servers = BTreeSet::new();
    let mut tools = BTreeSet::new();
    for condition in rule_conditions(&candidate.expanded_source) {
        for atom in conjuncts(&condition) {
            if let Some(name) = pinned_literal(atom, "server") {
                servers.insert(name.to_string());
            }
            if let Some(name) = pinned_literal(atom, "tool") {
                tools.insert(name.to_string());
            }
        }
    }
    Some((
        mcp_action_namespace(single(&servers)?),
        single(&tools)?.to_string(),
    ))
}

/// Each node a condition joins with `&&`, so that every one of them has to hold and a pin read out
/// of one is a pin the rule requires. A node under any other operator stays whole, and
/// `pinned_literal` then declines it.
fn conjuncts(condition: &serde_json::Value) -> Vec<&serde_json::Value> {
    match condition.get("&&") {
        Some(both) => {
            let mut out = Vec::new();
            for side in ["left", "right"] {
                if let Some(operand) = both.get(side) {
                    out.extend(conjuncts(operand));
                }
            }
            out
        }
        None => vec![condition],
    }
}

/// The string literal an atom compares `context.input.<attribute>` to with `==`, in either operand
/// order. `None` for every other node, so a negation, a disjunction, an `if`, a `like`, a set
/// membership, and a comparison of comparisons each state no pin. An `unless` condition reaches
/// here as a negation, so it states none either.
fn pinned_literal<'a>(atom: &'a serde_json::Value, attribute: &str) -> Option<&'a str> {
    let equality = atom.get("==")?;
    let (left, right) = (equality.get("left")?, equality.get("right")?);
    if reads_input(left, attribute) {
        literal(right)
    } else if reads_input(right, attribute) {
        literal(left)
    } else {
        None
    }
}

/// Whether a node is exactly the read `context.input.<attribute>`.
fn reads_input(node: &serde_json::Value, attribute: &str) -> bool {
    let outer = node.get(".");
    let names = |access: Option<&serde_json::Value>, attr: &str| {
        access.is_some_and(|access| access.get("attr").and_then(|a| a.as_str()) == Some(attr))
    };
    names(outer, attribute)
        && outer
            .and_then(|access| access.get("left"))
            .map(|input| {
                names(input.get("."), "input")
                    && input
                        .get(".")
                        .and_then(|access| access.get("left"))
                        .and_then(|root| root.get("Var"))
                        .and_then(|var| var.as_str())
                        == Some("context")
            })
            .unwrap_or(false)
}

/// The string a literal node carries, already decoded by the parse.
fn literal(node: &serde_json::Value) -> Option<&str> {
    node.get("Value")?.as_str()
}

/// The only name in `names`, or `None` when it holds none or several.
fn single(names: &BTreeSet<String>) -> Option<&str> {
    match names.iter().next() {
        Some(name) if names.len() == 1 => Some(name.as_str()),
        _ => None,
    }
}

/// Every `(namespace, tool)` one candidate names, in its head, in a condition, or through a
/// `when temporal` history reference.
fn named_typed_tools(candidate: &CandidatePolicy) -> BTreeSet<(String, String)> {
    let mut out: BTreeSet<(String, String)> = candidate.head_tools.iter().cloned().collect();
    collect_typed_actions(
        &candidate.expanded_source,
        HistoryReferences::Named,
        &mut out,
    );
    out
}

/// The servers each pending rule still waits for, which is what the operator must fix. A rule waits
/// for every tool it names to be declared, so an undeclared tool names its own server. A rule that
/// stays pending for another reason — an argument name or a type its server declares differently —
/// leaves every tool declared, and then every server it names is what it waits on. Falling back
/// that way is what keeps the warning from going silent, because `names_a_typed_action` parks a
/// rule only when it names at least one typed tool, so no pending rule contributes nothing.
fn servers_a_pending_rule_waits_for(
    proposal: &ProposalState,
    engine: &DogwoodEngine,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for &ordinal in proposal.pending.keys() {
        let Some(candidate) = proposal.candidates.get(ordinal) else {
            continue;
        };
        let named = named_typed_tools(candidate);
        let undeclared: BTreeSet<String> = named
            .iter()
            .filter(|(namespace, tool)| !declares(engine, namespace, tool))
            .map(|(namespace, _)| namespace.clone())
            .collect();
        if undeclared.is_empty() {
            out.extend(named.into_iter().map(|(namespace, _)| namespace));
        } else {
            out.extend(undeclared);
        }
    }
    out
}

/// Whether the committed schema declares `<namespace>::Action::"<tool>"`. A name the engine cannot
/// parse counts as undeclared, so the server reaches the warning rather than going quiet.
fn declares(engine: &DogwoodEngine, namespace: &str, tool: &str) -> bool {
    let identity = ActionIdentity::McpTool {
        namespace: namespace.to_string(),
        tool: tool.to_string(),
    };
    EntityUid::from_str(&identity.observer_action())
        .map(|action| engine.declares_tool_action(&action))
        .unwrap_or(false)
}

/// Whether a scan keeps the tool names that only a `when temporal` history reference spells.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HistoryReferences {
    /// Keep them: such a rule still needs that tool's schema before it can load.
    Named,
    /// Drop them: such a rule reads that tool's history and decides no call to it.
    Skipped,
}

/// Extracts every `<ns>::Action::"<tool>"` typed action from a macro-expanded policy source,
/// excluding the fixed `Box::Action` vocabulary and every qualified namespace, such as a tool
/// grammar's `Tool::<name>`, which no MCP schema declares. It keeps one that only a condition
/// names, and treats a `when temporal` history reference as `references` says. The scan finds the
/// candidate text, and `decoded_tool_action` is the one decoder that says which tool it names.
fn collect_typed_actions(
    source: &str,
    references: HistoryReferences,
    out: &mut BTreeSet<(String, String)>,
) {
    const MARKER: &str = "::Action::\"";
    let mut rest = source;
    while let Some(pos) = rest.find(MARKER) {
        let namespace: String = rest[..pos]
            .chars()
            .rev()
            .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        let qualified = rest[..pos - namespace.len()].ends_with("::");
        let after = &rest[pos + MARKER.len()..];
        match closing_quote(after) {
            Some(end) => {
                let literal = &after[..end];
                rest = &after[end + 1..];
                // A name that `::` follows is an event a `when temporal` predicate reads
                // (`::request{`, `::response{`, `::error{`), and not an action the rule decides.
                let history = rest.starts_with("::");
                let keep = !history || references == HistoryReferences::Named;
                if keep && !qualified {
                    out.extend(decoded_tool_action(&namespace, literal));
                }
            }
            None => break,
        }
    }
}

/// Every action under a qualified namespace, such as `Tool::git::Action::"push"`, in `source`.
fn qualified_actions(source: &str) -> Vec<EntityUid> {
    const MARKER: &str = "::Action::\"";
    let mut out = Vec::new();
    let mut rest = source;
    while let Some(pos) = rest.find(MARKER) {
        let start = rest[..pos]
            .rfind(|character: char| {
                !(character.is_ascii_alphanumeric() || character == '_' || character == ':')
            })
            .map_or(0, |index| index + 1);
        let namespace = &rest[start..pos];
        let after = &rest[pos + MARKER.len()..];
        let Some(end) = closing_quote(after) else {
            break;
        };
        if namespace.contains("::")
            && let Ok(action) =
                EntityUid::from_str(&format!("{namespace}::Action::\"{}\"", &after[..end]))
        {
            out.push(action);
        }
        rest = &after[end + 1..];
    }
    out
}

/// The offset of the quote that ends a Cedar string literal, where `\` escapes the character
/// after it.
fn closing_quote(literal: &str) -> Option<usize> {
    let mut characters = literal.char_indices();
    while let Some((offset, character)) = characters.next() {
        match character {
            '\\' => {
                characters.next();
            }
            '"' => return Some(offset),
            _ => {}
        }
    }
    None
}

/// The `(namespace, tool)` that a rendered `<ns>::Action::"<literal>"` names, through the decoder
/// a parsed head uses, or `None` for the fixed `Box::Action` vocabulary.
fn decoded_tool_action(namespace: &str, literal: &str) -> Option<(String, String)> {
    if namespace.is_empty() {
        return None;
    }
    let action = EntityUid::from_str(&format!("{namespace}::Action::\"{literal}\"")).ok()?;
    mcp_tool_action(&action)
}

/// What `open_staged` refuses in `sources`, or its warnings and the rules it holds pending.
pub(super) fn check_staged(
    operator: &Operator,
    sources: &[Policy],
    grammar_schemas: Vec<String>,
) -> Result<(Vec<PolicyWarning>, Vec<RuleRef>), Vec<Finding>> {
    let candidates = candidates(&authored(sources)).map_err(|refused| refused.findings)?;
    let mut proposal = ProposalState {
        operator: operator.clone(),
        candidates,
        grammar_schemas,
        schemas: BTreeMap::new(),
        ready: BTreeSet::new(),
        pending: BTreeMap::new(),
    };
    let unlocated = |findings: Vec<Finding>| -> Vec<Finding> {
        findings.into_iter().map(Finding::without_span).collect()
    };
    refuse_input_reads_before_discovery(&proposal.complete_policy_set())
        .map_err(|refused| unlocated(refused.findings))?;
    match check_canonical_policy_set(
        &proposal.complete_policy_set(),
        &proposal.grammar_schemas,
        &[],
        operator,
        &[],
    ) {
        Ok((_, warnings)) => return Ok((warnings, Vec::new())),
        Err(refused) if is_inert(&refused.error) => return Err(unlocated(refused.findings)),
        Err(_) => {}
    }
    if let Err((ordinal, refused)) = proposal.classify_naming(&[]) {
        return Err(unlocated(refused.findings)
            .into_iter()
            .map(|finding| {
                if finding.rules().is_empty() {
                    finding.with_rules(vec![proposal.rule(ordinal)])
                } else {
                    finding
                }
            })
            .collect());
    }
    let (_, warnings) = check_canonical_policy_set(
        &proposal.ready_policy_set(),
        &proposal.grammar_schemas,
        &[],
        operator,
        &proposal.ready_positions(),
    )
    .map_err(|refused| unlocated(refused.findings))?;
    let unchecked = proposal
        .pending
        .keys()
        .map(|ordinal| proposal.rule(*ordinal))
        .collect();
    Ok((warnings, unchecked))
}

/// Whether a refusal names a rule that no discovered schema can make valid.
fn is_inert(error: &PolicyError) -> bool {
    matches!(
        error,
        PolicyError::Spelling(_)
            | PolicyError::InputAcrossFamilies(_)
            | PolicyError::SharedRuleId(_)
            | PolicyError::ReservedAction(_)
            | PolicyError::InertTemporalPermit(_)
            | PolicyError::UnsupportedClause(_)
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use dogwood_local_engine::fault_injection::{FaultInjector, FaultPoint};
    use dogwood_local_engine::{
        DurableLog, DurableTemporalEngine, PolicySet, Snapshot, SnapshotPayload, Write,
    };

    use super::*;
    use crate::{Delivery, DenyReason, Request};

    fn source(text: &str) -> Vec<Policy> {
        vec![Policy {
            origin: PathBuf::from("candidate.dw"),
            text: text.to_string(),
        }]
    }

    /// A policy that opens `Discovering`: it constrains `alpha`'s `read` tool (a typed rule that
    /// still needs alpha's schema) while permitting alpha's `mcp:call`, so `tools/list` is allowed
    /// and the contradiction check passes. The `read` tool stays pending until it stages.
    fn staged_source() -> Vec<Policy> {
        source(
            r#"permit(principal, action == alpha::Action::"read", resource);
permit(principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "alpha" };"#,
        )
    }

    fn generated(server: &str, tool: &str, field: &str) -> String {
        crate::generate_mcp_schema(
            server,
            &format!(
                r#"{{
                    "result": {{
                        "tools": [{{
                            "name": "{tool}",
                            "inputSchema": {{
                                "type": "object",
                                "properties": {{"{field}": {{"type": "string"}}}},
                                "required": ["{field}"]
                            }}
                        }}]
                    }}
                }}"#
            ),
        )
        .expect("the MCP schema generates")
    }

    fn governed() -> GovernedBox {
        GovernedBox::assigned("test-box")
    }

    fn shell_request() -> Request<'static> {
        Request::ShellExec {
            command: "printf ready",
            program: "printf",
            args: &[],
            cwd: "/work",
        }
    }

    fn decide(authority: &Authority, request: &Request<'_>) -> Decision {
        authority
            .decide(
                &governed(),
                &Principal::agent(),
                ActionRequest::Request(request),
            )
            .0
    }

    fn submitted_http_request(authority: &Authority) -> RequestId {
        authority
            .decide(
                &governed(),
                &Principal::agent(),
                ActionRequest::Request(&Request::Http {
                    host: "api.example.com",
                    port: 443,
                    method: "POST",
                    path: "/v1",
                    body_bytes: 1,
                    intercepted: true,
                }),
            )
            .1
            .expect("the fixture request is submitted")
    }

    fn http_outcome() -> Outcome<'static> {
        Outcome::Http {
            host: "api.example.com",
            port: 443,
            method: "POST",
            path: "/v1",
            delivery: Delivery::Completed { bytes: 1 },
            status: Some(200),
            intercepted: true,
        }
    }

    fn poison<T>(mutex: &Mutex<T>) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = mutex.lock().expect("the mutex is not yet poisoned");
            panic!("simulated state transition panic");
        }));
        assert!(result.is_err(), "the poison panic must occur");
    }

    #[test]
    fn fixed_authority_rejects_runtime_schema_proposals() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_complete(
            source(r#"permit(principal, action == Box::Action::"shell:exec", resource);"#),
            &[],
            &history.path().join("dogwood.redb"),
        )
        .expect("the fixed authority opens");

        assert_eq!(
            authority
                .stage_mcp_schema("alpha", generated("alpha", "read", "path"))
                .expect("the fixed-authority refusal is not terminal"),
            SchemaStage::Rejected {
                reason: "the authority was not opened for runtime staging".to_string(),
            }
        );
    }

    #[test]
    fn proposal_lock_poison_is_terminal() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_staged(
            &Operator::unanchored(),
            staged_source(),
            &history.path().join("dogwood.redb"),
        )
        .expect("the staged authority opens");
        poison(&authority.proposal);

        let error = authority
            .stage_mcp_schema("alpha", generated("alpha", "read", "path"))
            .expect_err("a poisoned proposal lock is terminal");
        assert!(matches!(
            error,
            PolicyStagingError::Durable(ref reason) if reason.contains("staging lock poisoned")
        ));
    }

    #[test]
    fn live_authority_lock_poison_is_terminal_for_staging() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_staged(
            &Operator::unanchored(),
            staged_source(),
            &history.path().join("dogwood.redb"),
        )
        .expect("the staged authority opens");
        poison(&authority.live);

        let error = authority
            .stage_mcp_schema("alpha", generated("alpha", "read", "path"))
            .expect_err("a poisoned live-authority lock is terminal");
        assert!(matches!(
            error,
            PolicyStagingError::Durable(ref reason) if reason.contains("authority lock poisoned")
        ));
    }

    #[test]
    fn scope_lock_poison_is_terminal_for_staging() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_staged(
            &Operator::unanchored(),
            staged_source(),
            &history.path().join("dogwood.redb"),
        )
        .expect("the staged authority opens");
        authority
            .live
            .lock()
            .expect("live authority lock")
            .engine
            .poison_scope_for_test();

        let error = authority
            .stage_mcp_schema("alpha", generated("alpha", "read", "path"))
            .expect_err("a poisoned Dogwood scope is terminal");
        assert!(matches!(
            error,
            PolicyStagingError::Durable(ref reason)
                if reason.contains("dogwood durable engine lock poisoned")
        ));
    }

    #[test]
    fn durable_commit_error_is_terminal() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_staged(
            &Operator::unanchored(),
            staged_source(),
            &history.path().join("dogwood.redb"),
        )
        .expect("the staged authority opens");
        authority
            .live
            .lock()
            .expect("live authority lock")
            .engine
            .poison_scope_for_test();

        assert!(matches!(
            authority.stage_mcp_schema("alpha", generated("alpha", "read", "path")),
            Err(PolicyStagingError::Durable(_))
        ));
    }

    #[test]
    fn a_grammar_action_decides_the_same_while_mcp_discovery_holds_or_degrades_a_tool() {
        let grammar = crate::grammar::Grammar::load(std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/grammars/valid/git.grammar.toml"
        )))
        .expect("the git grammar loads");
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_complete_with_grammars(
            source(
                r#"permit (principal, action == Tool::git::Action::"push", resource);
                forbid (principal, action == Tool::git::Action::"push", resource)
                when { context.input.force };"#,
            ),
            &[grammar.schema()],
            &[],
            &history.path().join("dogwood.redb"),
        )
        .expect("authority opens");
        let decide = |words: &[&str]| {
            let args: Vec<String> = words.iter().map(ToString::to_string).collect();
            let request = crate::grammar::GrammarInvocation::new(
                &grammar,
                "git",
                &crate::grammar::ProgramFile::fixed("/usr/bin/git", 1),
                None,
                "/work",
                &args,
                &[],
            )
            .request();
            authority
                .decide(
                    &governed(),
                    &Principal::agent(),
                    ActionRequest::Grammar(&request),
                )
                .0
        };
        let push = ["push", "origin", "main"];
        let forced = ["push", "--force", "origin", "main"];
        let before = (decide(&push), decide(&forced));

        {
            let mut live = authority.live.lock().expect("the live authority lock");
            live.readiness = Readiness::Discovering;
            let held = ("Tool::git".to_string(), "push".to_string());
            live.pending_tools.insert(held.clone());
            live.degraded_tools.insert(held);
        }
        let during = (decide(&push), decide(&forced));

        assert!(before.0.is_allow(), "{:?}", before.0);
        assert!(
            matches!(
                before.1,
                Decision::Deny {
                    reason: DenyReason::Forbidden,
                    ..
                }
            ),
            "{:?}",
            before.1
        );
        assert_eq!(during, before);
    }

    #[test]
    fn live_authority_lock_poison_denies_decisions() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_complete(
            source(r#"permit(principal, action == Box::Action::"shell:exec", resource);"#),
            &[],
            &history.path().join("dogwood.redb"),
        )
        .expect("the fixed authority opens");
        poison(&authority.live);

        assert!(matches!(
            decide(&authority, &shell_request()),
            Decision::Deny {
                reason: DenyReason::InternalFault,
                ..
            }
        ));
    }

    #[test]
    fn live_authority_lock_poison_refuses_records() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_complete(
            source(r#"permit(principal, action == Box::Action::"http:request", resource);"#),
            &[],
            &history.path().join("dogwood.redb"),
        )
        .expect("the fixed authority opens");
        let request_id = submitted_http_request(&authority);
        poison(&authority.live);

        let error = authority
            .record(
                &governed(),
                &Principal::agent(),
                &request_id,
                &http_outcome(),
            )
            .expect_err("a poisoned live-authority lock must refuse records");
        assert!(error.to_string().contains("authority lock poisoned"));
    }

    #[test]
    fn scope_lock_poison_refuses_records() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_complete(
            source(r#"permit(principal, action == Box::Action::"http:request", resource);"#),
            &[],
            &history.path().join("dogwood.redb"),
        )
        .expect("the fixed authority opens");
        let request_id = submitted_http_request(&authority);
        authority
            .live
            .lock()
            .expect("live authority lock")
            .engine
            .poison_scope_for_test();

        let error = authority
            .record(
                &governed(),
                &Principal::agent(),
                &request_id,
                &http_outcome(),
            )
            .expect_err("a poisoned Dogwood scope must refuse records");
        assert!(
            error
                .to_string()
                .contains("dogwood durable engine lock poisoned")
        );
    }

    #[test]
    fn fixed_open_refuses_unrecoverable_history() {
        let history = tempfile::tempdir().expect("history directory");
        let path = history.path().join("dogwood.redb");
        std::fs::write(&path, b"not a redb database").expect("the corrupt history writes");

        assert!(
            Authority::open_complete(
                source(r#"permit(principal, action == Box::Action::"shell:exec", resource);"#),
                &[],
                &path,
            )
            .is_err(),
            "fixed open must refuse corrupt durable history"
        );
    }

    #[test]
    fn complete_validation_overrides_stale_candidate_diagnostics() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_staged(
            &Operator::unanchored(),
            source(r#"permit(principal, action == Box::Action::"shell:exec", resource);"#),
            &history.path().join("dogwood.redb"),
        )
        .expect("the canonical authority opens");

        {
            let mut proposal = authority.proposal.lock().expect("proposal lock");
            let state = proposal.as_mut().expect("runtime proposal state");
            state.ready.clear();
            state.pending.insert(0, "stale diagnostic".to_string());
            authority
                .live
                .lock()
                .expect("live authority lock")
                .readiness = Readiness::Discovering;
        }

        assert_eq!(
            authority
                .stage_mcp_schema("alpha", generated("alpha", "read", "path"))
                .expect("the complete bundle stages"),
            SchemaStage::Accepted {
                authority_ready: true,
            },
            "candidate diagnostics must not suppress complete-bundle validation"
        );
    }

    #[test]
    fn durable_rejection_refuses_only_the_schema_proposal() {
        let history = tempfile::tempdir().expect("history directory");
        let path = history.path().join("dogwood.redb");
        // The pre-populated store holds the whole schema-independent subset (the `shell:exec`
        // permit and the coarse `alpha` permit), so `open_staged`'s subset commit reinstalls only
        // unchanged policies — it mints no ordinal and succeeds into `Discovering` even on the
        // exhausted store. Only the staged typed rule below needs a fresh ordinal, so the rejection
        // bites at `stage_mcp_schema`, which is what this test pins.
        let canonical = source(
            r#"permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "alpha" };"#,
        );
        {
            let authority =
                Authority::open_complete(canonical.clone(), &[], &path).expect("authority opens");
            assert!(decide(&authority, &shell_request()).is_allow());
        }
        {
            let mut durable =
                DurableTemporalEngine::open(&path, 10_000).expect("durable policy opens");
            durable.checkpoint().expect("history checkpoints");
        }
        {
            let log = DurableLog::open(&path).expect("durable log opens");
            let snapshot = log
                .get_snapshot()
                .expect("history snapshot reads")
                .expect("history snapshot exists");
            let mut payload =
                SnapshotPayload::decode(&snapshot.payload).expect("history snapshot decodes");
            let entries = payload.bundle.policies.entries().cloned().collect();
            payload.bundle.policies = PolicySet::from_recorded(entries, u64::MAX);
            let exhausted = Snapshot {
                up_to_offset: snapshot.up_to_offset,
                payload: payload.encode().expect("exhausted snapshot encodes"),
            };
            log.commit(&[Write::Snapshot(&exhausted)])
                .expect("exhausted cursor stores");
        }
        let before = {
            let snapshot = DurableLog::open(&path)
                .expect("durable log opens")
                .get_snapshot()
                .expect("history snapshot reads");
            let durable =
                DurableTemporalEngine::open(&path, 10_000).expect("exhausted store opens");
            (
                durable.list(),
                durable.policy_source(),
                durable.action_schema(),
                durable.event_schema(),
                durable.log_offset(),
                snapshot,
            )
        };

        let mut staged_sources = canonical;
        staged_sources.push(Policy {
            origin: PathBuf::from("alpha.dw"),
            // Only the typed rule is new; the coarse alpha permit already lives in `canonical`, so
            // the subset the box commits at open is unchanged and mints no ordinal. This one typed
            // rule is the sole new policy, so the exhausted ordinal space rejects it at stage time.
            text: r#"permit(principal, action == alpha::Action::"read", resource);"#.to_string(),
        });
        let authority = Authority::open_staged(&Operator::unanchored(), staged_sources, &path)
            .expect("staged policy opens");
        let result = authority
            .stage_mcp_schema("alpha", generated("alpha", "read", "path"))
            .expect("durable rejection is proposal-specific");
        assert!(
            matches!(
                result,
                SchemaStage::Rejected { ref reason }
                    if reason.contains("policy ordinal space exhausted")
            ),
            "the durable rejection must become a rejected schema proposal: {result:?}"
        );
        // The rejected proposal left alpha's schema unstaged, so its `read` tool is still held:
        // the authority did not silently advance to enforcing an unstaged rule.
        let arguments = serde_json::json!({ "path": "x" });
        let held = Request::McpCall {
            server: "alpha",
            method: "tools/call",
            tool: Some("read"),
            prompt: None,
            uri: None,
            arguments: Some(&arguments),
        };
        assert!(matches!(
            decide(&authority, &held),
            Decision::Deny {
                reason: DenyReason::PolicyPending,
                ..
            }
        ));
        drop(authority);

        let after = {
            let snapshot = DurableLog::open(&path)
                .expect("durable log opens")
                .get_snapshot()
                .expect("history snapshot reads");
            let durable = DurableTemporalEngine::open(&path, 10_000).expect("rejected store opens");
            (
                durable.list(),
                durable.policy_source(),
                durable.action_schema(),
                durable.event_schema(),
                durable.log_offset(),
                snapshot,
            )
        };
        assert_eq!(
            after, before,
            "durable rejection must preserve policy, schemas, log position, and history"
        );
    }

    // ---- `Discovering`, the pending-tool guard, and the `tools/list` contradiction ----

    /// A policy that opens `Discovering`: a coarse `alpha` permit (so `tools/list` is allowed and
    /// nothing contradicts) plus a typed `alpha::read` rule that stays pending until its schema
    /// stages, plus a `shell:exec` permit that lets a non-typed request prove the subset is served.
    fn discovering_source() -> Vec<Policy> {
        source(
            r#"permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "alpha" };
permit(principal, action == alpha::Action::"read", resource);"#,
        )
    }

    fn alpha_tool_call(arguments: &serde_json::Value) -> Request<'_> {
        Request::McpCall {
            server: "alpha",
            method: "tools/call",
            tool: Some("read"),
            prompt: None,
            uri: None,
            arguments: Some(arguments),
        }
    }

    fn alpha_tools_list() -> Request<'static> {
        Request::McpCall {
            server: "alpha",
            method: "tools/list",
            tool: None,
            prompt: None,
            uri: None,
            arguments: None,
        }
    }

    /// A rule over the fixed vocabulary that fails validation is refused at staging. No tool
    /// schema can repair it, so setting it aside as pending would drop it when discovery ends.
    #[test]
    fn an_invalid_fixed_vocabulary_rule_is_refused_and_not_set_aside() {
        let history = tempfile::tempdir().expect("history directory");
        let mut policies = discovering_source();
        policies.push(Policy {
            origin: PathBuf::from("misspelled.dw"),
            text: r#"forbid(principal, action == Box::Action::"http:request", resource)
when temporal {
  exists (n: Long). (
    (count for (t: Timepoint). where (
      formerly within 60s (
        Box::Action::"http:request"::response{ input.status: 500 } && tp(t)
      )
    )) == n
    && n >= 3
  )
};"#
            .to_string(),
        });
        let refused = Authority::open_staged(
            &Operator::unanchored(),
            policies,
            &history.path().join("dogwood.redb"),
        );
        match refused {
            Ok(_) => panic!("a misspelled field on a fixed action must refuse the load"),
            Err(PolicyStagingError::Policy(error)) => {
                let reason = error.to_string();
                assert!(reason.contains("input.status"), "{reason}");
                assert!(reason.contains("output.status"), "{reason}");
            }
            Err(other) => panic!("expected a policy load error, got {other}"),
        }
    }

    /// Opening with a typed rule whose schema has not staged serves the schema-independent
    /// subset (`Discovering`), holds the pending tool transiently, and does not deny everything.
    #[test]
    fn a_typed_rule_opens_discovering_and_holds_only_its_pending_tool() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_staged(
            &Operator::unanchored(),
            discovering_source(),
            &history.path().join("dogwood.redb"),
        )
        .expect("a typed rule with tools/list permitted opens Discovering");
        // The pending typed tool is held with a transient PolicyPending (the pending-tool guard).
        let arguments = serde_json::json!({ "path": "x" });
        assert!(matches!(
            decide(&authority, &alpha_tool_call(&arguments)),
            Decision::Deny {
                reason: DenyReason::PolicyPending,
                ..
            }
        ));
        // A non-typed request is served from the subset — proof this is Discovering, not deny-all.
        assert!(decide(&authority, &shell_request()).is_allow());
        // A coarse (non-typed) mcp:call such as tools/list is likewise served, not held.
        assert!(decide(&authority, &alpha_tools_list()).is_allow());
    }

    /// The pending tool is held until its schema stages, then the typed rule enforces it.
    #[test]
    fn discovering_holds_a_pending_tool_then_allows_it_after_stage() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_staged(
            &Operator::unanchored(),
            discovering_source(),
            &history.path().join("dogwood.redb"),
        )
        .expect("opens Discovering");
        let in_bounds = serde_json::json!({ "path": "x" });
        assert!(
            matches!(
                decide(&authority, &alpha_tool_call(&in_bounds)),
                Decision::Deny {
                    reason: DenyReason::PolicyPending,
                    ..
                }
            ),
            "the tool is held while its schema is pending"
        );
        assert_eq!(
            authority
                .stage_mcp_schema("alpha", generated("alpha", "read", "path"))
                .expect("alpha's schema stages"),
            SchemaStage::Accepted {
                authority_ready: true,
            }
        );
        assert!(
            decide(&authority, &alpha_tool_call(&in_bounds)).is_allow(),
            "once staged, the typed rule enforces and the call is allowed"
        );
    }

    /// A `tools/list` forbid for a server that also has a typed rule LOADS (no refusal). The
    /// box opens `Discovering`; at `finish_mcp_discovery` that server is degraded — named in the
    /// return, and its tool call denied fail-closed.
    #[test]
    fn degrades_a_server_whose_explicit_toolslist_forbid_leaves_a_typed_rule() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_staged(&Operator::unanchored(),
            source(
                r#"permit(principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "alpha" };
forbid(principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "alpha" && context.input.method == "tools/list" };
permit(principal, action == alpha::Action::"read", resource);"#,
            ),
            &history.path().join("dogwood.redb"),
        )
        .expect(
            "a tools/list-denied server with a typed rule loads, with no refusal \
             (docs/design/decisions.md#a-server-whose-discovery-a-policy-denies-degrades-alone)",
        );
        let degraded = authority
            .finish_mcp_discovery()
            .expect("finish degrades the server rather than fataling");
        assert_eq!(
            degraded,
            vec!["alpha".to_string()],
            "the degraded server is named in the finish result"
        );
        assert!(
            !decide(&authority, &alpha_tool_call(&serde_json::json!({}))).is_allow(),
            "a degraded server's tool call is denied fail-closed, not riding the coarse permit"
        );
    }

    /// Robust degradation: the handshake-only recipe (no `tools/list` permit at all, so it is
    /// default-denied) plus a typed rule also degrades — a syntactic forbid-scan would miss it.
    #[test]
    fn degrades_a_default_denied_toolslist_with_a_typed_rule() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_staged(&Operator::unanchored(),
            source(
                r#"permit(principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "alpha" && context.input.method == "initialize" };
permit(principal, action == alpha::Action::"read", resource);"#,
            ),
            &history.path().join("dogwood.redb"),
        )
        .expect("a default-denied tools/list with a typed rule loads");
        let degraded = authority
            .finish_mcp_discovery()
            .expect("finish degrades rather than fataling");
        assert_eq!(degraded, vec!["alpha".to_string()]);
        assert!(
            !decide(&authority, &alpha_tool_call(&serde_json::json!({}))).is_allow(),
            "the degraded tool call is denied fail-closed"
        );
    }

    /// Normalization: a hyphenated server name round-trips through `cedar_identifier`
    /// (`issues-mcp` -> `issues_mcp`), so a `tools/call` to it is matched and denied fail-closed.
    #[test]
    fn degrades_a_hyphenated_server_and_denies_its_tool() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_staged(&Operator::unanchored(),
            source(
                r#"permit(principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "issues-mcp" };
forbid(principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "issues-mcp" && context.input.method == "tools/list" };
permit(principal, action == issues_mcp::Action::"search", resource);"#,
            ),
            &history.path().join("dogwood.redb"),
        )
        .expect("a hyphenated tools/list-denied server with a typed rule loads");
        let degraded = authority
            .finish_mcp_discovery()
            .expect("finish degrades rather than fataling");
        assert_eq!(
            degraded,
            vec!["issues_mcp".to_string()],
            "the degraded set names the normalized server namespace"
        );
        let call = Request::McpCall {
            server: "issues-mcp",
            method: "tools/call",
            tool: Some("search"),
            prompt: None,
            uri: None,
            arguments: Some(&serde_json::Value::Null),
        };
        assert!(
            !authority
                .decide(
                    &governed(),
                    &Principal::agent(),
                    ActionRequest::Request(&call)
                )
                .0
                .is_allow(),
            "a hyphenated degraded server's tool call is denied fail-closed"
        );
    }

    /// No false positive: a `tools/list` forbid ALONE (no typed rule) loads and enforces the
    /// denial — nothing to contradict.
    #[test]
    fn a_toolslist_forbid_without_a_typed_rule_loads_and_denies() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_staged(&Operator::unanchored(),
            source(
                r#"permit(principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "alpha" };
forbid(principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "alpha" && context.input.method == "tools/list" };"#,
            ),
            &history.path().join("dogwood.redb"),
        )
        .expect("a tools/list forbid without a typed rule loads");
        assert!(
            !decide(&authority, &alpha_tools_list()).is_allow(),
            "tools/list is denied by the forbid, and the box serves the decision"
        );
    }

    /// Fail-closed: if the schema-independent subset commit itself is rejected (an exhausted
    /// durable store), `open_staged` fails closed rather than opening a box that serves nothing.
    #[test]
    fn open_staged_fails_closed_when_the_subset_commit_is_rejected() {
        let history = tempfile::tempdir().expect("history directory");
        let path = history.path().join("dogwood.redb");
        // A store holding one shell:exec permit, then exhausted.
        {
            let authority = Authority::open_complete(
                source(r#"permit(principal, action == Box::Action::"shell:exec", resource);"#),
                &[],
                &path,
            )
            .expect("authority opens");
            assert!(decide(&authority, &shell_request()).is_allow());
        }
        {
            let mut durable =
                DurableTemporalEngine::open(&path, 10_000).expect("durable policy opens");
            durable.checkpoint().expect("history checkpoints");
        }
        {
            let log = DurableLog::open(&path).expect("durable log opens");
            let snapshot = log
                .get_snapshot()
                .expect("history snapshot reads")
                .expect("history snapshot exists");
            let mut payload =
                SnapshotPayload::decode(&snapshot.payload).expect("history snapshot decodes");
            let entries = payload.bundle.policies.entries().cloned().collect();
            payload.bundle.policies = PolicySet::from_recorded(entries, u64::MAX);
            let exhausted = Snapshot {
                up_to_offset: snapshot.up_to_offset,
                payload: payload.encode().expect("exhausted snapshot encodes"),
            };
            log.commit(&[Write::Snapshot(&exhausted)])
                .expect("exhausted cursor stores");
        }
        // The staged subset adds a NEW coarse alpha permit, so the subset commit must mint an
        // ordinal — which the exhausted store rejects. Open fails closed rather than half-serving.
        let sources = source(
            r#"permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "alpha" };
permit(principal, action == alpha::Action::"read", resource);"#,
        );
        let error = Authority::open_staged(&Operator::unanchored(), sources, &path)
            .err()
            .expect("an exhausted subset commit fails open closed");
        assert!(
            matches!(
                error,
                PolicyStagingError::Durable(ref reason) if reason.contains("ordinal space exhausted")
            ),
            "open must fail closed on an exhausted subset commit: {error:?}"
        );
    }

    /// The formerly-refused contradiction now LOADS at both `validate_staged` and
    /// `open_staged` — the degradation is a run-time outcome, not a load refusal. A clean
    /// `Discovering` policy also loads at both.
    #[test]
    fn validate_and_open_both_accept_a_toolslist_denied_typed_rule() {
        let history = tempfile::tempdir().expect("history directory");
        let contradiction = source(
            r#"permit(principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "alpha" };
forbid(principal, action == Box::Action::"mcp:call", resource) when { context.input.server == "alpha" && context.input.method == "tools/list" };
permit(principal, action == alpha::Action::"read", resource);"#,
        );
        assert!(
            crate::PolicyEngine::validate_staged(&contradiction).is_ok(),
            "validate no longer refuses the contradiction \
             (docs/design/decisions.md#a-server-whose-discovery-a-policy-denies-degrades-alone)"
        );
        assert!(
            Authority::open_staged(
                &Operator::unanchored(),
                contradiction,
                &history.path().join("c.redb")
            )
            .is_ok(),
            "open no longer refuses the contradiction \
             (docs/design/decisions.md#a-server-whose-discovery-a-policy-denies-degrades-alone)"
        );

        let clean = discovering_source();
        assert!(crate::PolicyEngine::validate_staged(&clean).is_ok());
        assert!(
            Authority::open_staged(
                &Operator::unanchored(),
                clean,
                &history.path().join("d.redb")
            )
            .is_ok()
        );
    }

    struct ReleaseFaultOnDrop(Arc<FaultInjector>);

    impl Drop for ReleaseFaultOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    #[test]
    fn record_waits_for_the_authority_transaction() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_staged(
            &Operator::unanchored(),
            staged_source(),
            &history.path().join("initial.redb"),
        )
        .expect("the blocked authority opens");
        // The recording thread completes a request submitted before the staged transaction.
        // Seed the replacement test store with a policy so that request has a real token.
        drop(
            DogwoodEngine::open(
                r#"permit(principal, action == Box::Action::"http:request", resource);"#,
                &history.path().join("faulted.redb"),
            )
            .expect("the pre-transaction policy installs"),
        );
        let faults = Arc::new(FaultInjector::new());
        let _release = ReleaseFaultOnDrop(Arc::clone(&faults));
        let engine = DogwoodEngine::open_for_staging_with_faults(
            &history.path().join("faulted.redb"),
            Arc::clone(&faults),
        )
        .expect("the faulted durable engine opens");
        authority.live.lock().expect("live authority lock").engine = engine;
        let request_id = submitted_http_request(&authority);
        let authority = Arc::new(authority);

        faults.arm(FaultPoint::CommitBeforeCommit);
        let staging_authority = Arc::clone(&authority);
        let staging = std::thread::spawn(move || {
            staging_authority.stage_mcp_schema("alpha", generated("alpha", "read", "value"))
        });
        assert!(
            faults.wait_until_reached(Duration::from_secs(30)),
            "the authority transaction must reach its commit point"
        );

        let (started, start) = std::sync::mpsc::channel();
        let (recorded, outcome) = std::sync::mpsc::channel();
        let recording_authority = Arc::clone(&authority);
        let recording = std::thread::spawn(move || {
            let _ = started.send(());
            let result = recording_authority.record(
                &governed(),
                &Principal::agent(),
                &request_id,
                &http_outcome(),
            );
            let _ = recorded.send(result);
        });
        start
            .recv_timeout(Duration::from_secs(30))
            .expect("the recording thread starts");
        assert!(matches!(
            outcome.recv_timeout(Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        faults.release();
        assert_eq!(
            staging
                .join()
                .expect("the staging thread exits")
                .expect("the schema stages"),
            SchemaStage::Accepted {
                authority_ready: true,
            }
        );
        outcome
            .recv_timeout(Duration::from_secs(30))
            .expect("record resumes after the transaction")
            .expect("the outcome records");
        recording.join().expect("the recording thread exits");
    }

    #[test]
    fn decision_waits_for_the_request_schema_after_the_durable_commit() {
        let history = tempfile::tempdir().expect("history directory");
        let authority = Authority::open_staged(
            &Operator::unanchored(),
            staged_source(),
            &history.path().join("initial.redb"),
        )
        .expect("the blocked authority opens");
        let faults = Arc::new(FaultInjector::new());
        let _release = ReleaseFaultOnDrop(Arc::clone(&faults));
        let engine = DogwoodEngine::open_for_staging_with_faults(
            &history.path().join("faulted.redb"),
            Arc::clone(&faults),
        )
        .expect("the faulted durable engine opens");
        authority.live.lock().expect("live authority lock").engine = engine;
        let authority = Arc::new(authority);

        faults.arm(FaultPoint::CommitAfterCommit);
        let staging_authority = Arc::clone(&authority);
        let staging = std::thread::spawn(move || {
            staging_authority.stage_mcp_schema("alpha", generated("alpha", "read", "value"))
        });
        assert!(
            faults.wait_until_reached(Duration::from_secs(30)),
            "the staged authority must reach the post-commit point"
        );

        let (started, start) = std::sync::mpsc::channel();
        let (decided, decision) = std::sync::mpsc::channel();
        let deciding_authority = Arc::clone(&authority);
        let deciding = std::thread::spawn(move || {
            let _ = started.send(());
            let arguments = serde_json::json!({"value": "ready"});
            let request = Request::McpCall {
                server: "alpha",
                method: "tools/call",
                tool: Some("read"),
                prompt: None,
                uri: None,
                arguments: Some(&arguments),
            };
            let verdict = decide(&deciding_authority, &request);
            let _ = decided.send(verdict);
        });
        start
            .recv_timeout(Duration::from_secs(30))
            .expect("the decision thread starts");
        assert!(matches!(
            decision.recv_timeout(Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        faults.release();
        assert_eq!(
            staging
                .join()
                .expect("the staging thread exits")
                .expect("the schema stages"),
            SchemaStage::Accepted {
                authority_ready: true,
            }
        );
        assert!(
            decision
                .recv_timeout(Duration::from_secs(30))
                .expect("the decision resumes")
                .is_allow(),
            "the resumed generated action must pass the cumulative request gate"
        );
        deciding.join().expect("the decision thread exits");
    }
}
