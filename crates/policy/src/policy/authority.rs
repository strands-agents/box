//! Coordinates policy proposal state and live-authority transitions.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::Path;
use std::sync::Mutex;

use dogwood_local_engine::DurableError;

use super::{Policy, SchemaStage, authored};
use crate::dogwood::{DogwoodEngine, parse_policy_source, validate_canonical_policy_set};
use crate::schema::{ActionIdentity, GovernedBox};
use crate::spelling::{Operator, PolicyWarning};
use crate::{Decision, Outcome, PolicyError, PolicyStagingError, Principal, Request};

#[derive(Debug, Clone)]
struct CandidatePolicy {
    ordinal: usize,
    expanded_source: String,
}

#[derive(Debug, Clone)]
struct ProposalState {
    operator: Operator,
    candidates: Vec<CandidatePolicy>,
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
    /// The `(namespace, tool)` typed actions whose schema will never stage — the server's
    /// `tools/list` was denied, so discovery finished without it. A `tools/call` naming one
    /// is denied fail-closed in any state, so a hardcoded call cannot ride the coarse `mcp:call`
    /// permit with its argument constraint unenforced. Empty until `finish_mcp_discovery` degrades.
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
        let (engine, warnings) = DogwoodEngine::open_with_mcp_schemas(
            &authored(&sources),
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
        Self::open_staged_with_engine(operator, sources, DogwoodEngine::open_for_staging(history)?)
    }

    pub(super) fn open_staged_file(
        operator: &Operator,
        sources: Vec<Policy>,
        history: File,
        label: std::path::PathBuf,
    ) -> Result<Self, PolicyStagingError> {
        Self::open_staged_with_engine(
            operator,
            sources,
            DogwoodEngine::open_for_staging_file(history, label)?,
        )
    }

    fn open_staged_with_engine(
        operator: &Operator,
        sources: Vec<Policy>,
        mut engine: DogwoodEngine,
    ) -> Result<Self, PolicyStagingError> {
        let candidates = parse_policy_source(&authored(&sources))?
            .into_iter()
            .enumerate()
            .map(|(ordinal, expanded_source)| CandidatePolicy {
                ordinal,
                expanded_source,
            })
            .collect::<Vec<_>>();
        let mut proposal = ProposalState {
            operator: operator.clone(),
            candidates,
            schemas: BTreeMap::new(),
            ready: BTreeSet::new(),
            pending: BTreeMap::new(),
        };
        let complete = proposal.complete_policy_set();
        let (readiness, pending_tools, warnings) =
            match validate_canonical_policy_set(&complete, &[], operator) {
                Ok((effective_schema, warnings)) => {
                    engine
                        .commit_staged(&complete, effective_schema)
                        .map_err(|error| PolicyStagingError::Durable(error.to_string()))?;
                    proposal.mark_all_ready();
                    (Readiness::Ready, BTreeSet::new(), warnings)
                }
                Err(
                    inert @ (PolicyError::Spelling(_)
                    | PolicyError::SharedRuleId(_)
                    | PolicyError::ReservedAction(_)
                    | PolicyError::InertTemporalPermit(_)),
                ) => {
                    return Err(inert.into());
                }
                Err(_) => {
                    proposal.classify(&[])?;
                    // Serve the schema-independent subset while typed schemas stage
                    // (`Discovering`), instead of denying every request. A per-tool rule whose server
                    // never stages (its `tools/list` is denied) is not refused here;
                    // `finish_mcp_discovery` degrades that one server instead.
                    let subset = proposal.ready_policy_set();
                    let (effective_schema, warnings) =
                        validate_canonical_policy_set(&subset, &[], operator)?;
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

        match validate_canonical_policy_set(&complete, &schemas, &proposed.operator) {
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
                let (subset_schema, _) =
                    validate_canonical_policy_set(&subset, &schemas, &proposed.operator)?;
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
    /// Every door has drained, so a candidate still pending means its server's `tools/list` was
    /// denied and its schema will never arrive. Rather than fatally refuse the whole box, the still
    /// -pending typed tools become `degraded_tools` — denied fail-closed in `decide` — the committed
    /// schema-independent subset becomes the final `Ready` authority, and the degraded server
    /// namespaces are returned so the caller can warn. Only a genuine durable fault is an `Err`.
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
        // The still-pending typed rules cannot stage (their servers finished discovery denied), so
        // their tools are permanently unenforceable. Hold them fail-closed and finish `Ready`.
        let degraded = proposal
            .as_ref()
            .map(pending_typed_tools)
            .unwrap_or_default();
        live.degraded_tools = degraded.clone();
        live.pending_tools = BTreeSet::new();
        live.readiness = Readiness::Ready;
        let servers: BTreeSet<String> = degraded
            .into_iter()
            .map(|(namespace, _)| namespace)
            .collect();
        Ok(servers.into_iter().collect())
    }

    /// Decides through a ready live authority and denies every other state.
    pub(super) fn decide(
        &self,
        governed: &GovernedBox,
        principal: &Principal,
        request: &Request<'_>,
        identity: &ActionIdentity,
    ) -> Decision {
        match self.live.lock() {
            Ok(live) => {
                // Fail-closed for a degraded tool: its schema will never stage, so its
                // argument constraint can never be enforced. Deny outright — in any state — rather
                // than let a hardcoded call ride the coarse `mcp:call` permit unconstrained.
                if let ActionIdentity::McpTool { namespace, tool } = identity
                    && live
                        .degraded_tools
                        .contains(&(namespace.clone(), tool.clone()))
                {
                    return Decision::no_match();
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
                            return Decision::policy_pending();
                        }
                        live.engine
                            .decide_with_identity(governed, principal, request, identity)
                    }
                    Readiness::Ready => live
                        .engine
                        .decide_with_identity(governed, principal, request, identity),
                }
            }
            Err(_) => Decision::internal_fault(),
        }
    }

    /// Records one outcome. The live authority always serves decisions (`Discovering` or `Ready`),
    /// so no readiness state refuses a record.
    pub(super) fn record(
        &self,
        governed: &GovernedBox,
        principal: &Principal,
        outcome: &Outcome<'_>,
    ) -> Result<(), PolicyError> {
        let live = self
            .live
            .lock()
            .map_err(|_| PolicyError::Evaluation("policy authority lock poisoned".to_string()))?;
        live.engine.observe_outcome(governed, principal, outcome)
    }

    /// Returns whether the live authority declares a tool action, or true when its lock is unavailable.
    pub(super) fn declares_tool_action(&self, action: &cedar_policy::EntityUid) -> bool {
        match self.live.lock() {
            Ok(live) => live.engine.declares_tool_action(action),
            Err(_) => true,
        }
    }

    /// Whether a tool call names a typed action whose schema has not staged yet while
    /// `Discovering`. Such a call is held transiently rather than letting it ride the coarse allow
    /// with its argument constraint unenforceable. A poisoned lock fails closed (held).
    pub(super) fn is_tool_pending(&self, identity: &ActionIdentity) -> bool {
        let ActionIdentity::McpTool { namespace, tool } = identity else {
            return false;
        };
        match self.live.lock() {
            Ok(live) => {
                live.readiness == Readiness::Discovering
                    && live
                        .pending_tools
                        .contains(&(namespace.clone(), tool.clone()))
            }
            Err(_) => true,
        }
    }

    /// Whether a tool call names a degraded typed action — one whose server's `tools/list` was
    /// denied so its schema never staged. Such a call is denied fail-closed at the per-tool
    /// gate, so it cannot ride the coarse allow with its argument constraint unenforceable. A
    /// poisoned lock fails closed (degraded).
    pub(super) fn is_tool_degraded(&self, identity: &ActionIdentity) -> bool {
        let ActionIdentity::McpTool { namespace, tool } = identity else {
            return false;
        };
        match self.live.lock() {
            Ok(live) => live
                .degraded_tools
                .contains(&(namespace.clone(), tool.clone())),
            Err(_) => true,
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
        validate_canonical_policy_set(&self.ready_policy_set(), schemas, &self.operator).map(|_| ())
    }

    fn classify(&mut self, schemas: &[String]) -> Result<(), PolicyError> {
        loop {
            let mut changed = false;
            for ordinal in 0..self.candidates.len() {
                if self.ready.contains(&ordinal) {
                    continue;
                }
                let candidate = self.candidate_policy_set(ordinal);
                match validate_canonical_policy_set(&candidate, schemas, &self.operator) {
                    Ok(_) => {
                        self.ready.insert(ordinal);
                        self.pending.remove(&ordinal);
                        changed = true;
                    }
                    Err(
                        inert @ (PolicyError::Spelling(_)
                        | PolicyError::SharedRuleId(_)
                        | PolicyError::ReservedAction(_)
                        | PolicyError::InertTemporalPermit(_)),
                    ) => {
                        return Err(inert);
                    }
                    Err(error) => {
                        if !self.names_a_typed_action(ordinal) {
                            return Err(error);
                        }
                        self.pending.insert(ordinal, error.to_string());
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
    fn names_a_typed_action(&self, ordinal: usize) -> bool {
        let mut typed = BTreeSet::new();
        if let Some(candidate) = self.candidates.get(ordinal) {
            collect_typed_actions(&candidate.expanded_source, &mut typed);
        }
        !typed.is_empty()
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

/// The pending typed `(namespace, tool)` pairs a proposal still needs a discovered schema for.
fn pending_typed_tools(proposal: &ProposalState) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for &ordinal in proposal.pending.keys() {
        if let Some(candidate) = proposal.candidates.get(ordinal) {
            collect_typed_actions(&candidate.expanded_source, &mut out);
        }
    }
    out
}

/// Extracts every `<ns>::Action::"<tool>"` typed action from a macro-expanded policy source,
/// excluding the fixed `Box::Action` vocabulary. A per-tool rule's head is
/// `action == <ns>::Action::"<tool>"`, and `<ns>` is a single normalized identifier
/// ([`mcp_action_namespace`](crate::schema::mcp_action_namespace)), so a scan for the marker
/// recovers `(namespace, tool)`.
fn collect_typed_actions(source: &str, out: &mut BTreeSet<(String, String)>) {
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
        let after = &rest[pos + MARKER.len()..];
        match after.find('"') {
            Some(end) => {
                if !namespace.is_empty() && namespace != "Box" {
                    out.insert((namespace, after[..end].to_string()));
                }
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
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
    use crate::{Delivery, DenyReason};

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
        let identity = ActionIdentity::for_request(request);
        authority.decide(&governed(), &Principal::agent(), request, &identity)
    }

    fn http_outcome() -> Outcome<'static> {
        Outcome::Http {
            host: "api.example.com",
            port: 443,
            method: "POST",
            path: "/v1",
            delivery: Delivery::Completed { bytes: 1 },
            status: Some(200),
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
        poison(&authority.live);

        let error = authority
            .record(&governed(), &Principal::agent(), &http_outcome())
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
        authority
            .live
            .lock()
            .expect("live authority lock")
            .engine
            .poison_scope_for_test();

        let error = authority
            .record(&governed(), &Principal::agent(), &http_outcome())
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
        let identity = ActionIdentity::for_request(&call);
        assert!(
            !authority
                .decide(&governed(), &Principal::agent(), &call, &identity)
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
        let faults = Arc::new(FaultInjector::new());
        let _release = ReleaseFaultOnDrop(Arc::clone(&faults));
        let engine = DogwoodEngine::open_for_staging_with_faults(
            &history.path().join("faulted.redb"),
            Arc::clone(&faults),
        )
        .expect("the faulted durable engine opens");
        authority.live.lock().expect("live authority lock").engine = engine;
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
            let result =
                recording_authority.record(&governed(), &Principal::agent(), &http_outcome());
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
