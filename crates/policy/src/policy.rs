//! The concrete policy authority.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod authority;

use crate::dogwood::{DogwoodEngine, parse_policy_source};
use crate::schema::GovernedBox;
use crate::{
    Decision, Operator, Outcome, PolicyError, PolicyStagingError, PolicyWarning, Principal, Request,
};
use authority::Authority;

/// The policy engine and pinned version.
pub const ENGINE_ID: &str = crate::dogwood::ENGINE_ID;

/// The former fixed authority filenames.
pub const SELF_DEFENDED_FILES: [&str; 2] = ["box.toml", "policy.dw"];

/// One authored Dogwood policy document and its diagnostic origin.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Human-facing source origin, normally a file path.
    pub origin: PathBuf,
    /// Authored policy text.
    pub text: String,
}

/// Diagnostic identity of the loaded policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePolicy {
    /// Policy engine and pinned version.
    pub engine: &'static str,
    /// The origins of the sources that contribute permits.
    pub policy_id: String,
}

/// The result of one MCP schema proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaStage {
    /// The schema joined the cumulative staged schema set.
    Accepted {
        /// Whether the complete policy bundle is installed.
        authority_ready: bool,
    },
    /// The proposal did not change staging or durable authority.
    Rejected {
        /// The validation or durable refusal.
        reason: String,
    },
}

/// One durable policy authority.
pub struct PolicyEngine {
    authority: Authority,
    effective: EffectivePolicy,
    observer: Option<Arc<dyn crate::observe::DecisionObserver>>,
}

impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PolicyEngine")
            .field("effective", &self.effective)
            .finish_non_exhaustive()
    }
}

impl PolicyEngine {
    /// Open durable history, then parse and install owned policy sources for an unanchored operator.
    pub fn open(sources: Vec<Policy>, history: &Path) -> Result<Self, PolicyError> {
        Self::open_with_mcp_schemas(sources, &[], history)
    }

    /// Open durable history with generated MCP action-schema fragments.
    pub fn open_with_mcp_schemas(
        sources: Vec<Policy>,
        mcp_schemas: &[String],
        history: &Path,
    ) -> Result<Self, PolicyError> {
        let effective = EffectivePolicy {
            engine: ENGINE_ID,
            policy_id: effective_policy_id(&sources),
        };

        Ok(Self {
            authority: Authority::open_complete(sources, mcp_schemas, history)?,
            effective,
            observer: None,
        })
    }

    /// Open durable history and stage policies against runtime MCP schemas.
    pub fn open_staged(
        operator: &Operator,
        sources: Vec<Policy>,
        history: &Path,
    ) -> Result<Self, PolicyStagingError> {
        let effective = EffectivePolicy {
            engine: ENGINE_ID,
            policy_id: effective_policy_id(&sources),
        };
        Ok(Self {
            authority: Authority::open_staged(operator, sources, history)?,
            effective,
            observer: None,
        })
    }

    /// Open durable history through an already-open file and stage runtime MCP schemas.
    pub fn open_staged_file(
        operator: &Operator,
        sources: Vec<Policy>,
        history: File,
        label: PathBuf,
    ) -> Result<Self, PolicyStagingError> {
        let effective = EffectivePolicy {
            engine: ENGINE_ID,
            policy_id: effective_policy_id(&sources),
        };
        Ok(Self {
            authority: Authority::open_staged_file(operator, sources, history, label)?,
            effective,
            observer: None,
        })
    }

    /// Open with a fault injector on the durable log, for tests that pause the store.
    #[cfg(test)]
    pub(crate) fn open_with_faults(
        sources: Vec<Policy>,
        history: &Path,
        faults: Arc<dogwood_local_engine::fault_injection::FaultInjector>,
    ) -> Result<Self, PolicyError> {
        let effective = EffectivePolicy {
            engine: ENGINE_ID,
            policy_id: effective_policy_id(&sources),
        };
        Ok(Self {
            authority: Authority::open_with_faults(sources, history, faults)?,
            effective,
            observer: None,
        })
    }

    /// Puts the store into its terminal fault state, for fail-closed tests.
    #[cfg(test)]
    pub(crate) fn poison_store_for_test(&self) {
        self.authority.poison_scope_for_test();
    }

    /// Report every verdict to `observer`.
    ///
    /// A consuming setter, so the authority is either observed for its whole life or not at all.
    /// Installing one later would leave a window in which decisions were taken and recorded
    /// nowhere — and a box whose audit lane starts one request late is a box an operator cannot
    /// reason about.
    ///
    /// One observer, not a list. A second sink would be a second answer to "what did this box
    /// decide", and the composition that wants two fan-outs owns that fan-out itself.
    #[must_use]
    pub fn observed_by(mut self, observer: Arc<dyn crate::observe::DecisionObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Strict-validate a candidate source set **without** producing an authority.
    ///
    /// Answers "would `open` accept this text", and nothing else. There is no value to hold, so
    /// no history to accumulate and no `decide` to reach.
    ///
    /// This exists so a caller that must refuse bad text *before* writing it does not have to
    /// open a second `PolicyEngine` to find out. One instance per box is a premise
    /// (docs/design/decisions.md#one-policy-engine-per-box): two instances mean two temporal
    /// histories, so a rule spanning `fs:*` and `net:*` loads cleanly and enforces nothing.
    /// `strands-box` guards it by scanning its own source for `PolicyEngine::open` and requiring
    /// exactly one call. A validation-only call is harmless in behaviour and indistinguishable to
    /// that guard, which is the right way round: the guard should not have to reason about intent.
    /// So the capability moves here, where it cannot return an authority at all.
    pub fn validate(operator: &Operator, sources: &[Policy]) -> Result<(), PolicyError> {
        Self::validate_with_mcp_schemas(operator, sources, &[])
    }

    /// Strict-validate candidate sources with generated MCP action-schema fragments.
    pub fn validate_with_mcp_schemas(
        operator: &Operator,
        sources: &[Policy],
        mcp_schemas: &[String],
    ) -> Result<(), PolicyError> {
        DogwoodEngine::validate_with_mcp_schemas(&authored(sources), mcp_schemas, operator)
            .map(|_| ())
    }

    /// Validate syntax, macro expansion, and provider use without an action schema.
    ///
    /// A `tools/list`-denied-plus-typed-rule policy is NOT refused here:
    /// it loads, and `finish_mcp_discovery` degrades that one server at run rather than blocking
    /// the whole box.
    pub fn validate_staged(sources: &[Policy]) -> Result<(), PolicyError> {
        parse_policy_source(&authored(sources)).map(|_| ())
    }

    /// Propose one generated MCP action-schema fragment.
    pub fn stage_mcp_schema(
        &self,
        server: &str,
        fragment: String,
    ) -> Result<SchemaStage, PolicyStagingError> {
        self.authority.stage_mcp_schema(server, fragment)
    }

    /// Finish discovery, returning the server namespaces degraded because their per-tool rule could
    /// not stage (its `tools/list` was denied). An empty vec is a clean completion; a genuine
    /// durable fault is an `Err`.
    pub fn finish_mcp_discovery(&self) -> Result<Vec<String>, PolicyStagingError> {
        self.authority.finish_mcp_discovery()
    }

    /// Decide whether `principal` may perform `request`.
    ///
    /// An installed [`DecisionObserver`](crate::DecisionObserver) sees every verdict this
    /// returns, including a default-deny. It sees the verdict *after* it is reached and can
    /// never change it.
    #[must_use]
    pub fn decide(
        &self,
        governed: &GovernedBox,
        principal: &Principal,
        request: &Request<'_>,
    ) -> Decision {
        let identity = crate::schema::ActionIdentity::for_request(request);
        let decision = self
            .authority
            .decide(governed, principal, request, &identity);
        self.conclude(&identity, request, decision)
    }

    /// Name the request's resource on the verdict, then report it once.
    fn conclude(
        &self,
        identity: &crate::schema::ActionIdentity,
        request: &Request<'_>,
        decision: Decision,
    ) -> Decision {
        let decision = decision.naming(request.resource());
        if let Some(observer) = &self.observer {
            observer.observed(
                identity.observer_action().as_ref(),
                decision.resource(),
                &decision,
            );
        }
        decision
    }

    /// Record one completed effect as policy history.
    pub fn record(
        &self,
        governed: &GovernedBox,
        principal: &Principal,
        outcome: &Outcome<'_>,
    ) -> Result<(), PolicyError> {
        self.authority.record(governed, principal, outcome)
    }

    /// Return the loaded engine and source identity.
    #[must_use]
    pub fn effective(&self) -> &EffectivePolicy {
        &self.effective
    }

    /// The load-time findings that did not refuse the policy.
    #[must_use]
    pub fn warnings(&self) -> &[PolicyWarning] {
        self.authority.warnings()
    }

    pub(crate) fn declares_tool_action(&self, action: &cedar_policy::EntityUid) -> bool {
        self.authority.declares_tool_action(action)
    }

    /// The per-tool refinement for one `tools/call`.
    ///
    /// Returns `Allow` when the composed schema declares no per-tool action for the tool (it rides
    /// the coarse grant) or when no rule forbids it; returns `Deny` only on an explicit `forbid` or
    /// an evaluation fault. `arguments` is the raw `params.arguments`, typed against the composed
    /// schema by the engine's request gate (`context_for`'s `from_json`).
    pub fn refine_tool_call(
        &self,
        governed: &GovernedBox,
        principal: &Principal,
        server: &str,
        tool: &str,
        arguments: &serde_json::Value,
    ) -> Decision {
        let identity = crate::schema::ActionIdentity::mcp_tool(server, tool);
        let request = Request::McpCall {
            server,
            method: "tools/call",
            tool: Some(tool),
            prompt: None,
            uri: None,
            arguments: Some(arguments),
        };
        let action = match identity.cedar_uid() {
            Ok(action) => action,
            Err(_) => return self.conclude(&identity, &request, Decision::internal_fault()),
        };
        if !self.declares_tool_action(&action) {
            // A tool with no declared per-tool action can be one of three things while its schema is
            // absent: degraded (its server's `tools/list` was denied, so it never stages) →
            // deny fail-closed, so a hardcoded call cannot ride the coarse allow with its argument
            // constraint unenforceable; pending (still discovering) → hold transiently; or a
            // genuinely unruled tool → ride the coarse allow as before.
            let decision = if self.authority.is_tool_degraded(&identity) {
                Decision::no_match()
            } else if self.authority.is_tool_pending(&identity) {
                Decision::policy_pending()
            } else {
                Decision::Allow {
                    rule: crate::RuleId::default_deny(),
                    attribution: Vec::new(),
                    resource: String::new(),
                }
            };
            return self.conclude(&identity, &request, decision);
        }
        let decision = match self
            .authority
            .decide(governed, principal, &request, &identity)
        {
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
        };
        self.conclude(&identity, &request, decision)
    }
}

/// The text the engine loads, shared by [`PolicyEngine::open`] and [`PolicyEngine::validate`].
fn authored(sources: &[Policy]) -> String {
    sources
        .iter()
        .map(|source| source.text.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn effective_policy_id(sources: &[Policy]) -> String {
    let origins = sources
        .iter()
        .map(|source| source.origin.display().to_string())
        .collect::<Vec<_>>();
    if origins.is_empty() {
        "<deny-by-default>".to_string()
    } else {
        origins.join(",")
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use super::*;
    use crate::path::ApprovedPath;

    struct PolicyFixture {
        authority: PolicyEngine,
        _history: tempfile::TempDir,
    }

    impl Deref for PolicyFixture {
        type Target = PolicyEngine;

        fn deref(&self) -> &Self::Target {
            &self.authority
        }
    }

    fn try_open(sources: Vec<Policy>) -> Result<PolicyFixture, PolicyError> {
        let history = tempfile::tempdir().expect("history directory");
        let authority = PolicyEngine::open(sources, &history.path().join("dogwood.redb"))?;
        Ok(PolicyFixture {
            authority,
            _history: history,
        })
    }

    fn policy(source: &str) -> PolicyFixture {
        try_open(vec![Policy {
            origin: PathBuf::from("principal-test.cedar"),
            text: source.to_string(),
        }])
        .expect("policy opens")
    }

    /// One source set, as both a validation and an open, so the two cannot drift apart.
    fn source(text: &str) -> Vec<Policy> {
        vec![Policy {
            origin: PathBuf::from("candidate.dw"),
            text: text.to_string(),
        }]
    }

    fn mcp_fragment(server: &str, tool: &str) -> String {
        crate::generate_mcp_schema(
            server,
            &format!(
                r#"{{
                    "result": {{
                        "tools": [{{
                            "name": "{tool}",
                            "inputSchema": {{
                                "type": "object",
                                "properties": {{"path": {{"type": "string"}}}},
                                "required": ["path"]
                            }}
                        }}]
                    }}
                }}"#
            ),
        )
        .expect("the MCP schema generates")
    }

    fn policy_at(source: &str, history: &Path, now_secs: i64) -> PolicyEngine {
        let sources = self::source(source);
        PolicyEngine {
            authority: Authority::open_with_test_clock(sources.clone(), history, now_secs)
                .expect("policy opens"),
            effective: EffectivePolicy {
                engine: ENGINE_ID,
                policy_id: effective_policy_id(&sources),
            },
            observer: None,
        }
    }

    #[test]
    fn a_denied_attempt_is_durable_until_its_wall_clock_window_expires() {
        let source = r#"
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when { context.input.path == "/tmp/first-attempt" };
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
unless temporal {
    formerly within 1h (
        Box::Action::"fs:read"::request{
            input.path: "/tmp/first-attempt",
            input.operation: Box::FsReadOperation::"read_content"
        }
    )
};
"#;
        let history = tempfile::tempdir().expect("history directory");
        let path = history.path().join("dogwood.redb");
        let governed = GovernedBox::assigned("test-box");
        let principal = Principal::agent();
        let attempted_path = ApprovedPath::interpreter_resolved("/tmp/first-attempt");
        let attempted_read = Request::Fs {
            path: &attempted_path,
            operation: crate::request::FsOperation::ReadContent,
        };
        let dependent_path = ApprovedPath::interpreter_resolved("/tmp/dependent-write");
        let dependent_write = Request::Fs {
            path: &dependent_path,
            operation: crate::request::FsOperation::WriteContent,
        };

        {
            let authority = PolicyEngine::open(self::source(source), &path).expect("policy opens");
            assert!(
                !authority
                    .decide(&governed, &principal, &attempted_read)
                    .is_allow(),
                "the first attempt must be denied"
            );
        }

        {
            let recovered =
                PolicyEngine::open(self::source(source), &path).expect("history recovers");
            assert!(
                !recovered
                    .decide(&governed, &principal, &dependent_write)
                    .is_allow(),
                "the recovered denied attempt must remain in force within one hour"
            );
        }

        let recovered_at = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("wall clock is after the Unix epoch")
                .as_secs(),
        )
        .expect("wall-clock seconds fit in i64");
        {
            let within_window = policy_at(source, &path, recovered_at.saturating_add(60));
            assert!(
                !within_window
                    .decide(&governed, &principal, &dependent_write)
                    .is_allow(),
                "reapplying the same policy must retain the attempt within one hour"
            );
        }

        let after_window = recovered_at.saturating_add(3_601);
        let recovered = policy_at(source, &path, after_window);
        assert!(
            recovered
                .decide(&governed, &principal, &dependent_write)
                .is_allow(),
            "the recovered denied attempt must expire after one hour"
        );
    }

    #[test]
    fn a_slow_store_holds_every_verdict_until_it_resumes() {
        use dogwood_local_engine::fault_injection::{FaultInjector, FaultPoint};

        let history = tempfile::tempdir().expect("history directory");
        let faults = std::sync::Arc::new(FaultInjector::new());
        let authority = PolicyEngine::open_with_faults(
            self::source(r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);"#),
            &history.path().join("dogwood.redb"),
            std::sync::Arc::clone(&faults),
        )
        .expect("policy opens");
        let governed = GovernedBox::assigned("test-box");
        let principal = Principal::agent();
        let notes = ApprovedPath::interpreter_resolved("/workspace/notes.txt");
        let request = Request::Fs {
            path: &notes,
            operation: crate::request::FsOperation::ReadContent,
        };
        let (decided, verdicts) = std::sync::mpsc::channel();

        faults.arm(FaultPoint::AppendBeforeCommit);
        let verdict = std::thread::scope(|scope| {
            scope.spawn(|| {
                let verdict = authority.decide(&governed, &principal, &request);
                decided.send(verdict).expect("the test is waiting");
            });
            let reached = faults.wait_until_reached(std::time::Duration::from_secs(30));
            let early = verdicts.recv_timeout(std::time::Duration::from_millis(200));
            faults.release();
            assert!(reached, "the decision must reach the store's append");
            assert!(
                matches!(early, Err(std::sync::mpsc::RecvTimeoutError::Timeout)),
                "no verdict may return while the store blocks: {early:?}"
            );
            verdicts
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the decision completes once the store resumes")
        });
        assert!(verdict.is_allow(), "{verdict:?}");
    }

    /// Five live permits, one per action family the vocabulary names.
    fn five_permits() -> PolicyFixture {
        policy(
            r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:delete", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"http:request", resource);
"#,
        )
    }

    fn five_requests(notes: &ApprovedPath) -> [Request<'_>; 5] {
        [
            Request::Fs {
                path: notes,
                operation: crate::request::FsOperation::ReadContent,
            },
            Request::Fs {
                path: notes,
                operation: crate::request::FsOperation::WriteContent,
            },
            Request::Fs {
                path: notes,
                operation: crate::request::FsOperation::RemoveFile,
            },
            Request::ShellExec {
                command: "printf ready",
                program: "printf",
                args: &[],
                cwd: "/workspace",
            },
            Request::Http {
                host: "api.example.com",
                port: 443,
                method: "POST",
                path: "/v1",
                body_bytes: 10,
                intercepted: true,
            },
        ]
    }

    fn assert_every_permit_is_live(authority: &PolicyEngine, notes: &ApprovedPath) {
        let governed = GovernedBox::assigned("test-box");
        let principal = Principal::agent();
        for request in &five_requests(notes) {
            assert!(
                authority.decide(&governed, &principal, request).is_allow(),
                "every permit is live before the fault: {request:?}"
            );
        }
    }

    /// Ten decisions across the five requests, each an `InternalFault` with the rendered text,
    /// then a record that is refused rather than lost.
    fn assert_every_verdict_is_an_internal_fault(authority: &PolicyEngine, notes: &ApprovedPath) {
        let governed = GovernedBox::assigned("test-box");
        let principal = Principal::agent();
        for request in five_requests(notes).iter().cycle().take(10) {
            let decision = authority.decide(&governed, &principal, request);
            assert!(
                matches!(
                    decision,
                    Decision::Deny {
                        reason: crate::DenyReason::InternalFault,
                        ..
                    }
                ),
                "{request:?} -> {decision:?}"
            );
            assert!(
                decision
                    .to_string()
                    .ends_with(" because the request could not be evaluated."),
                "{decision}"
            );
        }
        assert!(
            authority
                .record(
                    &governed,
                    &principal,
                    &Outcome::Fs {
                        path: Path::new("/workspace/notes.txt"),
                        operation: crate::request::FsOperation::ReadContent,
                        result: crate::FsResult::Completed,
                    },
                )
                .is_err(),
            "a record after the fault is refused rather than lost"
        );
    }

    #[test]
    fn every_decision_after_the_store_poisons_is_an_internal_fault() {
        let authority = five_permits();
        let notes = ApprovedPath::interpreter_resolved("/workspace/notes.txt");
        assert_every_permit_is_live(&authority, &notes);

        authority.poison_store_for_test();

        assert_every_verdict_is_an_internal_fault(&authority, &notes);
    }

    #[test]
    #[cfg(unix)]
    #[ignore = "runs only as the child process that every_decision_after_a_storage_write_error_is_an_internal_fault starts through rerun::stderr_of"]
    fn decisions_meet_a_store_that_refuses_every_write() {
        let authority = five_permits();
        let notes = ApprovedPath::interpreter_resolved("/workspace/notes.txt");
        assert_every_permit_is_live(&authority, &notes);

        crate::rerun::refuse_every_file_write();

        assert_every_verdict_is_an_internal_fault(&authority, &notes);
    }

    #[test]
    #[cfg(unix)]
    fn every_decision_after_a_storage_write_error_is_an_internal_fault() {
        let stderr = crate::rerun::stderr_of(&crate::rerun::test_name(
            module_path!(),
            "decisions_meet_a_store_that_refuses_every_write",
        ));
        assert!(
            stderr.contains("File too large"),
            "the store itself must have refused the first append: {stderr}"
        );
        assert!(
            stderr.contains("Previous I/O error occurred"),
            "the store must hold every later append closed: {stderr}"
        );
    }

    /// `validate` answers exactly what `open` would, and yields nothing to hold.
    ///
    /// The agreement is the whole property. A validator that accepts text the authority would
    /// refuse is worse than no validator: it moves the refusal from before the write to after
    /// it, which is the atomic-recomposition failure it exists to prevent.
    ///
    /// Both directions are asserted, because only one of them looks like a bug. An over-strict
    /// validator refuses a good bundle loudly. A lax one writes a bundle the daemon then cannot
    /// load, and the box that will not start is a different box from the one that was edited.
    #[test]
    fn validation_accepts_and_refuses_exactly_what_open_does() {
        let good = r#"permit(principal, action == Box::Action::"fs:read", resource);"#;
        // A typo'd action. `lower()` alone accepts this and it then matches nothing, so it is
        // the case strict validation exists for rather than a parse failure.
        let bad = r#"permit(principal, action == Box::Action::"fs:reed", resource);"#;

        assert!(
            PolicyEngine::validate(&Operator::unanchored(), &source(good)).is_ok(),
            "text `open` accepts must validate"
        );
        assert!(
            try_open(source(good)).is_ok(),
            "and the control: `open` really does accept it"
        );

        assert!(
            PolicyEngine::validate(&Operator::unanchored(), &source(bad)).is_err(),
            "an unknown action must be refused before it is written, not after"
        );
        assert!(
            try_open(source(bad)).is_err(),
            "and the control: `open` really does refuse it, so the two agree"
        );
    }

    /// An empty source set validates, because that is default-deny rather than an error.
    #[test]
    fn validating_no_sources_is_default_deny_not_an_error() {
        assert!(PolicyEngine::validate(&Operator::unanchored(), &[]).is_ok());
    }

    /// Integration metadata cannot change the fixed principal.
    #[test]
    fn every_principal_uses_agent_self() {
        let policy = policy(
            r#"permit(
                   principal == Box::Agent::"self",
                   action == Box::Action::"fs:read",
                   resource
               );"#,
        );
        let approved = ApprovedPath::interpreter_resolved("/workspace/main.py");
        let request = Request::Fs {
            path: &approved,
            operation: crate::request::FsOperation::ReadContent,
        };

        assert!(
            policy
                .decide(
                    &GovernedBox::assigned("test-box"),
                    &Principal::agent(),
                    &request
                )
                .is_allow(),
            "the rule names Box::Agent::\"self\", which is what the default principal is"
        );
        assert!(
            policy
                .decide(
                    &GovernedBox::assigned("test-box"),
                    &Principal::agent().with_id("worker-1"),
                    &request
                )
                .is_allow(),
            "integration ids must not change the fixed Box::Agent::\"self\" identity"
        );
    }

    /// No authored source opens an empty policy set, and an empty set has no `permit` to match.
    #[test]
    fn an_absent_policy_opens_an_empty_set_and_denies_by_default() {
        let policy = try_open(Vec::new()).expect("an empty policy set opens");
        assert_eq!(policy.effective().policy_id, "<deny-by-default>");
        assert!(
            !policy
                .decide(
                    &GovernedBox::assigned("test-box"),
                    &Principal::agent(),
                    &Request::ShellExec {
                        command: "printf hello",
                        program: "printf",
                        args: &["hello".to_string()],
                        cwd: "/home",
                    }
                )
                .is_allow()
        );
    }

    /// The engine gives ordinary filenames no compiled-in meaning.
    #[test]
    fn ordinary_filenames_follow_the_authored_policy() {
        let policy = policy(r#"permit(principal, action, resource);"#);
        for path in ["/workspace/box.toml", "/workspace/policy.dw"] {
            let approved = ApprovedPath::interpreter_resolved(path);
            assert!(
                policy
                    .decide(
                        &GovernedBox::assigned("test-box"),
                        &Principal::agent(),
                        &Request::Fs {
                            path: &approved,
                            operation: crate::request::FsOperation::WriteContent,
                        }
                    )
                    .is_allow(),
                "the authored catch-all permit must govern {path}"
            );
        }
    }

    /// A sink that keeps what it was told, so a test reads the record rather than a side effect.
    #[derive(Default)]
    struct Recording {
        seen: std::sync::Mutex<Vec<(String, String, bool, String)>>,
    }

    impl crate::DecisionObserver for Recording {
        fn observed(&self, action: &str, resource: &str, decision: &Decision) {
            let rule = match decision {
                Decision::Allow { rule, .. } | Decision::Deny { rule, .. } => rule.to_string(),
            };
            if let Ok(mut seen) = self.seen.lock() {
                seen.push((
                    action.to_string(),
                    resource.to_string(),
                    decision.is_allow(),
                    rule,
                ));
            }
        }
    }

    /// The observer sees every verdict, and a refusal is the one an audit store most needs.
    #[test]
    fn an_observer_sees_a_permit_and_a_default_deny() {
        let history = tempfile::tempdir().expect("history directory");
        let recording = std::sync::Arc::new(Recording::default());
        let authority = PolicyEngine::open(
            vec![Policy {
                origin: PathBuf::from("observed.dw"),
                text: r#"permit(principal, action == Box::Action::"fs:read", resource);"#
                    .to_string(),
            }],
            &history.path().join("dogwood.redb"),
        )
        .expect("policy opens")
        .observed_by(recording.clone());

        let governed = GovernedBox::assigned("observed-box");
        let approved = ApprovedPath::interpreter_resolved("/workspace/main.py");
        let permitted = authority.decide(
            &governed,
            &Principal::agent(),
            &Request::Fs {
                path: &approved,
                operation: crate::request::FsOperation::ReadContent,
            },
        );
        // Nothing permits a write, so this is the default deny.
        let refused = authority.decide(
            &governed,
            &Principal::agent(),
            &Request::Fs {
                path: &approved,
                operation: crate::request::FsOperation::WriteContent,
            },
        );

        assert!(permitted.is_allow());
        assert!(!refused.is_allow());

        let seen = recording.seen.lock().expect("the recording").clone();
        assert_eq!(seen.len(), 2, "both verdicts were reported: {seen:?}");
        assert_eq!(seen[0].0, r#"Box::Action::"fs:read""#);
        assert_eq!(seen[0].1, "/workspace/main.py");
        assert!(seen[0].2, "the permit is reported as a permit");
        assert_eq!(seen[1].0, r#"Box::Action::"fs:write""#);
        assert!(!seen[1].2, "the refusal is reported as a refusal");
        assert_eq!(
            seen[1].3,
            crate::RuleId::DEFAULT_DENY,
            "and a default deny names the sentinel rather than nothing"
        );
    }

    /// An observer is not an authority: an authority with none decides identically.
    #[test]
    fn an_observer_changes_no_verdict() {
        let source = r#"permit(principal, action == Box::Action::"fs:read", resource);"#;
        let observed_history = tempfile::tempdir().expect("history directory");
        let plain_history = tempfile::tempdir().expect("history directory");
        let make = |history: &tempfile::TempDir| {
            PolicyEngine::open(
                vec![Policy {
                    origin: PathBuf::from("candidate.dw"),
                    text: source.to_string(),
                }],
                &history.path().join("dogwood.redb"),
            )
            .expect("policy opens")
        };

        let observed =
            make(&observed_history).observed_by(std::sync::Arc::new(Recording::default()));
        let plain = make(&plain_history);

        let governed = GovernedBox::assigned("test-box");
        let approved = ApprovedPath::interpreter_resolved("/workspace/main.py");
        for operation in [
            crate::request::FsOperation::ReadContent,
            crate::request::FsOperation::WriteContent,
        ] {
            let request = Request::Fs {
                path: &approved,
                operation,
            };
            assert_eq!(
                observed
                    .decide(&governed, &Principal::agent(), &request)
                    .is_allow(),
                plain
                    .decide(&governed, &Principal::agent(), &request)
                    .is_allow(),
                "an observer must not move a verdict for {operation:?}"
            );
        }
    }

    #[test]
    fn an_undeclared_refinement_observes_one_final_allow() {
        let history = tempfile::tempdir().expect("history directory");
        let recording = std::sync::Arc::new(Recording::default());
        let authority = PolicyEngine::open(
            source(r#"permit(principal, action == Box::Action::"mcp:call", resource);"#),
            &history.path().join("dogwood.redb"),
        )
        .expect("the policy opens")
        .observed_by(recording.clone());

        let decision = authority.refine_tool_call(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            "issues-mcp",
            "read",
            &serde_json::json!({"path": "/workspace/input"}),
        );

        assert!(decision.is_allow());
        assert!(decision.attribution().is_empty());
        let seen = recording.seen.lock().expect("the recording").clone();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert_eq!(seen[0].0, r#"issues_mcp::Action::"read""#);
        assert_eq!(seen[0].1, "issues-mcp/read");
        assert!(seen[0].2);
        assert_eq!(seen[0].3, crate::RuleId::DEFAULT_DENY);
    }

    #[test]
    fn a_refinement_no_match_observes_one_final_allow() {
        let history = tempfile::tempdir().expect("history directory");
        let recording = std::sync::Arc::new(Recording::default());
        let authority = PolicyEngine::open_with_mcp_schemas(
            source(r#"permit(principal, action == Box::Action::"mcp:call", resource);"#),
            &[mcp_fragment("issues-mcp", "read")],
            &history.path().join("dogwood.redb"),
        )
        .expect("the policy opens")
        .observed_by(recording.clone());
        let arguments = serde_json::json!({"path": "/workspace/input"});

        let decision = authority.refine_tool_call(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            "issues-mcp",
            "read",
            &arguments,
        );

        assert!(decision.is_allow());
        assert!(decision.attribution().is_empty());
        let seen = recording.seen.lock().expect("the recording").clone();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert_eq!(seen[0].0, r#"issues_mcp::Action::"read""#);
        assert_eq!(seen[0].1, "issues-mcp/read");
        assert!(seen[0].2);
        assert_eq!(seen[0].3, crate::RuleId::DEFAULT_DENY);
    }

    #[test]
    fn a_refinement_forbid_observes_one_final_denial() {
        let history = tempfile::tempdir().expect("history directory");
        let recording = std::sync::Arc::new(Recording::default());
        let authority = PolicyEngine::open_with_mcp_schemas(
            source(
                r#"
permit(principal, action == Box::Action::"mcp:call", resource);
forbid(principal, action == issues_mcp::Action::"read", resource);
"#,
            ),
            &[mcp_fragment("issues-mcp", "read")],
            &history.path().join("dogwood.redb"),
        )
        .expect("the policy opens")
        .observed_by(recording.clone());
        let arguments = serde_json::json!({"path": "/workspace/input"});

        let decision = authority.refine_tool_call(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            "issues-mcp",
            "read",
            &arguments,
        );

        assert!(matches!(
            decision,
            Decision::Deny {
                reason: crate::DenyReason::Forbidden,
                ..
            }
        ));
        let seen = recording.seen.lock().expect("the recording").clone();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert_eq!(seen[0].0, r#"issues_mcp::Action::"read""#);
        assert!(!seen[0].2);
    }

    #[test]
    fn a_refinement_internal_fault_observes_one_final_denial() {
        let history = tempfile::tempdir().expect("history directory");
        let recording = std::sync::Arc::new(Recording::default());
        let authority = PolicyEngine::open_with_mcp_schemas(
            source(r#"permit(principal, action == Box::Action::"mcp:call", resource);"#),
            &[mcp_fragment("issues-mcp", "read")],
            &history.path().join("dogwood.redb"),
        )
        .expect("the policy opens")
        .observed_by(recording.clone());
        authority.authority.poison_live_for_test();
        let arguments = serde_json::json!({"path": "/workspace/input"});

        let decision = authority.refine_tool_call(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            "issues-mcp",
            "read",
            &arguments,
        );

        assert!(matches!(
            decision,
            Decision::Deny {
                reason: crate::DenyReason::InternalFault,
                ..
            }
        ));
        let seen = recording.seen.lock().expect("the recording").clone();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert_eq!(seen[0].0, r#"issues_mcp::Action::"read""#);
        assert!(!seen[0].2);
        assert_eq!(seen[0].3, crate::RuleId::DEFAULT_DENY);
    }

    #[test]
    fn tool_action_lookup_poison_denies_refinement() {
        let history = tempfile::tempdir().expect("history directory");
        let schema = crate::generate_mcp_schema(
            "alpha",
            r#"{
                "result": {
                    "tools": [{
                        "name": "read",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"path": {"type": "string"}},
                            "required": ["path"]
                        }
                    }]
                }
            }"#,
        )
        .expect("the MCP schema generates");
        let authority = PolicyEngine::open_with_mcp_schemas(
            source(r#"permit(principal, action == Box::Action::"mcp:call", resource);"#),
            &[schema],
            &history.path().join("dogwood.redb"),
        )
        .expect("the authority opens");
        authority.authority.poison_live_for_test();

        let arguments = serde_json::json!({"path": "/workspace/input"});
        assert!(matches!(
            authority.refine_tool_call(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                "alpha",
                "read",
                &arguments,
            ),
            Decision::Deny {
                reason: crate::DenyReason::InternalFault,
                ..
            }
        ));
    }

    /// Every box maps to the fixed resource.
    #[test]
    fn every_box_uses_resource_unused() {
        let request = Request::ShellExec {
            command: "printf hello",
            program: "printf",
            args: &[],
            cwd: "/home",
        };
        let shell = Principal::agent();
        let fixed = policy(r#"permit(principal, action, resource == Box::Resource::"unused");"#);
        let other = policy(r#"permit(principal, action, resource == Box::Resource::"other");"#);

        for name in ["codex", "review"] {
            let governed = GovernedBox::assigned(name);
            assert!(
                fixed.decide(&governed, &shell, &request).is_allow(),
                "{name} must map to Resource::\"unused\""
            );
            assert!(
                !other.decide(&governed, &shell, &request).is_allow(),
                "no box may map to another resource id"
            );
        }
    }
}
