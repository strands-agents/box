//! This box's collector and final policy enforcement point decision recorder.
//!
//! One collector per box, in the box's own trusted process. It is opened before the boundary is
//! assembled, because its port has to be pinned in the containment config the workload runs under.

use std::cell::RefCell;
use std::io;
use std::sync::Arc;

use egress_gateway::{
    AuditDecision, EffectAttempt as EgressEffectAttempt,
    EffectInterceptor as EgressEffectInterceptor, EffectPermit as EgressEffectPermit,
    EgressDecision, Emitter, McpFrame,
};
use policy::{Decision, DecisionObserver, DenyReason, PolicyAttribution, RuleId};
use telemetry::{DecisionCause, DecisionRecord};

use crate::error::BoxError;

/// Re-exported so a caller naming this module reaches the live handle through it.
pub(crate) use telemetry::Collector;

/// Re-exported on the same terms, because this module shadows the crate's own name.
pub(crate) use telemetry::{ControlOperation, ControlRecord};

/// Which policy a control record names, by file name rather than by path.
pub(crate) fn policy_subject(sources: &[policy::Policy]) -> String {
    if sources.is_empty() {
        return "<no authored policy>".to_string();
    }
    sources
        .iter()
        .map(|source| {
            source.origin.file_name().map_or_else(
                || source.origin.to_string_lossy().into_owned(),
                |name| name.to_string_lossy().into_owned(),
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The effective decision that one policy enforcement point applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectiveDecision {
    correlation: telemetry::Correlation,
    action: String,
    resource: String,
    rule: EffectiveRule,
    verdict: EffectiveVerdict,
    reason: Option<String>,
    cause: DecisionCause,
    attribution: Vec<PolicyAttribution>,
    subject: Option<telemetry::Subject>,
    /// Whether Box applied the verdict; `false` for a denial log-only mode let through.
    enforced: bool,
    /// Each rule log-only mode let through across the attempt's legs and gates.
    would_deny: Vec<String>,
}

/// What determined an effective decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EffectiveRule {
    Policy(RuleId),
    Enforcement(&'static str),
}

/// The authorization result that a policy enforcement point applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EffectiveVerdict {
    Permit,
    Deny,
}

/// One policy verdict an enforcement point observed, with what it was about.
#[derive(Clone)]
pub(crate) struct ObservedDecision {
    action: String,
    resource: String,
    decision: Decision,
    /// Each rule log-only mode let through across the attempt, on the observation that decides it.
    would_deny: Vec<String>,
}

impl ObservedDecision {
    pub(crate) fn action(&self) -> &str {
        &self.action
    }
}

struct PendingEgressDecision {
    identity: EgressIdentity,
    verdict: AuditDecision,
    effective: EffectiveDecision,
    /// One remote `tools/call`'s server, tool, and raw arguments, held until the emitter knows
    /// the request's own context.
    tool_call: Option<RemoteToolCall>,
}

/// One remote `tools/call` as the gateway presented it.
struct RemoteToolCall {
    server: String,
    tool: String,
    arguments: String,
    /// Where the emitter leaves the call's record for the reply observer to end.
    record: ToolCallSlot,
}

/// The record of one permitted remote tool call, filled when its decision is emitted and taken
/// when its reply ends it. A slot dropped while full ends the call `indeterminate`.
type ToolCallSlot = Arc<std::sync::Mutex<Option<McpToolCallRecord>>>;

#[cfg(test)]
thread_local! {
    /// How many permits this thread wrapped to observe a reply, for the tests that pin when.
    static OBSERVING_PERMITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// How many tool-call records this thread built, so a test can see that none was built for a
    /// box whose targets take none.
    static TOOL_CALLS_BUILT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

thread_local! {
    static POLICY_OBSERVATIONS: RefCell<Option<Vec<ObservedDecision>>> =
        const { RefCell::new(None) };
    static PENDING_EGRESS_DECISION: RefCell<Option<PendingEgressDecision>> =
        const { RefCell::new(None) };
}

impl EffectiveDecision {
    /// Carry one policy verdict when it is also the effective decision.
    pub(crate) fn from_policy(
        action: impl Into<String>,
        resource: impl Into<String>,
        decision: &Decision,
    ) -> Self {
        match decision {
            // A denial log-only mode let through keeps the policy's verdict, marked unenforced.
            Decision::Allow {
                rule,
                would_deny: Some(reason),
                ..
            } => Self {
                correlation: telemetry::Correlation::current(),
                subject: None,
                action: action.into(),
                resource: resource.into(),
                rule: EffectiveRule::Policy(rule.clone()),
                verdict: EffectiveVerdict::Deny,
                reason: Some(deny_reason(reason).to_string()),
                cause: decision_cause(reason),
                attribution: decision.attribution().to_vec(),
                enforced: false,
                would_deny: would_deny_ids([decision]),
            },
            Decision::Allow { rule, .. } => Self {
                correlation: telemetry::Correlation::current(),
                subject: None,
                action: action.into(),
                resource: resource.into(),
                rule: EffectiveRule::Policy(rule.clone()),
                verdict: EffectiveVerdict::Permit,
                reason: None,
                cause: DecisionCause::Permitted,
                attribution: decision.attribution().to_vec(),
                enforced: true,
                would_deny: Vec::new(),
            },
            Decision::Deny { reason, rule, .. } => Self {
                correlation: telemetry::Correlation::current(),
                subject: None,
                action: action.into(),
                resource: resource.into(),
                rule: EffectiveRule::Policy(rule.clone()),
                verdict: EffectiveVerdict::Deny,
                reason: Some(deny_reason(reason).to_string()),
                cause: decision_cause(reason),
                attribution: decision.attribution().to_vec(),
                enforced: true,
                would_deny: Vec::new(),
            },
        }
    }

    /// Create a permit for a gate that does not retain the raw policy rule.
    pub(crate) fn enforcement_permit(
        action: impl Into<String>,
        resource: impl Into<String>,
        gate: &'static str,
    ) -> Self {
        Self {
            correlation: telemetry::Correlation::current(),
            subject: None,
            action: action.into(),
            resource: resource.into(),
            rule: EffectiveRule::Enforcement(gate),
            verdict: EffectiveVerdict::Permit,
            reason: None,
            cause: DecisionCause::Enforcement,
            attribution: Vec::new(),
            enforced: true,
            would_deny: Vec::new(),
        }
    }

    /// Create a denial for a gate that does not retain the raw policy rule.
    pub(crate) fn enforcement_deny(
        action: impl Into<String>,
        resource: impl Into<String>,
        gate: &'static str,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            correlation: telemetry::Correlation::current(),
            subject: None,
            action: action.into(),
            resource: resource.into(),
            rule: EffectiveRule::Enforcement(gate),
            verdict: EffectiveVerdict::Deny,
            reason: Some(reason.into()),
            cause: DecisionCause::Enforcement,
            attribution: Vec::new(),
            enforced: true,
            would_deny: Vec::new(),
        }
    }

    /// A gate's permit, reported as the policy verdict beneath it when the gate kept one.
    pub(crate) fn gate_permit(
        action: impl Into<String>,
        resource: impl Into<String>,
        gate: &'static str,
        determined: Option<&ObservedDecision>,
    ) -> Self {
        let decision = match determined.filter(|observed| observed.decision.is_allow()) {
            Some(observed) => Self::from_policy(action, resource, &observed.decision),
            None => Self::enforcement_permit(action, resource, gate),
        };
        decision.with_would_deny(
            determined
                .into_iter()
                .flat_map(|observed| observed.would_deny.clone()),
        )
    }

    /// A gate's denial, reported as the policy verdict beneath it when the gate kept one.
    pub(crate) fn gate_deny(
        action: impl Into<String>,
        resource: impl Into<String>,
        gate: &'static str,
        reason: impl Into<String>,
        determined: Option<&ObservedDecision>,
    ) -> Self {
        let decision = match determined.filter(|observed| !observed.decision.is_allow()) {
            Some(observed) => Self::from_policy(action, resource, &observed.decision),
            None => Self::enforcement_deny(action, resource, gate, reason),
        };
        decision.with_would_deny(
            determined
                .into_iter()
                .flat_map(|observed| observed.would_deny.clone()),
        )
    }

    /// One check of a native filesystem operation the kernel refused overall: the gate's refusal,
    /// naming in `would_deny` the rule of a check log-only mode let through.
    pub(crate) fn refused_check(
        action: impl Into<String>,
        resource: impl Into<String>,
        decision: &Decision,
        gate: &'static str,
        reason: impl Into<String>,
    ) -> Self {
        Self::enforcement_deny(action, resource, gate, reason)
            .with_would_deny(would_deny_ids([decision]))
    }

    /// Name every rule log-only mode let through across the attempt, when there are any; a
    /// decision keeps its own when `rules` names none.
    pub(crate) fn with_would_deny(mut self, rules: impl IntoIterator<Item = String>) -> Self {
        let rules: Vec<String> = rules.into_iter().collect();
        if !rules.is_empty() {
            self.would_deny = rules;
        }
        self
    }

    /// State what this decision was about, under the standard names.
    ///
    /// `None` leaves the resource string as the whole statement, which is what a path already is.
    pub(crate) fn about(mut self, subject: Option<telemetry::Subject>) -> Self {
        if subject.is_some() {
            self.subject = subject;
        }
        self
    }

    /// Replace a raw denial with a labeled permit that the enforcement point applies.
    pub(crate) fn into_enforcement_permit(self, gate: &'static str) -> Self {
        Self {
            correlation: self.correlation,
            subject: self.subject,
            action: self.action,
            resource: self.resource,
            rule: EffectiveRule::Enforcement(gate),
            verdict: EffectiveVerdict::Permit,
            reason: None,
            cause: DecisionCause::Enforcement,
            attribution: Vec::new(),
            enforced: true,
            would_deny: Vec::new(),
        }
    }

    fn into_record(self) -> DecisionRecord {
        let rule = match self.rule {
            EffectiveRule::Policy(rule) => rule.to_string(),
            EffectiveRule::Enforcement(gate) => format!("enforcement:{gate}"),
        };
        let record = match self.verdict {
            EffectiveVerdict::Permit => DecisionRecord::permit(&self.action, &self.resource, &rule),
            EffectiveVerdict::Deny => DecisionRecord::deny(
                &self.action,
                &self.resource,
                &rule,
                self.reason.as_deref().unwrap_or("the effect was refused"),
            ),
        };
        let record = match self.subject {
            Some(subject) => record.about(subject),
            None => record,
        };
        let record = if self.enforced {
            record
        } else {
            record.not_enforced()
        };
        let record = if self.would_deny.is_empty() {
            record
        } else {
            record.with_would_deny(self.would_deny)
        };
        record
            .correlated(self.correlation)
            .caused_by(self.cause)
            .determined_by(self.attribution.iter().map(|entry| {
                telemetry::DeterminingPolicy::new(&policy_identifier(entry))
                    .described(entry.description.as_deref())
            }))
    }

    #[cfg(test)]
    pub(crate) fn attribution(&self) -> &[PolicyAttribution] {
        &self.attribution
    }

    #[cfg(test)]
    pub(crate) fn cause(&self) -> DecisionCause {
        self.cause
    }

    #[cfg(test)]
    pub(crate) fn enforced(&self) -> bool {
        self.enforced
    }

    #[cfg(test)]
    pub(crate) fn would_deny(&self) -> &[String] {
        &self.would_deny
    }

    #[cfg(test)]
    pub(crate) fn correlation(&self) -> &telemetry::Correlation {
        &self.correlation
    }

    #[cfg(test)]
    pub(crate) fn parts(&self) -> (&str, &str, &EffectiveRule, EffectiveVerdict, Option<&str>) {
        (
            &self.action,
            &self.resource,
            &self.rule,
            self.verdict,
            self.reason.as_deref(),
        )
    }
}

/// Capture policy verdicts only while a Policy Enforcement Point requests them.
pub(crate) struct PolicyDecisionObserver;

impl DecisionObserver for PolicyDecisionObserver {
    fn observed(&self, action: &str, resource: &str, decision: &Decision) {
        POLICY_OBSERVATIONS.with(|observations| {
            if let Some(observations) = observations.borrow_mut().as_mut() {
                observations.push(ObservedDecision {
                    action: action.to_string(),
                    resource: resource.to_string(),
                    decision: decision.clone(),
                    would_deny: Vec::new(),
                });
            }
        });
    }
}

/// Collect every policy verdict this thread reaches until it is read.
///
/// The collection is per thread, so hold one only across work that cannot move to another.
pub(crate) struct ObservationCapture {
    previous: Option<Option<Vec<ObservedDecision>>>,
}

impl ObservationCapture {
    pub(crate) fn begin() -> Self {
        let previous =
            POLICY_OBSERVATIONS.with(|observations| observations.borrow_mut().replace(Vec::new()));
        Self {
            previous: Some(previous),
        }
    }

    /// The deciding verdict: an adapter asking about several legs stops at the first denial, and
    /// the last permit stands when every leg allowed. In log-only mode a let-through denial does
    /// not stop the legs, so it decides, unless a later leg's real denial stopped the attempt.
    pub(crate) fn last(self) -> Option<ObservedDecision> {
        let observations = self.finish();
        let index = deciding_index(&observations)?;
        let would_deny = would_deny_ids(observations.iter().map(|observed| &observed.decision));
        let mut deciding = observations.into_iter().nth(index)?;
        deciding.would_deny = would_deny;
        Some(deciding)
    }

    fn finish(mut self) -> Vec<ObservedDecision> {
        POLICY_OBSERVATIONS.with(|observations| {
            let current = std::mem::replace(
                &mut *observations.borrow_mut(),
                self.previous.take().unwrap_or_default(),
            );
            current.unwrap_or_default()
        })
    }
}

impl Drop for ObservationCapture {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            POLICY_OBSERVATIONS.with(|observations| {
                *observations.borrow_mut() = previous;
            });
        }
    }
}

/// Capture the canonical action from one synchronous policy decision.
pub(crate) fn capture_policy_action(
    evaluate: impl FnOnce() -> Decision,
) -> (Decision, Option<String>) {
    let capture = ObservationCapture::begin();
    let decision = evaluate();
    let action = capture
        .finish()
        .into_iter()
        .next_back()
        .map(|observed| observed.action);
    (decision, action)
}

/// Preserve the remote MCP gate identity until the egress emitter runs.
pub(crate) struct EgressDecisionInterceptor {
    inner: Arc<dyn EgressEffectInterceptor>,
    recorder: Arc<DecisionRecorder>,
}

impl EgressDecisionInterceptor {
    /// Wrap the policy adapter without changing its public seam.
    pub(crate) fn over(
        inner: Arc<dyn EgressEffectInterceptor>,
        recorder: Arc<DecisionRecorder>,
    ) -> Arc<dyn EgressEffectInterceptor> {
        Arc::new(Self { inner, recorder })
    }
}

/// Observes one remote `tools/call` reply for the record, and passes it to the policy's own
/// observer unchanged.
struct ObservedToolReply {
    inner: Option<Box<dyn egress_gateway::ReplyObserver>>,
    reader: policy::ReplyReader,
    record: ToolCallSlot,
}

impl ObservedToolReply {
    /// Record how the call ended, from the reply body when one arrived.
    fn completed(&mut self, body: Option<&[u8]>) {
        let Some(record) = self.record.lock().ok().and_then(|mut slot| slot.take()) else {
            return;
        };
        let reply = body.and_then(|body| self.reader.reply_in(body));
        let end = reply
            .as_ref()
            .map_or(policy::McpReply::Indeterminate, policy::McpReply::of_reply);
        record.completed(
            end,
            reply
                .as_ref()
                .and_then(|reply| reply.pointer("/result/structuredContent")),
        );
    }
}

impl egress_gateway::ReplyObserver for ObservedToolReply {
    fn complete(&mut self, reply: &[u8]) -> bool {
        match self.inner.as_mut() {
            // Defer to the policy's observer, so its early finish is unchanged.
            Some(inner) => inner.complete(reply),
            // With no policy observer, finish as soon as the reply has arrived, so a stream the
            // server holds open releases its copy at the answer.
            None => self.reader.holds_the_reply(reply),
        }
    }

    fn finished(mut self: Box<Self>, reply: &[u8]) {
        self.completed(Some(reply));
        if let Some(inner) = self.inner.take() {
            inner.finished(reply);
        }
    }

    fn abandoned(mut self: Box<Self>) {
        self.completed(None);
        if let Some(inner) = self.inner.take() {
            inner.abandoned();
        }
    }
}

impl Drop for ObservedToolReply {
    // A reply the gateway never read, such as one refused before it streamed, still ends the
    // call, as the stdio broker records a call whose connection ended.
    fn drop(&mut self) {
        self.completed(None);
    }
}

/// One permit whose reply the box observes beside the policy's own observer.
struct ObservingPermit {
    inner: Box<dyn EgressEffectPermit>,
    record: ToolCallSlot,
}

impl EgressEffectPermit for ObservingPermit {
    fn record_outcome(self: Box<Self>, outcome: egress_gateway::EffectOutcome) -> io::Result<()> {
        self.inner.record_outcome(outcome)
    }

    fn mark_indeterminate(self: Box<Self>) {
        self.inner.mark_indeterminate();
    }

    fn reply_observer(
        &mut self,
        request_id: Option<&str>,
    ) -> Option<Box<dyn egress_gateway::ReplyObserver>> {
        let inner = self.inner.reply_observer(request_id);
        // A permit is wrapped only when a target takes tool calls, so every reply is read. The copy
        // counts against the gateway's shared budget unless the policy reads the reply anyway.
        Some(Box::new(ObservedToolReply {
            inner,
            reader: policy::ReplyReader::for_request(request_id),
            record: Arc::clone(&self.record),
        }))
    }
}

/// One recorded MCP tool call that still owes the record of how it ended.
///
/// Both transports end it here: `completed` with the reply, or `refused` when the call never ran.
/// One dropped while open records `indeterminate`, so a path that forgets to end it loses nothing.
#[must_use = "a tool call records how it ended; dropping it records `indeterminate`"]
pub(crate) struct McpToolCallRecord {
    collector: Arc<Collector>,
    server: String,
    tool: String,
    correlation: telemetry::Correlation,
    open: bool,
}

impl McpToolCallRecord {
    /// Record how the call ended, with the tool's `structuredContent` when it declared one.
    pub(crate) fn completed(mut self, reply: policy::McpReply, output: Option<&serde_json::Value>) {
        self.end(reply, output);
    }

    /// End a call that never ran, which records no completion.
    pub(crate) fn refused(mut self) {
        self.open = false;
    }

    fn end(&mut self, reply: policy::McpReply, output: Option<&serde_json::Value>) {
        if !std::mem::replace(&mut self.open, false) {
            return;
        }
        #[cfg(test)]
        TOOL_CALLS_BUILT.with(|count| count.set(count.get() + 1));
        self.collector.mcp_tool_call(
            telemetry::McpToolCall::completed(&self.server, &self.tool, reply.as_str(), output)
                .correlated(self.correlation.clone()),
        );
    }
}

impl Drop for McpToolCallRecord {
    fn drop(&mut self) {
        self.end(policy::McpReply::Indeterminate, None);
    }
}

impl EgressEffectInterceptor for EgressDecisionInterceptor {
    fn intercept(
        &self,
        effect: &EgressEffectAttempt<'_>,
    ) -> io::Result<Box<dyn EgressEffectPermit>> {
        let Some(identity) = EgressIdentity::of(effect) else {
            return self.inner.intercept(effect);
        };

        let capture = ObservationCapture::begin();
        let result = self.inner.intercept(effect);
        let observations = capture.finish();
        let verdict = if result.is_ok() {
            AuditDecision::Allow
        } else {
            AuditDecision::Deny
        };
        let refusal = result.as_ref().err().map(std::string::ToString::to_string);
        let effective = match effect {
            EgressEffectAttempt::HttpRequest {
                mcp: Some(frame), ..
            } => remote_mcp_decision(frame, refusal, &observations),
            _ => ordinary_egress_decision(&identity, refusal, &observations),
        };
        // Copy a call's arguments only when some target takes tool-call records, so a box whose
        // targets take none does no work for them on the enforcement path.
        let wants_tool_calls = self.recorder.wants_tool_calls();
        let tool_call = match effect {
            EgressEffectAttempt::HttpRequest {
                mcp:
                    Some(McpFrame::ToolCall {
                        server,
                        tool,
                        arguments,
                    }),
                ..
            } if wants_tool_calls => Some(RemoteToolCall {
                server: (*server).to_string(),
                tool: (*tool).to_string(),
                arguments: (*arguments).to_string(),
                record: ToolCallSlot::default(),
            }),
            _ => None,
        };
        // Observe every permitted remote `tools/call` reply, so a completion record states how
        // the call ended whether or not a per-tool rule named the tool.
        // Only when some target takes tool-call records: the copy counts against the gateway's
        // shared budget, so reading a reply nobody records would cost the policy's own reads.
        let result = match (result, &tool_call) {
            (Ok(permit), Some(call)) => {
                #[cfg(test)]
                OBSERVING_PERMITS.with(|count| count.set(count.get() + 1));
                Ok(Box::new(ObservingPermit {
                    inner: permit,
                    record: Arc::clone(&call.record),
                }) as Box<dyn EgressEffectPermit>)
            }
            (result, _) => result,
        };
        PENDING_EGRESS_DECISION.with(|pending| {
            pending.borrow_mut().replace(PendingEgressDecision {
                identity,
                verdict,
                effective,
                tool_call,
            });
        });

        result
    }

    fn stage_mcp_catalog(
        &self,
        server: &str,
        reply: egress_gateway::McpListReply<'_>,
    ) -> io::Result<()> {
        self.inner.stage_mcp_catalog(server, reply)
    }
}

/// Which leg of one exchange a decision is about.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EgressLeg {
    Connection,
    Request,
}

impl EgressLeg {
    /// The leg an emitted decision is about. The gateway states a method on a request and none on a
    /// connection, so this is the one place that convention is read.
    fn of_emitted(method: &str) -> Self {
        if method.is_empty() {
            Self::Connection
        } else {
            Self::Request
        }
    }
}

/// The identity one egress decision is about.
struct EgressIdentity {
    leg: EgressLeg,
    host: String,
    port: u16,
    method: String,
    path: String,
}

impl EgressIdentity {
    /// The identity of an attempt the policy decides, or `None` for one it does not.
    fn of(effect: &EgressEffectAttempt<'_>) -> Option<Self> {
        match effect {
            EgressEffectAttempt::Resolve { host, port }
            | EgressEffectAttempt::Connect { host, port, .. } => Some(Self {
                leg: EgressLeg::Connection,
                host: (*host).to_string(),
                port: *port,
                method: String::new(),
                path: String::new(),
            }),
            EgressEffectAttempt::HttpRequest {
                host,
                port,
                method,
                path,
                ..
            } => Some(Self {
                leg: EgressLeg::Request,
                host: (*host).to_string(),
                port: *port,
                method: (*method).to_string(),
                path: (*path).to_string(),
            }),
            _ => None,
        }
    }

    /// The identity one emitted decision is about.
    fn emitted(decision: &EgressDecision) -> Self {
        Self {
            leg: EgressLeg::of_emitted(&decision.method),
            host: decision.host.clone(),
            port: decision.port,
            method: decision.method.clone(),
            path: decision.path.clone(),
        }
    }

    /// The destination, under the standard names. The gateway already holds each value apart, so
    /// nothing re-parses the resource string.
    fn subject(&self) -> telemetry::Subject {
        match self.leg {
            EgressLeg::Connection => telemetry::Subject::destination(&self.host, self.port),
            EgressLeg::Request => telemetry::Subject::http(&self.host, self.port, &self.method),
        }
    }

    /// Whether both name the same leg of the same exchange.
    ///
    /// A connection compares on host and port alone, because the gateway emits a placeholder for
    /// the method and path a connection does not have.
    fn is(&self, other: &Self) -> bool {
        if self.leg != other.leg || self.host != other.host || self.port != other.port {
            return false;
        }
        match self.leg {
            EgressLeg::Connection => true,
            EgressLeg::Request => self.method == other.method && self.path == other.path,
        }
    }

    fn action(&self) -> &'static str {
        match self.leg {
            EgressLeg::Connection => r#"Box::Action::"net:connect""#,
            EgressLeg::Request => r#"Box::Action::"http:request""#,
        }
    }

    fn resource(&self) -> String {
        match self.leg {
            EgressLeg::Connection => format!("{}:{}", self.host, self.port),
            EgressLeg::Request => format!("{}:{}{}", self.host, self.port, self.path),
        }
    }
}

/// The effective decision for an egress attempt that carries no MCP frame.
fn ordinary_egress_decision(
    identity: &EgressIdentity,
    refusal: Option<String>,
    observations: &[ObservedDecision],
) -> EffectiveDecision {
    let determined = deciding(observations);
    let would_deny = would_deny_ids(observations.iter().map(|observed| &observed.decision));
    let decision = match refusal {
        Some(refusal) => EffectiveDecision::gate_deny(
            identity.action(),
            identity.resource(),
            "egress",
            refusal,
            determined,
        ),
        None => EffectiveDecision::gate_permit(
            identity.action(),
            identity.resource(),
            "egress",
            determined,
        ),
    };
    decision.with_would_deny(would_deny)
}

/// The verdict that decides an attempt over `observations`: the first denial log-only mode let
/// through, since in log-only mode a denial does not stop the later gates, else the last verdict.
fn deciding(observations: &[ObservedDecision]) -> Option<&ObservedDecision> {
    observations.get(deciding_index(observations)?)
}

/// Each rule that would have denied one of `decisions` and that log-only mode let through, in the
/// order decided, named as its record names it.
pub(crate) fn would_deny_ids<'a>(decisions: impl IntoIterator<Item = &'a Decision>) -> Vec<String> {
    let mut rules: Vec<String> = Vec::new();
    for decision in decisions {
        let Decision::Allow {
            rule,
            attribution,
            would_deny: Some(_),
            ..
        } = decision
        else {
            continue;
        };
        let named = attribution
            .first()
            .map_or_else(|| rule.as_str().to_string(), policy_identifier);
        if !rules.contains(&named) {
            rules.push(named);
        }
    }
    rules
}

/// Which of `observations` decides the attempt: a real denial in the last leg stopped it, so that
/// leg; otherwise the first denial log-only mode let through; otherwise the last verdict.
fn deciding_index(observations: &[ObservedDecision]) -> Option<usize> {
    let last = observations.len().checked_sub(1)?;
    if !observations[last].decision.is_allow() {
        return Some(last);
    }
    Some(
        observations
            .iter()
            .position(|observed| observed.decision.would_deny().is_some())
            .unwrap_or(last),
    )
}

fn remote_mcp_decision(
    frame: &McpFrame<'_>,
    refusal: Option<String>,
    observations: &[ObservedDecision],
) -> EffectiveDecision {
    remote_mcp_record(frame, refusal, observations).with_would_deny(would_deny_ids(
        observations.iter().map(|observed| &observed.decision),
    ))
}

fn remote_mcp_record(
    frame: &McpFrame<'_>,
    refusal: Option<String>,
    observations: &[ObservedDecision],
) -> EffectiveDecision {
    if refusal.is_none()
        && let Some(flipped) = observations
            .iter()
            .find(|observed| observed.decision.would_deny().is_some())
    {
        return EffectiveDecision::from_policy(
            &flipped.action,
            &flipped.resource,
            &flipped.decision,
        );
    }
    let last = observations.last();
    if refusal.is_none() {
        if matches!(
            last.map(|observed| &observed.decision),
            Some(Decision::Deny {
                reason: DenyReason::PolicyPending,
                ..
            })
        ) {
            return EffectiveDecision::enforcement_permit(
                r#"Box::Action::"mcp:call""#,
                mcp_resource(frame),
                "policy-pending-bootstrap",
            );
        }
        let keeps_coarse_permit = last.is_some_and(|observed| {
            matches!(
                &observed.decision,
                Decision::Deny {
                    reason: DenyReason::NoMatch,
                    ..
                }
            ) || matches!(
                &observed.decision,
                Decision::Allow { rule, .. } if rule.as_str() == RuleId::DEFAULT_DENY
            )
        });
        if keeps_coarse_permit
            && let Some(coarse) = observations.iter().rev().skip(1).find(|observed| {
                observed.action == r#"Box::Action::"mcp:call""#
                    && matches!(&observed.decision, Decision::Allow { .. })
            })
        {
            return EffectiveDecision::from_policy(
                &coarse.action,
                &coarse.resource,
                &coarse.decision,
            );
        }
        if let Some(observed) = last
            && matches!(&observed.decision, Decision::Allow { .. })
        {
            return EffectiveDecision::from_policy(
                &observed.action,
                &observed.resource,
                &observed.decision,
            );
        }
        return EffectiveDecision::enforcement_permit(
            r#"Box::Action::"mcp:call""#,
            mcp_resource(frame),
            "mcp-composite",
        );
    }

    if let Some(observed) = last
        && matches!(&observed.decision, Decision::Deny { .. })
    {
        return EffectiveDecision::from_policy(
            &observed.action,
            &observed.resource,
            &observed.decision,
        );
    }

    let (action, resource) = last
        .map(|observed| (observed.action.clone(), observed.resource.clone()))
        .unwrap_or_else(|| {
            (
                r#"Box::Action::"mcp:call""#.to_string(),
                mcp_resource(frame),
            )
        });
    EffectiveDecision::enforcement_deny(
        action,
        resource,
        "mcp-refinement",
        refusal.unwrap_or_else(|| "the remote MCP request was refused".to_string()),
    )
}

fn mcp_resource(frame: &McpFrame<'_>) -> String {
    match frame {
        McpFrame::ToolCall { server, tool, .. } => format!("{server}/{tool}"),
        McpFrame::PromptGet { server, prompt } => format!("{server}/{prompt}"),
        McpFrame::ResourceRead { server, uri } => format!("{server}/{uri}"),
        McpFrame::List { server, method } => format!("{server}/{method}"),
    }
}

/// The box-owned sink for final policy enforcement point decisions.
pub(crate) struct DecisionRecorder {
    collector: Option<Arc<Collector>>,
    decisions: Option<Arc<super::decisions::PolicyDecisionSender>>,
    correlation: Option<telemetry::Correlation>,
    /// Whether this run has recorded a denial that was not enforced, shared by every copy.
    flipped: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    recorded: Arc<std::sync::Mutex<Vec<EffectiveDecision>>>,
}

impl DecisionRecorder {
    /// Bind effective decision recording to this box's collector and the caller's decision channel.
    pub(crate) fn over(
        collector: Arc<Collector>,
        decisions: Option<super::decisions::PolicyDecisionSender>,
    ) -> Arc<Self> {
        Arc::new(Self {
            collector: Some(collector),
            decisions: decisions.map(Arc::new),
            correlation: None,
            flipped: Arc::default(),
            #[cfg(test)]
            recorded: Arc::new(std::sync::Mutex::new(Vec::new())),
        })
    }

    pub(crate) fn for_request(&self, correlation: telemetry::Correlation) -> Arc<Self> {
        Arc::new(Self {
            collector: self.collector.clone(),
            decisions: self.decisions.clone(),
            correlation: Some(correlation),
            flipped: Arc::clone(&self.flipped),
            #[cfg(test)]
            recorded: Arc::clone(&self.recorded),
        })
    }

    pub(crate) fn request_context(&self) -> telemetry::Correlation {
        self.correlation
            .clone()
            .unwrap_or_else(telemetry::Correlation::current)
    }

    /// Submit one effective decision without changing it.
    pub(crate) fn record(&self, mut decision: EffectiveDecision) {
        if let Some(context) = &self.correlation {
            decision.correlation = context.clone();
        }
        #[cfg(test)]
        if let Ok(mut recorded) = self.recorded.lock() {
            recorded.push(decision.clone());
        }
        let enforced = decision.enforced;
        let mut record = decision.into_record();
        // After the first denial Box let through, the run can drift from what enforcing would do.
        if !enforced && !self.flipped.swap(true, std::sync::atomic::Ordering::SeqCst) {
            record = record.first_flip();
        }
        if let Some(decisions) = &self.decisions {
            decisions.send(&record);
        }
        if let Some(collector) = &self.collector {
            collector.record(record);
        }
    }

    /// Whether any target takes tool-call records, so the box reads a remote reply only for one.
    pub(crate) fn wants_tool_calls(&self) -> bool {
        self.collector
            .as_ref()
            .is_some_and(|collector| collector.accepts(telemetry::Signal::McpToolCalls))
    }

    /// Record one decided MCP tool call, and return what records how it ends; `None` when no
    /// target takes MCP tool calls.
    ///
    /// `arguments` is the call's JSON text, and text that does not parse records no field. The
    /// returned record reuses `correlation`, so the call's two records join on every transport.
    pub(crate) fn mcp_tool_called(
        &self,
        server: &str,
        tool: &str,
        arguments: &str,
        correlation: telemetry::Correlation,
    ) -> Option<McpToolCallRecord> {
        if !self.wants_tool_calls() {
            return None;
        }
        let collector = Arc::clone(self.collector.as_ref()?);
        #[cfg(test)]
        TOOL_CALLS_BUILT.with(|count| count.set(count.get() + 1));
        let arguments = serde_json::from_str(arguments).unwrap_or(serde_json::Value::Null);
        collector.mcp_tool_call(
            telemetry::McpToolCall::called(server, tool, &arguments)
                .correlated(correlation.clone()),
        );
        Some(McpToolCallRecord {
            collector,
            server: server.to_string(),
            tool: tool.to_string(),
            correlation,
            open: true,
        })
    }

    pub(crate) fn mcp_unmatched(&self, program: &str, arguments: &[String]) {
        if let Some(collector) = &self.collector {
            collector.mcp_unmatched(
                telemetry::McpUnmatched::new(program, arguments).correlated(self.request_context()),
            );
        }
    }

    #[cfg(test)]
    pub(crate) fn discarding() -> Arc<Self> {
        Arc::new(Self {
            collector: None,
            decisions: None,
            correlation: None,
            flipped: Arc::default(),
            recorded: Arc::new(std::sync::Mutex::new(Vec::new())),
        })
    }

    #[cfg(test)]
    pub(crate) fn recorded(&self) -> Vec<EffectiveDecision> {
        self.recorded
            .lock()
            .map(|recorded| recorded.clone())
            .unwrap_or_default()
    }
}

/// Connect the egress gateway's effective decisions to this box's recorder.
pub(crate) struct EgressDecisionRecorder {
    recorder: Arc<DecisionRecorder>,
}

impl EgressDecisionRecorder {
    /// Bind the gateway emitter to the shared decision recorder.
    pub(crate) fn over(recorder: Arc<DecisionRecorder>) -> Self {
        Self { recorder }
    }
}

impl Emitter for EgressDecisionRecorder {
    fn emit(&self, decision: EgressDecision) {
        let request = &decision.correlation;
        let transport = telemetry::Correlation::from_headers(
            request.context("traceparent"),
            request.context("tracestate"),
        );
        let correlation = telemetry::Correlation::from_headers(
            request.context("mcp_traceparent"),
            request.context("mcp_tracestate"),
        )
        .with_transport(transport)
        .mcp(request.context("jsonrpc_request_id"))
        .request(Some(request.as_str()));
        let identity = EgressIdentity::emitted(&decision);
        if let Some((mut effective, tool_call)) = PENDING_EGRESS_DECISION.with(|pending| {
            let held = pending.borrow_mut().take()?;
            (held.verdict == decision.decision && held.identity.is(&identity))
                .then_some((held.effective, held.tool_call))
        }) {
            effective.correlation = correlation.clone();
            effective.subject = Some(identity.subject());
            // Every decided remote `tools/call` states its own arguments, allowed or refused, so a
            // reader learns what was asked for and not only what was judged.
            if let Some(call) = tool_call
                && let Some(record) = self.recorder.mcp_tool_called(
                    &call.server,
                    &call.tool,
                    &call.arguments,
                    correlation,
                )
            {
                // A permitted call is ended by its reply; a refused one never ran.
                match (decision.decision, call.record.lock()) {
                    (AuditDecision::Allow, Ok(mut slot)) => *slot = Some(record),
                    _ => record.refused(),
                }
            }
            self.recorder.record(effective);
            return;
        }

        let mut effective = match decision.decision {
            AuditDecision::Allow => EffectiveDecision::enforcement_permit(
                identity.action(),
                identity.resource(),
                "egress",
            ),
            AuditDecision::Deny => EffectiveDecision::enforcement_deny(
                identity.action(),
                identity.resource(),
                "egress",
                decision.reason,
            ),
        };
        effective.correlation = correlation;
        effective.subject = Some(identity.subject());
        self.recorder.record(effective);
    }
}

/// The authored `@id`, or the engine's own rule identifier when the policy authored none.
fn policy_identifier(attribution: &PolicyAttribution) -> String {
    attribution
        .annotation_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| attribution.rule.as_str())
        .to_string()
}

/// A refusal's class, as the wire vocabulary names it.
fn decision_cause(reason: &DenyReason) -> DecisionCause {
    match reason {
        DenyReason::Forbidden => DecisionCause::Forbidden,
        DenyReason::NoMatch => DecisionCause::NoMatch,
        DenyReason::PolicyPending => DecisionCause::PolicyPending,
        DenyReason::InternalFault => DecisionCause::InternalFault,
    }
}

/// A refusal's class, in words an operator reads rather than a type name.
fn deny_reason(reason: &DenyReason) -> &'static str {
    match reason {
        DenyReason::Forbidden => "a forbid rule matched",
        DenyReason::NoMatch => "no permit matched",
        DenyReason::PolicyPending => "the complete policy bundle is not installed",
        DenyReason::InternalFault => "the request could not be evaluated, so it was refused",
    }
}

/// Open this box's collector from its stored record, with each target's secret read through
/// `secrets`.
pub(crate) fn open(
    layout: &crate::record::layout::BoxRoot,
    stored: &crate::record::config::Record,
    secrets: &crate::run::secret_sources::TelemetrySecrets,
) -> Result<Arc<Collector>, BoxError> {
    let directory = layout.telemetry_directory();
    layout.create_child_directory(&directory)?;

    let mut request = crate::record::config::telemetry::config_for(
        &stored.box_id,
        &stored.telemetry,
        layout,
        &stored.declared_sources()?,
        secrets.backend(),
    )?;
    if std::env::var_os(FAILURE_REPORT_VARIABLE).is_some_and(|value| !value.is_empty()) {
        request = request.reporting_failures();
    }
    Ok(Arc::new(telemetry::open(request)?))
}

/// The operator's variable that prints each failed telemetry batch to stderr with its full cause.
const FAILURE_REPORT_VARIABLE: &str = "STRANDS_BOX_TELEMETRY_DEBUG";

#[cfg(test)]
mod tests {
    use super::*;
    use egress_gateway::RequestId;
    use policy::{EgressPolicyInterceptor, GovernedBox, Policy, PolicyEngine, Principal};
    use std::path::PathBuf;
    use std::sync::Mutex;

    #[test]
    fn a_request_recorder_sends_to_the_callers_channel() {
        let (sender, receiver) = crate::policy_decisions(4);
        let recorder = DecisionRecorder {
            collector: None,
            decisions: Some(Arc::new(sender)),
            flipped: Arc::default(),
            correlation: None,
            recorded: Arc::new(Mutex::new(Vec::new())),
        };
        recorder
            .for_request(telemetry::Correlation::current())
            .record(EffectiveDecision::enforcement_deny(
                r#"Box::Action::"net:connect""#,
                "example.net:443",
                "egress",
                "refused",
            ));
        let decision = receiver
            .try_recv()
            .expect("the per-request recorder kept the channel");
        assert_eq!(
            (
                decision.permitted,
                decision.action.as_str(),
                decision.rule.as_str(),
                decision.cause.as_str()
            ),
            (false, "net:connect", "enforcement:egress", "enforcement")
        );
    }

    /// **A native check log-only mode let through, in an operation the kernel refused overall, is
    /// the gate's refusal that still names the rule in `would_deny`**, so a trial loses no rule and
    /// no record says a log-only policy blocked something; a real permit is the gate's refusal.
    #[test]
    fn a_refused_native_check_keeps_the_rule_log_only_let_through() {
        let flipped = connect_decision(
            r#"permit(principal, action, resource);
               @id("no-connect")
               forbid(principal, action == Box::Action::"net:connect", resource);"#,
            true,
        );
        let refused = EffectiveDecision::refused_check(
            r#"Box::Action::"fs:write""#,
            "/w/a",
            &flipped,
            "native-filesystem-policy",
            "refused",
        );
        assert_eq!(refused.parts().3, EffectiveVerdict::Deny);
        assert_eq!(
            refused.cause(),
            DecisionCause::Enforcement,
            "the kernel refused it, not the log-only policy"
        );
        assert!(refused.enforced);
        assert_eq!(
            refused.would_deny,
            ["no-connect"],
            "the rule is still named"
        );

        let permit = connect_decision("permit(principal, action, resource);", false);
        let gate = EffectiveDecision::refused_check(
            r#"Box::Action::"fs:write""#,
            "/w/a",
            &permit,
            "native-filesystem-policy",
            "refused",
        );
        assert_eq!(gate.cause(), DecisionCause::Enforcement);
    }

    /// **A real block after a let-through leg names that leg's rule**, on a record Box applied: it
    /// carries `would_deny` and no `enforced = false`, so a trial still finds the rule.
    #[test]
    fn a_real_block_after_a_let_through_leg_still_names_its_rule() {
        let flipped = connect_decision(
            r#"permit(principal, action, resource);
               @id("no-connect")
               forbid(principal, action == Box::Action::"net:connect", resource);"#,
            true,
        );
        let capture = ObservationCapture::begin();
        PolicyDecisionObserver.observed(r#"Box::Action::"fs:read""#, "/w/a", &flipped);
        let deciding = capture.last().expect("a verdict was observed");
        let blocked = EffectiveDecision::gate_deny(
            r#"Box::Action::"fs:read""#,
            "/w/a",
            "floor",
            "refused",
            Some(&deciding),
        );
        assert!(blocked.enforced);
        assert_eq!(blocked.would_deny, ["no-connect"]);
        let record = blocked.into_record();
        assert!(record.enforced());
        assert_eq!(record.would_deny(), ["no-connect"]);
    }

    /// One `net:connect` decided by an engine over `policy`, in log-only mode when `log_only` holds.
    ///
    /// An empty `policy` stands for one that permits no connection, since an engine with no policy
    /// at all never lets a denial through.
    fn connect_decision(policy: &str, log_only: bool) -> Decision {
        let history = tempfile::tempdir().expect("history directory");
        let text = if policy.is_empty() {
            r#"permit(principal, action == Box::Action::"fs:read", resource);"#
        } else {
            policy
        };
        let sources = vec![Policy {
            origin: PathBuf::from("policy.dw"),
            text: text.to_string(),
        }];
        let engine = PolicyEngine::open(sources, &history.path().join("dogwood.redb"))
            .expect("policy opens");
        let engine = if log_only { engine.log_only() } else { engine };
        engine
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &policy::Request::Connect {
                    host: "example.com",
                    ip: None,
                    port: 443,
                },
            )
            .0
    }

    /// A denial log-only mode let through is recorded as the policy's denial, unenforced, and only
    /// the run's first one is its first flip, across every per-request copy of the recorder.
    #[test]
    fn a_let_through_denial_is_recorded_unenforced_and_the_first_is_the_first_flip() {
        let (sender, receiver) = crate::policy_decisions(8);
        let recorder = DecisionRecorder {
            collector: None,
            decisions: Some(Arc::new(sender)),
            flipped: Arc::default(),
            correlation: None,
            recorded: Arc::new(Mutex::new(Vec::new())),
        };
        let flipped = connect_decision("", true);
        assert!(flipped.would_deny().is_some(), "{flipped:?}");
        for _ in 0..2 {
            recorder
                .for_request(telemetry::Correlation::current())
                .record(EffectiveDecision::from_policy(
                    r#"Box::Action::"net:connect""#,
                    "example.com:443",
                    &flipped,
                ));
        }
        recorder.record(EffectiveDecision::enforcement_deny(
            r#"Box::Action::"net:connect""#,
            "example.com:443",
            "egress",
            "refused",
        ));
        let decisions: Vec<_> = std::iter::from_fn(|| receiver.try_recv().ok()).collect();
        let shape: Vec<_> = decisions
            .iter()
            .map(|decision| {
                (
                    decision.permitted,
                    decision.cause.as_str(),
                    decision.enforcement,
                )
            })
            .collect();
        assert_eq!(
            shape,
            [
                (
                    false,
                    "no_match",
                    crate::Enforcement::LetThrough { first: true }
                ),
                (
                    false,
                    "no_match",
                    crate::Enforcement::LetThrough { first: false }
                ),
                (false, "enforcement", crate::Enforcement::Applied),
            ]
        );
    }

    /// In log-only mode a denied leg does not stop the next, so the first leg log-only mode let
    /// through decides the record, not the last permit.
    #[test]
    fn the_first_let_through_leg_decides_the_record() {
        let permit = connect_decision("permit(principal, action, resource);", false);
        let flipped = connect_decision("", true);
        assert_eq!(permit.would_deny(), None);
        let capture = ObservationCapture::begin();
        for decision in [&permit, &flipped, &permit] {
            PolicyDecisionObserver.observed(r#"Box::Action::"fs:read""#, "/w/a", decision);
        }
        let deciding = capture.last().expect("a verdict was observed");
        assert_eq!(&deciding.decision, &flipped);

        let capture = ObservationCapture::begin();
        for decision in [&permit, &permit] {
            PolicyDecisionObserver.observed(r#"Box::Action::"fs:read""#, "/w/a", decision);
        }
        assert_eq!(
            capture.last().map(|observed| observed.decision),
            Some(permit.clone()),
            "with no let-through leg, the last verdict still decides"
        );

        // Every leg log-only mode let through is named, in order, on the deciding observation.
        let forbidden = connect_decision(
            r#"permit(principal, action, resource);
               @id("no-connect")
               forbid(principal, action == Box::Action::"net:connect", resource);"#,
            true,
        );
        assert!(forbidden.would_deny().is_some(), "{forbidden:?}");
        let capture = ObservationCapture::begin();
        for decision in [&forbidden, &permit, &flipped] {
            PolicyDecisionObserver.observed(r#"Box::Action::"fs:read""#, "/w/a", decision);
        }
        let deciding = capture.last().expect("a verdict was observed");
        assert_eq!(deciding.would_deny, ["no-connect", "<default-deny>"]);
        let record = EffectiveDecision::gate_permit(
            r#"Box::Action::"fs:read""#,
            "/w/a",
            "shell",
            Some(&deciding),
        );
        assert_eq!(record.would_deny, ["no-connect", "<default-deny>"]);

        // A later leg's real denial stopped the attempt, so that denial decides the record.
        let denied = connect_decision(
            r#"permit(principal, action == Box::Action::"fs:read", resource);"#,
            false,
        );
        assert!(!denied.is_allow(), "{denied:?}");
        let capture = ObservationCapture::begin();
        for decision in [&flipped, &denied] {
            PolicyDecisionObserver.observed(r#"Box::Action::"fs:read""#, "/w/a", decision);
        }
        assert_eq!(
            capture.last().map(|observed| observed.decision),
            Some(denied),
            "a real denial in the last leg is what stopped the attempt"
        );
    }

    #[test]
    fn empty_attribution_keeps_policy_denial_classes_distinct() {
        let history = tempfile::tempdir().expect("history directory");
        let policy = PolicyEngine::open(Vec::new(), &history.path().join("dogwood.redb"))
            .expect("policy opens");
        let (no_match, _) = policy.decide(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &policy::Request::Connect {
                host: "example.com",
                ip: None,
                port: 443,
            },
        );
        let Decision::Deny { rule, .. } = no_match else {
            panic!("absent policy denies");
        };
        // Each class is named against the wire spelling a consumer reads, rather than against the
        // mapping under test: comparing it with `decision_cause` is a comparison with itself, and
        // one collapsing every class onto a single spelling passed.
        for (reason, spelling) in [
            (DenyReason::Forbidden, "forbidden"),
            (DenyReason::NoMatch, "no_match"),
            (DenyReason::InternalFault, "internal_fault"),
            (DenyReason::PolicyPending, "policy_pending"),
        ] {
            let raw = Decision::Deny {
                rule: rule.clone(),
                reason: reason.clone(),
                attribution: Vec::new(),
                resource: "resource".to_string(),
            };
            let effective = EffectiveDecision::from_policy("action", "resource", &raw);
            assert_eq!(
                effective.cause().as_str(),
                spelling,
                "{reason:?} must reach a consumer as {spelling}"
            );
            assert!(effective.attribution.is_empty());
            assert!(matches!(effective.rule, EffectiveRule::Policy(_)));
            let bootstrap = effective.into_enforcement_permit("policy-pending-bootstrap");
            assert_eq!(bootstrap.cause().as_str(), "enforcement");
            assert!(bootstrap.attribution.is_empty());
            assert!(matches!(bootstrap.rule, EffectiveRule::Enforcement(_)));
        }
        let floor = EffectiveDecision::enforcement_deny("action", "resource", "floor", "refused");
        assert_eq!(floor.cause().as_str(), "enforcement");
        assert!(floor.attribution.is_empty());
    }

    #[test]
    fn a_transformed_policy_verdict_keeps_only_the_effective_result() {
        let pending = EffectiveDecision::enforcement_deny(
            r#"Box::Action::"mcp:call""#,
            "server/tools/list",
            "policy-pending",
            "the complete policy bundle is not installed",
        );
        let permitted = pending.into_enforcement_permit("policy-pending-bootstrap");

        assert_eq!(
            permitted,
            EffectiveDecision::enforcement_permit(
                r#"Box::Action::"mcp:call""#,
                "server/tools/list",
                "policy-pending-bootstrap",
            )
        );
    }

    #[test]
    fn the_egress_adapter_maps_connection_and_request_decisions() {
        let recorder = DecisionRecorder::discarding();
        let adapter = EgressDecisionRecorder::over(Arc::clone(&recorder));

        adapter.emit(EgressDecision {
            host: "api.example.com".to_string(),
            port: 443,
            method: String::new(),
            path: "/".to_string(),
            decision: AuditDecision::Allow,
            reason: String::new(),
            correlation: RequestId::new("connection"),
        });
        adapter.emit(EgressDecision {
            host: "api.example.com".to_string(),
            port: 443,
            method: "POST".to_string(),
            path: "/v1/run".to_string(),
            decision: AuditDecision::Deny,
            reason: "request control denied the request".to_string(),
            correlation: RequestId::new("request"),
        });

        let recorded = recorder.recorded();
        assert_eq!(recorded.len(), 2);
        assert_eq!(
            recorded[0].parts(),
            (
                r#"Box::Action::"net:connect""#,
                "api.example.com:443",
                &EffectiveRule::Enforcement("egress"),
                EffectiveVerdict::Permit,
                None,
            )
        );
        assert_eq!(
            recorded[1].parts(),
            (
                r#"Box::Action::"http:request""#,
                "api.example.com:443/v1/run",
                &EffectiveRule::Enforcement("egress"),
                EffectiveVerdict::Deny,
                Some("request control denied the request"),
            )
        );
    }

    #[test]
    fn remote_tool_permit_no_match_and_forbid_record_the_final_decisions() {
        const TOOLS: &str = r#"{"result":{"tools":[
          {"name":"add","inputSchema":{"type":"object",
            "properties":{"a":{"type":"integer"}},"required":["a"]}}
        ]}}"#;
        let history = tempfile::tempdir().expect("history directory");
        let schema = policy::generate_mcp_schema("demo", TOOLS).expect("schema generates");
        let policy = PolicyEngine::open_with_mcp_schemas(
            vec![Policy {
                origin: PathBuf::from("remote-mcp-telemetry.cedar"),
                text: r#"
                    permit(principal, action == Box::Action::"http:request", resource)
                    when { context.input.host == "mcp-fixture.demo" };
                    @id("coarse") @description("coarse permit")
                    permit(principal, action == Box::Action::"mcp:call", resource)
                    when { context.input.server == "demo" };
                    @id("tool") @description("")
                    permit(principal, action == demo::Action::"add", resource)
                    when { context.input.a == 2 };
                    @id("refusal") @description("tool forbid")
                    forbid(principal, action == demo::Action::"add", resource)
                    when { context.input.a > 5 };
                "#
                .to_string(),
            }],
            &[schema],
            &history.path().join("dogwood.redb"),
        )
        .expect("policy opens")
        .observed_by(Arc::new(PolicyDecisionObserver));
        let policy = EgressPolicyInterceptor::into_handle(
            Arc::new(policy),
            Principal::agent(),
            GovernedBox::assigned("test-box"),
        );
        let recorder = DecisionRecorder::discarding();
        let interceptor = EgressDecisionInterceptor::over(policy, Arc::clone(&recorder));
        let emitter = EgressDecisionRecorder::over(Arc::clone(&recorder));

        let permit = interceptor
            .intercept(&remote_tool_attempt(r#"{"a":2}"#))
            .expect("the per-tool permit admits the call");
        emitter.emit(remote_tool_emission(AuditDecision::Allow, ""));
        permit.mark_indeterminate();

        let no_match = interceptor
            .intercept(&remote_tool_attempt(r#"{"a":4}"#))
            .expect("the coarse permit admits a per-tool no-match");
        emitter.emit(remote_tool_emission(AuditDecision::Allow, ""));
        no_match.mark_indeterminate();

        let denial = interceptor
            .intercept(&remote_tool_attempt(r#"{"a":9}"#))
            .err()
            .expect("the per-tool forbid refuses the call");
        emitter.emit(remote_tool_emission(
            AuditDecision::Deny,
            &denial.to_string(),
        ));

        let recorded = recorder.recorded();
        assert_eq!(recorded.len(), 3);
        for (decision, id, description, cause) in [
            (&recorded[0], "tool", "", DecisionCause::Permitted),
            (
                &recorded[1],
                "coarse",
                "coarse permit",
                DecisionCause::Permitted,
            ),
            (
                &recorded[2],
                "refusal",
                "tool forbid",
                DecisionCause::Forbidden,
            ),
        ] {
            let [attribution] = decision.attribution() else {
                panic!("one determining policy");
            };
            assert_eq!(attribution.annotation_id.as_deref(), Some(id));
            assert_eq!(attribution.description.as_deref(), Some(description));
            assert!(!attribution.token.is_empty());
            assert_eq!(
                decision.rule,
                EffectiveRule::Policy(attribution.rule.clone())
            );
            assert_eq!(decision.cause(), cause);
            assert_eq!(
                policy_identifier(attribution),
                id,
                "the authored id is the identifier a consumer reads"
            );
            let bootstrap = decision.clone().into_enforcement_permit("bootstrap");
            assert!(bootstrap.attribution.is_empty());
            assert_eq!(bootstrap.cause(), DecisionCause::Enforcement);
        }
        let (action, resource, rule, verdict, reason) = recorded[0].parts();
        assert_eq!(action, r#"demo::Action::"add""#);
        assert_eq!(resource, "demo/add");
        assert!(matches!(rule, EffectiveRule::Policy(_)));
        assert_eq!(verdict, EffectiveVerdict::Permit);
        assert_eq!(reason, None);

        let (action, resource, rule, verdict, reason) = recorded[1].parts();
        assert_eq!(action, r#"Box::Action::"mcp:call""#);
        assert_eq!(resource, "demo/add");
        assert!(matches!(rule, EffectiveRule::Policy(_)));
        assert_eq!(verdict, EffectiveVerdict::Permit);
        assert_eq!(reason, None);

        let (action, resource, rule, verdict, reason) = recorded[2].parts();
        assert_eq!(action, r#"demo::Action::"add""#);
        assert_eq!(resource, "demo/add");
        assert!(matches!(rule, EffectiveRule::Policy(_)));
        assert_eq!(verdict, EffectiveVerdict::Deny);
        assert_eq!(reason, Some("a forbid rule matched"));
    }

    /// **The capture covers every attempt the policy decides, and no other.** Ordinary egress is
    /// one of them, so a connection and a plain request each keep the rule that admitted them. The
    /// response leg takes no decision, so a capture there would hold a verdict from the request it
    /// followed.
    #[test]
    fn raw_verdict_capture_is_scoped_to_decided_egress_attempts() {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let interceptor = EgressDecisionInterceptor::over(
            Arc::new(CaptureProbe {
                observed: Arc::clone(&observed),
            }),
            DecisionRecorder::discarding(),
        );

        interceptor
            .intercept(&EgressEffectAttempt::Connect {
                host: "api.example.com",
                port: 443,
                address: "192.0.2.1:443".parse().expect("a peer address"),
                http_visibility: true,
            })
            .expect("a connection is admitted")
            .mark_indeterminate();
        interceptor
            .intercept(&EgressEffectAttempt::HttpRequest {
                host: "api.example.com",
                port: 443,
                method: "GET",
                path: "/",
                body_bytes: 0,
                intercepted: true,
                mcp: None,
            })
            .expect("ordinary HTTP is admitted")
            .mark_indeterminate();
        interceptor
            .intercept(&remote_tool_attempt(r#"{"a":2}"#))
            .expect("remote MCP is admitted")
            .mark_indeterminate();
        interceptor
            .intercept(&EgressEffectAttempt::ResponseRelease {
                host: "api.example.com",
                port: 443,
                method: "GET",
                path: "/",
                status: 200,
            })
            .expect("the response leg is admitted")
            .mark_indeterminate();

        assert_eq!(
            *observed.lock().expect("capture observations"),
            vec![true, true, true, false],
        );
        PENDING_EGRESS_DECISION.with(|pending| {
            pending.borrow_mut().take();
        });
    }

    /// **Ordinary egress keeps the policy that admitted it**, on the `net:connect` and
    /// `http:request` gates.
    #[test]
    fn ordinary_egress_records_the_policy_that_decided_it() {
        let history = tempfile::tempdir().expect("history directory");
        let policy = PolicyEngine::open(
            vec![Policy {
                origin: PathBuf::from("ordinary-egress-telemetry.cedar"),
                text: r#"
                    @id("reach-the-model") @description("the model endpoint")
                    permit(principal, action == Box::Action::"net:connect", resource)
                    when { context.input.host == "api.example.com" };
                    @id("post-to-the-model")
                    permit(principal, action == Box::Action::"http:request", resource)
                    when { context.input.method == "POST" };
                "#
                .to_string(),
            }],
            &history.path().join("dogwood.redb"),
        )
        .expect("policy opens")
        .observed_by(Arc::new(PolicyDecisionObserver));
        let recorder = DecisionRecorder::discarding();
        let interceptor = EgressDecisionInterceptor::over(
            EgressPolicyInterceptor::into_handle(
                Arc::new(policy),
                Principal::agent(),
                GovernedBox::assigned("test-box"),
            ),
            Arc::clone(&recorder),
        );
        let emitter = EgressDecisionRecorder::over(Arc::clone(&recorder));

        interceptor
            .intercept(&EgressEffectAttempt::Connect {
                host: "api.example.com",
                port: 443,
                address: "192.0.2.1:443".parse().expect("a peer address"),
                http_visibility: true,
            })
            .expect("the authored connect permit admits it")
            .mark_indeterminate();
        emitter.emit(EgressDecision {
            host: "api.example.com".to_string(),
            port: 443,
            method: String::new(),
            path: "/".to_string(),
            decision: AuditDecision::Allow,
            reason: String::new(),
            correlation: RequestId::new("connection"),
        });

        // A `GET` matches no permit, so the same destination is refused on the request leg.
        let refusal = interceptor
            .intercept(&EgressEffectAttempt::HttpRequest {
                host: "api.example.com",
                port: 443,
                method: "GET",
                path: "/v1/messages",
                body_bytes: 0,
                intercepted: true,
                mcp: None,
            })
            .err()
            .expect("no permit matches a GET");
        emitter.emit(EgressDecision {
            host: "api.example.com".to_string(),
            port: 443,
            method: "GET".to_string(),
            path: "/v1/messages".to_string(),
            decision: AuditDecision::Deny,
            reason: refusal.to_string(),
            correlation: RequestId::new("request"),
        });

        let recorded = recorder.recorded();
        assert_eq!(recorded.len(), 2);

        let (action, resource, rule, verdict, reason) = recorded[0].parts();
        assert_eq!(action, r#"Box::Action::"net:connect""#);
        assert_eq!(resource, "api.example.com:443");
        assert!(matches!(rule, EffectiveRule::Policy(_)));
        assert_eq!(verdict, EffectiveVerdict::Permit);
        assert_eq!(reason, None);
        assert_eq!(recorded[0].cause(), DecisionCause::Permitted);
        let [attribution] = recorded[0].attribution() else {
            panic!("one determining policy");
        };
        assert_eq!(
            attribution.annotation_id.as_deref(),
            Some("reach-the-model")
        );
        assert_eq!(
            attribution.description.as_deref(),
            Some("the model endpoint")
        );
        assert!(!attribution.token.is_empty());

        // A denial with no matching permit names no policy, and says so as its class.
        let (action, resource, _, verdict, reason) = recorded[1].parts();
        assert_eq!(action, r#"Box::Action::"http:request""#);
        assert_eq!(resource, "api.example.com:443/v1/messages");
        assert_eq!(verdict, EffectiveVerdict::Deny);
        assert_eq!(reason, Some("no permit matched"));
        assert_eq!(recorded[1].cause(), DecisionCause::NoMatch);
    }

    /// **In log-only mode the gateway sends a request the policy denies, and the record keeps the
    /// denial.** The request leg is permitted to the gateway, so it emits an allow, and the record
    /// still says `deny`, unenforced, with the policy's own class.
    #[test]
    fn a_log_only_request_leg_goes_ahead_and_records_the_denial() {
        let history = tempfile::tempdir().expect("history directory");
        let policy = PolicyEngine::open(
            vec![Policy {
                origin: PathBuf::from("policy.dw"),
                text: r#"permit(principal, action == Box::Action::"net:connect", resource);"#
                    .to_string(),
            }],
            &history.path().join("dogwood.redb"),
        )
        .expect("policy opens")
        .observed_by(Arc::new(PolicyDecisionObserver))
        .log_only();
        let recorder = DecisionRecorder::discarding();
        let interceptor = EgressDecisionInterceptor::over(
            EgressPolicyInterceptor::into_handle(
                Arc::new(policy),
                Principal::agent(),
                GovernedBox::assigned("test-box"),
            ),
            Arc::clone(&recorder),
        );
        let emitter = EgressDecisionRecorder::over(Arc::clone(&recorder));

        interceptor
            .intercept(&EgressEffectAttempt::HttpRequest {
                host: "api.example.com",
                port: 443,
                method: "DELETE",
                path: "/v1/items/7",
                body_bytes: 0,
                intercepted: true,
                mcp: None,
            })
            .expect("log-only mode lets the request through")
            .mark_indeterminate();
        emitter.emit(EgressDecision {
            host: "api.example.com".to_string(),
            port: 443,
            method: "DELETE".to_string(),
            path: "/v1/items/7".to_string(),
            decision: AuditDecision::Allow,
            reason: String::new(),
            correlation: RequestId::new("request"),
        });

        let recorded = recorder.recorded();
        let [request] = recorded.as_slice() else {
            panic!("one decision: {recorded:?}");
        };
        let (action, _, _, verdict, reason) = request.parts();
        assert_eq!(action, r#"Box::Action::"http:request""#);
        assert_eq!(verdict, EffectiveVerdict::Deny);
        assert_eq!(reason, Some("no permit matched"));
        assert_eq!(request.cause(), DecisionCause::NoMatch);
        assert!(
            !request.enforced,
            "the gateway sent it, so the denial was not enforced"
        );
    }

    /// **Over http, the first gate log-only mode let through is what the record keeps**, not the
    /// per-tool permit after it.
    #[test]
    fn a_remote_call_records_its_first_let_through_gate() {
        let flipped = connect_decision("", true);
        let permit = connect_decision("permit(principal, action, resource);", false);
        let observed = |action: &str, decision: &Decision| ObservedDecision {
            action: action.to_string(),
            resource: "demo/add".to_string(),
            decision: decision.clone(),
            would_deny: Vec::new(),
        };
        let effective = remote_mcp_decision(
            &McpFrame::ToolCall {
                server: "demo",
                tool: "add",
                arguments: "{}",
            },
            None,
            &[
                observed(r#"Box::Action::"http:request""#, &permit),
                observed(r#"Box::Action::"mcp:call""#, &flipped),
                observed(r#"demo::Action::"add""#, &permit),
            ],
        );
        let (action, _, _, verdict, _) = effective.parts();
        assert_eq!(action, r#"Box::Action::"mcp:call""#);
        assert_eq!(verdict, EffectiveVerdict::Deny);
        assert_eq!(effective.cause(), DecisionCause::NoMatch);
        assert!(!effective.enforced);
    }

    /// **One exchange's verdict never reaches another exchange's record.** The captured verdict is
    /// held in one slot, so an emitted decision naming a different exchange must fall back to the
    /// gateway's own label rather than take what is waiting there.
    #[test]
    fn a_held_verdict_reaches_no_other_exchange() {
        let history = tempfile::tempdir().expect("history directory");
        let policy = PolicyEngine::open(
            vec![Policy {
                origin: PathBuf::from("held-verdict.cedar"),
                text: r#"@id("reach-anything") permit(principal, action, resource);"#.to_string(),
            }],
            &history.path().join("dogwood.redb"),
        )
        .expect("policy opens")
        .observed_by(Arc::new(PolicyDecisionObserver));
        let recorder = DecisionRecorder::discarding();
        let interceptor = EgressDecisionInterceptor::over(
            EgressPolicyInterceptor::into_handle(
                Arc::new(policy),
                Principal::agent(),
                GovernedBox::assigned("test-box"),
            ),
            Arc::clone(&recorder),
        );
        let emitter = EgressDecisionRecorder::over(Arc::clone(&recorder));

        // Intercepted: one request to `first.example`. Emitted: a different exchange every way it
        // can differ — another host, another leg, and the same host on another port and path.
        let held = |method, path| EgressEffectAttempt::HttpRequest {
            host: "first.example",
            port: 443,
            method,
            path,
            body_bytes: 0,
            intercepted: true,
            mcp: None,
        };
        let emitted = |host: &str, port, method: &str, path: &str| EgressDecision {
            host: host.to_string(),
            port,
            method: method.to_string(),
            path: path.to_string(),
            decision: AuditDecision::Allow,
            reason: String::new(),
            correlation: RequestId::new("mismatched"),
        };
        for elsewhere in [
            emitted("second.example", 443, "GET", "/one"),
            emitted("first.example", 8443, "GET", "/one"),
            emitted("first.example", 443, "GET", "/two"),
            // The connection leg of the same destination, which is its own decision.
            emitted("first.example", 443, "", "/"),
        ] {
            interceptor
                .intercept(&held("GET", "/one"))
                .expect("the permit admits the request")
                .mark_indeterminate();
            emitter.emit(elsewhere);
        }

        // **And the mirror, which is the direction that can fail open**: a connection states no
        // method or path, so a match that skipped the leg would hand its verdict to a request.
        interceptor
            .intercept(&EgressEffectAttempt::Connect {
                host: "first.example",
                port: 443,
                address: "192.0.2.1:443".parse().expect("a peer address"),
                http_visibility: true,
            })
            .expect("the permit admits the connection")
            .mark_indeterminate();
        emitter.emit(emitted("first.example", 443, "GET", "/one"));

        for decision in recorder.recorded() {
            let (_, _, rule, _, _) = decision.parts();
            assert_eq!(
                *rule,
                EffectiveRule::Enforcement("egress"),
                "a verdict held for one exchange must not name another: {decision:?}"
            );
            assert!(decision.attribution().is_empty());
            assert_eq!(decision.cause(), DecisionCause::Enforcement);
        }

        // The paired positive: the same emitted identity does take the held verdict, or the
        // assertions above would pass on a slot nothing ever fills.
        interceptor
            .intercept(&held("GET", "/one"))
            .expect("the permit admits the request")
            .mark_indeterminate();
        emitter.emit(emitted("first.example", 443, "GET", "/one"));
        let recorded = recorder.recorded();
        let last = recorded.last().expect("the matching record");
        assert!(matches!(last.parts().2, EffectiveRule::Policy(_)));
        assert_eq!(last.cause(), DecisionCause::Permitted);
    }

    /// A gate whose own result disagrees with the policy verdict beneath it keeps the gate's label:
    /// a floor may refuse what policy permitted, and it is not that permit that decided.
    #[test]
    fn a_gate_that_overrides_the_policy_verdict_keeps_its_own_label() {
        let history = tempfile::tempdir().expect("history directory");
        let policy = PolicyEngine::open(
            vec![Policy {
                origin: PathBuf::from("gate-override.cedar"),
                text: r#"permit(principal, action == Box::Action::"net:connect", resource)
                         when { context.input.host == "allowed.example" };"#
                    .to_string(),
            }],
            &history.path().join("dogwood.redb"),
        )
        .expect("policy opens");
        let connect = |host: &'static str| {
            policy
                .decide(
                    &GovernedBox::assigned("test-box"),
                    &Principal::agent(),
                    &policy::Request::Connect {
                        host,
                        ip: None,
                        port: 443,
                    },
                )
                .0
        };
        let allowed = connect("allowed.example");
        let denied = connect("denied.example");
        assert!(allowed.is_allow() && !denied.is_allow());
        let observed = |decision: &Decision| ObservedDecision {
            action: r#"Box::Action::"fs:read""#.to_string(),
            resource: "~/secret".to_string(),
            decision: decision.clone(),
            would_deny: Vec::new(),
        };

        // A floor denial over a policy permit.
        let floored = EffectiveDecision::gate_deny(
            r#"Box::Action::"fs:read""#,
            "~/secret",
            "reach-floor",
            "the path is outside the reachable set",
            Some(&observed(&allowed)),
        );
        assert_eq!(floored.rule, EffectiveRule::Enforcement("reach-floor"));
        assert_eq!(floored.cause(), DecisionCause::Enforcement);
        assert!(floored.attribution().is_empty());

        // A bootstrap permit over a policy denial.
        let bootstrapped = EffectiveDecision::gate_permit(
            r#"Box::Action::"mcp:call""#,
            "demo/tools/list",
            "policy-pending-bootstrap",
            Some(&observed(&denied)),
        );
        assert_eq!(
            bootstrapped.rule,
            EffectiveRule::Enforcement("policy-pending-bootstrap")
        );
        assert_eq!(bootstrapped.cause(), DecisionCause::Enforcement);
        assert!(bootstrapped.attribution().is_empty());
    }

    /// **An authored `@id` is the identifier, and the engine's rule identifier is the fallback.**
    /// An operator reads their own name for a rule; a policy that authored none still has to be
    /// identifiable, and an empty `@id` identifies nothing.
    #[test]
    fn an_authored_id_is_preferred_and_the_rule_id_is_the_fallback() {
        let history = tempfile::tempdir().expect("history directory");
        let policy = PolicyEngine::open(
            vec![Policy {
                origin: PathBuf::from("authored-id.cedar"),
                text: r#"
                    @id("named") permit(principal, action == Box::Action::"net:connect", resource)
                    when { context.input.port == 443 };
                    @id("") permit(principal, action == Box::Action::"net:connect", resource)
                    when { context.input.port == 8443 };
                    permit(principal, action == Box::Action::"net:connect", resource)
                    when { context.input.port == 9443 };
                "#
                .to_string(),
            }],
            &history.path().join("dogwood.redb"),
        )
        .expect("policy opens");
        let identifier = |port: u16| {
            let (decision, _) = policy.decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &policy::Request::Connect {
                    host: "api.example.com",
                    ip: None,
                    port,
                },
            );
            let [attribution] = decision.attribution() else {
                panic!("one determining policy for port {port}");
            };
            (policy_identifier(attribution), attribution.rule.to_string())
        };

        let (named, _) = identifier(443);
        assert_eq!(named, "named");
        // An absent `@id` and an empty one both fall back to the engine's own identifier.
        let (absent, rule) = identifier(9443);
        assert_eq!(absent, rule);
        let (empty, rule) = identifier(8443);
        assert_eq!(empty, rule);
    }

    /// A recorder over a real collector writing tool-call records to `path`, or over a target
    /// taking no tool calls.
    fn tool_call_recorder(
        path: Option<&std::path::Path>,
    ) -> (Arc<Collector>, Arc<DecisionRecorder>) {
        let mut config = telemetry::TelemetryConfig::for_box("demo");
        if let Some(path) = path {
            config = config.with_target(
                telemetry::Target::new(
                    telemetry::TargetKind::File,
                    path.to_string_lossy().to_string(),
                )
                .receiving(vec![telemetry::Signal::McpToolCalls]),
            );
        } else {
            config = config.with_target(
                telemetry::Target::new(telemetry::TargetKind::File, "/dev/null".to_string())
                    .receiving(vec![telemetry::Signal::PolicyDenied]),
            );
        }
        let collector = Arc::new(telemetry::open(config).expect("open the collector"));
        let recorder = DecisionRecorder::over(Arc::clone(&collector), None);
        (collector, recorder)
    }

    /// A remote call admitted and its decision emitted, as the gateway does before it sends.
    fn admitted(recorder: Arc<DecisionRecorder>) -> Box<dyn EgressEffectPermit> {
        let permit = capture_probe(Arc::clone(&recorder))
            .intercept(&remote_tool_attempt(r#"{"a":1}"#))
            .expect("the call is admitted");
        EgressDecisionRecorder::over(recorder).emit(remote_tool_emission(AuditDecision::Allow, ""));
        permit
    }

    /// A tool-call record that no path ends records one `indeterminate` completion when it drops,
    /// and a refused one records none, so a missed path loses no record.
    #[tokio::test]
    async fn an_unended_tool_call_records_indeterminate_and_a_refused_one_records_nothing() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("tools.jsonl");
        let (collector, recorder) = tool_call_recorder(Some(&path));
        let joined = |id: &str| telemetry::Correlation::from_headers(None, None).mcp(Some(id));
        drop(recorder.mcp_tool_called("demo", "add", r#"{"a":1}"#, joined("dropped")));
        recorder
            .mcp_tool_called("demo", "add", r#"{"a":2}"#, joined("refused"))
            .expect("a target takes tool calls")
            .refused();
        recorder
            .mcp_tool_called("demo", "add", r#"{"a":3}"#, joined("ended"))
            .expect("a target takes tool calls")
            .completed(policy::McpReply::Result, None);
        collector.drained().await;

        let text = std::fs::read_to_string(&path).expect("the tool-call records");
        let completions: Vec<(String, String)> = text
            .lines()
            .flat_map(|line| {
                let request: serde_json::Value = serde_json::from_str(line).expect("json");
                request["resourceLogs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .flat_map(|resource| resource["scopeLogs"].as_array().into_iter().flatten())
                    .flat_map(|scope| scope["logRecords"].as_array().into_iter().flatten())
                    .filter(|record| record["eventName"] == "strands.box.mcp.tool.completion")
                    .map(|record| {
                        let value = |key: &str| {
                            record["attributes"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .find(|attribute| attribute["key"] == key)
                                .and_then(|attribute| attribute["value"]["stringValue"].as_str())
                                .unwrap_or_default()
                                .to_string()
                        };
                        (
                            value("jsonrpc.request.id"),
                            value("strands.box.mcp.tool.reply"),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(
            completions.len(),
            2,
            "the dropped and the ended call each end once; the refused one never ran: {text}"
        );
        assert!(
            completions.contains(&("dropped".to_string(), "indeterminate".to_string())),
            "{completions:?}"
        );
        assert!(
            completions.contains(&("ended".to_string(), "result".to_string())),
            "{completions:?}"
        );
    }

    /// Over http, a permitted call is ended by its reply, and the completion carries the call's
    /// own correlation rather than one rebuilt from the reply.
    #[tokio::test]
    async fn a_remote_call_is_ended_by_its_reply_with_the_calls_own_correlation() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("tools.jsonl");
        let (collector, recorder) = tool_call_recorder(Some(&path));
        let mut permit = admitted(recorder);
        permit
            .reply_observer(Some("1"))
            .expect("a target takes tool calls, so the box reads the reply")
            .finished(br#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#);
        collector.drained().await;

        let text = std::fs::read_to_string(&path).expect("the tool-call records");
        assert_eq!(
            text.matches("strands.box.mcp.tool.call").count(),
            1,
            "{text}"
        );
        assert_eq!(
            text.matches("strands.box.mcp.tool.completion").count(),
            1,
            "{text}"
        );
        assert_eq!(
            text.matches(r#""stringValue":"remote-tool""#).count(),
            2,
            "the completion carries the call's own request id: {text}"
        );
    }

    fn capture_probe(recorder: Arc<DecisionRecorder>) -> Arc<dyn EgressEffectInterceptor> {
        EgressDecisionInterceptor::over(
            Arc::new(CaptureProbe {
                observed: Arc::new(Mutex::new(Vec::new())),
            }),
            recorder,
        )
    }

    /// A permit whose policy observer reads the reply, as a per-tool rule's does.
    struct ObservedProbe;

    impl EgressEffectInterceptor for ObservedProbe {
        fn intercept(
            &self,
            _effect: &EgressEffectAttempt<'_>,
        ) -> io::Result<Box<dyn EgressEffectPermit>> {
            Ok(Box::new(ObservedPermit))
        }
    }

    struct ObservedPermit;

    impl EgressEffectPermit for ObservedPermit {
        fn record_outcome(
            self: Box<Self>,
            _outcome: egress_gateway::EffectOutcome,
        ) -> io::Result<()> {
            Ok(())
        }

        fn mark_indeterminate(self: Box<Self>) {}

        fn reply_observer(
            &mut self,
            _request_id: Option<&str>,
        ) -> Option<Box<dyn egress_gateway::ReplyObserver>> {
            Some(Box::new(SilentObserver))
        }
    }

    struct SilentObserver;

    impl egress_gateway::ReplyObserver for SilentObserver {
        fn finished(self: Box<Self>, _reply: &[u8]) {}

        fn abandoned(self: Box<Self>) {}
    }

    /// With no target taking tool calls, the box wraps no permit, even one whose policy observer
    /// reads the reply: no tool-call record would be written, so the box does no work for it.
    #[tokio::test]
    async fn no_permit_is_wrapped_when_no_target_takes_tool_calls() {
        let wrapped = |recorder: Arc<DecisionRecorder>| {
            let before = OBSERVING_PERMITS.with(std::cell::Cell::get);
            EgressDecisionInterceptor::over(Arc::new(ObservedProbe), recorder)
                .intercept(&remote_tool_attempt(r#"{"a":1}"#))
                .expect("the call is admitted");
            OBSERVING_PERMITS.with(std::cell::Cell::get) - before
        };
        let (_none, nobody) = tool_call_recorder(None);
        assert_eq!(
            wrapped(nobody),
            0,
            "nobody takes tool calls, so nothing is wrapped"
        );

        // The paired positive, so the count above cannot pass on a wrap nothing counts.
        let directory = tempfile::tempdir().expect("tempdir");
        let (_some, somebody) = tool_call_recorder(Some(&directory.path().join("t.jsonl")));
        assert_eq!(
            wrapped(somebody),
            1,
            "a target takes tool calls, so the call is wrapped"
        );
    }

    /// With no target taking tool calls, the box builds no tool-call record: neither a call nor a
    /// completion, and over http it copies no call's arguments.
    #[tokio::test]
    async fn no_tool_call_record_is_built_when_no_target_takes_tool_calls() {
        let built = |recorder: &Arc<DecisionRecorder>| {
            let before = TOOL_CALLS_BUILT.with(std::cell::Cell::get);
            if let Some(record) = recorder.mcp_tool_called(
                "demo",
                "add",
                r#"{"a":1}"#,
                telemetry::Correlation::current(),
            ) {
                record.completed(
                    policy::McpReply::Result,
                    Some(&serde_json::json!({"sum": 1})),
                );
            }
            TOOL_CALLS_BUILT.with(std::cell::Cell::get) - before
        };
        let (_none, nobody) = tool_call_recorder(None);
        assert_eq!(
            built(&nobody),
            0,
            "nobody takes tool calls, so nothing is built"
        );
        let directory = tempfile::tempdir().expect("tempdir");
        let (_some, somebody) = tool_call_recorder(Some(&directory.path().join("t.jsonl")));
        assert_eq!(
            built(&somebody),
            2,
            "a target takes tool calls, so both are built"
        );

        // Over http, the call's arguments are not copied for a box whose targets take none.
        EgressDecisionInterceptor::over(Arc::new(ObservedProbe), nobody)
            .intercept(&remote_tool_attempt(r#"{"a":1}"#))
            .expect("the call is admitted");
        let copied = PENDING_EGRESS_DECISION.with(|pending| {
            pending
                .borrow()
                .as_ref()
                .is_some_and(|pending| pending.tool_call.is_some())
        });
        assert!(!copied, "no tool call is held for a box that records none");
    }

    /// With a target taking tool calls, the box reads the reply even when the policy does not,
    /// and that target receives the tool's `structuredContent` in clear text.
    #[tokio::test]
    async fn a_reply_is_read_when_a_target_takes_tool_calls() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("tools.jsonl");
        let (collector, recorder) = tool_call_recorder(Some(&path));
        let mut permit = admitted(recorder);
        let observer = permit
            .reply_observer(Some("1"))
            .expect("a target takes tool calls, so the box reads the reply");
        observer.finished(
            br#"{"jsonrpc":"2.0","id":1,"result":{"content":[],"structuredContent":{"sum":"raw-sum-77"}}}"#,
        );
        collector.drained().await;
        let text = std::fs::read_to_string(&path).expect("the tool-call records");
        assert!(text.contains("strands.box.mcp.tool.completion"), "{text}");
        assert!(
            text.contains("raw-sum-77"),
            "the output arrives in clear text: {text}"
        );
    }

    /// With no policy observer, the box's own observer finishes at the reply, so a stream the
    /// server holds open releases its copy at the answer rather than at the end.
    #[tokio::test]
    async fn the_box_observer_finishes_at_the_reply_on_a_held_open_stream() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("tools.jsonl");
        let (collector, recorder) = tool_call_recorder(Some(&path));
        let mut permit = admitted(recorder);
        let mut observer = permit
            .reply_observer(Some("1"))
            .expect("a target takes tool calls, so the box observes the reply");
        let progress = b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n";
        assert!(!observer.complete(progress), "progress is not the reply");
        let replied = [
            &progress[..],
            b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}\n\n",
        ]
        .concat();
        assert!(observer.complete(&replied), "the reply has arrived");
        observer.finished(&replied);
        collector.drained().await;
        let text = std::fs::read_to_string(&path).expect("the tool-call records");
        assert!(text.contains("strands.box.mcp.tool.completion"), "{text}");
        assert!(text.contains(r#""stringValue":"result""#), "{text}");
    }

    /// A reply the gateway never read still ends the call, as `indeterminate`, once.
    #[tokio::test]
    async fn an_observer_dropped_before_its_reply_records_one_indeterminate_completion() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("tools.jsonl");
        let (collector, recorder) = tool_call_recorder(Some(&path));
        let mut permit = admitted(recorder);
        drop(permit.reply_observer(Some("1")).expect("an observer"));
        collector.drained().await;
        let text = std::fs::read_to_string(&path).expect("the tool-call records");
        assert_eq!(
            text.matches("strands.box.mcp.tool.completion").count(),
            1,
            "{text}"
        );
        assert!(text.contains(r#""stringValue":"indeterminate""#), "{text}");
    }

    struct CaptureProbe {
        observed: Arc<Mutex<Vec<bool>>>,
    }

    impl EgressEffectInterceptor for CaptureProbe {
        fn intercept(
            &self,
            _effect: &EgressEffectAttempt<'_>,
        ) -> io::Result<Box<dyn EgressEffectPermit>> {
            self.observed
                .lock()
                .expect("capture observations")
                .push(POLICY_OBSERVATIONS.with(|observations| observations.borrow().is_some()));
            Ok(Box::new(DiscardPermit))
        }
    }

    struct DiscardPermit;

    impl EgressEffectPermit for DiscardPermit {
        fn record_outcome(
            self: Box<Self>,
            _outcome: egress_gateway::EffectOutcome,
        ) -> io::Result<()> {
            Ok(())
        }

        fn mark_indeterminate(self: Box<Self>) {}
    }

    fn remote_tool_attempt(arguments: &'static str) -> EgressEffectAttempt<'static> {
        EgressEffectAttempt::HttpRequest {
            host: "mcp-fixture.demo",
            port: 8931,
            method: "POST",
            path: "/mcp",
            body_bytes: arguments.len(),
            intercepted: false,
            mcp: Some(McpFrame::ToolCall {
                server: "demo",
                tool: "add",
                arguments,
            }),
        }
    }

    fn remote_tool_emission(decision: AuditDecision, reason: &str) -> EgressDecision {
        EgressDecision {
            host: "mcp-fixture.demo".to_string(),
            port: 8931,
            method: "POST".to_string(),
            path: "/mcp".to_string(),
            decision,
            reason: reason.to_string(),
            correlation: RequestId::new("remote-tool"),
        }
    }
}
