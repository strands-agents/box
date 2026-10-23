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
}

impl ObservedDecision {
    #[cfg(test)]
    pub(crate) fn action(&self) -> &str {
        &self.action
    }
}

struct PendingEgressDecision {
    identity: EgressIdentity,
    verdict: AuditDecision,
    effective: EffectiveDecision,
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
        }
    }

    /// A gate's permit, reported as the policy verdict beneath it when the gate kept one.
    pub(crate) fn gate_permit(
        action: impl Into<String>,
        resource: impl Into<String>,
        gate: &'static str,
        determined: Option<&ObservedDecision>,
    ) -> Self {
        match determined.filter(|observed| observed.decision.is_allow()) {
            Some(observed) => Self::from_policy(action, resource, &observed.decision),
            None => Self::enforcement_permit(action, resource, gate),
        }
    }

    /// A gate's denial, reported as the policy verdict beneath it when the gate kept one.
    pub(crate) fn gate_deny(
        action: impl Into<String>,
        resource: impl Into<String>,
        gate: &'static str,
        reason: impl Into<String>,
        determined: Option<&ObservedDecision>,
    ) -> Self {
        match determined.filter(|observed| !observed.decision.is_allow()) {
            Some(observed) => Self::from_policy(action, resource, &observed.decision),
            None => Self::enforcement_deny(action, resource, gate, reason),
        }
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
    /// the last permit stands when every leg allowed.
    pub(crate) fn last(self) -> Option<ObservedDecision> {
        self.finish().pop()
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
}

impl EgressDecisionInterceptor {
    /// Wrap the policy adapter without changing its public seam.
    pub(crate) fn over(
        inner: Arc<dyn EgressEffectInterceptor>,
    ) -> Arc<dyn EgressEffectInterceptor> {
        Arc::new(Self { inner })
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
        PENDING_EGRESS_DECISION.with(|pending| {
            pending.borrow_mut().replace(PendingEgressDecision {
                identity,
                verdict,
                effective,
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
    let determined = observations.last();
    match refusal {
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
    }
}

fn remote_mcp_decision(
    frame: &McpFrame<'_>,
    refusal: Option<String>,
    observations: &[ObservedDecision],
) -> EffectiveDecision {
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
    correlation: Option<telemetry::Correlation>,
    #[cfg(test)]
    recorded: Arc<std::sync::Mutex<Vec<EffectiveDecision>>>,
}

impl DecisionRecorder {
    /// Bind effective decision recording to this box's collector.
    pub(crate) fn over(collector: Arc<Collector>) -> Arc<Self> {
        Arc::new(Self {
            collector: Some(collector),
            correlation: None,
            #[cfg(test)]
            recorded: Arc::new(std::sync::Mutex::new(Vec::new())),
        })
    }

    pub(crate) fn for_request(&self, correlation: telemetry::Correlation) -> Arc<Self> {
        Arc::new(Self {
            collector: self.collector.clone(),
            correlation: Some(correlation),
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
        if let Some(collector) = &self.collector {
            collector.record(decision.into_record());
        }
    }

    #[cfg(test)]
    pub(crate) fn discarding() -> Arc<Self> {
        Arc::new(Self {
            collector: None,
            correlation: None,
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
        if let Some(mut effective) = PENDING_EGRESS_DECISION.with(|pending| {
            let held = pending.borrow_mut().take()?;
            (held.verdict == decision.decision && held.identity.is(&identity))
                .then_some(held.effective)
        }) {
            effective.correlation = correlation;
            effective.subject = Some(identity.subject());
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

/// The variable an operator sets to add resource attributes to every record.
const RESOURCE_ATTRIBUTES: &str = "OTEL_RESOURCE_ATTRIBUTES";

/// The operator's resource attributes as text, or a refusal when the value is not UTF-8.
fn operator_resource_attributes(value: Option<std::ffi::OsString>) -> Result<String, BoxError> {
    match value {
        None => Ok(String::new()),
        Some(value) => value.into_string().map_err(|_| {
            BoxError::from(telemetry::TelemetryError::Config {
                reason: format!("{RESOURCE_ATTRIBUTES} is not UTF-8"),
            })
        }),
    }
}

/// Open this box's collector from its stored record.
pub(crate) fn open(
    layout: &crate::record::layout::BoxRoot,
    stored: &crate::record::config::Record,
) -> Result<Arc<Collector>, BoxError> {
    let directory = layout.telemetry_directory();
    layout.create_child_directory(&directory)?;

    let request =
        crate::record::config::telemetry::config_for(&stored.box_id, &stored.telemetry, layout)?
            .with_resource_attributes(operator_resource_attributes(std::env::var_os(
                RESOURCE_ATTRIBUTES,
            ))?);
    Ok(Arc::new(telemetry::open(request)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use egress_gateway::RequestId;
    use policy::{EgressPolicyInterceptor, GovernedBox, Policy, PolicyEngine, Principal};
    use std::path::PathBuf;
    use std::sync::Mutex;

    #[test]
    fn empty_attribution_keeps_policy_denial_classes_distinct() {
        let history = tempfile::tempdir().expect("history directory");
        let policy = PolicyEngine::open(Vec::new(), &history.path().join("dogwood.redb"))
            .expect("policy opens");
        let no_match = policy.decide(
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
        let interceptor = EgressDecisionInterceptor::over(policy);
        let recorder = DecisionRecorder::discarding();
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
        let interceptor = EgressDecisionInterceptor::over(Arc::new(CaptureProbe {
            observed: Arc::clone(&observed),
        }));

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
                body_bytes: 0,
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
        let interceptor = EgressDecisionInterceptor::over(EgressPolicyInterceptor::into_handle(
            Arc::new(policy),
            Principal::agent(),
            GovernedBox::assigned("test-box"),
        ));
        let recorder = DecisionRecorder::discarding();
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
        let interceptor = EgressDecisionInterceptor::over(EgressPolicyInterceptor::into_handle(
            Arc::new(policy),
            Principal::agent(),
            GovernedBox::assigned("test-box"),
        ));
        let recorder = DecisionRecorder::discarding();
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
            policy.decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &policy::Request::Connect {
                    host,
                    ip: None,
                    port: 443,
                },
            )
        };
        let allowed = connect("allowed.example");
        let denied = connect("denied.example");
        assert!(allowed.is_allow() && !denied.is_allow());
        let observed = |decision: &Decision| ObservedDecision {
            action: r#"Box::Action::"fs:read""#.to_string(),
            resource: "~/secret".to_string(),
            decision: decision.clone(),
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
            let decision = policy.decide(
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

    #[cfg(unix)]
    #[test]
    fn a_resource_attribute_value_that_is_not_utf8_refuses() {
        use std::os::unix::ffi::OsStringExt as _;
        let refusal = operator_resource_attributes(Some(std::ffi::OsString::from_vec(vec![0xff])))
            .expect_err("bytes that are not UTF-8 must refuse");
        assert!(
            refusal.to_string().contains("OTEL_RESOURCE_ATTRIBUTES"),
            "{refusal}"
        );
        assert_eq!(operator_resource_attributes(None).unwrap(), "");
    }
}
