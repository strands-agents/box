//! Decisions, control-plane operations, MCP routing diagnostics, and their signals.

use std::time::{SystemTime, UNIX_EPOCH};

use opentelemetry::logs::AnyValue;

/// One kind of record a target receives.
///
/// `Deserialize` is what parses the record spelling, so no caller hand-matches a string.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    /// An effective denial.
    PolicyDenied,
    /// An effective permit.
    PolicyPermitted,
    /// One span the agent's own instrumentation exported.
    AgentTrace,
    /// One log record the agent's own instrumentation exported.
    AgentLogs,
    /// One metric the agent's own instrumentation exported.
    AgentMetrics,
    /// One change to the authority this box holds, rather than one decision under it.
    ControlPlane,
    /// One MCP invocation that matches no declared command.
    McpUnmatched,
    /// One MCP tool call's own arguments and output, in clear text, and how it ended.
    McpToolCalls,
}

impl Signal {
    /// The record spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyDenied => "policy_denied",
            Self::PolicyPermitted => "policy_permitted",
            Self::AgentTrace => "agent_trace",
            Self::AgentLogs => "agent_logs",
            Self::AgentMetrics => "agent_metrics",
            Self::ControlPlane => "control_plane",
            Self::McpUnmatched => "mcp_unmatched",
            Self::McpToolCalls => "mcp_tool_calls",
        }
    }

    /// Every spelling, for a refusal that lists what an operator may write.
    #[must_use]
    pub fn every() -> Vec<&'static str> {
        Self::EVERY.iter().map(|s| s.as_str()).collect()
    }

    /// Every effective decision signal.
    #[must_use]
    pub fn every_verdict() -> Vec<Self> {
        vec![Self::PolicyDenied, Self::PolicyPermitted]
    }

    /// What a target receives when it names none: every signal except [`Self::McpToolCalls`].
    #[must_use]
    pub fn default_signals() -> Vec<Self> {
        // A tool call carries its values in clear text, so it reaches only a target that names it.
        Self::EVERY
            .into_iter()
            .filter(|signal| *signal != Self::McpToolCalls)
            .collect()
    }

    /// The signals every target receives, whatever it names.
    #[must_use]
    pub(crate) fn always_received() -> [Self; 2] {
        Self::ALWAYS
    }

    const ALWAYS: [Self; 2] = [Self::AgentLogs, Self::AgentMetrics];

    /// Whether this signal arrives already encoded rather than emitted through the SDK's logger.
    #[must_use]
    pub(crate) fn is_relayed(self) -> bool {
        matches!(
            self,
            Self::AgentTrace | Self::AgentLogs | Self::AgentMetrics
        )
    }

    /// The severity a record carries on the SDK's own channel.
    #[must_use]
    pub(crate) fn severity(self) -> opentelemetry::logs::Severity {
        match self {
            Self::PolicyDenied => opentelemetry::logs::Severity::Warn,
            Self::PolicyPermitted => opentelemetry::logs::Severity::Info,
            Self::AgentTrace => opentelemetry::logs::Severity::Trace,
            Self::AgentLogs => opentelemetry::logs::Severity::Trace2,
            Self::AgentMetrics => opentelemetry::logs::Severity::Trace3,
            Self::ControlPlane => opentelemetry::logs::Severity::Info2,
            Self::McpUnmatched => opentelemetry::logs::Severity::Info3,
            Self::McpToolCalls => opentelemetry::logs::Severity::Info4,
        }
    }

    /// The signal a severity came from, or `None` if the box did not write it.
    #[must_use]
    pub(crate) fn of_severity(severity: Option<opentelemetry::logs::Severity>) -> Option<Self> {
        Self::EVERY
            .iter()
            .copied()
            .find(|signal| Some(signal.severity()) == severity)
    }

    /// This signal's slot in a fixed-size acceptance set.
    #[must_use]
    pub(crate) fn slot(self) -> usize {
        match self {
            Self::PolicyDenied => 0,
            Self::PolicyPermitted => 1,
            Self::AgentTrace => 2,
            Self::AgentLogs => 3,
            Self::AgentMetrics => 4,
            Self::ControlPlane => 5,
            Self::McpUnmatched => 6,
            Self::McpToolCalls => 7,
        }
    }

    /// How many slots such a set needs.
    pub(crate) const SLOTS: usize = 8;

    const EVERY: [Self; 8] = [
        Self::PolicyDenied,
        Self::PolicyPermitted,
        Self::AgentTrace,
        Self::AgentLogs,
        Self::AgentMetrics,
        Self::ControlPlane,
        Self::McpUnmatched,
        Self::McpToolCalls,
    ];
}

/// Why one effective decision came out the way it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionCause {
    /// An authored `permit` matched, and no `forbid` overrode it.
    Permitted,
    /// An authored `forbid` matched.
    Forbidden,
    /// No authored `permit` matched.
    NoMatch,
    /// The complete authored policy is not installed.
    PolicyPending,
    /// The request could not be evaluated.
    InternalFault,
    /// An enforcement gate decided, so no authored policy determined the result.
    Enforcement,
}

impl DecisionCause {
    /// The wire spelling a consumer reads.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Permitted => "permitted",
            Self::Forbidden => "forbidden",
            Self::NoMatch => "no_match",
            Self::PolicyPending => "policy_pending",
            Self::InternalFault => "internal_fault",
            Self::Enforcement => "enforcement",
        }
    }

    /// Whether this cause can reach a permit.
    #[must_use]
    pub(crate) fn admits_permit(self) -> bool {
        matches!(self, Self::Permitted | Self::Enforcement)
    }

    /// Whether this cause can reach a deny.
    #[must_use]
    pub(crate) fn admits_deny(self) -> bool {
        matches!(
            self,
            Self::Forbidden
                | Self::NoMatch
                | Self::PolicyPending
                | Self::InternalFault
                | Self::Enforcement
        )
    }
}

/// What one decision was about, under the standard attribute names for its kind.
///
/// Every value is supplied by the enforcement point that already holds it, so nothing here re-parses
/// a resource string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject(SubjectKind);

#[derive(Debug, Clone, PartialEq, Eq)]
enum SubjectKind {
    Destination {
        address: String,
        port: u16,
        method: Option<String>,
    },
    File {
        path: String,
    },
    Process {
        program: String,
        args: Vec<String>,
        working_directory: String,
    },
}

impl Subject {
    /// A network destination, as `server.address` and `server.port`.
    #[must_use]
    pub fn destination(address: &str, port: u16) -> Self {
        Self(SubjectKind::Destination {
            address: bounded(address),
            port,
            method: None,
        })
    }

    /// An HTTP destination, which also states `http.request.method`.
    #[must_use]
    pub fn http(address: &str, port: u16, method: &str) -> Self {
        Self(SubjectKind::Destination {
            address: bounded(address),
            port,
            method: Some(bounded(method)),
        })
    }

    /// A filesystem path, as `file.path`.
    #[must_use]
    pub fn file(path: &str) -> Self {
        Self(SubjectKind::File {
            path: bounded(path),
        })
    }

    /// A resolved command line, as `process.command`, `process.command_args` and
    /// `process.working_directory`.
    ///
    /// `args` carries the expanded arguments without the program, and `literal` says for each one
    /// whether its word was literal in the submitted script. An argument is reported when it was
    /// literal, or when it is a plain flag; every other argument is replaced by
    /// [`REDACTED`]. A missing `literal` entry is treated as expanded, so a caller that supplies
    /// none redacts rather than leaks.
    #[must_use]
    pub fn process(
        program: &str,
        args: &[String],
        literal: &[bool],
        working_directory: &str,
    ) -> Self {
        let mut reported: Vec<String> = Vec::with_capacity(args.len() + 1);
        reported.push(bounded(program));
        reported.extend(args.iter().enumerate().take(MAXIMUM_COMMAND_ARGS).map(
            |(index, argument)| {
                if literal.get(index).copied().unwrap_or(false) {
                    bounded(argument)
                } else {
                    reportable(argument)
                }
            },
        ));
        if args.len() > MAXIMUM_COMMAND_ARGS {
            reported.push(format!(
                "{} more{TRUNCATED}",
                args.len() - MAXIMUM_COMMAND_ARGS
            ));
        }
        Self(SubjectKind::Process {
            program: bounded(program),
            args: reported,
            working_directory: bounded(working_directory),
        })
    }

    fn attributes(&self) -> Vec<(&'static str, AnyValue)> {
        match &self.0 {
            SubjectKind::Destination {
                address,
                port,
                method,
            } => {
                let mut pairs: Vec<(&'static str, AnyValue)> = vec![
                    ("server.address", address.clone().into()),
                    ("server.port", i64::from(*port).into()),
                ];
                if let Some(method) = method.as_deref().filter(|value| !value.is_empty()) {
                    pairs.push(("http.request.method", method.to_string().into()));
                }
                pairs
            }
            SubjectKind::File { path } => vec![("file.path", path.clone().into())],
            SubjectKind::Process {
                program,
                args,
                working_directory,
            } => {
                let mut pairs: Vec<(&'static str, AnyValue)> = vec![
                    ("process.command", program.clone().into()),
                    ("process.command_args", text_list(args.clone())),
                ];
                if !working_directory.is_empty() {
                    pairs.push((
                        "process.working_directory",
                        working_directory.clone().into(),
                    ));
                }
                pairs
            }
        }
    }
}

/// One MCP invocation that matches no declared command.
#[derive(Debug, Clone)]
pub struct McpUnmatched {
    subject: Subject,
    correlation: crate::Correlation,
    unix_nanos: u128,
}

impl McpUnmatched {
    /// Record the program and its bounded, redacted arguments.
    #[must_use]
    pub fn new(program: &str, arguments: &[String]) -> Self {
        Self {
            subject: Subject::process(program, arguments, &[], ""),
            correlation: crate::Correlation::current(),
            unix_nanos: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_nanos()),
        }
    }

    /// Attach the context of the routing request.
    #[must_use]
    pub fn correlated(mut self, correlation: crate::Correlation) -> Self {
        self.correlation = correlation;
        self
    }

    pub(crate) fn correlation(&self) -> &crate::Correlation {
        &self.correlation
    }

    pub(crate) fn attributes(&self) -> Vec<(&'static str, AnyValue)> {
        self.subject.attributes()
    }

    pub(crate) fn unix_nanos(&self) -> u128 {
        self.unix_nanos
    }
}

/// One MCP tool call: the arguments it was decided with, and how it ended.
#[derive(Debug, Clone)]
pub struct McpToolCall {
    server: String,
    tool: String,
    arguments: Option<crate::tool::ToolFields>,
    reply: Option<String>,
    output: Option<crate::tool::ToolFields>,
    phase: ToolCallPhase,
    correlation: crate::Correlation,
    unix_nanos: u128,
}

/// Which half of one tool call a record states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolCallPhase {
    /// The call was decided, and its arguments are what policy judged.
    Called,
    /// The call ended, however it ended.
    Completed,
}

impl ToolCallPhase {
    pub(crate) fn event_name(self) -> &'static str {
        match self {
            Self::Called => "strands.box.mcp.tool.call",
            Self::Completed => "strands.box.mcp.tool.completion",
        }
    }
}

impl McpToolCall {
    /// Record one decided call's `server`, `tool`, and `arguments`, flattened into fields.
    #[must_use]
    pub fn called(server: &str, tool: &str, arguments: &serde_json::Value) -> Self {
        Self {
            server: bounded(server),
            tool: bounded(tool),
            arguments: Some(crate::tool::ToolFields::of(arguments)),
            reply: None,
            output: None,
            phase: ToolCallPhase::Called,
            correlation: crate::Correlation::current(),
            unix_nanos: now_unix_nanos(),
        }
    }

    /// Record how one call ended, with `reply` naming the end and `output` the tool's
    /// `structuredContent`, flattened into fields like arguments.
    #[must_use]
    pub fn completed(
        server: &str,
        tool: &str,
        reply: &str,
        output: Option<&serde_json::Value>,
    ) -> Self {
        Self {
            server: bounded(server),
            tool: bounded(tool),
            arguments: None,
            reply: Some(bounded(reply)),
            output: output.map(crate::tool::ToolFields::of),
            phase: ToolCallPhase::Completed,
            correlation: crate::Correlation::current(),
            unix_nanos: now_unix_nanos(),
        }
    }

    /// Attach the context of the MCP request this call belongs to.
    #[must_use]
    pub fn correlated(mut self, correlation: crate::Correlation) -> Self {
        self.correlation = correlation;
        self
    }

    pub(crate) fn phase(&self) -> ToolCallPhase {
        self.phase
    }

    pub(crate) fn correlation(&self) -> &crate::Correlation {
        &self.correlation
    }

    pub(crate) fn unix_nanos(&self) -> u128 {
        self.unix_nanos
    }

    pub(crate) fn attributes(&self) -> Vec<(&'static str, AnyValue)> {
        let mut pairs: Vec<(&'static str, AnyValue)> = vec![
            (crate::tool::SERVER, self.server.clone().into()),
            (crate::tool::NAME, self.tool.clone().into()),
        ];
        if let Some(arguments) = &self.arguments {
            pairs.push((crate::tool::ARGUMENTS, arguments.attribute()));
            if let Some(omitted) = arguments.omitted() {
                pairs.push((crate::tool::ARGUMENTS_OMITTED, omitted.into()));
            }
        }
        if let Some(reply) = &self.reply {
            pairs.push(("strands.box.mcp.tool.reply", reply.clone().into()));
        }
        if let Some(output) = &self.output {
            pairs.push((crate::tool::OUTPUT, output.attribute()));
            if let Some(omitted) = output.omitted() {
                pairs.push((crate::tool::OUTPUT_OMITTED, omitted.into()));
            }
        }
        pairs
    }
}

/// One policy that determined an effective decision.
#[derive(Debug, Clone)]
pub struct DeterminingPolicy {
    id: String,
    description: Option<String>,
}

impl DeterminingPolicy {
    /// Name one determining policy by its identifier, which is bounded here.
    #[must_use]
    pub fn new(id: &str) -> Self {
        Self {
            id: bounded(id),
            description: None,
        }
    }

    /// Carry the authored description, which reaches `strands.box.policy.description`.
    #[must_use]
    pub fn described(mut self, description: Option<&str>) -> Self {
        self.description = description.map(bounded);
        self
    }
}

/// One effective decision, as a target receives it.
#[derive(Debug, Clone)]
pub struct DecisionRecord {
    correlation: crate::Correlation,
    action: String,
    resource: String,
    rule: String,
    permitted: bool,
    reason: Option<String>,
    cause: DecisionCause,
    determining: Vec<DeterminingPolicy>,
    subject: Option<Subject>,
    /// Whether Box applied this verdict; `false` for a denial log-only mode let through.
    enforced: bool,
    /// Whether this is the run's first denial that was not enforced.
    first_flip: bool,
    /// Each rule that would have denied the action in log-only mode, across all its legs and gates.
    would_deny: Vec<String>,
    /// What each enrichment entry answered about the destination, by entry name.
    enrichment: Vec<EnrichmentAttribute>,
    unix_nanos: u128,
}

/// One enrichment entry's answer about a destination, as a decision record states it.
#[derive(Debug, Clone)]
struct EnrichmentAttribute {
    name: String,
    answered: bool,
    labels: Vec<String>,
}

impl DecisionRecord {
    /// Attach request correlation to the decision span and its audit log.
    #[must_use]
    pub fn correlated(mut self, correlation: crate::Correlation) -> Self {
        self.correlation = correlation;
        self
    }

    pub(crate) fn correlation(&self) -> &crate::Correlation {
        &self.correlation
    }

    /// A permit, by `rule`.
    #[must_use]
    pub fn permit(action: &str, resource: &str, rule: &str) -> Self {
        Self::new(action, resource, rule, true, None)
    }

    /// A refusal, by `rule`, for `reason`.
    #[must_use]
    pub fn deny(action: &str, resource: &str, rule: &str, reason: &str) -> Self {
        Self::new(action, resource, rule, false, Some(reason.to_string()))
    }

    /// State what the decision was about, under the standard names for its kind.
    #[must_use]
    pub fn about(mut self, subject: Subject) -> Self {
        self.subject = Some(subject);
        self
    }

    /// State which class of result this is.
    ///
    /// # Panics
    ///
    /// When the cause cannot reach the verdict this record already holds.
    #[must_use]
    pub fn caused_by(mut self, cause: DecisionCause) -> Self {
        assert!(
            if self.permitted {
                cause.admits_permit()
            } else {
                cause.admits_deny()
            },
            "cause {} cannot reach verdict {}",
            cause.as_str(),
            self.verdict(),
        );
        self.cause = cause;
        self
    }

    /// State that Box did not apply this denial: log-only mode let the action go ahead.
    ///
    /// Only a denial can go unenforced, so a permit is left as it is, and a debug build asserts.
    #[must_use]
    pub fn not_enforced(mut self) -> Self {
        debug_assert!(!self.permitted, "only a denial can go unenforced");
        if !self.permitted {
            self.enforced = false;
        }
        self
    }

    /// Mark this unenforced denial as the run's first, after which the run can drift from what
    /// enforcing would have done.
    ///
    /// Only an unenforced denial can be a flip, so an enforced record is left as it is, and a debug
    /// build asserts.
    #[must_use]
    pub fn first_flip(mut self) -> Self {
        debug_assert!(!self.enforced, "only an unenforced denial can be a flip");
        if !self.enforced {
            self.first_flip = true;
        }
        self
    }

    /// Whether Box applied this verdict.
    #[must_use]
    pub fn enforced(&self) -> bool {
        self.enforced
    }

    /// Whether this is the run's first denial that was not enforced.
    #[must_use]
    pub fn is_first_flip(&self) -> bool {
        self.first_flip
    }

    /// Name each rule that would have denied the action in log-only mode, one per leg or gate it
    /// let through, in the order they were decided.
    #[must_use]
    pub fn with_would_deny(mut self, rules: impl IntoIterator<Item = String>) -> Self {
        self.would_deny = rules.into_iter().collect();
        self
    }

    /// Each rule that would have denied the action in log-only mode.
    #[must_use]
    pub fn would_deny(&self) -> &[String] {
        &self.would_deny
    }

    /// State what the enrichment entry `name` answered about the destination, as
    /// `strands.box.enrichment.<name>.answered` and `strands.box.enrichment.<name>.labels`.
    #[must_use]
    pub fn enriched(
        mut self,
        name: &str,
        answered: bool,
        labels: impl IntoIterator<Item = String>,
    ) -> Self {
        self.enrichment.push(EnrichmentAttribute {
            name: bounded(name),
            answered,
            labels: labels.into_iter().map(|label| bounded(&label)).collect(),
        });
        self
    }

    /// The enrichment attributes, whose keys carry each entry's name.
    pub(crate) fn enrichment_attributes(&self) -> Vec<(String, AnyValue)> {
        self.enrichment
            .iter()
            .flat_map(|entry| {
                [
                    (
                        format!("{ENRICHMENT_PREFIX}{}.answered", entry.name),
                        AnyValue::Boolean(entry.answered),
                    ),
                    (
                        format!("{ENRICHMENT_PREFIX}{}.labels", entry.name),
                        text_list(entry.labels.iter().cloned()),
                    ),
                ]
            })
            .collect()
    }

    /// Name every policy that determined this decision. The first one governs, so it supplies
    /// `strands.box.policy.rule` and `strands.box.policy.description`.
    #[must_use]
    pub fn determined_by(mut self, policies: impl IntoIterator<Item = DeterminingPolicy>) -> Self {
        self.determining = policies.into_iter().collect();
        self
    }

    /// The signal this record arrives on.
    #[must_use]
    pub(crate) fn signal(&self) -> Signal {
        if self.permitted {
            Signal::PolicyPermitted
        } else {
            Signal::PolicyDenied
        }
    }

    /// The action, as `strands.box.policy.action` states it.
    #[must_use]
    pub fn action(&self) -> &str {
        vocabulary_term(&self.action)
    }

    /// The namespace of the action, as `strands.box.policy.category` states it.
    #[must_use]
    pub fn category(&self) -> &str {
        action_category(&self.action)
    }

    /// The resource, as `strands.box.policy.resource` states it.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Whether the decision is a permit.
    #[must_use]
    pub fn permitted(&self) -> bool {
        self.permitted
    }

    /// The class of result, as `strands.box.policy.cause` states it.
    #[must_use]
    pub fn cause(&self) -> DecisionCause {
        self.cause
    }

    /// The governing rule, as `strands.box.policy.rule` states it.
    #[must_use]
    pub fn rule(&self) -> &str {
        // An authored policy is named only when one actually decided, which the cause states. A
        // fault keeps its attribution while the engine reaches `<default-deny>`, so naming the first
        // entry there would report a policy that did not decide.
        self.governing()
            .map_or(self.rule.as_str(), |policy| policy.id.as_str())
    }

    /// The reason for a refusal, as `strands.box.policy.reason` states it.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// The time of the decision, which is the record's timestamp.
    #[must_use]
    pub fn time(&self) -> SystemTime {
        UNIX_EPOCH
            + std::time::Duration::from_nanos(u64::try_from(self.unix_nanos).unwrap_or(u64::MAX))
    }

    /// The attributes a consumer reads, in the order the box states them.
    pub(crate) fn attributes(&self) -> Vec<(&'static str, AnyValue)> {
        let mut pairs: Vec<(&'static str, AnyValue)> = vec![
            ("strands.box.policy.principal", PRINCIPAL.into()),
            (
                "strands.box.policy.action",
                self.action().to_string().into(),
            ),
            (
                "strands.box.policy.resource",
                self.resource().to_string().into(),
            ),
            ("strands.box.policy.verdict", self.verdict().into()),
        ];
        pairs.push(("strands.box.policy.cause", self.cause().as_str().into()));
        if self.cause() == DecisionCause::InternalFault {
            pairs.push(("error.type", "strands.box.policy.evaluation_error".into()));
        }
        if let Some(reason) = self.reason() {
            pairs.push(("strands.box.policy.reason", reason.to_string().into()));
        }
        // Only a denial log-only mode let through says so; an applied verdict carries neither.
        if !self.enforced {
            pairs.push(("strands.box.policy.enforced", AnyValue::Boolean(false)));
        }
        if self.first_flip {
            pairs.push(("strands.box.policy.first_flip", AnyValue::Boolean(true)));
        }
        if !self.would_deny.is_empty() {
            pairs.push((WOULD_DENY_IDS, text_list(self.would_deny.iter().cloned())));
        }

        // The governing rule, under this product's own namespace.
        let governing = self.governing();
        pairs.push((RULE, self.rule().to_string().into()));
        pairs.push((CATEGORY, self.category().to_string().into()));
        if let Some(description) = governing
            .and_then(|policy| policy.description.as_deref())
            .filter(|text| !text.is_empty())
        {
            pairs.push((DESCRIPTION, description.to_string().into()));
        }

        // What the decision was about. An `fs:*` resource **is** the approved path, so it is copied
        // unchanged; every other lane states its own subject. The box's own namespace is what
        // selects this, because a tool identifier is server-supplied text and may spell `fs:read`.
        match &self.subject {
            Some(subject) => pairs.extend(subject.attributes()),
            None if self.is_box_filesystem_action() => {
                pairs.extend(Subject::file(&self.resource).attributes());
            }
            None => {}
        }

        if !self.determining.is_empty() {
            pairs.push((
                DETERMINING_IDS,
                text_list(self.determining.iter().map(|policy| policy.id.clone())),
            ));
        }
        pairs
    }

    /// The one policy that decided, or `None` when no authored policy did.
    ///
    /// Only `Permitted` and `Forbidden` mean an authored rule reached the verdict. `NoMatch`,
    /// `PolicyPending`, `InternalFault`, and `Enforcement` each mean it did not, and a fault keeps
    /// its attribution, so the cause is what separates them.
    fn governing(&self) -> Option<&DeterminingPolicy> {
        match self.cause {
            DecisionCause::Permitted | DecisionCause::Forbidden => self.determining.first(),
            _ => None,
        }
    }

    /// Whether this is one of the box's own `fs:*` actions, by the box's own namespace.
    ///
    /// A tool identifier reaches the action verbatim, so a server may declare a tool called
    /// `fs:read`. Reading the namespace is what keeps that from reporting a filesystem decision.
    fn is_box_filesystem_action(&self) -> bool {
        self.action
            .strip_prefix("Box::Action::")
            .is_some_and(|action| action.trim_matches('"').starts_with("fs:"))
    }

    pub(crate) fn verdict(&self) -> &'static str {
        if self.permitted() { "permit" } else { "deny" }
    }

    pub(crate) fn unix_nanos(&self) -> u128 {
        self.unix_nanos
    }

    fn new(
        action: &str,
        resource: &str,
        rule: &str,
        permitted: bool,
        reason: Option<String>,
    ) -> Self {
        Self {
            correlation: crate::Correlation::current(),
            action: action.to_string(),
            resource: resource.to_string(),
            rule: rule.to_string(),
            permitted,
            reason,
            cause: if permitted {
                DecisionCause::Permitted
            } else {
                DecisionCause::Forbidden
            },
            determining: Vec::new(),
            subject: None,
            enforced: true,
            first_flip: false,
            would_deny: Vec::new(),
            enrichment: Vec::new(),
            unix_nanos: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_nanos()),
        }
    }
}

/// The identifiers of every policy that determined one decision.
const DETERMINING_IDS: &str = "strands.box.policy.determining.ids";
/// Each rule that would have denied an action log-only mode let through.
const WOULD_DENY_IDS: &str = "strands.box.policy.would_deny.ids";

/// The prefix of each enrichment entry's attributes.
const ENRICHMENT_PREFIX: &str = "strands.box.enrichment.";

/// The rule that decided, by the identifier the operator authored.
const RULE: &str = "strands.box.policy.rule";

/// The namespace that rule's action belongs to.
const CATEGORY: &str = "strands.box.policy.category";

/// The authored note on why that rule exists.
const DESCRIPTION: &str = "strands.box.policy.description";

/// One OTLP array attribute, so a consumer reads a list rather than parsing one string.
fn text_list(values: impl IntoIterator<Item = String>) -> AnyValue {
    AnyValue::ListAny(Box::new(values.into_iter().map(AnyValue::from).collect()))
}

/// The policy identity every effective decision is reached against.
///
/// Fixed, because `policy` documents itself as ignoring caller-supplied integration metadata.
const PRINCIPAL: &str = "agent:self";

/// The name identifying the structure of one decision event.
///
/// It reaches the log record's own `event_name` field, which is what marks the record as an event.
pub(crate) const EVENT_NAME: &str = "strands.box.policy.decision";

/// The vocabulary term inside a Cedar-qualified identifier.
///
/// A consumer reads `fs:read`, never `Box::Action::"fs:read"`.
fn vocabulary_term(value: &str) -> &str {
    value
        .rsplit_once("::")
        .map_or(value, |(_, term)| term)
        .trim_matches('"')
}

/// The namespace one action belongs to, as `strands.box.policy.category` states it.
///
/// The box's own vocabulary spells the group inside the term, so `Box::Action::"fs:read"` gives `fs`.
/// Any other declaring namespace **is** the category, because the term after it is server-supplied
/// text: `alpha::Action::"read"` gives `alpha`, the server, and a tool a server chose to call
/// `fs:read` still gives `alpha` rather than impersonating the filesystem lane.
/// `Tool::git::Action::"push"` gives `Tool::git`, the tool grammar.
fn action_category(action: &str) -> &str {
    let term = vocabulary_term(action);
    fn group(term: &str) -> &str {
        term.split_once(':').map_or(term, |(group, _)| group)
    }
    match action.split_once("::") {
        Some((BOX_NAMESPACE, _)) => group(term),
        Some((namespace, _)) if !namespace.is_empty() => action
            .split_once("::Action::")
            .map_or(namespace, |(declaring, _)| declaring),
        _ => group(term),
    }
}

/// The Cedar namespace the box's own action vocabulary declares.
const BOX_NAMESPACE: &str = "Box";

/// One change to the authority a box holds, rather than one decision taken under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlOperation {
    /// The box installed its authored policy.
    PolicyInstalled,
    /// The box refused an authored policy.
    PolicyRefused,
    /// One MCP server's generated tool vocabulary joined the policy.
    SchemaInstalled,
    /// Every discovery door drained, so the authority is complete.
    DiscoveryComplete,
    /// This run took the box.
    BoxStarted,
    /// The box finished its setup and launched the workload.
    WorkloadStarted,
    /// This run is giving the box up.
    BoxStopped,
    /// The box read one secret of a configuration entry through a declared secret source.
    SecretFetched,
}

impl ControlOperation {
    /// The wire spelling a consumer reads.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyInstalled => "policy_installed",
            Self::PolicyRefused => "policy_refused",
            Self::SchemaInstalled => "schema_installed",
            Self::DiscoveryComplete => "discovery_complete",
            Self::BoxStarted => "box_started",
            Self::WorkloadStarted => "workload_started",
            Self::BoxStopped => "box_stopped",
            Self::SecretFetched => "secret_fetched",
        }
    }
}

/// The most text one attribute may carry.
const MAXIMUM_ATTRIBUTE_BYTES: usize = 4 * 1024;

/// What was cut, so a reader knows the value is not the whole one.
const TRUNCATED: &str = "… (truncated)";

/// The most arguments one reported command line may carry, so a very long line stays one bounded
/// record rather than a megabyte of attribute.
const MAXIMUM_COMMAND_ARGS: usize = 64;

/// What stands in for an argument the record does not carry.
pub(crate) const REDACTED: &str = "<redacted>";

/// The most characters a reported long-option name may carry.
const MAXIMUM_FLAG_NAME_CHARS: usize = 32;

/// Whether `argument` is a plain flag, carrying a name and no value of its own.
///
/// A single `-` takes one letter, because a longer tail is how a value rides on a short option. A
/// `--` name takes lowercase letters and dashes, bounded, because every other spelling is a shape a
/// credential shares.
fn plain_flag(argument: &str) -> bool {
    if let Some(name) = argument.strip_prefix("--") {
        return !name.is_empty()
            && name.chars().count() <= MAXIMUM_FLAG_NAME_CHARS
            && name.starts_with(|first: char| first.is_ascii_lowercase())
            && name
                .chars()
                .all(|character| character.is_ascii_lowercase() || character == '-');
    }
    argument.strip_prefix('-').is_some_and(|name| {
        name.len() == 1 && name.starts_with(|first: char| first.is_ascii_alphabetic())
    })
}

/// One EXPANDED argument as the record carries it: a plain flag's name, and [`REDACTED`] otherwise.
///
/// A flag that carries its own value keeps the name and always loses the value. A literal argument
/// never reaches this function — `Subject::process` reports it unchanged.
fn reportable(argument: &str) -> String {
    if plain_flag(argument) {
        return bounded(argument);
    }
    if argument.starts_with('-')
        && let Some((name, _)) = argument.split_once('=')
        && plain_flag(name)
    {
        return format!("{}={REDACTED}", bounded(name));
    }
    REDACTED.to_string()
}

/// The wall-clock reading a record carries, or zero when the clock is before the epoch.
fn now_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos())
}

/// `text` bounded to [`MAXIMUM_ATTRIBUTE_BYTES`], cut on a character boundary.
pub(crate) fn bounded(text: &str) -> String {
    if text.len() <= MAXIMUM_ATTRIBUTE_BYTES {
        return text.to_string();
    }
    let keep = text
        .char_indices()
        .map(|(at, _)| at)
        .take_while(|at| *at <= MAXIMUM_ATTRIBUTE_BYTES - TRUNCATED.len())
        .last()
        .unwrap_or(0);
    format!("{}{TRUNCATED}", &text[..keep])
}

/// One control-plane operation, as a target receives it.
#[derive(Debug, Clone)]
pub struct ControlRecord {
    operation: ControlOperation,
    subject: Option<String>,
    refusal: Option<String>,
    detail: Option<String>,
    unix_nanos: u128,
    /// How the installed policy's verdicts apply, on a `policy_installed` record.
    enforcement: Option<&'static str>,
}

impl ControlRecord {
    /// An operation that succeeded, against `subject`, which is bounded here.
    #[must_use]
    pub fn completed(operation: ControlOperation, subject: &str) -> Self {
        Self::new(operation, Some(bounded(subject)), None, None)
    }

    /// An operation the box refused, for `reason`, which is bounded here.
    #[must_use]
    pub fn refused(operation: ControlOperation, subject: &str, reason: &str) -> Self {
        Self::new(
            operation,
            Some(bounded(subject)),
            Some(bounded(reason)),
            None,
        )
    }

    /// Add one non-secret detail an operator reads, such as how many actions a schema carried.
    #[must_use]
    pub fn detailed(mut self, detail: &str) -> Self {
        self.detail = Some(bounded(detail));
        self
    }

    /// State how the installed policy's verdicts apply: `enforce` or `log_only`.
    #[must_use]
    pub fn enforcing(mut self, enforcement: &'static str) -> Self {
        self.enforcement = Some(enforcement);
        self
    }

    /// The signal this record arrives on. Every control-plane record shares one.
    #[must_use]
    pub(crate) fn signal(&self) -> Signal {
        Signal::ControlPlane
    }

    /// The attributes a consumer reads, in the order the box states them.
    pub(crate) fn attributes(&self) -> Vec<(&'static str, String)> {
        let mut pairs = vec![
            (
                "strands.box.control.operation",
                self.operation.as_str().to_string(),
            ),
            ("strands.box.control.outcome", self.outcome().to_string()),
        ];
        if let Some(subject) = &self.subject {
            pairs.push(("strands.box.control.subject", subject.clone()));
        }
        if let Some(reason) = &self.refusal {
            pairs.push(("strands.box.control.reason", reason.clone()));
        }
        if let Some(detail) = &self.detail {
            pairs.push(("strands.box.control.detail", detail.clone()));
        }
        if let Some(enforcement) = self.enforcement {
            pairs.push(("strands.box.control.enforcement", enforcement.to_string()));
        }
        pairs
    }

    pub(crate) fn outcome(&self) -> &'static str {
        if self.refusal.is_some() {
            "refused"
        } else {
            "ok"
        }
    }

    pub(crate) fn unix_nanos(&self) -> u128 {
        self.unix_nanos
    }

    fn new(
        operation: ControlOperation,
        subject: Option<String>,
        refusal: Option<String>,
        detail: Option<String>,
    ) -> Self {
        Self {
            operation,
            subject,
            refusal,
            detail,
            enforcement: None,
            unix_nanos: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_nanos()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Only a denial Box did not apply says so**, and only the run's first says it is the first
    /// flip; an applied verdict carries neither attribute.
    #[test]
    fn an_unenforced_denial_states_it_and_an_applied_verdict_does_not() {
        let keys = |record: &DecisionRecord| -> Vec<(&'static str, String)> {
            record
                .attributes()
                .into_iter()
                .filter(|(key, _)| key.ends_with(".enforced") || key.ends_with(".first_flip"))
                .map(|(key, value)| (key, format!("{value:?}")))
                .collect()
        };
        let applied = DecisionRecord::deny("Box::Action::\"fs:read\"", "/w/a", "r", "no permit");
        assert!(keys(&applied).is_empty());
        assert!(
            keys(&DecisionRecord::permit(
                "Box::Action::\"fs:read\"",
                "/w/a",
                "r"
            ))
            .is_empty()
        );

        let flip = applied.clone().not_enforced().first_flip();
        assert!(!flip.enforced() && flip.is_first_flip());
        assert_eq!(
            keys(&flip),
            [
                ("strands.box.policy.enforced", "Boolean(false)".to_string()),
                ("strands.box.policy.first_flip", "Boolean(true)".to_string()),
            ]
        );
        assert_eq!(keys(&applied.not_enforced()).len(), 1);
    }

    /// Every rule that would have denied the action is listed, in order, and a record that names
    /// none carries no such key.
    #[test]
    fn an_unenforced_denial_lists_every_rule_that_would_have_denied_it() {
        let record = DecisionRecord::deny("Box::Action::\"fs:move\"", "/w/b", "r", "forbid")
            .not_enforced()
            .with_would_deny(["no-read-a".to_string(), "no-move-onto-b".to_string()]);
        assert_eq!(record.would_deny(), ["no-read-a", "no-move-onto-b"]);
        let listed = record
            .attributes()
            .into_iter()
            .find(|(key, _)| *key == "strands.box.policy.would_deny.ids")
            .map(|(_, value)| format!("{value:?}"))
            .expect("the list is written");
        assert!(
            listed.contains("no-read-a") && listed.contains("no-move-onto-b"),
            "{listed}"
        );
        assert!(
            DecisionRecord::permit("Box::Action::\"fs:read\"", "/w/a", "r")
                .attributes()
                .iter()
                .all(|(key, _)| *key != "strands.box.policy.would_deny.ids")
        );
    }

    /// The `policy_installed` record states how the policy's verdicts apply.
    #[test]
    fn a_policy_installed_record_states_its_mode() {
        let record = ControlRecord::completed(ControlOperation::PolicyInstalled, "policy.dw")
            .enforcing("log_only");
        assert!(
            record
                .attributes()
                .contains(&("strands.box.control.enforcement", "log_only".to_string()))
        );
    }

    #[test]
    fn unmatched_mcp_routes_bound_and_redact_arguments_at_construction() {
        let long = "a".repeat(MAXIMUM_ATTRIBUTE_BYTES * 2);
        let mut arguments = vec!["diagnostic-secret".to_string(); MAXIMUM_COMMAND_ARGS + 1];
        arguments[0] = format!("--token={long}");
        let record = McpUnmatched::new(&long, &arguments);
        assert!(!format!("{record:?}").contains("diagnostic-secret"));
        let attributes = record.attributes();
        let program = text_of(&attributes, "process.command").unwrap();
        assert!(program.len() <= MAXIMUM_ATTRIBUTE_BYTES);
        assert!(program.ends_with(TRUNCATED));
        let reported = list_of(&attributes, "process.command_args");
        assert_eq!(reported.len(), MAXIMUM_COMMAND_ARGS + 2);
        assert_eq!(reported[0], program);
        assert_eq!(reported[1], "--token=<redacted>");
        assert!(
            reported[2..=MAXIMUM_COMMAND_ARGS]
                .iter()
                .all(|arg| arg == REDACTED)
        );
        assert!(reported.last().unwrap().starts_with("1 more"));
    }

    /// A verdict arrives on the signal its outcome names, and on no other.
    #[test]
    fn a_verdict_arrives_on_the_signal_its_outcome_names() {
        assert_eq!(
            DecisionRecord::permit(r#"Box::Action::"fs:read""#, "~/x", "r1").signal(),
            Signal::PolicyPermitted
        );
        assert_eq!(
            DecisionRecord::deny(
                r#"Box::Action::"fs:read""#,
                "~/x",
                "r1",
                "no permit matched",
            )
            .signal(),
            Signal::PolicyDenied
        );
    }

    /// No signal contains another, so naming one never implies a second.
    #[test]
    fn no_signal_implies_another() {
        let every = Signal::EVERY;
        for (index, one) in every.iter().enumerate() {
            for other in &every[index + 1..] {
                assert_ne!(one, other, "each signal is its own kind");
            }
        }
        assert!(!Signal::every_verdict().contains(&Signal::AgentTrace));
    }

    /// **`as_str` and the serde spelling agree**, and nothing outside the vocabulary parses.
    ///
    /// Serde owns the parsing now, so a `rename_all` disagreeing with `as_str` would store one
    /// signal and read back another.
    #[test]
    fn every_signal_spelling_round_trips_through_serde() {
        for spelling in Signal::every() {
            let parsed: Signal = serde_json::from_str(&format!("\"{spelling}\""))
                .unwrap_or_else(|error| panic!("{spelling} must deserialize: {error}"));
            assert_eq!(parsed.as_str(), spelling);
        }
        // `trace`, `logs`, and `metrics` are the OPERATOR's words, which `box.toml` expands. None is
        // a record spelling, so reading one here would mean the two vocabularies had merged.
        for absent in ["debug", "trace", "logs", "metrics"] {
            assert!(serde_json::from_str::<Signal>(&format!("\"{absent}\"")).is_err());
        }
    }

    /// **Every attribute is bounded at construction, so no call site can forget.** The reason on a
    /// refusal is derived from an MCP server's own schema or from a policy diagnostic list, and
    /// neither has a length the box chooses.
    #[test]
    fn every_control_attribute_is_bounded_at_construction() {
        let long = "A".repeat(512 * 1024);
        let record =
            ControlRecord::refused(ControlOperation::PolicyRefused, &long, &long).detailed(&long);
        for (key, value) in record.attributes() {
            assert!(
                value.len() <= MAXIMUM_ATTRIBUTE_BYTES,
                "{key} is {} bytes, over the bound",
                value.len()
            );
        }
        assert!(
            record
                .attributes()
                .iter()
                .any(|(key, value)| *key == "strands.box.control.reason"
                    && value.ends_with(TRUNCATED)),
            "a cut value says so"
        );

        // A short value is untouched, or the bound would rewrite every record.
        let short = ControlRecord::completed(ControlOperation::BoxStarted, "demo");
        assert!(
            short
                .attributes()
                .contains(&("strands.box.control.subject", "demo".to_string()))
        );
    }

    /// A multi-byte value is cut on a character boundary, never through one.
    #[test]
    fn a_bounded_value_is_still_valid_utf8() {
        // 3 bytes per character, so the naive byte cut lands mid-character.
        let wide = "日".repeat(MAXIMUM_ATTRIBUTE_BYTES);
        let cut = bounded(&wide);
        assert!(cut.len() <= MAXIMUM_ATTRIBUTE_BYTES);
        assert!(cut.ends_with(TRUNCATED));
        assert!(
            cut.trim_end_matches(TRUNCATED).chars().all(|c| c == '日'),
            "the kept prefix is whole characters: {cut}"
        );
    }

    /// **A control-plane record carries an operation, a subject and an outcome, and no verdict.**
    /// That is why it is its own type: `DecisionRecord`'s three fields have no meaning here.
    #[test]
    fn a_control_record_carries_an_operation_and_never_a_verdict() {
        let installed = ControlRecord::completed(ControlOperation::SchemaInstalled, "issues-mcp")
            .detailed("27 tools");
        let attributes = installed.attributes();
        assert_eq!(installed.outcome(), "ok");
        assert!(attributes.contains(&(
            "strands.box.control.operation",
            "schema_installed".to_string()
        )));
        assert!(attributes.contains(&("strands.box.control.subject", "issues-mcp".to_string())));
        assert!(attributes.contains(&("strands.box.control.detail", "27 tools".to_string())));
        assert!(
            attributes
                .iter()
                .all(|(key, _)| !key.contains("verdict") && !key.contains("principal")),
            "a control record states no verdict and no principal: {attributes:?}"
        );

        let refused = ControlRecord::refused(
            ControlOperation::PolicyRefused,
            "policy.dw",
            "the schema does not validate",
        );
        assert_eq!(refused.outcome(), "refused");
        assert!(refused.attributes().contains(&(
            "strands.box.control.reason",
            "the schema does not validate".to_string()
        )));
    }

    /// **Each control operation keeps its wire spelling**, which a consumer selects records by.
    #[test]
    fn each_control_operation_keeps_its_wire_spelling() {
        assert_eq!(
            [
                ControlOperation::PolicyInstalled,
                ControlOperation::PolicyRefused,
                ControlOperation::SchemaInstalled,
                ControlOperation::DiscoveryComplete,
                ControlOperation::BoxStarted,
                ControlOperation::WorkloadStarted,
                ControlOperation::BoxStopped,
                ControlOperation::SecretFetched,
            ]
            .map(ControlOperation::as_str),
            [
                "policy_installed",
                "policy_refused",
                "schema_installed",
                "discovery_complete",
                "box_started",
                "workload_started",
                "box_stopped",
                "secret_fetched",
            ]
        );
    }

    /// **Every signal carries its own severity**, because that is what routes a record to a lane.
    #[test]
    fn no_two_signals_share_a_severity() {
        for (index, one) in Signal::EVERY.iter().enumerate() {
            for other in &Signal::EVERY[index + 1..] {
                assert_ne!(
                    one.severity(),
                    other.severity(),
                    "{} and {} would route to the same lane",
                    one.as_str(),
                    other.as_str()
                );
            }
        }
    }

    /// **The default set is EVERY signal but `mcp_tool_calls`**, so a target that names no `include`
    /// also receives the harness's own spans, logs and metrics, and never a tool call's values.
    ///
    /// Named signal by signal rather than by length, because a count passes on a set that holds the
    /// wrong members.
    #[test]
    fn the_default_set_is_every_signal_but_tool_calls() {
        let default = Signal::default_signals();
        for signal in Signal::EVERY {
            assert_eq!(
                default.contains(&signal),
                signal != Signal::McpToolCalls,
                "{} must reach a target that names no include unless it is mcp_tool_calls",
                signal.as_str()
            );
        }
        assert_eq!(
            default.len(),
            Signal::EVERY.len() - 1,
            "the default set names no signal twice"
        );

        // Which half of the collector carries each one. A relayed signal arrives already encoded
        // and never reaches the SDK's log lane.
        for relayed in [Signal::AgentTrace, Signal::AgentLogs, Signal::AgentMetrics] {
            assert!(relayed.is_relayed(), "{} is relayed", relayed.as_str());
        }
        for own in [
            Signal::PolicyDenied,
            Signal::PolicyPermitted,
            Signal::ControlPlane,
            Signal::McpToolCalls,
        ] {
            assert!(!own.is_relayed(), "{} is the box's own", own.as_str());
        }
    }

    /// Every tool-call value is bounded at construction, so one long argument or answer stays one
    /// bounded attribute.
    #[test]
    fn every_tool_call_value_is_bounded_at_construction() {
        let long = "x".repeat(MAXIMUM_ATTRIBUTE_BYTES * 3);
        let value = serde_json::json!({ "field": long });
        let texts = |value: &AnyValue| -> Vec<String> {
            match value {
                AnyValue::String(text) => vec![text.as_str().to_string()],
                AnyValue::Map(map) => map
                    .values()
                    .filter_map(|value| match value {
                        AnyValue::String(text) => Some(text.as_str().to_string()),
                        _ => None,
                    })
                    .collect(),
                other => panic!("an unexpected value: {other:?}"),
            }
        };
        for record in [
            McpToolCall::called(&long, &long, &value),
            McpToolCall::completed(&long, &long, &long, Some(&value)),
        ] {
            for (key, value) in record.attributes() {
                for text in texts(&value) {
                    assert!(
                        text.len() <= MAXIMUM_ATTRIBUTE_BYTES,
                        "{key} is {} bytes",
                        text.len()
                    );
                    assert!(text.ends_with(TRUNCATED), "{key} says it was cut");
                }
            }
        }
    }

    /// The record names the fixed policy identity, never a caller-supplied one.
    #[test]
    fn the_record_names_the_policy_identity() {
        let record = DecisionRecord::deny(
            r#"Box::Action::"net:connect""#,
            "example.com",
            "r2",
            "a forbid matched",
        );
        let attributes = record.attributes();
        assert_eq!(
            text_of(&attributes, "strands.box.policy.principal").as_deref(),
            Some(PRINCIPAL)
        );
        assert_eq!(
            text_of(&attributes, "strands.box.policy.verdict").as_deref(),
            Some("deny")
        );
        assert!(
            attributes
                .iter()
                .any(|(key, _)| *key == "strands.box.policy.reason")
        );
    }

    /// **No attribute value carries a Cedar spelling.** A consumer reads the vocabulary term, so the
    /// engine's qualified form stays inside the engine.
    #[test]
    fn no_value_carries_the_engines_qualified_spelling() {
        for authored in [
            r#"Box::Action::"fs:read""#,
            r#"demo::Action::"echo""#,
            "fs:read",
        ] {
            let attributes = DecisionRecord::permit(authored, "~/ok", "r1").attributes();
            for (key, value) in &attributes {
                let AnyValue::String(text) = value else {
                    continue;
                };
                assert!(
                    !text.as_str().contains("::") && !text.as_str().contains('"'),
                    "{key} carries a Cedar spelling: {text:?}"
                );
            }
        }
        let attributes =
            DecisionRecord::permit(r#"Box::Action::"fs:read""#, "~/ok", "r1").attributes();
        assert_eq!(
            text_of(&attributes, "strands.box.policy.action").as_deref(),
            Some("fs:read")
        );
        assert_eq!(
            text_of(&attributes, "strands.box.policy.principal").as_deref(),
            Some("agent:self")
        );
    }

    /// **The governing rule reaches this product's own names, and the synthetic index is gone.** An
    /// enforcement gate keeps its identity through the same key, because no authored policy
    /// determined it.
    #[test]
    fn the_governing_rule_reaches_the_box_rule_names() {
        let authored = DecisionRecord::permit(r#"Box::Action::"fs:read""#, "~/ok", "policy_2")
            .caused_by(DecisionCause::Permitted)
            .determined_by([
                DeterminingPolicy::new("allow_reads").described(Some("reads are fine")),
                DeterminingPolicy::new("second"),
            ])
            .attributes();
        assert_eq!(text_of(&authored, RULE).as_deref(), Some("allow_reads"));
        assert_eq!(
            text_of(&authored, DESCRIPTION).as_deref(),
            Some("reads are fine")
        );
        assert_eq!(text_of(&authored, CATEGORY).as_deref(), Some("fs"));
        // A per-tool action carries no namespace of its own, so the declaring one is the category.
        let per_tool =
            DecisionRecord::permit(r#"alpha::Action::"read""#, "demo/read", "r1").attributes();
        assert_eq!(
            text_of(&per_tool, "strands.box.policy.action").as_deref(),
            Some("read")
        );
        assert_eq!(text_of(&per_tool, CATEGORY).as_deref(), Some("alpha"));
        let grammar = DecisionRecord::deny(
            r#"Tool::git::Action::"push""#,
            "/usr/bin/git",
            "no_push",
            "forbidden",
        )
        .attributes();
        assert_eq!(
            text_of(&grammar, "strands.box.policy.action").as_deref(),
            Some("push")
        );
        assert_eq!(text_of(&grammar, CATEGORY).as_deref(), Some("Tool::git"));

        // An enforcement gate has no attribution, so the rule it was reached by supplies the name.
        let gate = DecisionRecord::deny(
            r#"Box::Action::"fs:read""#,
            "~/no",
            "enforcement:reach-floor",
            "outside the reachable set",
        )
        .attributes();
        assert_eq!(
            text_of(&gate, RULE).as_deref(),
            Some("enforcement:reach-floor")
        );
        // Entry zero governs, and the rest reach the audit arrays only. `policy` defines the
        // decision's rule as `attribution.first()`, so a reorder here would make this key disagree
        // with the rule the engine says decided.
        assert_eq!(
            list_of(&authored, DETERMINING_IDS),
            vec!["allow_reads".to_string(), "second".to_string()]
        );

        // An unauthored description is absent rather than a repeat of the identifier.
        let bare = DecisionRecord::permit(r#"Box::Action::"fs:read""#, "~/ok", "r1")
            .determined_by([DeterminingPolicy::new("allow_reads")])
            .attributes();
        assert!(
            !bare.iter().any(|(key, _)| *key == DESCRIPTION),
            "an unauthored description is omitted: {bare:?}"
        );
    }

    /// **Only a cause that says an authored policy decided may name one.** The engine reaches
    /// `<default-deny>` on an evaluator fault and **keeps its attribution**, so naming the first
    /// entry would report a policy that did not decide. Reachable from the workload: a rule reading a
    /// context attribute that only some request kinds carry errors per request.
    #[test]
    fn a_fault_names_no_authored_policy_although_it_keeps_attribution() {
        let determining = [DeterminingPolicy::new("allow_reads")
            .described(Some("a policy that did not decide this"))];
        for cause in [
            DecisionCause::InternalFault,
            DecisionCause::PolicyPending,
            DecisionCause::NoMatch,
            DecisionCause::Enforcement,
        ] {
            let attributes = DecisionRecord::deny(
                r#"Box::Action::"fs:read""#,
                "~/no",
                "<default-deny>",
                "the request could not be evaluated",
            )
            .caused_by(cause)
            .determined_by(determining.clone())
            .attributes();
            assert_eq!(
                text_of(&attributes, RULE).as_deref(),
                Some("<default-deny>"),
                "{cause:?} must name the rule reached, not an authored policy"
            );
            assert!(
                !attributes.iter().any(|(found, _)| *found == DESCRIPTION),
                "{cause:?} must not carry {DESCRIPTION}: {attributes:?}"
            );
            // The audit arrays still name every policy the engine returned.
            assert_eq!(
                list_of(&attributes, DETERMINING_IDS),
                vec!["allow_reads".to_string()]
            );
        }
    }

    /// **A tool identifier may not impersonate a box lane.** A server declares its own tool names and
    /// the identifier reaches the action verbatim, so a tool called `fs:read` would otherwise produce
    /// a `file.path` indistinguishable from a real filesystem decision.
    #[test]
    fn a_tool_named_like_a_box_action_states_no_filesystem_subject() {
        for forged in [
            r#"alpha::Action::"fs:read""#,
            r#"alpha::Action::"net:connect""#,
        ] {
            let attributes = DecisionRecord::permit(forged, "alpha/fs:read", "r1").attributes();
            for key in ["file.path", "server.address", "server.port"] {
                assert!(
                    !attributes.iter().any(|(found, _)| *found == key),
                    "{forged} must state no {key}: {attributes:?}"
                );
            }
            assert_eq!(
                text_of(&attributes, CATEGORY).as_deref(),
                Some("alpha"),
                "the declaring namespace names the origin: {forged}"
            );
        }
        // The box's own namespace still states the path.
        let genuine =
            DecisionRecord::permit(r#"Box::Action::"fs:read""#, "~/notes.txt", "r1").attributes();
        assert_eq!(
            text_of(&genuine, "file.path").as_deref(),
            Some("~/notes.txt")
        );
    }

    /// **Each lane states its subject under the standard names.** A destination comes from the
    /// enforcement point that holds it apart; an `fs:*` resource is already the path.
    /// A LITERAL argument is reported whatever its shape, and an expanded one still meets the rule.
    #[test]
    fn a_literal_argument_is_reported_and_an_expanded_one_is_judged() {
        let args = vec![
            "pipefail".to_string(),           // literal: a shell option name
            "allowed.txt".to_string(),        // literal: a bare relative filename
            "]]".to_string(),                 // literal: a closing bracket
            "hunter2-TOP-SECRET".to_string(), // expanded: a value that arrived at runtime
        ];
        let literal = [true, true, true, false];
        let record = DecisionRecord::permit(r#"Box::Action::"shell:exec""#, "setopt", "r1")
            .about(Subject::process("setopt", &args, &literal, "/workspace"))
            .attributes();
        let rendered = format!("{record:?}");
        for reported in ["pipefail", "allowed.txt", "]]"] {
            assert!(
                rendered.contains(reported),
                "a literal word is reported: {reported} missing from {rendered}"
            );
        }
        assert!(
            !rendered.contains("hunter2-TOP-SECRET"),
            "an expanded word is still judged: {rendered}"
        );
        assert!(rendered.contains(REDACTED), "{rendered}");
    }

    /// A caller that supplies no mask redacts rather than leaks.
    #[test]
    fn an_absent_mask_entry_is_treated_as_expanded() {
        let args = vec!["hunter2-TOP-SECRET".to_string()];
        for mask in [&[][..], &[false][..]] {
            let record = DecisionRecord::permit(r#"Box::Action::"shell:exec""#, "echo", "r1")
                .about(Subject::process("echo", &args, mask, "/workspace"))
                .attributes();
            let rendered = format!("{record:?}");
            assert!(
                !rendered.contains("hunter2-TOP-SECRET"),
                "mask {mask:?} must not leak: {rendered}"
            );
        }
    }

    /// An EXPANDED argument reaches the record only when it is a plain flag.
    ///
    /// A record excludes `process.command_line` because an argument routinely carries a
    /// secret. This is what keeps that exclusion true while still naming what a command touched.
    #[test]
    fn an_expanded_argument_is_reported_only_when_it_is_a_plain_flag() {
        for kept in ["-l", "-L", "--color", "--no-pager", "--log-level"] {
            assert_eq!(reportable(kept), kept, "a plain flag is reported");
        }
        // Both sides of the name bound, derived from the constant: a hand-counted literal pins one
        // side only, and an off-by-one comparison then keeps the suite green.
        let at_bound = format!("--{}", "a".repeat(MAXIMUM_FLAG_NAME_CHARS));
        let past_bound = format!("--{}", "a".repeat(MAXIMUM_FLAG_NAME_CHARS + 1));
        assert_eq!(
            reportable(&at_bound),
            at_bound,
            "a name at the bound is kept"
        );
        assert_eq!(
            reportable(&past_bound),
            REDACTED,
            "a name past the bound carries a value the record must not hold"
        );
        for redacted in [
            "hunter2-TOP-SECRET",
            "eyJhbGciOiJIUzI1NiJ9.payload.signature",
            "postgres://user:password@host/db",
            "https://example.com/?token=abc",
            "relative/path/without/a/dot",
            "-",
            "--",
            "-=x",
            // A value rides on a short option, so one `-` takes exactly one letter. `-la` is a real
            // flag and is redacted with these: an EXPANDED `-la` and `-lhunter2` are one shape.
            "-la",
            "-lhunter2",
            "-deadbeef1234abcd",
            // A name opens with a letter, so a digit and a `-` cannot open one.
            "-1abc",
            "-0000-0000-0000",
            "--1password",
            // **A path shape no longer reports an expanded value.** `/workspace` and a 40-character
            // key opening with `/` are one shape, so no syntactic rule separates them. The same
            // command's own `fs:*` decision already records the path it reached.
            "/etc/hosts",
            "~/notes.txt",
            "./local",
            "../up",
            "~",
            ".",
            "..",
            // A long-option name is bounded and lowercase, or a credential rides as `--<secret>`.
            "--wJalrXUtnFEMIAK7MDENGAbPxRfiCYEXAMPLEKE1",
            "--deadbeef1234abcd",
        ] {
            assert_eq!(
                reportable(redacted),
                REDACTED,
                "{redacted} carries a value the record must not hold"
            );
        }
        // A flag that carries its own value keeps the name and always loses the value, because the
        // value is where a secret rides and a path is no longer an exemption.
        assert_eq!(reportable("--password=hunter2"), "--password=<redacted>");
        assert_eq!(reportable("--token=abc123"), "--token=<redacted>");
        assert_eq!(reportable("--output=/tmp/out.txt"), "--output=<redacted>");
        assert_eq!(reportable("--config=~/.config/app"), "--config=<redacted>");
        // The name is bounded on this route too, or `--<secret>=x` reports the secret as a name.
        assert_eq!(
            reportable("--wJalrXUtnFEMIAK7MDENGAbPxRfiCYEXAMPLEKE1=x"),
            REDACTED
        );
    }

    /// No prefix carries an expanded secret into the record.
    #[test]
    fn a_prefix_cannot_carry_an_expanded_secret_into_the_record() {
        // Identical 40-character keys over the AWS secret access key alphabet.
        let bare = "wJalrXUtnFEMIAK7MDENGAbPxRfiCYEXAMPLEKE1";
        for spelling in [
            bare.to_string(),
            format!("/{bare}"),
            format!("--{bare}"),
            format!("--{bare}=x"),
            format!("./{bare}"),
            format!("~/{bare}"),
        ] {
            let args = vec![spelling.clone()];
            let record = DecisionRecord::permit(r#"Box::Action::"shell:exec""#, "echo", "r1")
                .about(Subject::process("echo", &args, &[false], "/workspace"))
                .attributes();
            let rendered = format!("{record:?}");
            assert!(
                !rendered.contains(bare),
                "{spelling} carried the secret into the record: {rendered}"
            );
        }
    }

    /// The whole point, end to end: a read secret passed as an argument never reaches the record.
    #[test]
    fn a_secret_passed_as_an_argument_never_reaches_the_record() {
        let args = vec!["hunter2-TOP-SECRET".to_string()];
        let record = DecisionRecord::permit(r#"Box::Action::"shell:exec""#, "echo", "r1")
            .about(Subject::process("echo", &args, &[], "/workspace"))
            .attributes();
        let rendered = format!("{record:?}");
        assert!(
            !rendered.contains("hunter2-TOP-SECRET"),
            "the record holds the value: {rendered}"
        );
        assert!(
            rendered.contains(REDACTED),
            "the argument is named: {rendered}"
        );
    }

    #[test]
    fn a_command_line_states_its_program_its_arguments_and_its_directory() {
        // `-l` is expanded and is a plain flag; the path is LITERAL, because an expanded path is
        // redacted now. This test pins the order and the program's place, not the redaction rule.
        let args = vec!["-l".to_string(), "/workspace".to_string()];
        let record = DecisionRecord::permit(r#"Box::Action::"shell:exec""#, "ls", "r1")
            .about(Subject::process("ls", &args, &[false, true], "/workspace"))
            .attributes();
        assert_eq!(text_of(&record, "process.command").as_deref(), Some("ls"));
        assert_eq!(
            text_of(&record, "process.working_directory").as_deref(),
            Some("/workspace")
        );
        // The program comes first, because the convention names the whole vector.
        let reported = format!(
            "{:?}",
            record
                .iter()
                .find(|(key, _)| *key == "process.command_args")
                .map(|(_, value)| value)
                .expect("the argument vector")
        );
        let mut at = 0;
        for expected in ["\"ls\"", "\"-l\"", "\"/workspace\""] {
            let found = reported[at..]
                .find(expected)
                .unwrap_or_else(|| panic!("{expected} in order: {reported}"));
            at += found + expected.len();
        }
        assert_eq!(reported.matches("String(").count(), 3, "{reported}");
        // The resource still names the program alone, so nothing that reads it has to change.
        assert_eq!(
            text_of(&record, "strands.box.policy.resource").as_deref(),
            Some("ls")
        );
    }

    /// A very long command line stays one bounded record.
    #[test]
    fn a_reported_command_line_is_bounded_in_both_directions() {
        let args: Vec<String> = (0..MAXIMUM_COMMAND_ARGS * 2)
            .map(|index| index.to_string())
            .collect();
        let long = "x".repeat(MAXIMUM_ATTRIBUTE_BYTES * 2);
        let record = DecisionRecord::permit(r#"Box::Action::"shell:exec""#, "ls", "r1")
            .about(Subject::process(&long, &args, &[], &long))
            .attributes();
        let reported = format!(
            "{:?}",
            record
                .iter()
                .find(|(key, _)| *key == "process.command_args")
                .map(|(_, value)| value)
                .expect("the argument vector")
        );
        // The program, the capped arguments, and one entry saying what was left out.
        assert_eq!(
            reported.matches("String(").count(),
            MAXIMUM_COMMAND_ARGS + 2,
            "{reported}"
        );
        assert!(
            reported.contains(&format!("{MAXIMUM_COMMAND_ARGS} more")),
            "{reported}"
        );
        for key in ["process.command", "process.working_directory"] {
            let value = text_of(&record, key).expect(key);
            assert!(
                value.len() <= MAXIMUM_ATTRIBUTE_BYTES,
                "{key} is bounded: {}",
                value.len()
            );
            assert!(value.ends_with(TRUNCATED), "{key} says it was cut: {value}");
        }
    }

    #[test]
    fn each_lane_states_its_subject_under_the_standard_names() {
        let file =
            DecisionRecord::permit(r#"Box::Action::"fs:read""#, "~/notes.txt", "r1").attributes();
        assert_eq!(
            text_of(&file, "file.path").as_deref(),
            Some("~/notes.txt"),
            "an fs resource is the path"
        );

        let connect = DecisionRecord::permit(r#"Box::Action::"net:connect""#, "ignored", "r1")
            .about(Subject::destination("example.com", 443))
            .attributes();
        assert_eq!(
            text_of(&connect, "server.address").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            connect
                .iter()
                .find(|(key, _)| *key == "server.port")
                .map(|(_, value)| format!("{value:?}")),
            Some("Int(443)".to_string())
        );
        assert!(
            !connect.iter().any(|(key, _)| *key == "http.request.method"),
            "a connection has no method: {connect:?}"
        );

        let request = DecisionRecord::permit(r#"Box::Action::"http:request""#, "ignored", "r1")
            .about(Subject::http("example.com", 443, "GET"))
            .attributes();
        assert_eq!(
            text_of(&request, "http.request.method").as_deref(),
            Some("GET")
        );
        // A stated subject wins, so no lane falls back to the resource when one is supplied.
        assert!(
            !request.iter().any(|(key, _)| *key == "file.path"),
            "{request:?}"
        );
    }

    /// **Attribution is one array attribute, so a consumer reads a list rather than parsing a
    /// string.** An authored `@id` may hold any character a separator could claim.
    #[test]
    fn the_determining_policies_reach_one_array() {
        let record = DecisionRecord::deny(
            r#"demo::Action::"add""#,
            "demo/add",
            "policy0",
            "a forbid rule matched",
        )
        .caused_by(DecisionCause::Forbidden)
        .determined_by([
            DeterminingPolicy::new("refusal"),
            DeterminingPolicy::new("policy1"),
        ]);
        let attributes = record.attributes();

        assert_eq!(
            text_of(&attributes, "strands.box.policy.cause").as_deref(),
            Some("forbidden")
        );
        assert_eq!(
            list_of(&attributes, DETERMINING_IDS),
            vec!["refusal".to_string(), "policy1".to_string()]
        );
    }

    /// A record that names no policy carries no list, so an absent authority is not reported as an
    /// empty one. **The cause is not optional**, so it is present even here: a permit built with no
    /// `caused_by` reads `permitted`.
    #[test]
    fn a_record_naming_no_policy_carries_no_attribution() {
        let attributes =
            DecisionRecord::permit(r#"Box::Action::"fs:read""#, "~/ok", "r1").attributes();
        assert!(
            !attributes
                .iter()
                .any(|(named, _)| *named == DETERMINING_IDS),
            "{DETERMINING_IDS} must be absent: {attributes:?}"
        );
        assert_eq!(
            text_of(&attributes, "strands.box.policy.cause").as_deref(),
            Some("permitted"),
            "the cause is mandatory, so a permit defaults to permitted: {attributes:?}"
        );
    }

    /// **A deny built with no `caused_by` defaults to `forbidden`**, so the pair is never unset.
    #[test]
    fn a_default_cause_follows_the_verdict() {
        let denial =
            DecisionRecord::deny(r#"Box::Action::"fs:read""#, "~/no", "r1", "refused").attributes();
        assert_eq!(
            text_of(&denial, "strands.box.policy.cause").as_deref(),
            Some("forbidden")
        );
    }

    /// **A cause that cannot reach the verdict is refused at construction**, so no target receives a
    /// record whose verdict and cause disagree. `Permitted` is the one cause a deny cannot hold.
    #[test]
    #[should_panic(expected = "cause permitted cannot reach verdict deny")]
    fn a_cause_that_contradicts_its_verdict_is_refused() {
        let _ = DecisionRecord::deny(r#"Box::Action::"fs:read""#, "~/no", "r1", "refused")
            .caused_by(DecisionCause::Permitted);
    }

    /// **Every cause a permit may hold is accepted, and every cause a deny may hold is accepted.**
    /// `Enforcement` is the one cause both verdicts share, because a deny-only floor permits by
    /// staying silent and denies by firing.
    #[test]
    fn each_verdict_admits_the_causes_it_can_reach() {
        for cause in [DecisionCause::Permitted, DecisionCause::Enforcement] {
            assert!(cause.admits_permit(), "{} permits", cause.as_str());
        }
        for cause in [
            DecisionCause::Forbidden,
            DecisionCause::NoMatch,
            DecisionCause::PolicyPending,
            DecisionCause::InternalFault,
            DecisionCause::Enforcement,
        ] {
            assert!(cause.admits_deny(), "{} denies", cause.as_str());
        }
        assert!(
            !DecisionCause::Permitted.admits_deny(),
            "a deny is never caused by a permit"
        );
        assert!(
            !DecisionCause::NoMatch.admits_permit(),
            "an absent permit never reaches a permit"
        );
    }

    /// **Every attribution value is bounded at construction, on the same terms as a control
    /// attribute.** An authored `@id` is the operator's own text, of a length the box does not
    /// choose.
    #[test]
    fn every_attribution_value_is_bounded_at_construction() {
        let long = "A".repeat(512 * 1024);
        let record = DecisionRecord::permit(r#"Box::Action::"fs:read""#, "~/ok", "r1")
            .caused_by(DecisionCause::Permitted)
            .determined_by([DeterminingPolicy::new(&long).described(Some(&long))]);
        let attributes = record.attributes();
        for key in [DETERMINING_IDS] {
            for value in list_of(&attributes, key) {
                assert!(
                    value.len() <= MAXIMUM_ATTRIBUTE_BYTES,
                    "{key} carries {} bytes, over the bound",
                    value.len()
                );
                assert!(value.ends_with(TRUNCATED), "a cut value says so: {key}");
            }
        }
        // The standard rule names carry the same operator-authored text, so each is bounded too.
        for key in [RULE, DESCRIPTION] {
            let value = text_of(&attributes, key).unwrap_or_else(|| panic!("{key} is absent"));
            assert!(
                value.len() <= MAXIMUM_ATTRIBUTE_BYTES,
                "{key} carries {} bytes, over the bound",
                value.len()
            );
            assert!(value.ends_with(TRUNCATED), "a cut value says so: {key}");
        }
    }

    /// Every cause spelling is its own, so two classes never read as one.
    #[test]
    fn no_two_causes_share_a_spelling() {
        let every = [
            DecisionCause::Permitted,
            DecisionCause::Forbidden,
            DecisionCause::NoMatch,
            DecisionCause::PolicyPending,
            DecisionCause::InternalFault,
            DecisionCause::Enforcement,
        ];
        for (index, one) in every.iter().enumerate() {
            for other in &every[index + 1..] {
                assert_ne!(one.as_str(), other.as_str());
            }
        }
    }

    fn text_of(attributes: &[(&'static str, AnyValue)], key: &str) -> Option<String> {
        attributes.iter().find_map(|(named, value)| match value {
            AnyValue::String(text) if *named == key => Some(text.as_ref().to_string()),
            _ => None,
        })
    }

    fn list_of(attributes: &[(&'static str, AnyValue)], key: &str) -> Vec<String> {
        attributes
            .iter()
            .find_map(|(named, value)| match value {
                AnyValue::ListAny(values) if *named == key => Some(values),
                _ => None,
            })
            .map(|values| {
                values
                    .iter()
                    .map(|value| match value {
                        AnyValue::String(text) => text.as_ref().to_string(),
                        other => panic!("an attribution list holds text: {other:?}"),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}
