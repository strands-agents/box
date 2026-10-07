//! Load/compose-time error taxonomy.

/// A fallible policy-operation fault outside the hot decision path.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// A local policy source failed to parse as valid Cedar.
    #[error("failed to parse policy source: {0}")]
    Parse(String),

    /// Strict schema validation reported an undeclared or mistyped attribute.
    #[error("policy fails schema validation: {0}")]
    Schema(String),

    /// Strict schema validation reported an unknown action — e.g. a typo like
    /// `Box::Action::"fs:raed"`. Failing loud at load forecloses the silent
    /// no-match class a typo would otherwise reach.
    #[error("policy references unknown action: {0}")]
    UnknownAction(String),

    /// A path or program literal that no reported spelling can match, so the rule is inert.
    #[error("policy compares an inert literal: {0}")]
    Spelling(String),

    /// Two rules carry one non-blank `@id`.
    #[error("policy gives one @id to more than one rule: {0}")]
    SharedRuleId(String),

    /// A rule's scope is only the reserved `fs:other`, which no operation raises.
    #[error("policy names only a reserved action: {0}")]
    ReservedAction(String),

    /// A permit's temporal clause sits beside an unconditioned permit for the same principal and action.
    #[error("policy writes a cap as a permit: {0}")]
    InertTemporalPermit(String),

    /// Reserved for API compatibility.
    #[error("policy uses an unsupported clause: {0}")]
    UnsupportedClause(String),

    /// The durable engine could not open or recover its store, install sources,
    /// or submit an event.
    #[error("policy history failure: {0}")]
    Evaluation(String),
}

/// One policy that remained unresolved after MCP discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDiagnostic {
    /// Zero-based position in the macro-expanded authored bundle.
    pub policy_ordinal: usize,
    /// The strict validator diagnostic.
    pub reason: String,
}

impl std::fmt::Display for PolicyDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "policy {}: {}",
            self.policy_ordinal.saturating_add(1),
            self.reason
        )
    }
}

/// A runtime policy-staging operation failed.
#[derive(Debug, thiserror::Error)]
pub enum PolicyStagingError {
    /// Policy parsing or validation failed before staging could continue.
    #[error(transparent)]
    Policy(#[from] PolicyError),

    /// The durable authority could not recover or commit.
    #[error("policy staging history failure: {0}")]
    Durable(String),

    /// MCP discovery ended before every policy became valid.
    #[error(
        "MCP discovery ended with unresolved policies{diagnostics}",
        diagnostics = policy_diagnostic_suffix(.0)
    )]
    UnresolvedPolicies(Vec<PolicyDiagnostic>),
}

fn policy_diagnostic_suffix(diagnostics: &[PolicyDiagnostic]) -> String {
    diagnostics
        .iter()
        .map(|diagnostic| format!("; {diagnostic}"))
        .collect()
}
