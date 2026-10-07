//! Fail-closed policy verdicts.

mod message;

/// Policy identifier that determined a [`Decision`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleId(String);

impl RuleId {
    /// Synthetic identifier used when no policy determined the verdict.
    pub const DEFAULT_DENY: &'static str = "<default-deny>";
    /// Synthetic identifier used while the complete policy bundle is pending.
    pub const POLICY_PENDING: &'static str = "<policy-pending>";

    /// A determining rule as the engine names it.
    pub(crate) fn from_engine(value: String) -> Self {
        Self(value)
    }

    pub(crate) fn default_deny() -> Self {
        Self(Self::DEFAULT_DENY.to_string())
    }

    pub(crate) fn policy_pending() -> Self {
        Self(Self::POLICY_PENDING.to_string())
    }

    /// Return the policy identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for RuleId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Why a request was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// An explicit `forbid` matched.
    Forbidden,
    /// No `permit` matched.
    NoMatch,
    /// The complete authored policy bundle is not installed.
    PolicyPending,
    /// Request construction or policy evaluation failed.
    InternalFault,
}

/// Authorization verdict for one request.
#[derive(Clone, PartialEq, Eq)]
pub enum Decision {
    /// An explicit permit matched with no overriding forbid.
    Allow {
        /// Determining policy id.
        rule: RuleId,
        /// All determining policies from the authorization response.
        attribution: Vec<PolicyAttribution>,
        /// What the request named, as the decision log spells it.
        resource: String,
    },
    /// The request did not receive a clean allow.
    Deny {
        /// Denial class.
        reason: DenyReason,
        /// Determining policy id or the default-deny sentinel.
        rule: RuleId,
        /// All determining policies from the authorization response.
        attribution: Vec<PolicyAttribution>,
        /// What the request named, as the decision log spells it.
        resource: String,
    },
}

/// Owned identity and authored annotations for one determining policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyAttribution {
    /// Opaque durable policy token.
    pub token: String,
    /// Synthetic policy identifier.
    pub rule: RuleId,
    /// Authored `@id`, including an empty value when present.
    pub annotation_id: Option<String>,
    /// Authored `@description`, including an empty value when present.
    pub description: Option<String>,
}

impl std::fmt::Debug for Decision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow { rule, resource, .. } => formatter
                .debug_struct("Allow")
                .field("rule", rule)
                .field("resource", resource)
                .finish(),
            Self::Deny {
                reason,
                rule,
                resource,
                ..
            } => formatter
                .debug_struct("Deny")
                .field("reason", reason)
                .field("rule", rule)
                .field("resource", resource)
                .finish(),
        }
    }
}

impl Decision {
    /// All determining policies from the authorization response.
    pub fn attribution(&self) -> &[PolicyAttribution] {
        match self {
            Self::Allow { attribution, .. } | Self::Deny { attribution, .. } => attribution,
        }
    }

    /// What the request named, as the decision log spells it.
    pub fn resource(&self) -> &str {
        match self {
            Self::Allow { resource, .. } | Self::Deny { resource, .. } => resource,
        }
    }

    /// Whether this verdict explicitly permits the request.
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// The same verdict, naming `resource`.
    #[must_use]
    pub fn naming(self, resource: String) -> Self {
        match self {
            Self::Allow {
                rule, attribution, ..
            } => Self::Allow {
                rule,
                attribution,
                resource,
            },
            Self::Deny {
                reason,
                rule,
                attribution,
                ..
            } => Self::Deny {
                reason,
                rule,
                attribution,
                resource,
            },
        }
    }

    pub(crate) fn no_match() -> Self {
        Self::Deny {
            reason: DenyReason::NoMatch,
            rule: RuleId::default_deny(),
            attribution: Vec::new(),
            resource: String::new(),
        }
    }

    pub(crate) fn internal_fault() -> Self {
        Self::Deny {
            reason: DenyReason::InternalFault,
            rule: RuleId::default_deny(),
            attribution: Vec::new(),
            resource: String::new(),
        }
    }

    pub(crate) fn policy_pending() -> Self {
        Self::Deny {
            reason: DenyReason::PolicyPending,
            rule: RuleId::policy_pending(),
            attribution: Vec::new(),
            resource: String::new(),
        }
    }
}
