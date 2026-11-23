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
    /// An explicit permit matched with no overriding forbid, or, in log-only mode, a policy
    /// denial that the engine did not enforce.
    Allow {
        /// Determining policy id.
        rule: RuleId,
        /// All determining policies from the authorization response.
        attribution: Vec<PolicyAttribution>,
        /// What the request named, as the decision log spells it.
        resource: String,
        /// The policy's denial that log-only mode let through, or `None` for a real permit.
        would_deny: Option<DenyReason>,
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
            Self::Allow {
                rule,
                resource,
                would_deny,
                ..
            } => {
                let mut allow = formatter.debug_struct("Allow");
                allow.field("rule", rule).field("resource", resource);
                if let Some(reason) = would_deny {
                    allow.field("would_deny", reason);
                }
                allow.finish()
            }
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

    /// Whether this verdict lets the request go ahead, including a log-only denial.
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// The policy's denial that log-only mode let through, or `None` when the verdict was applied.
    pub fn would_deny(&self) -> Option<&DenyReason> {
        match self {
            Self::Allow { would_deny, .. } => would_deny.as_ref(),
            Self::Deny { .. } => None,
        }
    }

    /// In log-only mode, a `forbid` or no-`permit` denial of a `recorded` request as `Allow` with
    /// `would_deny`; every other verdict unchanged.
    #[must_use]
    pub(crate) fn unenforced_when(self, log_only: bool, recorded: bool) -> Self {
        match self {
            Self::Deny {
                reason: reason @ (DenyReason::Forbidden | DenyReason::NoMatch),
                rule,
                attribution,
                resource,
            } if log_only && recorded => Self::Allow {
                rule,
                attribution,
                resource,
                would_deny: Some(reason),
            },
            other => other,
        }
    }

    /// The same verdict, naming `resource`.
    #[must_use]
    pub fn naming(self, resource: String) -> Self {
        match self {
            Self::Allow {
                rule,
                attribution,
                would_deny,
                ..
            } => Self::Allow {
                rule,
                attribution,
                resource,
                would_deny,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn forbidden() -> Decision {
        Decision::Deny {
            reason: DenyReason::Forbidden,
            rule: RuleId::default_deny(),
            attribution: Vec::new(),
            resource: String::new(),
        }
    }

    /// Only a recorded `forbid` or missing `permit` is let through, and only in log-only mode.
    #[test]
    fn only_a_recorded_policy_denial_is_let_through_and_only_in_log_only_mode() {
        for (denial, reason) in [
            (forbidden(), DenyReason::Forbidden),
            (Decision::no_match(), DenyReason::NoMatch),
        ] {
            assert_eq!(
                denial.clone().unenforced_when(true, true).would_deny(),
                Some(&reason)
            );
            assert_eq!(
                denial.clone().unenforced_when(false, true),
                denial,
                "enforce mode changes nothing"
            );
            assert_eq!(
                denial.clone().unenforced_when(true, false),
                denial,
                "a denial with no request id still denies"
            );
        }
        for held in [Decision::policy_pending(), Decision::internal_fault()] {
            assert_eq!(
                held.clone().unenforced_when(true, true),
                held,
                "a pending policy or a fault still denies"
            );
        }
    }
}
