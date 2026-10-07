//! The [`EgressCapability`] trait, the [`CapabilityContext`] it evaluates against, and the
//! per-capability [`CapabilityOutcome`].

use credentials::DestinationPattern;

use crate::audit::RequestId;

use crate::boundary::Target;
use crate::boundary::{InterceptedRequest, InterceptedResponse, Mutation};

/// What one capability produced for a request or response leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityOutcome {
    /// The edits to apply. Empty when this capability does not apply to the exchange — not applying
    /// and applying nothing are the same thing, so there is no separate "abstain".
    Applied(Vec<Mutation>),
    /// This capability cannot perform its edit safely, so nothing may egress.
    Unavailable(CapabilityFault),
}

impl CapabilityOutcome {
    /// No edits, because this capability does not apply to the exchange.
    pub(crate) fn none() -> Self {
        CapabilityOutcome::Applied(Vec::new())
    }

    /// The edits this capability wants applied.
    pub(crate) fn applied(mutations: Vec<Mutation>) -> Self {
        CapabilityOutcome::Applied(mutations)
    }

    /// This capability cannot complete its edit; nothing egresses.
    pub(crate) fn unavailable(message: impl Into<String>) -> Self {
        CapabilityOutcome::Unavailable(CapabilityFault {
            message: message.into(),
        })
    }

    /// Whether this outcome stops the exchange.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_unavailable(&self) -> bool {
        matches!(self, CapabilityOutcome::Unavailable(_))
    }

    /// The edits this outcome carries; empty when it is unavailable.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn edits(&self) -> &[Mutation] {
        match self {
            CapabilityOutcome::Applied(edits) => edits,
            CapabilityOutcome::Unavailable(_) => &[],
        }
    }
}

/// Why a capability could not perform its edit — a non-secret, operator-facing message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityFault {
    message: String,
}

impl CapabilityFault {
    /// The non-secret reason this capability was unavailable.
    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for CapabilityFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// The shared, read-only context a capability evaluates against.
#[derive(Debug, Clone)]
pub struct CapabilityContext {
    /// The correlation id for this request, tying a capability's audit to the matching
    /// `EgressDecision` and `CredentialAcquire`.
    pub correlation: RequestId,
    /// The current wall-clock time as Unix seconds — a clock seam so tests are deterministic.
    pub now_unix_secs: u64,
    /// The request [`Target`] this exchange is bound to. Carried on the context so the **response**
    /// leg (which has no target of its own) can resolve the same vault binding the request leg used —
    /// needed by credential leak-back scrubbing.
    pub target: Target,
}

impl CapabilityContext {
    /// Build a context from a correlation id, a signing/eval time, and the request target.
    pub fn new(correlation: RequestId, now_unix_secs: u64, target: Target) -> Self {
        Self {
            correlation,
            now_unix_secs,
            target,
        }
    }
}

/// One edit-producing capability on the L7 request and response legs — in v1, credential injection.
pub(crate) trait EgressCapability: Send + Sync {
    /// The destination pattern selecting which requests this instance governs — a
    /// `credentials::DestinationPattern`, so the proxy and the vault use the **same** matcher.
    fn pattern(&self) -> &DestinationPattern;

    /// Evaluate the request leg. Takes `&mut InterceptedRequest` for symmetry with the response leg
    /// and to allow reading (not applying) — the *interceptor* applies the returned mutations, never
    /// the capability.
    fn on_request(&self, req: &mut InterceptedRequest, cx: &CapabilityContext)
    -> CapabilityOutcome;

    /// Evaluate the response leg. Defaults to no edits so a request-only capability needs no impl.
    fn on_response(
        &self,
        _res: &mut InterceptedResponse,
        _cx: &CapabilityContext,
    ) -> CapabilityOutcome {
        CapabilityOutcome::none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::Mutation;

    #[test]
    fn outcome_constructors_carry_edits_or_a_fault() {
        // Not applying and applying nothing are the same thing.
        assert_eq!(
            CapabilityOutcome::none(),
            CapabilityOutcome::Applied(vec![])
        );

        // Edits ride the outcome; nothing here authorizes, because there is no variant that could.
        let strip = Mutation::StripHeader {
            name: "authorization".to_string(),
        };
        let applied = CapabilityOutcome::applied(vec![strip]);
        assert!(!applied.is_unavailable());
        match applied {
            CapabilityOutcome::Applied(edits) => assert_eq!(edits.len(), 1),
            other => panic!("expected edits, got {other:?}"),
        }

        // A fault stops the exchange and carries a non-secret reason.
        let fault = CapabilityOutcome::unavailable("phantom mismatch");
        assert!(fault.is_unavailable());
        match fault {
            CapabilityOutcome::Unavailable(fault) => {
                assert_eq!(fault.message(), "phantom mismatch")
            }
            other => panic!("expected a fault, got {other:?}"),
        }
    }

    #[test]
    fn context_carries_correlation_and_clock() {
        let cx = CapabilityContext::new(
            RequestId::new("t"),
            1_440_938_160,
            Target::new("api.example.com", 443),
        );
        assert_eq!(cx.correlation.as_str(), "t");
        assert_eq!(cx.now_unix_secs, 1_440_938_160);
        assert_eq!(cx.target.host, "api.example.com");
    }
}
