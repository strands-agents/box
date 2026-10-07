//! The request-leg evaluate → apply → forward decision.

use crate::boundary::{InterceptedRequest, Mutation, Verdict};
use crate::capability::{CapabilityContext, CapabilitySet};

/// The result of evaluating + applying the request leg: either forward the (mutated) request, or
/// block with the deny reason.
pub(super) enum RequestDecision {
    /// Forward the request; its headers/target have had the allowed mutations applied.
    Forward,
    /// Block the request with this reason.
    Block(crate::boundary::DenyReason),
}

/// Evaluate `req` against `controls`, applying any allowed mutations to it in place, and return the
/// forward/block decision.
pub(super) fn evaluate_and_apply(
    controls: &CapabilitySet,
    req: &mut InterceptedRequest,
    cx: &CapabilityContext,
) -> RequestDecision {
    // The Request scope runs HTTP guards and credential controls deny-overrides;
    // the Connection gate (DNS/IP) already authorized the connection on the pinned IPs at the
    // Connection phase and is not re-run here. The adapter has already AND-ed the Connection
    // verdict (a Deny there blocked before this leg), so a Request-scope Allow here is the final
    // Allow for a TLS-terminated route.
    match controls.evaluate_request(req, cx) {
        Verdict::Allow { mutations } => {
            apply_all(mutations, req);
            RequestDecision::Forward
        }
        Verdict::Deny { reason } => RequestDecision::Block(reason),
    }
}

/// Apply every mutation to the request's headers and target, in order (the interceptor's job).
/// Consumes the owned `Vec` and **moves** each mutation's value in, with no copy of the secret on
/// the credential path. Within one allow the strip-then-set idiom of the credential swap applies
/// cleanly in order.
fn apply_all(mutations: Vec<Mutation>, req: &mut InterceptedRequest) {
    for m in mutations {
        m.into_apply(&mut req.headers, &mut req.target);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::{HeaderMap, Target};
    use crate::capability::{CapabilityOutcome, CapabilitySet, EgressCapability};
    use credentials::DestinationPattern;

    use crate::audit::RequestId;

    /// A credential-like mutator: abstains-with-mutations (the swap), never authorizes.
    struct SwapControl;
    impl EgressCapability for SwapControl {
        fn pattern(&self) -> &DestinationPattern {
            // A leaked 'static pattern for the test.
            static PAT: std::sync::OnceLock<DestinationPattern> = std::sync::OnceLock::new();
            PAT.get_or_init(|| DestinationPattern::parse("*.example.com").unwrap())
        }
        fn on_request(
            &self,
            _req: &mut InterceptedRequest,
            _cx: &CapabilityContext,
        ) -> CapabilityOutcome {
            CapabilityOutcome::applied(vec![
                Mutation::StripHeader {
                    name: "Authorization".to_string(),
                },
                Mutation::SetHeader {
                    name: "Authorization".to_string(),
                    value: zeroize::Zeroizing::new("Bearer real".to_string()),
                },
            ])
        }
    }

    fn http_req() -> InterceptedRequest {
        let mut target = Target::new("api.example.com", 443);
        target.path = "/v1/x".to_string();
        let mut headers = HeaderMap::new();
        headers.append("Authorization", "Bearer phantom");
        InterceptedRequest {
            target,
            method: Some("GET".to_string()),
            headers,
            body: Default::default(),
            advisory_note: None,
        }
    }

    #[test]
    fn allow_applies_mutations_then_forwards() {
        let set = CapabilitySet::from_parts(vec![Box::new(SwapControl)]);
        let cx =
            CapabilityContext::new(RequestId::new("t"), 0, Target::new("api.example.com", 443));
        let mut req = http_req();
        let decision = evaluate_and_apply(&set, &mut req, &cx);
        assert!(matches!(decision, RequestDecision::Forward));
        // The phantom was stripped and the real secret attached (interceptor applied the mutations).
        assert_eq!(req.headers.get("authorization"), Some("Bearer real"));
    }

    #[test]
    fn integrity_deny_blocks() {
        // A credential integrity failure (phantom mismatch) on the L7 leg → the request blocks. This is
        // the only kind of deny a mutator can emit; it never authorizes.
        struct DenyControl;
        impl EgressCapability for DenyControl {
            fn pattern(&self) -> &DestinationPattern {
                static PAT: std::sync::OnceLock<DestinationPattern> = std::sync::OnceLock::new();
                PAT.get_or_init(|| DestinationPattern::parse("*.example.com").unwrap())
            }
            fn on_request(
                &self,
                _req: &mut InterceptedRequest,
                _cx: &CapabilityContext,
            ) -> CapabilityOutcome {
                CapabilityOutcome::unavailable("phantom mismatch")
            }
        }
        let set = CapabilitySet::from_parts(vec![Box::new(DenyControl)]);
        let cx =
            CapabilityContext::new(RequestId::new("t"), 0, Target::new("api.example.com", 443));
        let mut req = http_req();
        assert!(matches!(
            evaluate_and_apply(&set, &mut req, &cx),
            RequestDecision::Block(_)
        ));
    }
}
