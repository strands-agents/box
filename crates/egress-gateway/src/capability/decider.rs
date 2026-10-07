//! The capability fold — reduces every capability's outcome to a [`Verdict`], plus mutation-collision
//! detection.

use std::collections::HashMap;

use crate::boundary::{DenyReason, Mutation, MutationTarget, Verdict};
use crate::capability::traits::CapabilityOutcome;

/// Fold every capability's outcome into a [`Verdict`].
pub(super) fn decide_request(outcomes: impl IntoIterator<Item = CapabilityOutcome>) -> Verdict {
    let mut mutations: Vec<Mutation> = Vec::new();
    let mut first_fault: Option<String> = None;

    for outcome in outcomes {
        match outcome {
            CapabilityOutcome::Applied(edits) => mutations.extend(edits),
            CapabilityOutcome::Unavailable(fault) => {
                if first_fault.is_none() {
                    first_fault = Some(fault.message().to_string());
                }
            }
        }
    }

    match first_fault {
        // A mechanism failure, not a policy verdict: the boundary could not perform the edit, so
        // nothing egresses. `DenyReason::Credential` carries it because credential injection is the
        // only capability that can be unavailable.
        Some(message) => Verdict::Deny {
            reason: DenyReason::Credential(message),
        },
        None => finish_allow(mutations),
    }
}

/// Turn the accumulated mutations into a [`Verdict::Allow`], failing closed on a cross-capability
/// mutation collision.
fn finish_allow(mutations: Vec<Mutation>) -> Verdict {
    if let Some(target) = first_collision(&mutations) {
        return Verdict::Deny {
            reason: DenyReason::MutationCollision(format!(
                "conflicting mutations to the same target ({target:?}) — a config collision"
            )),
        };
    }
    Verdict::Allow { mutations }
}

/// The first target key edited by more than one mutation, if any.
fn first_collision(mutations: &[Mutation]) -> Option<MutationTarget> {
    let mut set_like: HashMap<MutationTarget, usize> = HashMap::new();
    for m in mutations {
        let is_set_like = !matches!(
            m,
            Mutation::StripHeader { .. } | Mutation::StripQueryParam { .. }
        );
        if is_set_like {
            let count = set_like.entry(m.target_key()).or_insert(0);
            *count += 1;
            if *count > 1 {
                return Some(m.target_key());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;
    use crate::boundary::Mutation;

    fn set(name: &str, value: &str) -> Mutation {
        Mutation::SetHeader {
            name: name.to_string(),
            value: Zeroizing::new(value.to_string()),
        }
    }

    // --- deny-overrides; an all-abstain scope allows ---------------

    #[test]
    fn all_abstain_allows_and_carries_mutations() {
        // Credential injection abstains-with-mutations on its happy path → allow, edits carried.
        let cred = CapabilityOutcome::applied(vec![set("Authorization", "Bearer real")]);
        match decide_request([cred]) {
            Verdict::Allow { mutations } => assert_eq!(mutations.len(), 1),
            v => panic!("expected allow, got {v:?}"),
        }
    }

    #[test]
    fn empty_scope_allows() {
        // No control matched. Cedar already authorized this request at the effect seam; an empty
        // mutator scope has nothing to add and nothing to deny.
        assert_eq!(
            decide_request(std::iter::empty()),
            Verdict::Allow { mutations: vec![] }
        );
    }

    #[test]
    fn integrity_deny_overrides() {
        // A credential integrity failure (phantom mismatch) denies the request.
        let cred = CapabilityOutcome::unavailable("phantom mismatch".to_string());
        assert!(decide_request([cred]).is_deny());
    }

    #[test]
    fn deny_wins_regardless_of_order() {
        let denying = || CapabilityOutcome::unavailable("phantom mismatch".to_string());
        let abstaining = || CapabilityOutcome::applied(vec![set("X-A", "1")]);
        assert!(decide_request([denying(), abstaining()]).is_deny());
        assert!(decide_request([abstaining(), denying()]).is_deny());
    }

    // --- mutations accumulate; collisions fail closed -------------

    #[test]
    fn allows_accumulate_mutations() {
        let a = CapabilityOutcome::applied(vec![set("X-A", "1")]);
        let b = CapabilityOutcome::applied(vec![set("X-B", "2")]);
        match decide_request([a, b]) {
            Verdict::Allow { mutations } => assert_eq!(mutations.len(), 2),
            v => panic!("expected allow, got {v:?}"),
        }
    }

    #[test]
    fn strip_then_set_same_header_is_not_a_collision() {
        // The credential swap idiom (one control emits strip + set of Authorization) is fine.
        let swap = CapabilityOutcome::applied(vec![
            Mutation::StripHeader {
                name: "Authorization".to_string(),
            },
            set("Authorization", "Bearer real"),
        ]);
        assert!(!decide_request([swap]).is_deny());
    }

    #[test]
    fn two_controls_setting_same_header_collide() {
        // Two controls fighting over one header is a misconfiguration → fail closed (case-insensitive).
        let a = CapabilityOutcome::applied(vec![set("Authorization", "one")]);
        let b = CapabilityOutcome::applied(vec![set("authorization", "two")]);
        assert!(
            decide_request([a, b]).is_deny(),
            "same-header set from two controls collides"
        );
    }

    /// The `QueryParam` swap idiom from ONE capability must not self-collide.
    #[test]
    fn strip_then_add_query_param_from_one_capability_is_not_a_collision() {
        let swap = CapabilityOutcome::applied(vec![
            Mutation::StripQueryParam {
                name: "api_key".to_string(),
            },
            Mutation::AddQueryParam {
                name: "api_key".to_string(),
                value: Zeroizing::new("wk_live_real".to_string()),
            },
        ]);
        match decide_request([swap]) {
            Verdict::Allow { mutations } => assert_eq!(mutations.len(), 2, "both edits survive"),
            v => panic!("the query swap idiom must not be a collision, got {v:?}"),
        }
    }

    /// Two capabilities adding the same parameter is still a fail-closed misconfiguration.
    #[test]
    fn two_capabilities_adding_one_query_param_collide() {
        let a = CapabilityOutcome::applied(vec![Mutation::AddQueryParam {
            name: "api_key".to_string(),
            value: Zeroizing::new("one".to_string()),
        }]);
        let b = CapabilityOutcome::applied(vec![Mutation::AddQueryParam {
            name: "api_key".to_string(),
            value: Zeroizing::new("two".to_string()),
        }]);
        assert!(decide_request([a, b]).is_deny());
    }

    #[test]
    fn colliding_path_rewrites_fail_closed() {
        let a = CapabilityOutcome::applied(vec![Mutation::RewritePath {
            path: Zeroizing::new("/a".to_string()),
        }]);
        let b = CapabilityOutcome::applied(vec![Mutation::RewritePath {
            path: Zeroizing::new("/b".to_string()),
        }]);
        assert!(decide_request([a, b]).is_deny());
    }
}
