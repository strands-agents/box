//! Load-time judgement of a permit whose temporal clause cannot narrow another permit.

use std::collections::BTreeSet;

use cedar_policy::{
    ActionConstraint, Effect, Policy, PolicySet, PrincipalConstraint, ResourceConstraint,
};
use dogwood_language::{LoweredPolicySet, ParsedPolicySet};

use crate::PolicyError;
use crate::spelling::{PolicyWarning, rule_name};

/// What a permit's `when`/`unless` clauses hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Condition {
    None,
    Temporal,
    Plain,
}

/// One permit, as the load judges it.
struct Permit<'a> {
    position: usize,
    policy: &'a Policy,
    condition: Condition,
}

impl Permit<'_> {
    fn name(&self) -> String {
        format!("{} (rule {})", rule_name(self.policy), self.position)
    }
}

/// Whether one rule's resource scope lexically covers another's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coverage {
    Covers,
    Disjoint,
    Undecided,
}

/// Refuse every temporal permit an unconditioned permit makes inert; warn on the heuristic shape.
pub(crate) fn judge(
    parsed: &ParsedPolicySet,
    lowered: &LoweredPolicySet,
) -> Result<Vec<PolicyWarning>, PolicyError> {
    let temporal: Vec<bool> = parsed
        .policies()
        .map(|policy| policy.uses_temporal())
        .collect();
    let permits = permits(lowered, &temporal)?;
    let budgets = permits
        .iter()
        .filter(|permit| permit.condition == Condition::Temporal);
    let (refusals, warnings): (Vec<_>, Vec<_>) = budgets
        .flat_map(|budget| {
            permits
                .iter()
                .filter(|other| other.position != budget.position)
                .filter_map(|other| finding(budget, other))
        })
        .partition(|(refused, _)| *refused);
    if !refusals.is_empty() {
        return Err(PolicyError::InertTemporalPermit(
            refusals
                .into_iter()
                .map(|(_, text)| text)
                .collect::<Vec<_>>()
                .join("; "),
        ));
    }
    Ok(warnings
        .into_iter()
        .map(|(_, text)| PolicyWarning::InertTemporalPermit { finding: text })
        .collect())
}

/// Every permit in the lowered set, with its 1-based position and what its clauses hold.
fn permits<'a>(
    lowered: &'a LoweredPolicySet,
    temporal: &[bool],
) -> Result<Vec<Permit<'a>>, PolicyError> {
    let cedar: &PolicySet = lowered.as_cedar();
    lowered
        .rules()
        .filter_map(|rule| {
            let policy_id = match rule.cedar_policy_id.parse::<cedar_policy::PolicyId>() {
                Ok(policy_id) => policy_id,
                Err(error) => {
                    return Some(Err(PolicyError::Schema(format!(
                        "dogwood rule id: {error}"
                    ))));
                }
            };
            let policy = cedar.policy(&policy_id)?;
            if policy.effect() != Effect::Permit {
                return None;
            }
            let condition = match (
                temporal.get(rule.rule_index).copied().unwrap_or(false),
                has_condition(policy),
            ) {
                (true, _) => Condition::Temporal,
                (false, Ok(true)) => Condition::Plain,
                (false, Ok(false)) => Condition::None,
                (false, Err(error)) => return Some(Err(error)),
            };
            Some(Ok(Permit {
                position: rule.rule_index.saturating_add(1),
                policy,
                condition,
            }))
        })
        .collect()
}

/// Whether the policy carries a clause that can exclude a request; Dogwood lowers a bare rule to
/// `when { true }`.
fn has_condition(policy: &Policy) -> Result<bool, PolicyError> {
    let est = policy.to_json().map_err(|error| {
        PolicyError::Schema(format!(
            "{} cannot be inspected at load: {error}",
            rule_name(policy)
        ))
    })?;
    let vacuous = |condition: &serde_json::Value| {
        let body = &condition["body"]["Value"];
        matches!(
            (condition["kind"].as_str(), body.as_bool()),
            (Some("when"), Some(true)) | (Some("unless"), Some(false))
        )
    };
    Ok(est["conditions"]
        .as_array()
        .is_some_and(|conditions| !conditions.iter().all(vacuous)))
}

/// The finding `other` earns beside `budget`: `(true, _)` refuses, `(false, _)` warns.
fn finding(budget: &Permit<'_>, other: &Permit<'_>) -> Option<(bool, String)> {
    if !principal_covers(other.policy, budget.policy) || !action_covers(other.policy, budget.policy)
    {
        return None;
    }
    let resource = resource_coverage(other.policy, budget.policy);
    if resource == Coverage::Disjoint {
        return None;
    }
    match (other.condition, resource) {
        (Condition::None, Coverage::Covers) => Some((
            true,
            format!(
                "{} carries a temporal clause beside {}, which permits the same action with no \
                 condition; a permit cannot narrow another permit, so write the cap as a forbid",
                budget.name(),
                other.name()
            ),
        )),
        (Condition::None | Condition::Plain, _) => Some((
            false,
            format!(
                "{} carries a temporal clause beside {}, which also permits that action; the \
                 budget is inert for every request the other rule admits, so write a cap as a \
                 forbid",
                budget.name(),
                other.name()
            ),
        )),
        (Condition::Temporal, _) => None,
    }
}

fn principal_covers(other: &Policy, budget: &Policy) -> bool {
    match other.principal_constraint() {
        PrincipalConstraint::Any => true,
        constraint => constraint == budget.principal_constraint(),
    }
}

/// The action ids a scope names, or `None` for an unconstrained scope.
fn actions(policy: &Policy) -> Option<BTreeSet<String>> {
    match policy.action_constraint() {
        ActionConstraint::Any => None,
        ActionConstraint::Eq(uid) => Some(BTreeSet::from([uid.to_string()])),
        ActionConstraint::In(uids) => Some(uids.iter().map(ToString::to_string).collect()),
    }
}

fn action_covers(other: &Policy, budget: &Policy) -> bool {
    match (actions(other), actions(budget)) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(wide), Some(narrow)) => narrow.is_subset(&wide),
    }
}

fn resource_coverage(other: &Policy, budget: &Policy) -> Coverage {
    match (other.resource_constraint(), budget.resource_constraint()) {
        (ResourceConstraint::Any, _) => Coverage::Covers,
        (ResourceConstraint::Eq(wide), ResourceConstraint::Eq(narrow)) => {
            if wide == narrow {
                Coverage::Covers
            } else {
                Coverage::Disjoint
            }
        }
        (wide, narrow) => {
            if wide == narrow {
                Coverage::Covers
            } else {
                Coverage::Undecided
            }
        }
    }
}
