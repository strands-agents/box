//! The seam every verdict is reported through.

use crate::Decision;

/// A sink that observes each verdict the authority reaches.
///
/// One implementor per composition, installed with
/// [`PolicyEngine::observed_by`](crate::PolicyEngine::observed_by). It is public because a policy
/// consumer can inspect policy-operation verdicts without this crate learning what it stores.
///
/// **`observed` runs inside `decide`, so it must not block, await, or perform input or output.**
/// `decide` is infallible and free of both, and an observer that broke either would move a
/// target's failure onto the enforcement path. Queue the record and return.
///
/// It takes the action and the resource already extracted rather than the `Request`, so this crate
/// exposes no accessor on that type and an observer cannot re-read what was judged. The principal is
/// absent for the same reason: every verdict is reached against one fixed identity, so passing it
/// would invite an observer to record a value that did not decide anything.
pub trait DecisionObserver: Send + Sync {
    /// Report one verdict. Fire-and-forget: it returns nothing and may not fail.
    fn observed(&self, action: &str, resource: &str, decision: &Decision);
}
