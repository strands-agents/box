//! Two-door MCP discovery completion
//! (docs/design/decisions.md#the-box-coordinates-discovery-completion).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use policy::PolicyEngine;
use telemetry::{ControlOperation, ControlRecord};

use crate::error::BoxError;
use crate::run::telemetry::Collector;

/// A discovery door the run waits to hear from before it checks for unresolved per-tool policies.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum DiscoveryDoor {
    /// The stdio broker.
    Stdio,
    /// The egress gateway.
    Egress,
}

struct CoordinatorState {
    remaining: BTreeSet<DiscoveryDoor>,
    verdict_ran: bool,
}

/// Runs the single cross-door `finish_mcp_discovery` verdict once every configured door has drained
/// its discovery. It replaces the shared atomic that let the egress door reach into the stdio
/// registry's completion check, and closes the re-trigger gap: each door reports with an explicit
/// call, so the door that finishes last runs the verdict itself.
pub(crate) struct DiscoveryCoordinator {
    state: Mutex<CoordinatorState>,
    policy: Arc<PolicyEngine>,
    fatal: tokio::sync::mpsc::UnboundedSender<BoxError>,
    /// This box's collector, so a change to the authority is recorded where it happens. Absent in a
    /// unit test that drives the coordinator without a box.
    collector: Option<Arc<Collector>>,
}

impl DiscoveryCoordinator {
    /// Seed the coordinator with the doors this run must hear from and the sink a fatal verdict
    /// reaches. Stdio is always present; Egress only when the record declares a remote MCP server.
    pub(crate) fn new(
        doors: BTreeSet<DiscoveryDoor>,
        policy: Arc<PolicyEngine>,
        fatal: tokio::sync::mpsc::UnboundedSender<BoxError>,
        collector: Option<Arc<Collector>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(CoordinatorState {
                remaining: doors,
                verdict_ran: false,
            }),
            policy,
            fatal,
            collector,
        })
    }

    /// Record one change to this box's authority.
    pub(crate) fn control(&self, record: ControlRecord) {
        if let Some(collector) = &self.collector {
            collector.control(record);
        }
    }

    /// Report that `door` drained its discovery. The door that empties the set runs the one
    /// unresolved-policy verdict; a still-blocked authority sends a fatal run error.
    pub(crate) fn report_finished(&self, door: DiscoveryDoor) {
        let run_verdict = {
            // A poisoned lock leaves the verdict unrun, so the box holds on a blocked authority
            // rather than fataling on a fault it cannot describe.
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            state.remaining.remove(&door);
            if state.remaining.is_empty() && !state.verdict_ran {
                state.verdict_ran = true;
                true
            } else {
                false
            }
        };
        if run_verdict {
            match self.policy.finish_mcp_discovery() {
                // A server whose `tools/list` was denied leaves its per-tool rule unstageable.
                // The box does not fatal — it degrades that one server (its tools denied fail-closed)
                // and warns, so a customer's contradictory policy blocks one server, never the box.
                Ok(degraded) if !degraded.is_empty() => {
                    eprintln!(
                        "strands-box: warning: discovery denied tools/list for {degraded:?}; each \
                         server's per-tool rule is inert and its tool calls are denied — permit \
                         tools/list for it or remove the per-tool rule"
                    );
                    self.control(
                        ControlRecord::completed(ControlOperation::DiscoveryComplete, "policy")
                            .detailed(&format!("degraded {degraded:?}")),
                    );
                }
                Ok(_) => {
                    self.control(ControlRecord::completed(
                        ControlOperation::DiscoveryComplete,
                        "policy",
                    ));
                }
                // A genuine durable fault is still fatal.
                Err(error) => {
                    self.control(ControlRecord::refused(
                        ControlOperation::DiscoveryComplete,
                        "policy",
                        &error.to_string(),
                    ));
                    let _ = self.fatal.send(BoxError::from(error));
                }
            }
        }
    }

    /// A coordinator seeded with the stdio door alone and a fatal sink that drops. For unit tests
    /// that drive a registry without the egress door or a supervised run.
    #[cfg(test)]
    pub(crate) fn testing(policy: Arc<PolicyEngine>) -> Arc<Self> {
        let (fatal, _drop) = tokio::sync::mpsc::unbounded_channel();
        Self::new(BTreeSet::from([DiscoveryDoor::Stdio]), policy, fatal, None)
    }
}
