//! The in-memory channel that gives a library caller each policy decision of its run as it is made.
//!
//! | Item | Role |
//! |---|---|
//! | [`policy_decisions`] | makes one bounded channel |
//! | [`PolicyDecisionSender`] | the half a caller hands to the run in `RunOptions` |
//! | [`PolicyDecisionReceiver`] | the half a caller reads |
//! | [`PolicyDecision`] | one decision, with the values its record states |

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{
    Receiver, RecvError, RecvTimeoutError, SyncSender, TryRecvError, TrySendError,
};
use std::time::{Duration, SystemTime};

use telemetry::DecisionRecord;

/// Make a channel that holds at most `capacity` policy decisions the caller has not yet received.
///
/// A `capacity` of zero holds one decision.
#[must_use]
pub fn policy_decisions(capacity: usize) -> (PolicyDecisionSender, PolicyDecisionReceiver) {
    let (sender, receiver) = std::sync::mpsc::sync_channel(capacity.max(1));
    let dropped = Arc::new(AtomicU64::new(0));
    (
        PolicyDecisionSender {
            sender,
            dropped: Arc::clone(&dropped),
        },
        PolicyDecisionReceiver { receiver, dropped },
    )
}

/// The half of a policy decision channel that a run sends on, which only the box can use.
#[derive(Debug)]
pub struct PolicyDecisionSender {
    sender: SyncSender<PolicyDecision>,
    dropped: Arc<AtomicU64>,
}

impl PolicyDecisionSender {
    /// Queue one decision without waiting, and count it as dropped when the channel is full.
    pub(crate) fn send(&self, record: &DecisionRecord) {
        match self.sender.try_send(PolicyDecision::of(record)) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// The half of a policy decision channel that a caller reads.
#[derive(Debug)]
pub struct PolicyDecisionReceiver {
    receiver: Receiver<PolicyDecision>,
    dropped: Arc<AtomicU64>,
}

impl PolicyDecisionReceiver {
    /// The next decision, waiting for one; an error means the run has ended and none is queued.
    pub fn recv(&self) -> Result<PolicyDecision, RecvError> {
        self.receiver.recv()
    }

    /// The next queued decision; `Empty` means none is queued yet, `Disconnected` that the run has
    /// ended.
    pub fn try_recv(&self) -> Result<PolicyDecision, TryRecvError> {
        self.receiver.try_recv()
    }

    /// The next decision within `timeout`; `Timeout` means none arrived yet, `Disconnected` that
    /// the run has ended.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<PolicyDecision, RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }

    /// The number of decisions the box did not queue because the channel was full.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// One policy decision, with the values that its `strands.box.policy.*` record attributes state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PolicyDecision {
    /// The time of the decision, which is the record's timestamp.
    pub time: SystemTime,
    /// Whether the decision is a permit.
    pub permitted: bool,
    /// The action, such as `fs:read` or `net:connect`.
    pub action: String,
    /// The namespace of the action, such as `fs`, or the MCP server or tool grammar that declares it.
    pub category: String,
    /// The resource, such as a path or `host:port`.
    pub resource: String,
    /// The rule that decided: an authored policy's identifier, `<default-deny>`, or an enforcement gate.
    pub rule: String,
    /// The class of result: `permitted`, `forbidden`, `no_match`, `policy_pending`,
    /// `internal_fault`, or `enforcement`.
    pub cause: String,
    /// The reason for a refusal.
    pub reason: Option<String>,
}

impl PolicyDecision {
    fn of(record: &DecisionRecord) -> Self {
        Self {
            time: record.time(),
            permitted: record.permitted(),
            action: record.action().to_string(),
            category: record.category().to_string(),
            resource: record.resource().to_string(),
            rule: record.rule().to_string(),
            cause: record.cause().as_str().to_string(),
            reason: record.reason().map(str::to_string),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    fn deny(resource: &str) -> DecisionRecord {
        DecisionRecord::deny(
            "Box::Action::\"net:connect\"",
            resource,
            "<default-deny>",
            "no permit matched",
        )
        .caused_by(telemetry::DecisionCause::NoMatch)
    }

    #[test]
    fn a_decision_carries_the_values_its_record_states() {
        let (sender, receiver) = policy_decisions(4);
        sender.send(&deny("example.net:443"));
        let decision = receiver.try_recv().unwrap();
        assert!(!decision.permitted);
        assert_eq!(decision.action, "net:connect");
        assert_eq!(decision.category, "net");
        assert_eq!(decision.resource, "example.net:443");
        assert_eq!(decision.rule, "<default-deny>");
        assert_eq!(decision.cause, "no_match");
        assert_eq!(decision.reason.as_deref(), Some("no permit matched"));
        assert!(receiver.try_recv().is_err());
    }

    /// Run `sends` on another thread, and fail when it does not return within a second.
    fn without_waiting(sends: impl FnOnce() + Send + 'static) {
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            sends();
            let _ = done.send(());
        });
        assert!(
            finished.recv_timeout(Duration::from_secs(1)).is_ok(),
            "sending on a full channel waited"
        );
    }

    #[test]
    fn a_full_channel_drops_and_counts_without_waiting() {
        let (sender, receiver) = policy_decisions(2);
        let sender = Arc::new(sender);
        let sending = Arc::clone(&sender);
        let started = Instant::now();
        without_waiting(move || {
            for index in 0..1_000 {
                sending.send(&deny(&format!("host-{index}:443")));
            }
        });
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(receiver.dropped(), 998);
        assert_eq!(receiver.try_recv().unwrap().resource, "host-0:443");
        assert_eq!(receiver.try_recv().unwrap().resource, "host-1:443");
        assert!(receiver.try_recv().is_err());
        sender.send(&deny("after:443"));
        assert_eq!(receiver.try_recv().unwrap().resource, "after:443");
    }

    #[test]
    fn a_receiver_that_is_gone_does_not_stop_the_sender() {
        let (sender, receiver) = policy_decisions(1);
        drop(receiver);
        sender.send(&deny("example.net:443"));
    }

    #[test]
    fn a_reader_tells_the_end_of_the_run_from_a_quiet_moment() {
        let (sender, receiver) = policy_decisions(4);
        assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
        assert_eq!(
            receiver.recv_timeout(Duration::from_millis(10)),
            Err(RecvTimeoutError::Timeout)
        );
        sender.send(&deny("last:443"));
        drop(sender);
        assert_eq!(receiver.recv().unwrap().resource, "last:443");
        assert_eq!(receiver.recv(), Err(RecvError));
        assert_eq!(receiver.try_recv(), Err(TryRecvError::Disconnected));
        let started = Instant::now();
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(5)),
            Err(RecvTimeoutError::Disconnected)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_zero_capacity_still_holds_one_decision() {
        let (sender, receiver) = policy_decisions(0);
        without_waiting(move || {
            sender.send(&deny("first:443"));
            sender.send(&deny("second:443"));
        });
        assert_eq!(receiver.try_recv().unwrap().resource, "first:443");
        assert_eq!(receiver.dropped(), 1);
    }
}
