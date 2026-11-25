//! The in-memory channel that tells a library caller what happened to its run.
//!
//! | Item | Role |
//! |---|---|
//! | [`run_events`] | makes one channel |
//! | [`RunEventSender`] | the half a caller hands to the run in `RunOptions` |
//! | [`RunEventReceiver`] | the half a caller reads |
//! | [`RunEvent`] | one event |
//!
//! The channel is unbounded, because an event here is never dropped. Unlike
//! [`policy_decisions`](crate::policy_decisions), a run sends only a handful of events.

use std::sync::mpsc::{Receiver, RecvError, RecvTimeoutError, Sender, TryRecvError};
use std::time::Duration;

/// Make a channel for the events of one run.
#[must_use]
pub fn run_events() -> (RunEventSender, RunEventReceiver) {
    let (sender, receiver) = std::sync::mpsc::channel();
    (RunEventSender { sender }, RunEventReceiver { receiver })
}

/// The half of a run event channel that a run sends on, which only the box can use.
#[derive(Debug, Clone)]
pub struct RunEventSender {
    sender: Sender<RunEvent>,
}

impl RunEventSender {
    /// Queue one event. A caller that dropped its receiver misses it, and the run goes on.
    pub(crate) fn send(&self, event: RunEvent) {
        let _ = self.sender.send(event);
    }
}

/// The half of a run event channel that a caller reads.
#[derive(Debug)]
pub struct RunEventReceiver {
    receiver: Receiver<RunEvent>,
}

impl RunEventReceiver {
    /// The next event, waiting for one; an error means the run has ended and none is queued.
    pub fn recv(&self) -> Result<RunEvent, RecvError> {
        self.receiver.recv()
    }

    /// The next queued event; `Empty` means none is queued yet, `Disconnected` that the run has
    /// ended.
    pub fn try_recv(&self) -> Result<RunEvent, TryRecvError> {
        self.receiver.try_recv()
    }

    /// The next event within `timeout`; `Timeout` means none arrived yet, `Disconnected` that the
    /// run has ended.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<RunEvent, RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }
}

/// One thing that happened to a run. More kinds of event may follow, so a caller matches with a
/// wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RunEvent {
    /// The box itself ended the run, before or after its workload started. A workload that exits
    /// non-zero is not a refusal. Sent at most once, as the run ends.
    Refused {
        /// The message code of the failure's stderr line (`docs/user/message-codes.md`), with no
        /// path or message.
        code: diagnostics::Kind,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused() -> RunEvent {
        RunEvent::Refused {
            code: diagnostics::Code::B0101.into(),
        }
    }

    #[test]
    fn an_event_is_queued_once() {
        let (sender, receiver) = run_events();
        sender.send(refused());
        assert_eq!(receiver.try_recv(), Ok(refused()));
        assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
    }

    #[test]
    fn a_dropped_receiver_does_not_stop_the_run() {
        let (sender, receiver) = run_events();
        drop(receiver);
        sender.send(refused());
    }

    #[test]
    fn the_receiver_disconnects_when_every_sender_is_gone() {
        let (sender, receiver) = run_events();
        let clone = sender.clone();
        drop(sender);
        clone.send(refused());
        drop(clone);
        assert_eq!(receiver.try_recv(), Ok(refused()));
        assert_eq!(receiver.try_recv(), Err(TryRecvError::Disconnected));
    }
}
