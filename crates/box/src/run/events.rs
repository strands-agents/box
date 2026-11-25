//! The in-memory channel that tells a library caller what happened to its run.
//!
//! | Item | Role |
//! |---|---|
//! | [`run_events`] | makes one channel |
//! | [`RunEventSender`] | the half a caller hands to the run in `RunOptions` |
//! | [`RunEventReceiver`] | the half a caller reads |
//! | [`RunEvent`] | one event |
//! | [`RefusalKind`] | the category of a box's own failure, which names no path or message |
//! | [`ContainmentStage`] | how far containment got before it failed |
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
    /// The box itself failed, before or after its workload started. A workload that exits
    /// non-zero is not a refusal. Sent at most once, as the run ends.
    Refused {
        /// Which part of Box Core failed.
        kind: RefusalKind,
        /// The message code of the failure's stderr line (`docs/user/message-codes.md`), which
        /// groups kinds by what the reader can fix.
        code: diagnostics::Kind,
    },
}

/// Which part of Box Core failed, one kind per error group, without the diagnostic text.
///
/// Exhaustive on purpose: a caller that maps each kind to its own categories must decide for a
/// new kind before it compiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    /// The supplied box ID is malformed.
    BoxId,
    /// This process already attempted to run a box.
    AlreadyRan,
    /// Core dumps or process-memory inspection could not be disabled.
    Hardening,
    /// The async runtime could not start.
    Runtime,
    /// The box configuration is not usable.
    Config,
    /// The folder that holds the box is not usable.
    Layout,
    /// The box lock, or a trusted Box operation, refused or failed.
    Daemon,
    /// The agent's program is not installed: a bare name on no `PATH` entry, or an absolute path
    /// that does not exist.
    AgentNotFound,
    /// A program other than the agent was not found or cannot be run.
    Executable,
    /// The containment trampoline is missing or failed outside a setup stage.
    Trampoline,
    /// Containment failed before the workload ran, at this stage.
    ContainmentSetup(ContainmentStage),
    /// The installed trusted executables could not keep their identities.
    Installation,
    /// Starting, waiting on, or controlling the workload failed.
    Supervise,
    /// The box's Shell could not be prepared.
    Shell,
    /// An MCP server's schema could not be read or written.
    McpSchema,
    /// MCP discovery could not run.
    McpDiscovery,
    /// The policy did not load.
    Policy,
    /// The policy could not be staged.
    PolicyStaging,
    /// A tool grammar could not be bound to the policy.
    GrammarBinding,
    /// The box's policy history disagrees with its record.
    HistoryMismatch,
    /// The policy history could not be flushed when the box stopped.
    HistoryFlush,
    /// A credential could not be read, resolved, or checked.
    Credential,
    /// The egress proxy failed.
    Proxy,
    /// The containment configuration failed.
    Containment,
    /// Telemetry could not be set up.
    Telemetry,
    /// The network relay failed.
    Relay,
    /// Native filesystem policy failed.
    NativeFilesystem,
}

/// How far containment got before it failed, as the trampoline reports it.
///
/// Exhaustive for the same reason as [`RefusalKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainmentStage {
    /// Reading the containment configuration.
    ConfigRead,
    /// Validating the containment configuration.
    ConfigValidation,
    /// Applying containment to the process.
    Apply,
    /// Building the workload's environment.
    TargetEnvironment,
    /// Executing the workload.
    Exec,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(kind: RefusalKind) -> RunEvent {
        RunEvent::Refused {
            kind,
            code: diagnostics::Code::B0101.into(),
        }
    }

    #[test]
    fn an_event_is_queued_once() {
        let (sender, receiver) = run_events();
        sender.send(refused(RefusalKind::Policy));
        assert_eq!(receiver.try_recv(), Ok(refused(RefusalKind::Policy)));
        assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
    }

    #[test]
    fn a_dropped_receiver_does_not_stop_the_run() {
        let (sender, receiver) = run_events();
        drop(receiver);
        sender.send(refused(RefusalKind::Config));
    }

    #[test]
    fn the_receiver_disconnects_when_every_sender_is_gone() {
        let (sender, receiver) = run_events();
        let clone = sender.clone();
        drop(sender);
        clone.send(refused(RefusalKind::Supervise));
        drop(clone);
        assert_eq!(receiver.try_recv(), Ok(refused(RefusalKind::Supervise)));
        assert_eq!(receiver.try_recv(), Err(TryRecvError::Disconnected));
    }
}
