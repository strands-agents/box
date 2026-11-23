//! Collection, identity, and event payloads for CLI telemetry.

mod collect;
mod consent;
mod context;
mod delivery;
mod events;
mod installation;
mod journal;
mod mcp;
mod packs;
mod polling;
mod session;
mod source;

pub use collect::ContextBuilder;
pub use consent::{Consent, ConsentSource};
pub use context::RunContext;
pub use events::{CoreOutcome, Event, ExitOutcome, FailureReason, Invocation, LaunchOutcome};
pub use installation::{InstallationId, save_telemetry_choice};
pub use journal::{Decision, Journal, Record, Verdict};
pub use mcp::{McpFormat, McpTarget};
pub use packs::Pack;
pub use polling::{ActionCatalog, DecisionInterval, POLLING_INTERVAL, Polling};
pub use session::{COMPLETION_BUDGET, Session};
pub use source::{PackLocation, read_pack};

/// Metadata that does not fit the telemetry schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error;

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("telemetry metadata does not fit the schema")
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "../build.rs"]
mod build;
