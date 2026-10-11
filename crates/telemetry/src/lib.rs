#![warn(missing_docs, unreachable_pub)]

//! `strands-box-telemetry` — where one box's decision records go.
//!
//! `README.md` serves a Rust consumer; `AGENTS.md` holds the boundaries.

mod collector;
mod config;
mod correlation;
mod error;
mod export;
mod receive;
mod record;

pub use collector::Collector;
pub use config::{Target, TargetKind, TargetSecret, TelemetryConfig};
pub use correlation::Correlation;
pub use error::{Result, TelemetryError};
pub use record::{
    ControlOperation, ControlRecord, DecisionCause, DecisionRecord, DeterminingPolicy,
    RefusalRecord, Signal, Subject,
};

/// Open the lane `config` describes.
///
/// Every refusal happens here. Call it inside a Tokio runtime, onto which it spawns.
pub fn open(config: TelemetryConfig) -> Result<Collector> {
    Collector::start(config)
}
