//! The typed refusals this crate reports.

/// A telemetry result.
pub type Result<T> = std::result::Result<T, TelemetryError>;

/// Why telemetry refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TelemetryError {
    /// A declared target no run could honour.
    #[error("telemetry configuration: {reason}")]
    Config {
        /// What is wrong, and what to write instead.
        reason: String,
    },
}
