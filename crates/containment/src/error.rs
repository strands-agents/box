//! Error types for the containment crate.

use crate::platform::Platform;
use std::path::PathBuf;

/// Errors that can occur during containment operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ContainmentError {
    /// Requested mechanism not available on this platform.
    #[error("mechanism '{requested}' is not available on {platform:?}")]
    MechanismUnavailable {
        /// The mechanism that was requested.
        requested: String,
        /// The detected platform.
        platform: Platform,
    },

    /// Backend failed to apply enforcement.
    #[error("backend '{backend}' failed to apply: {reason}")]
    ApplyFailed {
        /// Which backend failed.
        backend: String,
        /// Human-readable reason.
        reason: String,
    },

    /// Config contains a capability the backend cannot enforce.
    #[error("backend '{backend}' cannot enforce capability '{capability}'")]
    UnsupportedCapability {
        /// The unsupported capability.
        capability: String,
        /// The backend that rejected it.
        backend: String,
    },

    /// Platform unsupported with structured detail.
    #[error("platform {platform:?} unsupported: {reason}")]
    PlatformUnsupported {
        /// The unsupported platform.
        platform: Platform,
        /// Human-readable reason.
        reason: String,
    },

    /// A caller-supplied path (e.g. to [`crate::ContainmentConfig::allow`])
    /// does not exist.
    #[error("path does not exist: {}", .0.display())]
    PathNotFound(PathBuf),

    /// A directory was required but the path is a file.
    #[error("expected a directory but got a file: {}", .0.display())]
    ExpectedDirectory(PathBuf),

    /// A file was required but the path is a directory.
    #[error("expected a file but got a directory: {}", .0.display())]
    ExpectedFile(PathBuf),

    /// Port zero is not a concrete proxy, bind, or localhost service port.
    #[error("{field} port {port} is invalid; expected a port in 1..=65535")]
    InvalidPort {
        /// Config field containing the invalid port.
        field: &'static str,
        /// Rejected port value.
        port: u16,
    },

    /// `std::fs::canonicalize` failed for a reason other than absence.
    #[error("failed to canonicalize path '{}': {source}", path.display())]
    PathCanonicalization {
        /// The path that failed to canonicalize.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// A caller-supplied SBPL rule failed validation (malformed S-expression
    /// or a whole-containment-defeating allow).
    #[error("invalid platform rule: {0}")]
    InvalidPlatformRule(String),

    /// A serialized [`crate::ContainmentConfig`] failed conversion or revalidation due to malformed
    /// JSON, canonical path drift, or an invalid platform rule.
    #[error("containment config validation failed: {0}")]
    ConfigValidation(String),

    /// Two grants that are individually expressible combine into more authority
    /// than either states.
    #[error("conflicting grants: {reason}")]
    ConflictingGrants {
        /// Which two grants conflict, and what the union would have permitted.
        reason: String,
    },

    /// A grant names a path so broad that it would authorize an entire tree the
    /// caller cannot have meant to hand over.
    #[error("grant is too broad to be authorized: {} ({reason})", path.display())]
    GrantTooBroad {
        /// The offending path.
        path: PathBuf,
        /// Why this path is refused.
        reason: &'static str,
    },
}
