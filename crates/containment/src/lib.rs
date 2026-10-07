#![warn(missing_docs, unreachable_pub)]

//! Cross-platform process containment for Strands Box.

mod backend;
mod config;
mod error;
mod facade;
mod floors;
mod model;
mod os_paths;
mod platform;

#[cfg(any(test, feature = "test-support"))]
/// Test doubles (gated by the `test-support` cargo feature). Exposes
/// test support utilities for driving containment without kernel-level enforcement.
pub mod test_support;

// Public API surface
pub use config::ContainmentConfig;
pub use error::ContainmentError;
pub use facade::Containment;
pub use floors::{ContainmentWarning, home_relative_path_refusal, validate_grant};
pub use model::{
    BackendOverride, IpcMode, Network, Operation, PreparedFilesystemPath, ProcessInfoMode, Scope,
    SignalMode,
};
pub use os_paths::{os_minimum_cells, os_runtime_cells};
pub use platform::Platform;

/// Containment operation result.
pub type Result<T> = std::result::Result<T, ContainmentError>;
