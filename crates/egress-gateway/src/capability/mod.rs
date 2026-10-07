//! Part B — the platform- and interception-agnostic functionality.

mod builder;
mod credential;
mod decider;
mod set;
mod traits;

#[cfg(feature = "tls-intercept")]
mod host;

pub use builder::CapabilitySetBuilder;
pub use credential::CredentialCapability;
pub use set::CapabilitySet;
#[allow(unused_imports)] // in-crate tests implement this sealed trait
pub(crate) use traits::EgressCapability;
pub use traits::{CapabilityContext, CapabilityFault, CapabilityOutcome};

#[cfg(feature = "tls-intercept")]
pub(crate) use host::normalize_host;
