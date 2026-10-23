//! Part B — the platform- and interception-agnostic functionality.

mod builder;
mod credential;
mod decider;
mod set;
mod traits;

mod host;

pub use builder::CapabilitySetBuilder;
pub use credential::CredentialCapability;
pub use set::CapabilitySet;
#[allow(unused_imports)] // in-crate tests implement this sealed trait
pub(crate) use traits::EgressCapability;
pub use traits::{CapabilityContext, CapabilityFault, CapabilityOutcome};

pub use host::{is_bindable_host, normalize_host};
