//! The [`Interceptor`] trait — the Part A port.

use crate::capability::CapabilitySet;

/// The Part A port: something that captures outbound traffic and drives it through Part B.
pub trait Interceptor {
    /// The [`CapabilitySet`] this interceptor drives (Part B) — the credential mutators it applies
    /// on the L7 legs. A second adapter reuses the same value unchanged.
    fn credential_injection(&self) -> &CapabilitySet;
}
