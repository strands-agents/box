//! [`CapabilitySetBuilder`] — the developer-facing registration surface for Part B.

use crate::capability::CredentialCapability;
use crate::capability::set::CapabilitySet;
use crate::capability::traits::EgressCapability;

/// Builds a [`CapabilitySet`] from registered credential controls.
#[derive(Default)]
pub struct CapabilitySetBuilder {
    controls: Vec<Box<dyn EgressCapability>>,
}

impl CapabilitySetBuilder {
    /// A new, empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a `EgressCapability`, consuming self for a fluent chain. At most one per pattern is
    /// permitted — a duplicate is caught at
    /// [`validate`](crate::capability::CapabilitySet::validate).
    /// Register the credential capability for one destination pattern.
    pub fn add_credential(mut self, capability: CredentialCapability) -> Self {
        self.controls.push(Box::new(capability));
        self
    }

    /// Register an in-crate capability implementation.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn add_capability_boxed(mut self, capability: Box<dyn EgressCapability>) -> Self {
        self.controls.push(capability);
        self
    }

    /// The number of registered controls (for tests/diagnostics).
    pub fn len(&self) -> usize {
        self.controls.len()
    }

    /// Whether no controls are registered.
    pub fn is_empty(&self) -> bool {
        self.controls.is_empty()
    }

    /// Freeze the registrations into a [`CapabilitySet`].
    pub fn build(self) -> CapabilitySet {
        CapabilitySet::from_parts(self.controls)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::InterceptedRequest;
    use crate::capability::traits::{CapabilityContext, CapabilityOutcome};
    use credentials::DestinationPattern;

    struct Stub(DestinationPattern);
    impl EgressCapability for Stub {
        fn pattern(&self) -> &DestinationPattern {
            &self.0
        }
        fn on_request(
            &self,
            _req: &mut InterceptedRequest,
            _cx: &CapabilityContext,
        ) -> CapabilityOutcome {
            CapabilityOutcome::none()
        }
    }

    fn stub(pattern: &str) -> Stub {
        Stub(DestinationPattern::parse(pattern).unwrap())
    }

    #[test]
    fn builder_registers_controls() {
        let set = CapabilitySetBuilder::new()
            .add_capability_boxed(Box::new(stub("api.stripe.com")))
            .add_capability_boxed(Box::new(stub("*.amazonaws.com")))
            .build();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn empty_builder_builds_empty_set() {
        let set = CapabilitySetBuilder::new().build();
        assert!(set.is_empty());
    }
}
