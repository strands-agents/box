//! The `Emitter` seam for final outbound policy enforcement point decisions.

use std::sync::{Arc, Mutex};

use crate::audit::EgressDecision;

/// The producer seam a final outbound decision is emitted through.
pub trait Emitter: Send + Sync {
    /// Emit one connection or outbound request decision before the effect or refusal.
    fn emit(&self, record: EgressDecision);
}

/// The local stub sink captures emitted records for isolated consumers and tests.
#[derive(Debug, Clone, Default)]
pub struct StubEmitter {
    records: Arc<Mutex<Vec<EgressDecision>>>,
}

impl StubEmitter {
    /// An empty stub sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot of every record emitted so far (for tests/diagnostics).
    pub fn records(&self) -> Vec<EgressDecision> {
        self.records.lock().map(|r| r.clone()).unwrap_or_default()
    }
}

impl Emitter for StubEmitter {
    fn emit(&self, record: EgressDecision) {
        // Fire-and-forget: a poisoned lock is swallowed so the audit can never block/fail a request.
        if let Ok(mut records) = self.records.lock() {
            records.push(record);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Decision;
    use crate::audit::RequestId;

    fn decision() -> EgressDecision {
        EgressDecision {
            host: "api.example.com".to_string(),
            port: 443,
            method: "GET".to_string(),
            path: "/v1/models".to_string(),
            decision: Decision::Allow,
            reason: String::new(),
            correlation: RequestId::new("turn-1"),
        }
    }

    #[test]
    fn stub_emitter_captures_records() {
        let emitter = StubEmitter::new();
        emitter.emit(decision());
        assert_eq!(emitter.records().len(), 1);
    }

    #[test]
    fn emits_through_boxed_dyn_emitter() {
        let boxed: Box<dyn Emitter> = Box::new(StubEmitter::new());
        boxed.emit(decision()); // object-safe, fire-and-forget (returns ())
    }
}
