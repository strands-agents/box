//! Acquisition audit — the `CredentialAcquire` record and the `Emitter` producer seam.

use std::time::Instant;

use crate::{Result, redact_credential_ref};

/// The audit correlation id shared by credential acquisition and egress records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RequestId(String);

impl RequestId {
    /// Create a request id from its string representation.
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

/// The credential-acquisition audit record: `{ source, ref, ok, ms, request_id }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CredentialAcquire {
    /// The tenant whose vault performed the resolve. Non-secret, and the field that makes an
    /// acquisition record attributable: with isolation by instance, the tenant is not recoverable from
    /// anything else on the record.
    pub tenant: String,
    /// The source backend the reference routed to (e.g. `"env"`, `"file"`, `"op"`, `"aws"`).
    /// A non-secret routing/kind label, safe to log.
    pub source: String,
    /// The credential reference, **already redacted** for display (scheme kept, locator hidden).
    /// Never the raw locator, never the secret value.
    pub credential_ref: String,
    /// Whether the resolve succeeded. Emitted for both outcomes — a failure is security-relevant.
    pub ok: bool,
    /// Wall-clock duration of the resolve, in milliseconds (advisory timing).
    pub ms: u64,
    /// Request correlation id tying this to the matching `EgressDecision`.
    pub request_id: RequestId,
}

impl CredentialAcquire {
    /// Build a record, redacting `raw_reference` at construction (via `redact_credential_ref`) so
    /// the raw locator can never be stored. This is the only constructor, so redaction is not an
    /// easy-to-forget step.
    pub(crate) fn new(
        tenant: impl Into<String>,
        source: impl Into<String>,
        raw_reference: &str,
        ok: bool,
        ms: u64,
        request_id: RequestId,
    ) -> Self {
        Self {
            tenant: tenant.into(),
            source: source.into(),
            credential_ref: redact_credential_ref(raw_reference),
            ok,
            ms,
            request_id,
        }
    }
}

/// The producer seam a resolve emits an acquisition audit through.
pub(crate) trait Emitter: Send + Sync + std::fmt::Debug {
    /// Emit an acquisition audit record. Fire-and-forget: never awaits a receipt, never blocks the
    /// resolve, never propagates a sink error back to the caller.
    fn emit(&self, record: CredentialAcquire);
}

/// The sink a vault uses when the caller injects none: the record is built (so the redaction and
/// timing path is always exercised) and then dropped.
#[derive(Debug, Default)]
pub(crate) struct DiscardingEmitter;

impl Emitter for DiscardingEmitter {
    fn emit(&self, _record: CredentialAcquire) {}
}

/// Time `resolve`, emit a [`CredentialAcquire`] for its outcome — **success or failure** — through
/// the injected `emitter`, and return the resolve's result unchanged.
pub(crate) fn audit_resolve<T>(
    emitter: &dyn Emitter,
    tenant: &str,
    source: &str,
    raw_reference: &str,
    request_id: &RequestId,
    resolve: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let started = Instant::now();
    let outcome = resolve();
    let ms = started.elapsed().as_millis() as u64;
    emitter.emit(CredentialAcquire::new(
        tenant,
        source,
        raw_reference,
        outcome.is_ok(),
        ms,
        request_id.clone(),
    ));
    outcome
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use zeroize::Zeroizing;

    use super::*;
    use crate::CredentialError;

    /// A recording sink standing in for the injected L2 audit sink.
    #[derive(Debug, Default)]
    struct RecordingEmitter {
        records: Mutex<Vec<CredentialAcquire>>,
    }

    impl RecordingEmitter {
        fn records(&self) -> Vec<CredentialAcquire> {
            self.records.lock().unwrap().clone()
        }
    }

    impl Emitter for RecordingEmitter {
        fn emit(&self, record: CredentialAcquire) {
            self.records.lock().unwrap().push(record);
        }
    }

    fn req(id: &str) -> RequestId {
        RequestId::new(id)
    }

    #[test]
    fn record_carries_its_tenant_and_request_id() {
        let rid = RequestId::new("turn-42");
        let rec = CredentialAcquire::new(
            "tenant-a",
            "env",
            "env://GITHUB_TOKEN",
            true,
            3,
            rid.clone(),
        );
        assert_eq!(rec.request_id, rid);
        assert_eq!(rec.tenant, "tenant-a");
    }

    #[test]
    fn record_stores_the_redacted_ref_never_the_raw_locator() {
        let rec = CredentialAcquire::new("t", "op", "op://vault/gh/token", true, 1, req("r1"));
        // Scheme (source kind) survives; the specific locator does not.
        assert_eq!(rec.credential_ref, "op://[REDACTED]");
        assert!(!rec.credential_ref.contains("vault"));
        assert!(!rec.credential_ref.contains("token"));
        // Debug can't leak it either.
        assert!(!format!("{rec:?}").contains("vault"));
    }

    /// AC: the record carries the redacted ref and never the value — for a **successful** resolve.
    #[test]
    fn success_record_has_redacted_ref_and_never_the_value() {
        let emitter = RecordingEmitter::default();
        let secret = "super-secret-token-value";

        let out = audit_resolve(
            &emitter,
            "t",
            "env",
            "env://GITHUB_TOKEN",
            &req("turn-1"),
            || Ok(Zeroizing::new(secret.to_string())),
        );
        // The resolve's secret is returned to the caller untouched...
        assert_eq!(&**out.unwrap(), secret);

        let records = emitter.records();
        assert_eq!(records.len(), 1, "exactly one record for one resolve");
        let rec = &records[0];
        assert!(rec.ok, "a successful resolve records ok = true");
        assert_eq!(rec.source, "env");
        assert_eq!(rec.credential_ref, "env://[REDACTED]");
        // ...but never enters the audit record, in any field or its Debug.
        assert!(!rec.credential_ref.contains(secret));
        assert!(!rec.credential_ref.contains("GITHUB_TOKEN"));
        assert!(!format!("{rec:?}").contains(secret));
    }

    /// AC: the record carries the redacted ref and never the value — for a **failed** resolve.
    /// A failure is a security-relevant event, so it is audited too.
    #[test]
    fn failure_record_has_redacted_ref_and_never_the_value() {
        let emitter = RecordingEmitter::default();
        // A hard failure whose message happens to mention the raw var name — the record must still
        // not leak it (the record is built from the redacted ref, not the error string).
        let out: Result<Zeroizing<String>> = audit_resolve(
            &emitter,
            "t",
            "op",
            "op://vault/gh/token",
            &req("turn-2"),
            || Err(CredentialError::Credential("op read failed".into())),
        );
        assert!(out.is_err());

        let records = emitter.records();
        assert_eq!(records.len(), 1, "a failed resolve is still audited");
        let rec = &records[0];
        assert!(!rec.ok, "a failed resolve records ok = false");
        assert_eq!(rec.source, "op");
        assert_eq!(rec.credential_ref, "op://[REDACTED]");
        assert!(!rec.credential_ref.contains("vault"));
        assert!(!rec.credential_ref.contains("token"));
    }

    /// The injected sink is used through the object-safe `dyn Emitter` — the shape production uses.
    #[test]
    fn emits_through_boxed_dyn_emitter() {
        let boxed: Box<dyn Emitter> = Box::new(RecordingEmitter::default());
        boxed.emit(CredentialAcquire::new(
            "t",
            "file",
            "file:///etc/secret",
            true,
            0,
            req("r3"),
        ));
        // Object-safety holds (this compiles) and emission is fire-and-forget (returns ()).
    }

    #[test]
    fn both_outcomes_emit_exactly_one_record_each() {
        let emitter = RecordingEmitter::default();
        let _ = audit_resolve(&emitter, "t", "env", "env://A", &req("r"), || {
            Ok(Zeroizing::new("v".to_string()))
        });
        let _: Result<Zeroizing<String>> =
            audit_resolve(&emitter, "t", "env", "env://B", &req("r"), || {
                Err(CredentialError::SecretNotFound(redact_credential_ref(
                    "env://B",
                )))
            });
        let records = emitter.records();
        assert_eq!(records.len(), 2);
        assert!(records[0].ok);
        assert!(!records[1].ok);
    }
}
