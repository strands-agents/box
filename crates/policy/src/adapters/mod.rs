//! Adapters from the policy facade to each enforcement point's own effect seam.
//!
//! | | `egress` | `shell` | `script` |
//! |---|---|---|---|
//! | boundary | egress-proxy | Strands Shell | Monty |
//! | feature | `egress-adapter` | `shell-adapter` | `script-adapter` |
//! | actions | `net:connect`, `http:request` | `shell:exec`, `fs:*` | `fs:*` |
//! | refusal | `io::Error` | `io::Error` | a Python exception |
//!
//! The egress row names two actions because the release of a reply raises no decision. The
//! reply reaches history once, as `output.status` on the request's `http:request::response`.
//!
//! [`Request`]: crate::Request
//! [`PolicyEngine::decide`]: crate::PolicyEngine::decide
//! [`PolicyEngine::record`]: crate::PolicyEngine::record
//! [`Decision::Allow`]: crate::Decision::Allow

#[cfg(feature = "egress-adapter")]
pub(crate) mod egress;
#[cfg(feature = "script-adapter")]
pub(crate) mod script;
#[cfg(feature = "shell-adapter")]
pub(crate) mod shell;

#[cfg(all(
    test,
    any(
        feature = "egress-adapter",
        feature = "script-adapter",
        feature = "shell-adapter"
    )
))]
mod correlation_tests {
    pub(super) fn events(path: &std::path::Path) -> Vec<dogwood_language::Event> {
        let log = dogwood_local_engine::DurableLog::open(path).expect("history opens");
        let mut events = Vec::new();
        log.scan_from(0, |_, bytes| {
            if let dogwood_local_engine::Record::Event(event) =
                dogwood_local_engine::Record::decode(bytes).expect("history decodes")
            {
                events.push(event);
            }
        })
        .expect("history scans");
        events
    }

    pub(super) fn id(event: &dogwood_language::Event) -> String {
        match event.field_path(&["requestId".to_string()]) {
            Some(dogwood_language::Value::String(id)) if !id.is_empty() => id.clone(),
            value => panic!(
                "{} {} lacks its request identifier: {value:?}",
                event.action(),
                event.kind()
            ),
        }
    }

    pub(super) fn assert_pair(
        request: &dogwood_language::Event,
        outcome: &dogwood_language::Event,
    ) {
        assert_eq!(request.kind(), "request");
        assert!(matches!(outcome.kind(), "response" | "error"));
        assert_eq!(request.action(), outcome.action());
        assert_eq!(id(request), id(outcome));
    }
}
