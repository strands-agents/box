//! Shared test-side readers for the box's own output.
//!
//! # Why this is one crate and not a copy per suite
//!
//! Both test suites judge a run by reading the box's decision journal, and both must
//! agree on what a decision *is*. When they each carried their own reader they drifted:
//! the workload suite's `journal_find.py` queried `strands.policy.action` after the box
//! renamed the attribute to `strands.box.policy.action`, so every journal assertion in
//! that suite matched nothing and reported a schema drift as a containment failure.
//!
//! [`parse_decisions`] reads **every** key generation, newest first, so a suite built
//! against this crate runs against a box from either side of those renames. A shared
//! parser cannot drift per suite, which is the entire reason this crate exists.
//!
//! # What belongs here
//!
//! Readers of the box's output that more than one suite needs, and nothing else. No
//! assertions, no launcher, no verdict rule — those are suite-specific and live with
//! the suite that owns them (`test-integ/` for the deterministic cases,
//! `test-workload/verdict/` for the agent-driven ones).
//!
//! This crate links no product crate. Like the suites that depend on it, it reads the
//! built box's artefacts as data rather than calling into it.

/// One policy decision the box journaled: an OTLP log record carrying the
/// `strands.box.policy.*` attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// `Box::Action::"shell:spawn"`, `Box::Action::"fs:read"`, …
    pub action: String,
    /// The path or program as the box reports it (`~/…` under the operator home).
    pub resource: String,
    /// The engine's rule id (`policy_6`), `default-deny`, or `enforcement:<gate>` (e.g.
    /// `enforcement:reach-floor`). NOT the policy's `@id` annotation: the engine numbers rules by
    /// position, so an authored id must be read from [`Decision::determining_ids`].
    ///
    /// Carried by `strands.box.policy.rule`. Earlier boxes spelled it `security_rule.name`, and
    /// before that `strands.policy.rule` (see the box's `crates/telemetry/AGENTS.md`); the same
    /// value vocabulary throughout. Every generation is read, newest first, so this harness runs
    /// against a box from either side of those renames.
    pub rule: String,
    /// `permit` or `deny`.
    pub verdict: String,
    /// The refusal class as the box spells it (`telemetry.rs::deny_reason`): `a forbid rule
    /// matched`, `no permit matched`, …; empty on a permit.
    pub reason: String,
    /// `strands.box.policy.determining.ids`: for each policy that determined the decision, its `@id`
    /// annotation when it has one, else the engine rule id (`telemetry.rs::policy_identifier`).
    /// This is the only journal field that carries an authored id.
    pub determining_ids: Vec<String>,
    /// The record's `timeUnixNano`, or 0 when the record carries none.
    pub at_unix_nano: u64,
}

/// The box's spelling of a refusal caused by a matching `forbid` (`telemetry.rs::deny_reason`).
pub const FORBID_REASON: &str = "a forbid rule matched";

impl Decision {
    pub fn denied(&self) -> bool {
        self.verdict == "deny"
    }
    pub fn permitted(&self) -> bool {
        self.verdict == "permit"
    }
    /// Whether this decision is about `action` (a bare name like `shell:spawn`).
    pub fn is_action(&self, action: &str) -> bool {
        self.action == format!("Box::Action::\"{action}\"") || self.action == action
    }
    /// A deny caused by a `forbid` whose `@id` is `annotation_id`: the reason is the forbid class
    /// (not `no permit matched`, which is default-deny) and the determining ids name the annotation.
    /// The engine rule id is never consulted — it is positional and not the authored id.
    pub fn forbidden_by(&self, annotation_id: &str) -> bool {
        self.denied()
            && self.reason == FORBID_REASON
            && self.determining_ids.iter().any(|id| id == annotation_id)
    }
}

/// Parse the box's decision journal (one OTLP request per line) into decisions.
pub fn parse_decisions(journal: &str) -> Vec<Decision> {
    let mut found = Vec::new();
    for line in journal.lines() {
        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        for resource in parsed["resourceLogs"].as_array().into_iter().flatten() {
            for scope in resource["scopeLogs"].as_array().into_iter().flatten() {
                for entry in scope["logRecords"].as_array().into_iter().flatten() {
                    let read = |key: &str| {
                        entry["attributes"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .find(|attribute| attribute["key"] == key)
                            .and_then(|attribute| attribute["value"]["stringValue"].as_str())
                            .map(str::to_string)
                    };
                    // An OTLP array attribute (`record.rs::text_list`): `arrayValue.values[].stringValue`.
                    let read_list = |key: &str| -> Vec<String> {
                        entry["attributes"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .find(|attribute| attribute["key"] == key)
                            .and_then(|attribute| {
                                attribute["value"]["arrayValue"]["values"].as_array()
                            })
                            .into_iter()
                            .flatten()
                            .filter_map(|value| value["stringValue"].as_str())
                            .map(str::to_string)
                            .collect()
                    };
                    // Every box attribute moved under the `strands.box.` reserve (upstream
                    // "reserve strands.box. alone, and relay every harness signal"): a box key
                    // outside that prefix is forgeable by a harness payload, so the reserve was
                    // narrowed and the keys moved with it. Each lookup tries the current key
                    // first, then the pre-rename one, so this harness reports the same decisions
                    // against a box from either side of that change.
                    let read_any = |keys: &[&str]| keys.iter().find_map(|key| read(key));
                    let Some(action) =
                        read_any(&["strands.box.policy.action", "strands.policy.action"])
                    else {
                        continue;
                    };
                    found.push(Decision {
                        action,
                        resource: read_any(&[
                            "strands.box.policy.resource",
                            "strands.policy.resource",
                        ])
                        .unwrap_or_default(),
                        // `strands.box.policy.rule` is the current key. It replaced
                        // `security_rule.name`, which had itself replaced `strands.policy.rule`;
                        // all three carry the same value vocabulary. Read every generation, newest
                        // first, so a pre-rename box still reports its rule instead of an empty
                        // string — which would read as "no rule named" and fail every attribution
                        // assertion.
                        rule: read_any(&[
                            "strands.box.policy.rule",
                            "security_rule.name",
                            "strands.policy.rule",
                        ])
                        .unwrap_or_default(),
                        verdict: read_any(&[
                            "strands.box.policy.verdict",
                            "strands.policy.verdict",
                        ])
                        .unwrap_or_default(),
                        reason: read_any(&["strands.box.policy.reason", "strands.policy.reason"])
                            .unwrap_or_default(),
                        determining_ids: {
                            let ids = read_list("strands.box.policy.determining.ids");
                            if ids.is_empty() {
                                read_list("strands.policy.determining.ids")
                            } else {
                                ids
                            }
                        },
                        at_unix_nano: match &entry["timeUnixNano"] {
                            serde_json::Value::String(text) => text.parse().unwrap_or(0),
                            serde_json::Value::Number(number) => number.as_u64().unwrap_or(0),
                            _ => 0,
                        },
                    });
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decisions_parse_from_otlp_lines() {
        let line = serde_json::json!({
            "resourceLogs": [{"scopeLogs": [{"scope": {"name": "strands-box.policy"}, "logRecords": [
                {"timeUnixNano": "1700000000123456789", "attributes": [
                    {"key": "strands.box.policy.principal", "value": {"stringValue": "agent"}},
                    {"key": "strands.box.policy.action", "value": {"stringValue": "Box::Action::\"shell:spawn\""}},
                    {"key": "strands.box.policy.resource", "value": {"stringValue": "/usr/bin/git"}},
                    // All three rule-key generations, disagreeing: the current
                    // `strands.box.policy.rule` wins over `security_rule.name`, which in turn
                    // replaced `strands.policy.rule`.
                    {"key": "strands.box.policy.rule", "value": {"stringValue": "default-deny"}},
                    {"key": "security_rule.name", "value": {"stringValue": "the-middle-key"}},
                    {"key": "strands.policy.rule", "value": {"stringValue": "the-replaced-key"}},
                    {"key": "strands.box.policy.verdict", "value": {"stringValue": "deny"}},
                    {"key": "strands.box.policy.reason", "value": {"stringValue": "No permit policy matched"}}
                ]},
                {"timeUnixNano": 1700000000987654321u64, "attributes": [
                    // A pre-rename box: every key outside the `strands.box.` reserve. The
                    // fallbacks are what let this harness run against such a box.
                    {"key": "strands.policy.action", "value": {"stringValue": "Box::Action::\"fs:delete\""}},
                    {"key": "strands.policy.resource", "value": {"stringValue": "~/ws/cn-x-02.sh"}},
                    {"key": "strands.policy.rule", "value": {"stringValue": "policy_6"}},
                    {"key": "strands.policy.verdict", "value": {"stringValue": "deny"}},
                    {"key": "strands.policy.reason", "value": {"stringValue": "a forbid rule matched"}},
                    {"key": "strands.policy.determining.ids", "value": {"arrayValue": {"values": [{"stringValue": "no_deletes"}, {"stringValue": "policy_2"}]}}},
                    {"key": "strands.policy.determining.tokens", "value": {"arrayValue": {"values": [{"stringValue": "t1"}, {"stringValue": "t2"}]}}}
                ]},
                {"attributes": [{"key": "strands.control.operation", "value": {"stringValue": "load"}}]}
            ]}]}]
        });
        let journal = format!("{line}\nnot json\n{line}\n");
        let found = parse_decisions(&journal);
        assert_eq!(found.len(), 4);
        assert!(found[0].is_action("shell:spawn"));
        assert!(found[0].denied());
        assert_eq!(found[0].resource, "/usr/bin/git");
        assert_eq!(
            found[0].rule, "default-deny",
            "the current rule key must win over the ones it replaced"
        );
        assert_eq!(found[0].at_unix_nano, 1_700_000_000_123_456_789);
        assert_eq!(found[1].at_unix_nano, 1_700_000_000_987_654_321);
        assert_eq!(found[2].at_unix_nano, 1_700_000_000_123_456_789);
        assert!(found[0].determining_ids.is_empty());
        // The array attribute is read as a list; the engine rule id stays what the engine said. This
        // record carries ONLY `strands.policy.rule`, so it also pins the pre-rename fallback.
        assert_eq!(found[1].rule, "policy_6");
        assert_eq!(
            found[1].determining_ids,
            vec!["no_deletes".to_string(), "policy_2".to_string()]
        );
        assert!(
            found[1].forbidden_by("no_deletes")
                && !found[1].forbidden_by("policy_6")
                && !found[0].forbidden_by("no_deletes")
        );
    }
}
