use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::events::{MAX_INTEGER, elapsed_ms};
use crate::journal::{Decision, Verdict};

pub const POLLING_INTERVAL: Duration = Duration::from_secs(60);

const ACTIONS: [&str; 12] = [
    "fs:read",
    "fs:write",
    "fs:delete",
    "fs:move",
    "fs:other",
    "net:connect",
    "http:request",
    "shell:exec",
    "shell:spawn",
    "mcp:call",
    "mcp_tool",
    "unknown",
];
const OUTCOMES: [&str; 7] = [
    "permitted",
    "forbidden",
    "no_match",
    "policy_pending",
    "internal_fault",
    "enforcement",
    "unknown",
];

/// The MCP action namespaces for this invocation.
#[derive(Default)]
pub struct ActionCatalog {
    mcp: BTreeSet<String>,
    known: bool,
}

impl ActionCatalog {
    /// Normalize configured MCP names to Core's journal categories.
    pub fn new(mcp_names: impl IntoIterator<Item = String>) -> Self {
        Self {
            mcp: mcp_names
                .into_iter()
                .map(|name| mcp_namespace(&name))
                .collect(),
            known: true,
        }
    }

    fn action(&self, decision: &Decision) -> usize {
        let unknown = ACTIONS.len() - 1;
        if !self.known || decision.category.starts_with("Tool::") {
            return unknown;
        }
        if self.mcp.contains(&decision.category) {
            let collision = ACTIONS.iter().any(|action| {
                action
                    .split_once(':')
                    .is_some_and(|(category, _)| category == decision.category)
            });
            return if collision { unknown } else { 10 };
        }
        if !decision
            .action
            .split_once(':')
            .is_some_and(|(category, _)| category == decision.category)
        {
            return unknown;
        }
        ACTIONS
            .iter()
            .position(|action| *action == decision.action)
            .unwrap_or(if decision.category == "fs" {
                4
            } else {
                unknown
            })
    }
}

fn mcp_namespace(name: &str) -> String {
    let mut namespace: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect();
    if namespace.as_bytes().first().is_none_or(u8::is_ascii_digit) {
        namespace.insert(0, '_');
    }
    if matches!(
        namespace.as_str(),
        "true" | "false" | "if" | "then" | "else" | "in" | "is" | "like" | "has" | "__cedar"
    ) {
        namespace.push('_');
    }
    namespace
}

/// Decision deltas for one observed interval.
pub struct DecisionInterval {
    started: Instant,
    catalog: ActionCatalog,
    counts: [[u64; OUTCOMES.len()]; ACTIONS.len()],
}

/// The bounded data of a complete polling observation.
#[derive(Debug, Clone, Serialize)]
pub struct Polling {
    interval_duration_ms: u64,
    decisions: Vec<Count>,
}

#[derive(Debug, Clone, Serialize)]
struct Count {
    action: &'static str,
    outcome: &'static str,
    count: u64,
}

impl DecisionInterval {
    pub fn new(started: Instant, catalog: ActionCatalog) -> Self {
        Self {
            started,
            catalog,
            counts: [[0; OUTCOMES.len()]; ACTIONS.len()],
        }
    }

    /// Add one decision to exactly one bounded pair.
    pub fn observe(&mut self, decision: Decision) {
        let action = self.catalog.action(&decision);
        let outcome = match decision.verdict {
            Verdict::Permit => 0,
            Verdict::Deny => OUTCOMES[1..]
                .iter()
                .position(|outcome| Some(*outcome) == decision.cause.as_deref())
                .map_or(OUTCOMES.len() - 1, |index| index + 1),
        };
        self.counts[action][outcome] = self.counts[action][outcome]
            .saturating_add(1)
            .min(MAX_INTEGER);
    }

    /// Finish this interval and discard its counters if observation was incomplete.
    pub fn finish(&mut self, completed: Instant, complete: bool) -> Option<Polling> {
        let duration = completed.saturating_duration_since(self.started);
        self.started = completed;
        let counts = std::mem::replace(&mut self.counts, [[0; OUTCOMES.len()]; ACTIONS.len()]);
        complete.then(|| Polling {
            interval_duration_ms: elapsed_ms(duration),
            decisions: counts
                .into_iter()
                .enumerate()
                .flat_map(|(action, outcomes)| {
                    outcomes
                        .into_iter()
                        .enumerate()
                        .filter(|(_, count)| *count != 0)
                        .map(move |(outcome, count)| Count {
                            action: ACTIONS[action],
                            outcome: OUTCOMES[outcome],
                            count,
                        })
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(action: &str, category: &str, verdict: Verdict, cause: Option<&str>) -> Decision {
        Decision {
            action: action.into(),
            category: category.into(),
            verdict,
            cause: cause.map(str::to_owned),
        }
    }

    fn catalog() -> ActionCatalog {
        ActionCatalog::new([
            "server_a".into(),
            "issues-mcp".into(),
            "Tool::example".into(),
        ])
    }

    #[test]
    fn actions_follow_core_evidence_and_ambiguous_names_are_unknown() {
        let known = catalog();
        for (action, category, expected) in [
            ("fs:read", "fs", "fs:read"),
            ("fs:write", "fs", "fs:write"),
            ("fs:delete", "fs", "fs:delete"),
            ("fs:move", "fs", "fs:move"),
            ("fs:metadata", "fs", "fs:other"),
            ("net:connect", "net", "net:connect"),
            ("http:request", "http", "http:request"),
            ("shell:exec", "shell", "shell:exec"),
            ("shell:spawn", "shell", "shell:spawn"),
            ("mcp:call", "mcp", "mcp:call"),
            ("any_tool", "server_a", "mcp_tool"),
            ("fs:read", "server_a", "mcp_tool"),
            ("fs:read", "Tool::example", "unknown"),
            ("new:action", "new", "unknown"),
            ("fs:new", "fs", "fs:other"),
            ("fs:read", "shell", "unknown"),
            ("any_tool", "unrecognized_server", "unknown"),
            ("any_tool", "issues_mcp", "mcp_tool"),
        ] {
            let value = decision(action, category, Verdict::Permit, None);
            assert_eq!(ACTIONS[known.action(&value)], expected);
            assert_eq!(ACTIONS[ActionCatalog::default().action(&value)], "unknown");
        }
        let collision = ActionCatalog::new(["fs".into()]);
        assert_eq!(
            ACTIONS[collision.action(&decision("fs:read", "fs", Verdict::Permit, None))],
            "unknown"
        );
    }

    #[test]
    fn mcp_categories_follow_core_server_name_normalization() {
        for (configured, category) in [
            ("issues-mcp", "issues_mcp"),
            ("7-demo", "_7_demo"),
            ("if", "if_"),
            ("true", "true_"),
            ("false", "false_"),
            ("then", "then_"),
            ("else", "else_"),
            ("in", "in_"),
            ("is", "is_"),
            ("like", "like_"),
            ("has", "has_"),
            ("__cedar", "__cedar_"),
            ("réseau.tools", "r_seau_tools"),
            ("Github", "Github"),
        ] {
            let known = ActionCatalog::new([configured.into()]);
            let value = decision("SearchIssues", category, Verdict::Permit, None);
            assert_eq!(ACTIONS[known.action(&value)], "mcp_tool", "{configured}");
            assert_eq!(ACTIONS[ActionCatalog::default().action(&value)], "unknown");
        }
        let known = ActionCatalog::new(["issues-mcp".into()]);
        for category in ["issues-mcp", "Issues_mcp", "issues_mcp_", "unrelated"] {
            let value = decision("SearchIssues", category, Verdict::Permit, None);
            assert_eq!(ACTIONS[known.action(&value)], "unknown", "{category}");
        }
    }

    #[test]
    fn permits_ignore_cause_and_denials_use_only_bounded_causes() {
        let start = Instant::now();
        let mut interval = DecisionInterval::new(start, catalog());
        for cause in [
            None,
            Some("enforcement"),
            Some("forbidden"),
            Some("new-cause"),
        ] {
            for _ in 0..2 {
                interval.observe(decision("fs:read", "fs", Verdict::Permit, cause));
            }
        }
        for (count, cause) in [
            Some("forbidden"),
            Some("no_match"),
            Some("policy_pending"),
            Some("internal_fault"),
            Some("enforcement"),
            Some("new-cause"),
            Some("permitted"),
            None,
        ]
        .into_iter()
        .enumerate()
        {
            for _ in 0..=count {
                interval.observe(decision("fs:read", "fs", Verdict::Deny, cause));
            }
        }
        let polling = interval.finish(start + POLLING_INTERVAL, true).unwrap();
        assert_eq!(polling.decisions.len(), 7);
        for ((row, outcome), count) in polling
            .decisions
            .iter()
            .zip(OUTCOMES)
            .zip([8, 1, 2, 3, 4, 5, 21])
        {
            assert_eq!(row.action, "fs:read");
            assert_eq!(row.outcome, outcome);
            assert_eq!(row.count, count);
        }
    }

    #[test]
    fn complete_intervals_are_deltas_and_incomplete_intervals_are_discarded() {
        let start = Instant::now();
        let mut interval = DecisionInterval::new(start, catalog());
        interval.observe(decision("fs:read", "fs", Verdict::Permit, None));
        let first = interval.finish(start + POLLING_INTERVAL, true).unwrap();
        assert_eq!(first.interval_duration_ms, 60_000);
        assert_eq!(first.decisions[0].count, 1);
        interval.observe(decision("fs:write", "fs", Verdict::Permit, None));
        assert!(
            interval
                .finish(start + Duration::from_secs(61), false)
                .is_none()
        );
        let empty = interval
            .finish(start + Duration::from_micros(62_234_999), true)
            .unwrap();
        assert_eq!(empty.interval_duration_ms, 1234);
        assert!(empty.decisions.is_empty());
        let early = interval.finish(start, true).unwrap();
        assert_eq!(early.interval_duration_ms, 0);
    }

    #[test]
    fn counters_saturate_and_emit_at_most_one_row_per_pair() {
        let start = Instant::now();
        let mut interval = DecisionInterval::new(start, catalog());
        interval.counts.fill([MAX_INTEGER; OUTCOMES.len()]);
        interval.observe(decision("fs:read", "fs", Verdict::Permit, None));
        let polling = interval.finish(start, true).unwrap();
        assert_eq!(polling.decisions.len(), 84);
        let pairs: BTreeSet<_> = polling
            .decisions
            .iter()
            .map(|row| (row.action, row.outcome))
            .collect();
        assert_eq!(pairs.len(), 84);
        assert!(polling.decisions.iter().all(|row| row.count == MAX_INTEGER));
        assert!(interval.finish(start, true).unwrap().decisions.is_empty());
    }
}
