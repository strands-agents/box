use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ratatui::buffer::CellWidth;
use unicode_segmentation::UnicodeSegmentation;

use super::history::{ActivityEntry, ActivityView, HISTORY_LIMIT, Operation};

pub(super) const BANNER_ROWS: u16 = 8;

#[derive(Clone, Copy, Debug)]
pub(super) struct PolicyStatus {
    pub(super) enabled: bool,
    pub(super) changed_at: Option<Instant>,
    pub(super) failed: bool,
    pub(super) reloaded: bool,
    pub(super) pending: bool,
}

impl Default for PolicyStatus {
    fn default() -> Self {
        Self {
            enabled: true,
            changed_at: None,
            failed: false,
            reloaded: false,
            pending: false,
        }
    }
}

/// One policy decision the banner shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Decision {
    pub(super) permitted: bool,
    pub(super) action: String,
    pub(super) resource: String,
    pub(super) reason: Option<String>,
    pub(super) rule: String,
}

impl From<strands_box::PolicyDecision> for Decision {
    fn from(decision: strands_box::PolicyDecision) -> Self {
        Self {
            permitted: decision.permitted,
            action: decision.action,
            resource: decision.resource,
            reason: decision.reason,
            rule: decision.rule,
        }
    }
}

pub(super) struct Banner {
    profile: String,
    cwd: String,
    denial_at: Option<Instant>,
    pub(super) box_label: String,
    pub(super) policy_label: String,
    pub(super) box_file: String,
    pub(super) policy_file: String,
    pub(super) copied: Option<(String, Instant)>,
    blocked: u64,
    total: u64,
    denials: VecDeque<Arc<Operation>>,
    operations: VecDeque<Arc<Operation>>,
    pub(super) activity: ActivityView,
    pub(super) policy: PolicyStatus,
}

pub(super) struct Heading {
    pub(super) line: String,
    pub(super) policy: Range<usize>,
    pub(super) reload: Range<usize>,
    pub(super) minimize: Range<usize>,
    pub(super) activity: Range<usize>,
    pub(super) message: Range<usize>,
    pub(super) policy_notice: bool,
}

impl Banner {
    pub(super) fn new(profile: &str, box_file: &str, policy_file: &str) -> Self {
        let label = |file: &str| {
            std::env::var_os("HOME")
                .map(|home| {
                    crate::host::tilde(std::path::Path::new(&home), std::path::Path::new(file))
                })
                .unwrap_or_else(|| file.to_string())
        };
        Self {
            profile: clean(profile),
            cwd: std::env::current_dir()
                .map(|cwd| clean(&label(&cwd.display().to_string())))
                .unwrap_or_default(),
            denial_at: None,
            box_label: clean(&label(box_file)),
            policy_label: clean(&label(policy_file)),
            box_file: box_file.into(),
            policy_file: policy_file.into(),
            copied: None,
            blocked: 0,
            total: 0,
            denials: VecDeque::new(),
            operations: VecDeque::new(),
            activity: ActivityView::default(),
            policy: PolicyStatus::default(),
        }
    }

    pub(super) fn record(
        &mut self,
        permitted: bool,
        action: &str,
        resource: &str,
        reason: Option<&str>,
        rule: &str,
    ) {
        self.add(permitted, action, resource, reason, rule, None);
    }

    /// Add the decisions earlier runs of this box recorded, before this run makes any, so the
    /// counts start where `box runs history` does. None of them shows as a new denial.
    pub(super) fn restore(&mut self, saved: crate::records::Saved) {
        saved.each(|decision| {
            self.add(
                decision.permitted,
                decision.action,
                decision.resource,
                decision.reason,
                decision.rule,
                Some(decision.time.unwrap_or(UNIX_EPOCH)),
            );
        });
    }

    fn add(
        &mut self,
        permitted: bool,
        action: &str,
        resource: &str,
        reason: Option<&str>,
        rule: &str,
        recorded: Option<SystemTime>,
    ) {
        self.total = self.total.saturating_add(1);
        let operation = Arc::new(Operation::at(
            self.total,
            permitted,
            action,
            resource,
            reason,
            rule,
            recorded.unwrap_or_else(SystemTime::now),
        ));
        if !permitted {
            if recorded.is_none() {
                self.denial_at = Some(Instant::now());
            }
            self.blocked = self.blocked.saturating_add(1);
            if self.denials.len() == HISTORY_LIMIT {
                self.denials.pop_front();
            }
            self.denials.push_back(Arc::clone(&operation));
        }
        if self.operations.len() == HISTORY_LIMIT {
            self.operations.pop_front();
        }
        self.operations.push_back(operation);
    }

    fn top_denials(&self) -> Vec<ActivityEntry<'_>> {
        let mut groups = BTreeMap::new();
        for denial in &self.denials {
            let group = groups.entry(denial.kind).or_insert(ActivityEntry {
                operation: denial,
                count: 0,
            });
            group.count += 1;
            group.operation = denial;
        }
        let mut groups: Vec<_> = groups.into_values().collect();
        groups.sort_unstable_by_key(|group| {
            (
                std::cmp::Reverse(group.count),
                std::cmp::Reverse(group.operation.id),
            )
        });
        groups
    }

    pub(super) fn entries(&self) -> Vec<ActivityEntry<'_>> {
        let operations = match self.activity {
            ActivityView::TopDenials => return self.top_denials(),
            ActivityView::LatestDenials => &self.denials,
            ActivityView::AllOperations => &self.operations,
        };
        operations
            .iter()
            .rev()
            .map(|operation| ActivityEntry {
                operation,
                count: 1,
            })
            .collect()
    }

    fn retained(&self) -> (usize, u64) {
        if self.activity == ActivityView::AllOperations {
            (self.operations.len(), self.total)
        } else {
            (self.denials.len(), self.blocked)
        }
    }

    fn count(&self) -> String {
        format!(
            "{} {} denied",
            self.blocked,
            if self.blocked == 1 {
                "operation"
            } else {
                "operations"
            }
        )
    }

    pub(super) fn recent_denial(&self) -> Option<&Operation> {
        self.denial_at
            .filter(|at| at.elapsed() < Duration::from_secs(5))
            .and_then(|_| self.denials.back().map(Arc::as_ref))
    }

    pub(super) fn heading(
        &self,
        columns: usize,
        activity_start: Option<usize>,
        minimized: bool,
    ) -> Heading {
        let identity = if self.policy.enabled {
            "● box"
        } else {
            "○ box"
        };
        let profile = format!(" • {}", self.profile);
        let policy_notice = self
            .policy
            .changed_at
            .is_some_and(|at| !self.policy.enabled || at.elapsed() < Duration::from_secs(5));
        let message = policy_notice
            .then(|| {
                match (self.policy.enabled, self.policy.failed) {
                    (true, false) if self.policy.pending => " UPDATE READY • Ctrl+Alt+R reload ",
                    (true, true) if self.policy.pending => " RELOAD FAILED • Ctrl+Alt+R retry ",
                    (false, _) if self.policy.pending => " POLICY OFF (update ready) ",
                    (true, false) if self.policy.reloaded => " POLICY RELOADED ",
                    (true, false) => " POLICY ON ",
                    (false, false) => " POLICY OFF ",
                    (true, true) => " POLICY ON (update failed) ",
                    (false, true) => " POLICY OFF (update failed) ",
                }
                .to_owned()
            })
            .or_else(|| {
                self.recent_denial().filter(|_| minimized).map(|operation| {
                    format!(
                        "BLOCKED {} {} ({})",
                        operation.action, operation.resource, operation.reason
                    )
                })
            });
        let message_width = message.as_deref().map_or(0, display_width);
        let policy_width = if policy_notice { 3 + message_width } else { 0 };
        let notice_width =
            policy_notice.then(|| display_width(identity) + display_width(&profile) + policy_width);
        let title = self.activity.title();
        let compact_activity = format!("{title} • {} denied", self.blocked);
        let minimum_controls = display_width(r" Ctrl+\ • Ctrl+] ");
        let reload_hint = if self.policy.pending && self.policy.enabled && !policy_notice {
            fit(
                "Ctrl+Alt+R to reload policy",
                columns.saturating_sub(display_width(identity) + minimum_controls + 4),
            )
        } else {
            String::new()
        };
        let hint_width = if reload_hint.is_empty() {
            0
        } else {
            display_width(&reload_hint) + 2
        };
        let policy_space = display_width(identity)
            + if self.policy.pending {
                policy_width
            } else {
                display_width(" •  POLICY OFF ")
            };
        let activity_start = activity_start.filter(|start| {
            policy_space <= start.saturating_sub(2)
                && (hint_width == 0
                    || start + display_width(title) + hint_width + minimum_controls + 2 <= columns)
        });
        let count = if minimized || (policy_notice && activity_start.is_none()) {
            format!(" • {}", self.count())
        } else {
            String::new()
        };
        let size_control = if minimized {
            "Ctrl+] expand"
        } else {
            "Ctrl+] minimize"
        };
        let (retained, total) = self.retained();
        let scope = if total > retained as u64 {
            format!("Latest {retained} of {total} • ")
        } else {
            String::new()
        };
        let full_activity = format!("{title} • {scope}{}", self.count());
        let notice_space = columns.saturating_sub(minimum_controls);
        let left_width = if minimized || self.policy.pending {
            notice_width
                .map(|width| width + display_width(&count))
                .unwrap_or_else(|| display_width(identity))
                .min(notice_space)
                .max(display_width(identity))
        } else {
            policy_space
        };
        let controls_width = columns.saturating_sub(
            activity_start.map_or(left_width, |start| start + display_width(title) + 2)
                + hint_width,
        );
        let (policy, minimize) = [r"Ctrl+\ policy on/off", r"Ctrl+\"]
            .into_iter()
            .find_map(|policy| {
                [compact_activity.as_str(), title]
                    .into_iter()
                    .find_map(|activity| {
                        [size_control, "Ctrl+]"]
                            .into_iter()
                            .find(|minimize| {
                                let width = display_width(policy) + display_width(minimize) + 3;
                                width + 2 <= controls_width
                                    && activity_start.is_none_or(|begin| {
                                        begin + display_width(activity) + width + 3 + hint_width
                                            <= columns
                                    })
                            })
                            .map(|minimize| (policy, minimize))
                    })
            })
            .unwrap_or_default();
        let suffix = if minimize.is_empty() {
            String::new()
        } else {
            format!(" {policy} • {minimize} ")
        };
        let start = columns - display_width(&suffix);
        let content_end = start.saturating_sub(hint_width);
        let activity_start = activity_start.filter(|&begin| (2..content_end).contains(&begin));
        let width = activity_start.map_or(content_end, |begin| begin - 2);
        let profile = if policy_notice {
            fit(
                &profile,
                width
                    .saturating_sub(display_width(identity) + policy_width + display_width(&count)),
            )
        } else {
            profile
        };
        let path_width = width.saturating_sub(
            display_width(identity)
                + policy_width
                + display_width(&profile)
                + display_width(&count)
                + 3,
        );
        let cwd = if path_width > 0 && !self.cwd.is_empty() {
            format!(" • {}", fit(&self.cwd, path_width))
        } else {
            String::new()
        };
        let metadata = match &message {
            Some(message) if policy_notice => format!(" • {message}{profile}{cwd}{count}"),
            Some(message) => format!("{profile} • {message}"),
            None => format!("{profile}{cwd}{count}"),
        };
        let mut left = if width >= display_width(identity) {
            format!(
                "{identity}{}",
                fit(&metadata, width - display_width(identity))
            )
        } else {
            fit(identity, width)
        };
        let message = message.map_or(0..0, |_| {
            let start = display_width(identity)
                + 3
                + if policy_notice {
                    0
                } else {
                    display_width(&profile)
                };
            let end = display_width(&left).min(start + message_width);
            start.min(end)..end
        });
        let activity = if let Some(begin) = activity_start {
            let activity_room = content_end - begin;
            let activity = [full_activity, compact_activity, title.to_string()]
                .into_iter()
                .find(|activity| display_width(activity) <= activity_room)
                .unwrap_or_else(|| fit(title, activity_room));
            let title_width = display_width(title).min(display_width(&activity));
            left.push_str(&format!(
                " {} {activity}",
                " ".repeat(begin.saturating_sub(display_width(&left) + 2)),
            ));
            begin..begin + title_width
        } else {
            0..0
        };
        let reload = if !reload_hint.is_empty() {
            let left_end = display_width(&left);
            let begin = left_end + (start - left_end - display_width(&reload_hint)) / 2;
            left.push_str(&" ".repeat(begin - left_end));
            left.push_str(&reload_hint);
            begin..begin + display_width(&reload_hint)
        } else if self.policy.pending && self.policy.enabled && policy_notice {
            message.clone()
        } else {
            0..0
        };
        let remaining = start - display_width(&left);
        let policy_start = start + 1;
        let minimize_start = policy_start + display_width(policy) + 3;
        Heading {
            reload,
            message,
            policy_notice,
            line: format!("{left}{}{suffix}", " ".repeat(remaining)),
            policy: if suffix.is_empty() {
                0..0
            } else {
                policy_start..policy_start + display_width(policy)
            },
            minimize: if suffix.is_empty() {
                0..0
            } else {
                minimize_start..minimize_start + display_width(minimize)
            },
            activity,
        }
    }
}

pub(super) fn clean(text: &str) -> String {
    let mut characters = text.chars();
    let mut text = String::new();
    for character in characters.by_ref().take(2048) {
        if character.is_control()
            || matches!(character, '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}')
        {
            text.extend(character.escape_default());
        } else {
            text.push(character);
        }
    }
    if characters.next().is_some() {
        text.push('…');
    }
    text
}

pub(super) fn display_width(text: &str) -> usize {
    text.graphemes(true)
        .map(|grapheme| usize::from(grapheme.cell_width()))
        .sum()
}

pub(super) fn fit(text: &str, columns: usize) -> String {
    if display_width(text) <= columns {
        return text.to_owned();
    }
    let mut remaining = columns.saturating_sub(1);
    let mut clipped: String = text
        .graphemes(true)
        .take_while(|character| {
            let width = usize::from(character.cell_width());
            if width > remaining {
                return false;
            }
            remaining -= width;
            true
        })
        .collect();
    if columns > 0 {
        clipped.push('…');
    }
    clipped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn top_denials_count_matching_operation_target_and_policy() {
        let mut banner = Banner::new("custom", "/project", "/run/policy.dw");
        for (action, target, rule) in [
            ("fs:read", "/secret", "private"),
            ("fs:read", "/secret", "private"),
            ("fs:read", "/secret", "other"),
            ("fs:write", "/secret", "private"),
            ("fs:read", "/elsewhere", "private"),
        ] {
            banner.record(false, action, target, Some("refused"), rule);
        }
        banner.record(true, "fs:read", "/secret", None, "private");
        let groups = banner.top_denials();
        assert_eq!(groups.len(), 4);
        assert_eq!(groups[0].count, 2);
        assert_eq!(groups[0].operation.id, 2);
        assert_eq!(groups.iter().map(|group| group.count).sum::<usize>(), 5);
    }

    #[test]
    fn display_truncation_and_escaping_do_not_merge_distinct_denials() {
        let mut banner = Banner::new("custom", "/project", "/run/policy.dw");
        for target in [
            format!("{}a", "x".repeat(2048)),
            format!("{}b", "x".repeat(2048)),
            "line\nbreak".to_string(),
            r"line\nbreak".to_string(),
        ] {
            banner.record(false, "shell:exec", &target, None, "private");
        }
        assert_eq!(banner.top_denials().len(), 4);
    }

    #[test]
    fn a_reused_box_starts_from_the_denials_history_lists_without_a_new_denial_notice() {
        let home = tempfile::tempdir().unwrap();
        let run = home.path().join(".strands/box/r/b-5b8e3d70c92f14ab");
        std::fs::create_dir_all(&run).unwrap();
        let span = |verdict: &str, path: &str, enforced: Option<bool>| {
            let mut attributes = vec![
                serde_json::json!({"key": "strands.box.policy.action",
                    "value": {"stringValue": "Box::Action::\"fs:read\""}}),
                serde_json::json!({"key": "strands.box.policy.verdict",
                    "value": {"stringValue": verdict}}),
                serde_json::json!({"key": "strands.box.policy.resource",
                    "value": {"stringValue": path}}),
                serde_json::json!({"key": "strands.box.policy.rule",
                    "value": {"stringValue": "no_env"}}),
            ];
            if let Some(enforced) = enforced {
                attributes.push(serde_json::json!({"key": "strands.box.policy.enforced",
                    "value": {"boolValue": enforced}}));
            }
            serde_json::json!({"spanId": "1234567812345678", "name": "policy fs:read",
                "startTimeUnixNano": "1795000000000000000", "attributes": attributes})
        };
        let batch = serde_json::json!({"resourceSpans": [{"scopeSpans": [
            {"scope": {"name": "strands-box.policy"}, "spans": [
                span("deny", "/p/.env", None),
                span("permit", "/p/README.md", None),
                span("deny", "/p/.env", None),
                span("deny", "/p/would", Some(false)),
                span("deny", "/p/.env", None),
            ]},
            {"scope": {"name": "agent"}, "spans": [span("deny", "/p/agent", None)]}
        ]}]});
        std::fs::write(run.join("records.jsonl"), format!("{batch}\n")).unwrap();

        let saved = crate::records::saved(home.path(), &run.join("records.jsonl")).unwrap();
        // Bytes appended after the file was opened belong to this run, which the channel delivers.
        std::fs::OpenOptions::new()
            .append(true)
            .open(run.join("records.jsonl"))
            .unwrap()
            .write_all(format!("{batch}\n").as_bytes())
            .unwrap();

        let mut banner = Banner::new("claude", "/p/profile.toml", "/p/policy.dw");
        banner.restore(saved);
        assert_eq!((banner.blocked, banner.total), (3, 4));
        assert!(banner.recent_denial().is_none());
        assert_eq!(banner.entries()[0].count, 3);

        banner.record(false, "fs:read", "/p/live", None, "no_env");
        assert_eq!(banner.blocked, 4);
        assert_eq!(banner.recent_denial().unwrap().resource, "/p/live");
        assert_eq!(banner.recent_denial().unwrap().id, 5);

        assert!(
            crate::records::saved(
                home.path(),
                &home
                    .path()
                    .join(".strands/box/r/b-0000000000000000/records.jsonl")
            )
            .is_none()
        );
    }

    #[test]
    fn saved_history_uses_the_selected_home_without_following_links() {
        let home = tempfile::tempdir().unwrap();
        for folder in [".strands/box", "custom"] {
            let run = home.path().join(folder).join("r/b-5b8e3d70c92f14ab");
            std::fs::create_dir_all(&run).unwrap();
            let journal = run.join("records.jsonl");
            std::fs::write(&journal, "{}\n").unwrap();
            assert!(crate::records::saved(home.path(), &journal).is_some());
        }
        let strands = home.path().join(".strands");
        let outside = home.path().join("outside");
        std::fs::rename(&strands, &outside).unwrap();
        std::os::unix::fs::symlink(&outside, &strands).unwrap();
        let journal = strands.join("box/r/b-5b8e3d70c92f14ab/records.jsonl");
        assert!(crate::records::saved(home.path(), &journal).is_none());
    }

    #[test]
    fn top_denials_groups_refused_requests_by_host_and_shows_the_latest_path() {
        let mut banner = Banner::new("custom", "/run/box.toml", "/run/policy.dw");
        for path in ["/v1/a", "/v1/b", "/v1/a", "/v1/c"] {
            let resource = format!("example.org:443{path}");
            banner.record(false, "http:request", &resource, None, "no_org");
        }
        banner.record(false, "http:request", "example.net:443/", None, "no_org");
        banner.record(false, "fs:read", "/a/v1", None, "no_org");
        banner.record(false, "fs:read", "/b/v1", None, "no_org");
        let entries = banner.entries();
        let rows: Vec<_> = entries
            .iter()
            .map(|entry| (entry.count, entry.operation.resource.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                (4, "example.org:443/v1/c"),
                (1, "/b/v1"),
                (1, "/a/v1"),
                (1, "example.net:443/"),
            ]
        );
    }

    #[test]
    fn views_keep_counts_and_individual_approved_and_denied_operations() {
        let mut banner = Banner::new("custom", "/run/box.toml", "/run/policy.dw");
        banner.record(false, "http:request", "blocked", None, "private");
        banner.record(true, "http:request", "allowed", None, "permit");
        banner.record(false, "http:request", "blocked", None, "private");
        assert_eq!(banner.entries().len(), 1);
        assert_eq!(banner.entries()[0].count, 2);
        banner.activity = banner.activity.next();
        let latest = banner.entries();
        assert_eq!(
            latest
                .iter()
                .map(|entry| entry.operation.id)
                .collect::<Vec<_>>(),
            [3, 1]
        );
        banner.activity = banner.activity.next();
        let all = banner.entries();
        assert_eq!(
            all.iter()
                .map(|entry| entry.operation.id)
                .collect::<Vec<_>>(),
            [3, 2, 1]
        );
        assert!(all[1].operation.permitted);
        assert_eq!(banner.blocked, 2);
        assert_eq!(banner.total, 3);
        banner.cwd = "~/project".into();
        banner.policy.enabled = false;
        banner.policy.changed_at = Some(Instant::now());
        assert!(
            banner
                .heading(120, None, true)
                .line
                .contains(" • ~/project • 2 operations denied")
        );
    }

    #[test]
    fn approved_traffic_does_not_evict_denial_history() {
        let mut banner = Banner::new("custom", "/run/box.toml", "/run/policy.dw");
        banner.record(false, "fs:read", "/secret", None, "private");
        for _ in 0..HISTORY_LIMIT + 1 {
            banner.record(true, "fs:read", "/allowed", None, "permit");
        }
        assert_eq!(banner.denials.len(), 1);
        assert_eq!(banner.top_denials()[0].count, 1);
        banner.activity = ActivityView::AllOperations;
        assert_eq!(banner.retained(), (HISTORY_LIMIT, HISTORY_LIMIT as u64 + 2));
    }

    #[test]
    fn bounded_history_evicts_the_oldest_denial() {
        let mut banner = Banner::new(
            "claude",
            "/project",
            "/home/.strands/box/r/example/policy.dw",
        );
        banner.record(false, "http:request", "first", None, "<default-deny>");
        for _ in 0..HISTORY_LIMIT {
            banner.record(false, "http:request", "new", None, "<default-deny>");
        }
        assert_eq!(banner.denials.len(), HISTORY_LIMIT);
        assert_eq!(banner.blocked, HISTORY_LIMIT as u64 + 1);
        assert_eq!(banner.top_denials().len(), 1);
        assert_eq!(banner.top_denials()[0].count, HISTORY_LIMIT);
        assert_eq!(banner.denials.front().unwrap().resource, "new");
    }
}
