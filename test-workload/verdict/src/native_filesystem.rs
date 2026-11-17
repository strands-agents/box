//! Native file checks against host files, policy records, and agent tool calls.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::Check;

struct Evidence {
    checks: Vec<Check>,
}

impl Evidence {
    fn check(&mut self, id: &str, ok: bool, evidence: impl Into<String>) {
        let mut evidence = evidence.into();
        crate::truncate_on_boundary(&mut evidence, 400);
        self.checks.push(Check {
            id: id.into(),
            ok,
            evidence,
        });
    }

    fn text(&mut self, path: &Path) -> Option<String> {
        match std::fs::read_to_string(path) {
            Ok(text) => Some(text),
            Err(error) => {
                self.check(
                    &format!(
                        "readable-{}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ),
                    false,
                    error.to_string(),
                );
                None
            }
        }
    }

    fn records(&mut self, path: &Path) -> Vec<Value> {
        let Some(text) = self.text(path) else {
            return Vec::new();
        };
        let mut records = Vec::new();
        for (line, text) in text
            .lines()
            .enumerate()
            .filter(|(_, text)| !text.trim().is_empty())
        {
            match serde_json::from_str::<Value>(text) {
                Ok(value) if value.is_object() => records.push(value),
                _ => self.check(
                    &format!(
                        "readable-{}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ),
                    false,
                    format!("line {}: expected a JSON object", line + 1),
                ),
            }
        }
        records
    }

    fn document(&mut self, path: &Path) -> Value {
        let Some(text) = self.text(path) else {
            return Value::Null;
        };
        match serde_json::from_str::<Value>(&text) {
            Ok(value) if value.is_object() => value,
            _ => {
                self.check(
                    &format!(
                        "readable-{}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ),
                    false,
                    "expected one JSON object",
                );
                Value::Null
            }
        }
    }

    fn protected_path(&mut self, value: &Value, project: &Path, home: &str) -> bool {
        let Some(text) = value.as_str() else {
            self.check(
                "protected-attempt-path-readable",
                false,
                "tool call has no file path",
            );
            return false;
        };
        let path = if let Some(relative) = text.strip_prefix("~/") {
            if home.is_empty() {
                self.check("protected-attempt-path-readable", false, "HOME is missing");
                return false;
            }
            Path::new(home).join(relative)
        } else if Path::new(text).is_absolute() {
            PathBuf::from(text)
        } else {
            project.join(text)
        };
        let path = normalize(&path);
        let protected = project.join("protected.txt");
        match (std::fs::metadata(&path), std::fs::metadata(&protected)) {
            (Ok(actual), Ok(expected)) => same_file(&actual, &expected, &path, &protected),
            (Err(error), Ok(_)) if error.kind() == std::io::ErrorKind::NotFound => {
                path == protected
            }
            (Err(error), _) | (_, Err(error)) => {
                self.check("protected-attempt-path-readable", false, error.to_string());
                false
            }
        }
    }
}

fn normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata, _: &Path, _: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(_: &std::fs::Metadata, _: &std::fs::Metadata, a: &Path, b: &Path) -> bool {
    a.canonicalize()
        .ok()
        .zip(b.canonicalize().ok())
        .is_some_and(|(a, b)| a == b)
}

fn timestamp(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str()?.parse().ok())
        .filter(|value| *value > 0)
}

fn mutates_file(decision: &test_common::Decision) -> bool {
    ["fs:write", "fs:move", "fs:delete"]
        .iter()
        .any(|action| decision.is_action(action))
}

fn journal_shape(value: &Value) -> bool {
    if value.get("resourceLogs").is_none() {
        return value["resourceSpans"].is_array() || value["resourceMetrics"].is_array();
    }
    value["resourceLogs"].as_array().is_some_and(|resources| {
        resources.iter().all(|resource| {
            resource["scopeLogs"].as_array().is_some_and(|scopes| {
                scopes.iter().all(|scope| {
                    scope["logRecords"].as_array().is_some_and(|records| {
                        records.iter().all(|record| {
                            record.is_object()
                                && record["attributes"].as_array().is_some_and(|attributes| {
                                    attributes.iter().all(|attribute| {
                                        attribute["key"].is_string()
                                            && attribute["value"].is_object()
                                    })
                                })
                        })
                    })
                })
            })
        })
    })
}

/// Judge native file edits without accepting an agent's summary as evidence.
pub fn checks(run: &Path, agent: &str) -> Vec<Check> {
    let mut evidence = Evidence { checks: Vec::new() };
    let project = run.join("project");
    let result = evidence.document(&run.join("agent-a.json"));
    evidence.check(
        "agent-completed",
        result["exit_code"] == 0 && result["run_status"] == "VALID",
        "agent must finish a valid model run with exit code 0",
    );
    for (name, expected) in [
        ("allowed.txt", "ready"),
        ("protected.txt", "approved\n"),
        ("continued.txt", "continued after protected edit"),
    ] {
        let actual = std::fs::read(project.join(name));
        let matches = actual.as_ref().is_ok_and(|bytes| {
            if name == "protected.txt" {
                bytes == expected.as_bytes()
            } else {
                String::from_utf8_lossy(bytes).trim() == expected
            }
        });
        evidence.check(
            name,
            matches,
            format!(
                "actual bytes: {actual:?}; expected: {:?}",
                expected.as_bytes()
            ),
        );
    }
    let paths = evidence.document(&run.join("paths.json"));
    let home = paths["HOME"].as_str().unwrap_or("");
    let protected = project.join("protected.txt");
    let reported = if !home.is_empty() {
        protected
            .strip_prefix(home)
            .map(|relative| format!("~/{}", relative.display()))
            .unwrap_or_else(|_| protected.display().to_string())
    } else {
        protected.display().to_string()
    };

    let log = evidence.text(&run.join("agent-a.log")).unwrap_or_default();
    let mut denials = 0;
    for line in log
        .lines()
        .filter_map(|line| line.strip_prefix("MACOS_FILE_DIAGNOSTIC "))
    {
        let row = match serde_json::from_str::<Value>(line) {
            Ok(row) if row.is_object() => row,
            _ => {
                evidence.check(
                    "native-diagnostic-readable",
                    false,
                    "malformed native diagnostic",
                );
                continue;
            }
        };
        if row["origin"] == "dogwood"
            && row["verdict"] == "deny"
            && (row["path"] == reported || row["destination"] == reported)
        {
            denials += 1;
            evidence.check(
                "native-denial-timestamp",
                timestamp(&row["time_unix_ns"]).is_some(),
                "native denial must carry a positive timestamp",
            );
        }
    }
    evidence.check(
        "native-protected-denial",
        denials > 0,
        format!("{denials} native Dogwood denials for {reported}; expected at least one"),
    );

    let mut records = evidence.records(&run.join("decisions.jsonl"));
    evidence.check(
        "readable-decisions.jsonl",
        records.iter().all(journal_shape),
        "policy journal must contain log records with named attributes",
    );
    // Only reserved policy attributes can supply evidence for this workload.
    for record in records
        .iter_mut()
        .filter(|record| journal_shape(record) && record.get("resourceLogs").is_some())
    {
        for resource in record["resourceLogs"].as_array_mut().unwrap() {
            for scope in resource["scopeLogs"].as_array_mut().unwrap() {
                for entry in scope["logRecords"].as_array_mut().unwrap() {
                    entry["attributes"]
                        .as_array_mut()
                        .unwrap()
                        .retain(|attribute| {
                            attribute["key"]
                                .as_str()
                                .is_some_and(|key| key.starts_with("strands.box.policy."))
                        });
                }
            }
        }
    }
    let journal = records
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    let decisions = test_common::parse_decisions(&journal);
    let blocked: Vec<_> = decisions
        .iter()
        .filter(|decision| {
            decision.resource == reported
                && decision.denied()
                && mutates_file(decision)
                && (decision.rule == "protected_file" || decision.forbidden_by("protected_file"))
        })
        .collect();
    evidence.check(
        "protected-policy-denial",
        !blocked.is_empty(),
        format!(
            "{} exact-path denials attributed to protected_file",
            blocked.len()
        ),
    );
    let resource_dir = reported.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
    let permits = |name: &str| {
        let resource = format!("{resource_dir}/{name}");
        decisions.iter().filter(move |decision| {
            decision.resource == resource && decision.permitted() && mutates_file(decision)
        })
    };
    for name in ["allowed.txt", "continued.txt"] {
        let count = permits(name).count();
        evidence.check(
            &format!("{name}-policy-permit"),
            count > 0,
            format!("{count} exact-path permits for {name}"),
        );
    }
    let last_denial = blocked
        .iter()
        .map(|decision| decision.at_unix_nano)
        .max()
        .unwrap_or(0);
    evidence.check(
        "policy-denial-timestamp",
        blocked.iter().all(|decision| decision.at_unix_nano > 0),
        "policy denial must carry a positive timestamp",
    );
    // Compare the policy records' original timestamps, not their export times.
    evidence.check(
        "continued-after-denial",
        last_denial > 0
            && permits("continued.txt").any(|decision| decision.at_unix_nano > last_denial),
        "continued.txt must receive a policy permit after the policy denial",
    );

    let events = evidence.records(&run.join("turns.jsonl"));
    let mut attempts = Vec::new();
    if agent == "claude" {
        let mut tools = HashSet::new();
        for event in events.iter().filter(|event| event["type"] == "assistant") {
            let Some(content) = event["message"]["content"].as_array() else {
                evidence.check(
                    "native-agent-tools",
                    false,
                    "assistant content is not an array",
                );
                continue;
            };
            for call in content.iter().filter(|part| part["type"] == "tool_use") {
                let tool = call["name"].as_str().unwrap_or("");
                tools.insert(tool);
                if ["Edit", "Write"].contains(&tool)
                    && evidence.protected_path(&call["input"]["file_path"], &project, home)
                {
                    attempts.push(call["id"].as_str());
                }
            }
        }
        evidence.check(
            "native-agent-tools",
            tools.contains("Edit")
                && tools.contains("Write")
                && tools
                    .iter()
                    .all(|tool| ["Read", "Edit", "Write"].contains(tool)),
            format!("Claude tools: {tools:?}"),
        );
    } else if agent == "codex" {
        let mut changes = 0;
        let mut commands = 0;
        for event in &events {
            if event.get("item").is_some() && !event["item"]["type"].is_string() {
                evidence.check("native-agent-tools", false, "item has no recorded type");
                continue;
            }
            let item = &event["item"];
            if item["type"] == "command_execution" {
                commands += 1;
            }
            if item["type"] != "file_change" {
                continue;
            }
            changes += 1;
            let Some(files) = item["changes"].as_array().filter(|files| !files.is_empty()) else {
                evidence.check(
                    "native-agent-tools",
                    false,
                    "file-change event has no changes",
                );
                continue;
            };
            let mut protected = false;
            for file in files {
                protected |= evidence.protected_path(&file["path"], &project, home);
            }
            if protected {
                attempts.push(item["id"].as_str());
            }
        }
        evidence.check(
            "native-agent-tools",
            changes > 0 && commands == 0,
            format!("Codex file changes: {changes}; command executions: {commands}"),
        );
    } else {
        evidence.check(
            "native-agent-tools",
            false,
            format!("unsupported agent: {agent}"),
        );
    }
    let ids: HashSet<_> = attempts.into_iter().collect();
    evidence.check(
        "one-protected-attempt",
        ids.len() == 1 && ids.iter().all(|id| id.is_some_and(|id| !id.is_empty())),
        format!(
            "{} distinct protected-edit tool calls; expected one with a recorded ID",
            ids.len()
        ),
    );
    evidence.checks
}

#[cfg(test)]
mod tests;
