use super::*;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    run: PathBuf,
    denial: Value,
    events: Vec<Value>,
    journal: Vec<Value>,
}

impl Fixture {
    fn new() -> Self {
        let run = std::env::temp_dir().join(format!(
            "native-verdict-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(run.join("project")).unwrap();
        for (name, text) in [
            ("allowed.txt", "ready\n"),
            ("protected.txt", "approved\n"),
            ("continued.txt", "continued after protected edit\n"),
        ] {
            std::fs::write(run.join("project").join(name), text).unwrap();
        }
        let fixture = Self {
            run,
            denial: json!({"origin":"dogwood","verdict":"deny","path":"~/project/protected.txt","time_unix_ns":"20"}),
            events: vec![json!({"type":"assistant","message":{"content":[
                {"type":"tool_use","name":"Edit","id":"edit-1","input":{"file_path":"protected.txt"}},
                {"type":"tool_use","name":"Write","id":"write-1","input":{"file_path":"continued.txt"}}
            ]}})],
            journal: vec![
                decision("allowed.txt", "permit", "native_runtime", 10),
                decision("protected.txt", "deny", "protected_file", 19),
                decision("continued.txt", "permit", "native_runtime", 30),
            ],
        };
        fixture.records("paths.json", &[json!({"HOME":fixture.run})]);
        fixture.records(
            "agent-a.json",
            &[json!({"exit_code":0,"run_status":"VALID"})],
        );
        fixture.save();
        fixture
    }

    fn records(&self, name: &str, rows: &[Value]) {
        std::fs::write(
            self.run.join(name),
            rows.iter()
                .map(|row| format!("{row}\n"))
                .collect::<String>(),
        )
        .unwrap();
    }

    fn save(&self) {
        self.records("turns.jsonl", &self.events);
        self.records(
            "decisions.jsonl",
            &[json!({"resourceLogs":[{"scopeLogs":[{"logRecords":self.journal}]}]})],
        );
        self.denials(1);
    }

    fn denials(&self, count: usize) {
        std::fs::write(
            self.run.join("agent-a.log"),
            format!("MACOS_FILE_DIAGNOSTIC {}\n", self.denial).repeat(count),
        )
        .unwrap();
    }

    fn codex(&mut self) {
        self.events = vec![codex_call("edit-1", "protected.txt")];
    }

    fn fail(&self, agent: &str) -> HashSet<String> {
        checks(&self.run, agent)
            .into_iter()
            .filter(|check| !check.ok)
            .map(|check| check.id)
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.run);
    }
}

fn decision(name: &str, verdict: &str, rule: &str, stamp: u64) -> Value {
    let attrs = [
        ("resource", format!("~/project/{name}")),
        ("verdict", verdict.into()),
        ("rule", rule.into()),
        ("action", "fs:write".into()),
    ];
    json!({"timeUnixNano":stamp.to_string(),"attributes":attrs.into_iter().map(|(key,value)|
        json!({"key":format!("strands.box.policy.{key}"),"value":{"stringValue":value}})
    ).collect::<Vec<_>>()})
}

fn codex_call(id: &str, path: &str) -> Value {
    json!({"type":"item.completed","item":{"type":"file_change","id":id,"status":"failed",
        "changes":[{"path":path,"kind":"update"}]}})
}

#[test]
fn claude_native_edit() {
    assert!(Fixture::new().fail("claude").is_empty());
}

#[test]
fn codex_native_edit() {
    let mut f = Fixture::new();
    f.codex();
    f.save();
    assert!(f.fail("codex").is_empty());
}

#[test]
fn formatted_json_documents_are_valid() {
    let f = Fixture::new();
    for name in ["paths.json", "agent-a.json"] {
        let value: Value =
            serde_json::from_slice(&std::fs::read(f.run.join(name)).unwrap()).unwrap();
        std::fs::write(
            f.run.join(name),
            serde_json::to_string_pretty(&value).unwrap(),
        )
        .unwrap();
    }
    assert!(f.fail("claude").is_empty());
}

#[test]
fn journal_can_also_contain_traces_and_metrics() {
    let f = Fixture::new();
    let records = json!({"resourceLogs":[{"scopeLogs":[{"logRecords":f.journal}]}]});
    f.records(
        "decisions.jsonl",
        &[
            records.clone(),
            json!({"resourceSpans":[]}),
            json!({"resourceMetrics":[]}),
        ],
    );
    assert!(f.fail("claude").is_empty());
    f.records(
        "decisions.jsonl",
        &[records, json!({"resourceSpans":[], "resourceLogs":{}})],
    );
    assert!(f.fail("claude").contains("readable-decisions.jsonl"));
}

#[test]
fn legacy_policy_attributes_cannot_supply_evidence() {
    for legacy_keys in [
        vec!["action", "resource", "verdict", "rule"],
        vec!["resource"],
        vec!["verdict"],
        vec!["rule"],
    ] {
        let mut f = Fixture::new();
        for record in &mut f.journal {
            for attribute in record["attributes"].as_array_mut().unwrap() {
                let key = attribute["key"].as_str().unwrap();
                if legacy_keys
                    .iter()
                    .any(|name| key == format!("strands.box.policy.{name}"))
                {
                    attribute["key"] = json!(key.replace("strands.box.policy.", "strands.policy."));
                }
            }
        }
        f.save();
        assert!(
            f.fail("claude").contains("protected-policy-denial"),
            "{legacy_keys:?}"
        );
    }
}

#[test]
fn reserved_determining_ids_attribute_the_forbid() {
    let mut f = Fixture::new();
    f.journal[1] = decision("protected.txt", "deny", "policy_0", 19);
    let attributes = f.journal[1]["attributes"].as_array_mut().unwrap();
    attributes.push(json!({"key":"strands.box.policy.reason",
        "value":{"stringValue":test_common::FORBID_REASON}}));
    attributes.push(json!({"key":"strands.box.policy.determining.ids",
        "value":{"arrayValue":{"values":[{"stringValue":"protected_file"}]}}}));
    f.save();
    assert!(f.fail("claude").is_empty());
    f.journal[1]["attributes"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap()["key"] = json!("strands.policy.determining.ids");
    f.save();
    assert!(f.fail("claude").contains("protected-policy-denial"));
}

#[test]
fn malformed_codex_item_cannot_hide_a_tool_call() {
    for item in [json!([]), json!({}), json!(null)] {
        let mut f = Fixture::new();
        f.codex();
        f.events.push(json!({"type":"item.completed","item":item}));
        f.save();
        assert!(f.fail("codex").contains("native-agent-tools"));
    }
}

#[test]
fn one_tool_call_can_produce_many_native_denials() {
    for agent in ["claude", "codex"] {
        let mut f = Fixture::new();
        if agent == "codex" {
            f.codex();
        }
        f.save();
        for count in [1, 4, 5, 12] {
            f.denials(count);
            assert!(f.fail(agent).is_empty(), "{agent}, {count}");
        }
    }
}

#[test]
fn started_and_completed_events_count_once() {
    let mut f = Fixture::new();
    f.codex();
    let mut started = f.events[0].clone();
    started["type"] = json!("item.started");
    f.events.insert(0, started);
    f.save();
    assert!(f.fail("codex").is_empty());
}

#[test]
fn repeated_tool_calls_fail_with_one_or_many_denials() {
    for agent in ["claude", "codex"] {
        for count in [1, 5] {
            let mut f = Fixture::new();
            if agent == "codex" {
                f.codex();
                f.events.push(codex_call("edit-2", "protected.txt"));
            } else {
                let mut call = f.events[0]["message"]["content"][0].clone();
                call["id"] = json!("edit-2");
                f.events[0]["message"]["content"]
                    .as_array_mut()
                    .unwrap()
                    .push(call);
            }
            f.save();
            f.denials(count);
            assert!(f.fail(agent).contains("one-protected-attempt"));
        }
    }
}

#[test]
fn alternate_paths_cannot_hide_second_edit() {
    let mut f = Fixture::new();
    let project = f.run.join("project");
    let alias = project.join("PROTECTED.txt");
    if !alias.exists() {
        std::fs::hard_link(project.join("protected.txt"), &alias).unwrap();
    }
    let mut paths = vec![
        alias.display().to_string(),
        format!("{}/./protected.txt", project.display()),
        "./protected.txt".into(),
        "~/project/../project/protected.txt".into(),
    ];
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("protected.txt", project.join("alias.txt")).unwrap();
        paths.push("alias.txt".into());
    }
    for agent in ["claude", "codex"] {
        for path in &paths {
            if agent == "codex" {
                f.codex();
                f.events.push(codex_call("edit-2", path));
            } else {
                f.events = vec![json!({"type":"assistant","message":{"content":[
                    {"type":"tool_use","name":"Edit","id":"edit-1","input":{"file_path":"protected.txt"}},
                    {"type":"tool_use","name":"Edit","id":"edit-2","input":{"file_path":path}},
                    {"type":"tool_use","name":"Write","id":"write-1","input":{"file_path":"continued.txt"}}
                ]}})];
            }
            f.save();
            assert!(
                f.fail(agent).contains("one-protected-attempt"),
                "{agent}, {path}"
            );
        }
    }
}

#[test]
#[cfg(unix)]
fn unreadable_identity_fails() {
    let mut f = Fixture::new();
    std::os::unix::fs::symlink("loop", f.run.join("project/loop")).unwrap();
    f.events[0]["message"]["content"][0]["input"]["file_path"] = json!("loop");
    f.save();
    assert!(f.fail("claude").contains("protected-attempt-path-readable"));
}

#[test]
fn malformed_required_records_fail() {
    for name in [
        "agent-a.json",
        "decisions.jsonl",
        "turns.jsonl",
        "paths.json",
    ] {
        for suffix in [b"\xff\n".as_slice(), b"[]\n", b"{\"truncated\":"] {
            let f = Fixture::new();
            let path = f.run.join(name);
            let mut bytes = std::fs::read(&path).unwrap();
            bytes.extend_from_slice(suffix);
            std::fs::write(path, bytes).unwrap();
            assert!(f.fail("claude").contains(&format!("readable-{name}")));
        }
    }
}

#[test]
fn truncated_command_record_fails() {
    let mut f = Fixture::new();
    f.codex();
    f.save();
    let path = f.run.join("turns.jsonl");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        path,
        text + "{\"type\":\"item.completed\",\"item\":{\"type\":\"command_execution\"\n",
    )
    .unwrap();
    assert!(f.fail("codex").contains("readable-turns.jsonl"));
}

#[test]
fn damaged_journal_structure_cannot_hide_beside_good_records() {
    for extra in [
        json!({"resourceLogs":"broken"}),
        json!({"resourceLogs":[{"scopeLogs":[{"logRecords":[null]}]}]}),
        json!({"resourceLogs":[{"scopeLogs":[{"logRecords":[{"attributes":"broken"}]}]}]}),
    ] {
        let f = Fixture::new();
        let path = f.run.join("decisions.jsonl");
        let before = std::fs::read_to_string(&path).unwrap();
        std::fs::write(path, format!("{before}{extra}\n")).unwrap();
        assert!(f.fail("claude").contains("readable-decisions.jsonl"));
    }
}
#[test]
fn missing_required_files_fail() {
    for name in [
        "agent-a.json",
        "decisions.jsonl",
        "turns.jsonl",
        "agent-a.log",
        "paths.json",
    ] {
        let f = Fixture::new();
        std::fs::remove_file(f.run.join(name)).unwrap();
        assert!(!f.fail("claude").is_empty(), "{name}");
    }
}

#[test]
fn missing_or_invalid_tool_ids_fail() {
    for agent in ["claude", "codex"] {
        for id in [Value::Null, json!(""), json!(12)] {
            let mut f = Fixture::new();
            if agent == "codex" {
                f.codex();
                f.events[0]["item"]["id"] = id;
            } else {
                f.events[0]["message"]["content"][0]["id"] = id;
            }
            f.save();
            assert!(f.fail(agent).contains("one-protected-attempt"));
        }
    }
}

#[test]
fn malformed_tool_paths_fail() {
    for agent in ["claude", "codex"] {
        let mut f = Fixture::new();
        if agent == "codex" {
            f.codex();
            f.events[0]["item"]["changes"][0]["path"] = Value::Null;
        } else {
            f.events[0]["message"]["content"][0]["input"]["file_path"] = Value::Null;
        }
        f.save();
        assert!(f.fail(agent).contains("protected-attempt-path-readable"));
    }
}

#[test]
fn shell_fallback_fails_even_with_native_calls() {
    for agent in ["claude", "codex"] {
        let mut f = Fixture::new();
        if agent == "codex" {
            f.codex();
            f.events
                .push(json!({"item":{"type":"command_execution","id":"command-1"}}));
        } else {
            f.events[0]["message"]["content"]
                .as_array_mut()
                .unwrap()
                .push(json!({"type":"tool_use","name":"Bash","id":"command-1"}));
        }
        f.save();
        assert!(f.fail(agent).contains("native-agent-tools"));
    }
}

#[test]
fn summary_without_tool_event_fails() {
    let mut f = Fixture::new();
    f.events = vec![json!({"type":"result","result":"I used Edit and Write."})];
    f.save();
    assert!(f.fail("claude").contains("native-agent-tools"));
}

#[test]
fn malformed_diagnostics_fail_without_panicking() {
    for diagnostic in ["[]", "{", "{\"broken\":"] {
        let f = Fixture::new();
        let path = f.run.join("agent-a.log");
        let before = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            path,
            format!("{before}MACOS_FILE_DIAGNOSTIC {diagnostic}\n"),
        )
        .unwrap();
        assert!(f.fail("claude").contains("native-diagnostic-readable"));
    }
}

#[test]
fn missing_or_invalid_denial_timestamps_fail() {
    for stamp in [Value::Null, json!("bad"), json!(0), json!("-1")] {
        let mut f = Fixture::new();
        f.denial["time_unix_ns"] = stamp.clone();
        f.save();
        assert!(f.fail("claude").contains("native-denial-timestamp"));
        f.denial["time_unix_ns"] = json!("20");
        f.journal[1]["timeUnixNano"] = stamp;
        f.save();
        assert!(f.fail("claude").contains("policy-denial-timestamp"));
    }
}

#[test]
fn continuation_uses_policy_order_not_diagnostic_time() {
    let mut f = Fixture::new();
    f.denial["time_unix_ns"] = json!("900");
    f.save();
    assert!(f.fail("claude").is_empty());
    f.journal[2]["timeUnixNano"] = json!("15");
    f.save();
    assert!(f.fail("claude").contains("continued-after-denial"));
}

#[test]
fn zero_native_denials_fails() {
    let f = Fixture::new();
    f.denials(0);
    assert!(f.fail("claude").contains("native-protected-denial"));
}

#[test]
fn adapter_denial_is_not_policy_denial() {
    let mut f = Fixture::new();
    f.denial["origin"] = json!("adapter");
    f.save();
    assert!(f.fail("claude").contains("native-protected-denial"));
}

#[test]
fn rename_destination_matches_the_protected_file() {
    let mut f = Fixture::new();
    f.denial["path"] = json!("~/project/protected.txt.tmp");
    f.denial["destination"] = json!("~/project/protected.txt");
    f.save();
    assert!(f.fail("claude").is_empty());
}

#[test]
fn policy_resource_and_rule_must_match() {
    let mut f = Fixture::new();
    f.journal[1] = decision("protected.txt.tmp", "deny", "protected_file", 19);
    f.save();
    assert!(f.fail("claude").contains("protected-policy-denial"));
    f.journal[1] = decision("protected.txt", "deny", "other_rule", 19);
    f.save();
    assert!(f.fail("claude").contains("protected-policy-denial"));
}

#[test]
fn protected_file_comparison_and_message_preserve_bytes() {
    for bytes in [b"approved".as_slice(), b"approved\n\n", b"changed\n"] {
        let f = Fixture::new();
        std::fs::write(f.run.join("project/protected.txt"), bytes).unwrap();
        let rows = checks(&f.run, "claude");
        let row = rows.iter().find(|row| row.id == "protected.txt").unwrap();
        assert!(!row.ok);
        assert!(row.evidence.contains(&format!("{:?}", bytes)));
    }
}

#[test]
fn missing_continuation_fails() {
    let f = Fixture::new();
    std::fs::remove_file(f.run.join("project/continued.txt")).unwrap();
    assert!(f.fail("claude").contains("continued.txt"));
}

#[test]
fn failed_agent_run_fails() {
    let f = Fixture::new();
    f.records(
        "agent-a.json",
        &[json!({"exit_code":1,"run_status":"VALID"})],
    );
    assert!(f.fail("claude").contains("agent-completed"));
}
