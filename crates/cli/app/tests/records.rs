#![cfg(unix)]

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

const ID: &str = "probe-01234567";
const HEADER: &str = "TIME (UTC)\tRESULT\tACTION\tRESOURCE\tRULE\tREASON";
const PREFIX: &str = "strands.box.policy.";

struct Scene {
    _root: tempfile::TempDir,
    home: PathBuf,
    project: PathBuf,
    run: PathBuf,
}

impl Scene {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let project = root.path().join("project");
        let run = home.join(".strands/box/r").join(ID);
        std::fs::create_dir_all(&run).unwrap();
        std::fs::create_dir(&project).unwrap();
        std::fs::write(run.join("records.jsonl"), "").unwrap();
        Self {
            _root: root,
            home,
            project,
            run,
        }
    }

    fn write(&self, text: &str) {
        std::fs::write(self.run.join("records.jsonl"), text).unwrap();
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_box"));
        command
            .args(args)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", "")
            .env("BOX_RESOURCES", self.home.join("absent-resources"))
            .current_dir(&self.project)
            .stdin(Stdio::null());
        command
    }

    fn records(&self, deny: bool) -> Output {
        let mut command = self.command(&["runs", "history", ID]);
        if deny {
            command.arg("--deny");
        }
        command.output().unwrap()
    }

    fn records_with(&self, options: &[&str]) -> Output {
        self.command(&["runs", "history", ID])
            .args(options)
            .output()
            .unwrap()
    }
}

fn attr(name: &str, value: &str) -> Value {
    json!({"key": format!("{PREFIX}{name}"), "value": {"stringValue": value}})
}

fn decision(n: u64, verdict: &str, resource: &str) -> Value {
    json!({
        "traceId": format!("{n:032x}"), "spanId": format!("{n:016x}"),
        "name": "policy fs:read", "kind": 1,
        "startTimeUnixNano": "1735689600000000000",
        "endTimeUnixNano": "1735689600000000000",
        "attributes": [attr("principal", "agent:self"), attr("action", "fs:read"),
            attr("resource", resource), attr("verdict", verdict),
            attr("cause", if verdict == "deny" { "forbidden" } else { "permitted" }),
            attr("rule", "private_files"), attr("reason", "outside the project"),
            {"key": "file.path", "value": {"stringValue": resource}}]
    })
}

fn change(span: &mut Value, name: &str, value: Option<&str>) {
    let attributes = span["attributes"].as_array_mut().unwrap();
    attributes.retain(|a| a["key"] != format!("{PREFIX}{name}"));
    if let Some(value) = value {
        attributes.push(attr(name, value));
    }
}

fn batch(spans: Vec<Value>) -> Value {
    json!({"resourceSpans": [{
        "resource": {"attributes": [{"key": "strands.box.source", "value": {"stringValue": "box"}}]},
        "scopeSpans": [{"scope": {"name": "strands-box.policy"}, "spans": spans}]
    }]})
}

fn line(value: &Value) -> String {
    format!("{value}\n")
}
fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "status: {}\nstdout: {}\nstderr: {}",
        output.status,
        text(&output.stdout),
        text(&output.stderr)
    );
}

fn rows(output: &Output) -> Vec<Vec<String>> {
    let stdout = text(&output.stdout);
    let mut lines = stdout.lines();
    assert_eq!(lines.next(), Some(HEADER), "{stdout}");
    lines
        .map(|line| {
            let fields: Vec<String> = line.split('\t').map(str::to_owned).collect();
            assert_eq!(
                fields.len(),
                6,
                "a decision occupies one six-column row: {line}"
            );
            fields
        })
        .collect()
}

fn has_line_warning(output: &Output, number: usize) {
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains(&format!("line {number}")) || stderr.contains(&format!(":{number}:")),
        "warning must identify line {number}: {stderr}"
    );
}

#[test]
fn records_preserves_all_nine_denials_repeats_and_batch_order_without_mirrored_logs() {
    let scene = Scene::new();
    let resources = [
        "/p/zero",
        "/p/repeated",
        "/p/repeated",
        "/p/three",
        "/p/four",
        "/p/five",
        "/p/six",
        "/p/seven",
        "/p/eight",
    ];
    let mut denied: Vec<Value> = resources
        .iter()
        .enumerate()
        .map(|(i, resource)| decision(i as u64 + 1, "deny", resource))
        .collect();
    denied[2] = denied[1].clone();
    let mut first = denied[..4].to_vec();
    first.insert(2, decision(20, "permit", "/p/allowed-first"));
    let mut second = batch(denied[4..6].to_vec());
    let extra = batch(denied[6..].to_vec());
    second["resourceSpans"]
        .as_array_mut()
        .unwrap()
        .extend(extra["resourceSpans"].as_array().unwrap().clone());
    second["resourceSpans"][0]["scopeSpans"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "scope": {"name": "strands-box.policy"},
            "spans": [decision(21, "permit", "/p/allowed-second")]
        }));
    let mirror = json!({"resourceLogs": [{"scopeLogs": [{
        "scope": {"name": "strands-box.policy"}, "logRecords": [{
            "traceId": denied[0]["traceId"], "spanId": denied[0]["spanId"],
            "timeUnixNano": "1735689600000000000", "eventName": "strands.box.policy.decision",
            "attributes": denied[0]["attributes"]
        }]
    }]}]});
    let agent = json!({"resourceSpans": [{"scopeSpans": [{
        "scope": {"name": "strands.telemetry"},
        "spans": [{"name": "agent.run", "status": {"code": 2, "message": "deny"}},
            decision(30, "deny", "/p/agent-lookalike")]
    }, {
        "scope": {"name": "strands-box.control"},
        "spans": [decision(31, "deny", "/p/control-lookalike")]
    }]}], "resourceMetrics": [{"scopeMetrics": []}]});
    let mut missing_id = decision(32, "deny", "/p/not-a-span");
    missing_id.as_object_mut().unwrap().remove("spanId");
    let mut other_name = decision(33, "deny", "/p/not-a-policy-operation");
    other_name["name"] = json!("control ready");
    let incomplete = batch(vec![missing_id, other_name]);
    scene.write(
        &(line(&batch(first))
            + &line(&mirror)
            + &line(&agent)
            + &line(&incomplete)
            + &line(&second)),
    );
    let output = scene.records(false);
    success(&output);
    assert!(output.stderr.is_empty(), "{}", text(&output.stderr));
    let all = rows(&output);
    let actual: Vec<&str> = all.iter().map(|row| row[3].as_str()).collect();
    assert_eq!(
        actual,
        [
            "/p/zero",
            "/p/repeated",
            "/p/allowed-first",
            "/p/repeated",
            "/p/three",
            "/p/four",
            "/p/five",
            "/p/allowed-second",
            "/p/six",
            "/p/seven",
            "/p/eight"
        ]
    );
    let output = scene.records(true);
    success(&output);
    let filtered = rows(&output);
    assert_eq!(
        filtered
            .iter()
            .map(|row| row[3].as_str())
            .collect::<Vec<_>>(),
        resources
    );
    assert!(filtered.iter().all(|row| row[1] == "deny"));
}

#[test]
fn records_uses_recorded_time_and_fields_and_filters_only_the_exact_deny_verdict() {
    let scene = Scene::new();
    let mut denied = decision(1, "deny", "/p/no-match");
    change(&mut denied, "cause", Some("no_match"));
    change(&mut denied, "action", Some("Box::Action::\"fs:read\""));
    let mut missing = decision(2, "permit", "/p/missing");
    missing.as_object_mut().unwrap().remove("startTimeUnixNano");
    for name in ["verdict", "action", "resource", "rule", "reason"] {
        change(&mut missing, name, None);
    }
    missing["attributes"]
        .as_array_mut()
        .unwrap()
        .retain(|attribute| attribute["key"] != "file.path");
    let mut unexpected = decision(3, "DENY", "/p/unexpected");
    unexpected["startTimeUnixNano"] = json!("not a timestamp");
    scene.write(&line(&batch(vec![denied, missing, unexpected])));
    let output = scene.records(false);
    success(&output);
    let all = rows(&output);
    assert_eq!(all.len(), 3);
    assert!(
        all[0][0] == "2025-01-01T00:00:00Z"
            || all[0][0].starts_with("2025-01-01T00:00:00.000") && all[0][0].ends_with('Z'),
        "{:?}",
        all[0]
    );
    assert_eq!(
        &all[0][1..],
        [
            "deny",
            "fs:read",
            "/p/no-match",
            "private_files",
            "outside the project"
        ]
    );
    assert_eq!(all[1], ["unknown", "unknown", "-", "-", "-", "-"]);
    assert_eq!(all[2][0], "unknown");
    assert_eq!(all[2][1], "DENY");
    let output = scene.records(true);
    success(&output);
    let filtered = rows(&output);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0][3], "/p/no-match");
}

#[test]
fn records_distinguishes_would_denies_without_changing_recorded_verdicts() {
    let scene = Scene::new();
    let cases = [
        (
            "/would",
            Some("deny"),
            Some(json!({"boolValue": false})),
            json!(false),
            "would deny",
        ),
        (
            "/enforced",
            Some("deny"),
            Some(json!({"boolValue": true})),
            json!(true),
            "deny",
        ),
        ("/legacy", Some("deny"), None, Value::Null, "deny"),
        (
            "/string-false",
            Some("deny"),
            Some(json!({"stringValue": "false"})),
            Value::Null,
            "deny",
        ),
        (
            "/string-bool-false",
            Some("deny"),
            Some(json!({"boolValue": "false"})),
            Value::Null,
            "deny",
        ),
        (
            "/null-flag",
            Some("deny"),
            Some(json!({"boolValue": null})),
            Value::Null,
            "deny",
        ),
        (
            "/number-flag",
            Some("deny"),
            Some(json!({"boolValue": 0})),
            Value::Null,
            "deny",
        ),
        (
            "/permit",
            Some("permit"),
            Some(json!({"boolValue": false})),
            json!(false),
            "permit",
        ),
        (
            "/missing-verdict",
            None,
            Some(json!({"boolValue": false})),
            json!(false),
            "unknown",
        ),
        (
            "/other-verdict",
            Some("DENY"),
            Some(json!({"boolValue": false})),
            json!(false),
            "DENY",
        ),
    ];
    let spans = cases
        .iter()
        .enumerate()
        .map(|(n, (resource, verdict, enforcement, _, _))| {
            let mut span = decision(n as u64 + 1, verdict.unwrap_or("deny"), resource);
            change(&mut span, "verdict", *verdict);
            if let Some(value) = enforcement {
                span["attributes"].as_array_mut().unwrap().push(json!({
                    "key": "strands.box.policy.enforced", "value": value
                }));
            }
            span
        })
        .collect();
    scene.write(&line(&batch(spans)));
    let before = snapshot(&scene.home);
    let text_output = scene.records(false);
    success(&text_output);
    assert!(text_output.stderr.is_empty());
    assert_eq!(
        rows(&text_output)
            .into_iter()
            .map(|row| [row[1].clone(), row[3].clone()])
            .collect::<Vec<_>>(),
        cases
            .iter()
            .map(|(resource, _, _, _, display)| [display.to_string(), resource.to_string()])
            .collect::<Vec<_>>()
    );
    let json_output = scene.records_with(&["--format", "json"]);
    success(&json_output);
    assert!(json_output.stderr.is_empty());
    let actual = json_rows(&json_output);
    assert_eq!(actual.len(), cases.len());
    for (row, (resource, verdict, _, enforcement, _)) in actual.iter().zip(&cases) {
        assert_eq!(row["resource"], *resource);
        assert_eq!(
            row["result"],
            verdict.map_or(Value::Null, |value| json!(value))
        );
        assert_eq!(&row["enforced"], enforcement, "{resource}");
    }
    for (flag, expected, display) in [
        (
            "--deny",
            vec![
                "/enforced",
                "/legacy",
                "/string-false",
                "/string-bool-false",
                "/null-flag",
                "/number-flag",
            ],
            "deny",
        ),
        ("--would-deny", vec!["/would"], "would deny"),
    ] {
        let text_output = scene.records_with(&[flag]);
        success(&text_output);
        assert!(text_output.stderr.is_empty());
        let text_rows = rows(&text_output);
        assert!(text_rows.iter().all(|row| row[1] == display));
        assert_eq!(
            text_rows
                .into_iter()
                .map(|row| row[3].clone())
                .collect::<Vec<_>>(),
            expected,
            "{flag}"
        );
        let json_output = scene.records_with(&[flag, "--format", "json"]);
        success(&json_output);
        assert!(json_output.stderr.is_empty());
        assert_eq!(json_resources(&json_output), expected, "{flag}");
        assert!(
            json_rows(&json_output)
                .iter()
                .all(|row| row["result"] == "deny")
        );
    }
    assert_eq!(snapshot(&scene.home), before);
}

#[test]
fn records_rejects_conflicting_denial_filters_before_reading_history() {
    let scene = Scene::new();
    scene.write("{bad json}\n");
    let before = snapshot(&scene.home);
    for flags in [["--deny", "--would-deny"], ["--would-deny", "--deny"]] {
        for format in ["text", "json"] {
            let output = scene.records_with(&[flags[0], flags[1], "--format", format]);
            let stderr = text(&output.stderr);
            assert_eq!(output.status.code(), Some(2), "{flags:?}: {stderr}");
            assert!(
                output.stdout.is_empty(),
                "{flags:?}: {}",
                text(&output.stdout)
            );
            assert!(
                stderr.contains("cannot be used with"),
                "{flags:?}: {stderr}"
            );
            assert!(
                stderr.contains("--deny") && stderr.contains("--would-deny"),
                "{stderr}"
            );
            assert!(
                !stderr.contains("invalid JSON"),
                "usage is checked before reading: {stderr}"
            );
            assert_eq!(snapshot(&scene.home), before);
        }
    }
}

#[test]
fn records_escapes_control_characters_and_preserves_full_unicode_values() {
    let scene = Scene::new();
    let resource = format!(
        "/日本語/{}\tline\nnext\r\u{1b}]52;c;payload\u{7}\u{9b}tail😀",
        "long".repeat(100)
    );
    let mut span = decision(1, "deny", &resource);
    change(&mut span, "verdict", Some("deny\tuntrusted\n\u{1b}[31m"));
    change(&mut span, "action", Some("fs:read\nforged"));
    change(&mut span, "rule", Some("rule\tname\u{1b}[31m"));
    change(&mut span, "reason", Some("reason\r\nforged\0row"));
    scene.write(&line(&batch(vec![span])));
    let output = scene.records(false);
    success(&output);
    let all = rows(&output);
    assert_eq!(all.len(), 1);
    let stdout = text(&output.stdout);
    assert!(
        !stdout
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t'),
        "{stdout:?}"
    );
    assert!(all[0][3].contains(&format!("/日本語/{}", "long".repeat(100))));
    assert!(all[0][3].ends_with("tail😀"));
    for field in &all[0][1..] {
        assert!(field.contains('\\'), "control must be visible: {field:?}");
    }
    let denied = scene.records(true);
    success(&denied);
    assert_eq!(
        text(&denied.stdout).trim(),
        "No denied policy decisions recorded."
    );
}

#[test]
fn records_reports_bad_lines_and_still_prints_later_decisions() {
    let scene = Scene::new();
    scene.write(
        &(line(&batch(vec![decision(1, "deny", "/p/first")]))
            + "{bad json}\n\n"
            + &line(&batch(vec![decision(2, "permit", "/p/later")]))
            + "{\"resourceSpans\":"),
    );
    let output = scene.records(false);
    assert_eq!(output.status.code(), Some(1));
    let all = rows(&output);
    assert_eq!(
        all.iter().map(|row| row[3].as_str()).collect::<Vec<_>>(),
        ["/p/first", "/p/later"]
    );
    has_line_warning(&output, 2);
    has_line_warning(&output, 5);
}

#[test]
fn records_rejects_an_oversized_valid_json_line_and_recovers_at_the_next_line() {
    let scene = Scene::new();
    let limit = 8 * 1024 * 1024;
    let mut exact = batch(vec![decision(1, "deny", "/p/at-limit")]);
    exact["padding"] = json!("");
    let padding = limit - exact.to_string().len();
    exact["padding"] = json!("x".repeat(padding));
    let accepted = exact.to_string();
    assert_eq!(accepted.len(), limit);
    exact["padding"] = json!("x".repeat(padding + 1));
    let oversized = exact.to_string();
    assert_eq!(oversized.len(), limit + 1);
    scene.write(
        &(accepted
            + "\n"
            + &oversized
            + "\n"
            + &line(&batch(vec![decision(2, "deny", "/p/after-large-line")]))),
    );
    let output = scene.records(false);
    assert_eq!(output.status.code(), Some(1));
    has_line_warning(&output, 2);
    assert!(!text(&output.stderr).contains("line 1:"));
    let all = rows(&output);
    assert_eq!(all.len(), 2);
    assert_eq!(all[0][3], "/p/at-limit");
    assert_eq!(all[1][3], "/p/after-large-line");
}

#[test]
fn records_distinguishes_empty_results_from_missing_ids_and_logs() {
    let scene = Scene::new();
    for deny in [false, true] {
        let output = scene.records(deny);
        success(&output);
        let expected = if deny {
            "No denied policy decisions recorded."
        } else {
            "No policy decisions recorded."
        };
        assert_eq!(text(&output.stdout).trim(), expected);
    }
    scene.write(&line(&batch(vec![decision(1, "permit", "/p/allowed")])));
    let output = scene.records(true);
    success(&output);
    assert_eq!(
        text(&output.stdout).trim(),
        "No denied policy decisions recorded."
    );
    let missing = scene
        .command(&["runs", "history", "missing-01234567"])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(1));
    assert!(text(&missing.stderr).contains("missing-01234567"));
    std::fs::remove_file(scene.run.join("records.jsonl")).unwrap();
    let missing = scene.records(false);
    assert_eq!(missing.status.code(), Some(1));
    assert!(text(&missing.stderr).contains("records.jsonl"));
}

#[test]
fn records_does_not_follow_symlinks_or_read_nonregular_logs() {
    for component in [".strands", ".strands/box", "r", "run", "log"] {
        let scene = Scene::new();
        scene.write(&line(&batch(vec![decision(
            1,
            "deny",
            "/p/symlink-secret",
        )])));
        success(&scene.records(false));
        let selected = match component {
            ".strands" => scene.home.join(".strands"),
            ".strands/box" => scene.home.join(".strands/box"),
            "r" => scene.home.join(".strands/box/r"),
            "run" => scene.run.clone(),
            _ => scene.run.join("records.jsonl"),
        };
        let elsewhere = scene.project.join("elsewhere");
        std::fs::rename(&selected, &elsewhere).unwrap();
        symlink(&elsewhere, &selected).unwrap();
        let output = scene.records(false);
        assert!(!output.status.success(), "followed {component}");
        assert!(!text(&output.stdout).contains("symlink-secret"));
    }
    let scene = Scene::new();
    std::fs::remove_file(scene.run.join("records.jsonl")).unwrap();
    std::fs::create_dir(scene.run.join("records.jsonl")).unwrap();
    let output = scene.records(false);
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("records.jsonl"));
}

#[test]
fn records_rejects_nonliteral_ids_and_requires_home_even_when_cwd_has_records() {
    let scene = Scene::new();
    scene.write(&line(&batch(vec![decision(1, "deny", "/p/home-required")])));
    success(&scene.records(false));
    let absolute = scene.run.to_str().unwrap();
    for id in [
        ".",
        "..",
        "../probe-01234567",
        "probe/../probe-01234567",
        "./probe-01234567",
        "probe-01234567/",
        absolute,
    ] {
        let output = scene.command(&["runs", "history", id]).output().unwrap();
        assert!(!output.status.success(), "accepted {id:?}");
        assert!(!text(&output.stdout).contains("home-required"));
    }
    let output = scene
        .command(&["runs", "history", ID])
        .env_remove("HOME")
        .current_dir(&scene.home)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).to_lowercase().contains("home"));
    assert!(!text(&output.stdout).contains("home-required"));
}

fn snapshot(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>, std::time::SystemTime)> {
    let mut result = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        result.push((
            path.clone(),
            if metadata.is_file() {
                Some(std::fs::read(&path).unwrap())
            } else {
                None
            },
            metadata.modified().unwrap(),
        ));
        if metadata.is_dir() {
            result.extend(snapshot(&path));
        }
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

#[test]
fn records_needs_only_the_log_and_never_changes_the_home() {
    let scene = Scene::new();
    scene.write(&line(&batch(vec![decision(1, "deny", "/p/read-only")])));
    assert!(!scene.home.join(".strands/box/profiles").exists());
    assert!(!scene.run.join("box.toml").exists());
    assert!(!scene.run.join("box").exists());
    let before = snapshot(&scene.home);
    for deny in [false, true] {
        let output = scene.records(deny);
        success(&output);
        assert_eq!(rows(&output).len(), 1);
    }
    for box_home in [None, Some("")] {
        let mut command = scene.command(&["runs", "history", ID, "--format", "json"]);
        if let Some(value) = box_home {
            command.env("BOX_HOME", value);
        } else {
            command.env_remove("BOX_HOME");
        }
        let output = command.output().unwrap();
        success(&output);
        assert!(output.stderr.is_empty(), "{}", text(&output.stderr));
        assert_eq!(json_resources(&output), ["/p/read-only"]);
    }
    assert_eq!(snapshot(&scene.home), before);
}

#[test]
fn records_uses_the_configured_box_home_without_falling_back() {
    let scene = Scene::new();
    scene.write(&line(&batch(vec![decision(1, "deny", "/default-home")])));
    let box_home = scene._root.path().join("configured-box");
    let configured_run = box_home.join("r").join(ID);
    std::fs::create_dir_all(&configured_run).unwrap();
    std::fs::write(
        configured_run.join("records.jsonl"),
        line(&batch(vec![decision(2, "deny", "/configured-home")])),
    )
    .unwrap();
    let box_home = box_home.canonicalize().unwrap();
    let missing_id = "fallback-01234567";
    let fallback_run = scene.home.join(".strands/box/r").join(missing_id);
    std::fs::create_dir_all(&fallback_run).unwrap();
    std::fs::write(
        fallback_run.join("records.jsonl"),
        line(&batch(vec![decision(3, "deny", "/fallback-home")])),
    )
    .unwrap();
    let missing_log = box_home.join("r").join(missing_id).join("records.jsonl");
    std::fs::create_dir_all(missing_log.parent().unwrap()).unwrap();
    let before = snapshot(scene._root.path());

    for with_home in [true, false] {
        let mut command = scene.command(&["runs", "history", ID, "--format", "json"]);
        command.env("BOX_HOME", &box_home);
        if !with_home {
            command.env_remove("HOME");
        }
        let output = command.output().unwrap();
        success(&output);
        assert!(output.stderr.is_empty(), "{}", text(&output.stderr));
        assert_eq!(
            json_resources(&output),
            ["/configured-home"],
            "HOME is set: {with_home}"
        );
        assert_eq!(snapshot(scene._root.path()), before);
    }

    let missing = scene
        .command(&["runs", "history", missing_id, "--format", "json"])
        .env("BOX_HOME", &box_home)
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(1), "{}", text(&missing.stderr));
    assert!(missing.stdout.is_empty(), "{}", text(&missing.stdout));
    assert!(
        text(&missing.stderr)
            .split_whitespace()
            .collect::<String>()
            .contains(missing_log.to_str().unwrap()),
        "{}",
        text(&missing.stderr)
    );
    assert_eq!(snapshot(scene._root.path()), before);
}

#[test]
fn records_reads_complete_policy_batches_larger_than_sixty_four_kibibytes() {
    let scene = Scene::new();
    let resource = format!("/project/{}final.txt", "folder/".repeat(5_000));
    let encoded = line(&batch(vec![
        decision(1, "deny", &resource),
        decision(2, "permit", "/project/last.txt"),
    ]));
    assert!(encoded.len() > 64 * 1024);
    assert!(encoded.len() < 8 * 1024 * 1024);
    scene.write(&encoded);
    let output = scene.records(false);
    success(&output);
    assert!(output.stderr.is_empty(), "{}", text(&output.stderr));
    let all = rows(&output);
    assert_eq!(all.len(), 2);
    assert_eq!(all[0][3], resource);
    assert_eq!(all[1][3], "/project/last.txt");
}

fn wait_bounded(child: &mut std::process::Child) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("records did not exit within five seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn records_refuses_a_fifo_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    let scene = Scene::new();
    let path = scene.run.join("records.jsonl");
    std::fs::remove_file(&path).unwrap();
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: path is a valid C string, and the test owns its parent directory.
    assert_eq!(unsafe { nix::libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let mut child = scene
        .command(&["runs", "history", ID])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert_eq!(wait_bounded(&mut child).code(), Some(1));
}

#[test]
fn records_exits_successfully_when_the_output_pipe_closes() {
    let scene = Scene::new();
    scene.write(&line(&batch(
        (0..4000)
            .map(|n| decision(n, "deny", "/p/denied"))
            .collect(),
    )));
    for format in [None, Some("json")] {
        let mut command = scene.command(&["runs", "history", ID]);
        if let Some(format) = format {
            command.args(["--format", format]);
        }
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        assert!(
            wait_bounded(&mut child).success(),
            "a closed stdout pipe must exit successfully in {format:?} format"
        );
    }
}

#[test]
fn records_uses_exact_subject_keys_and_nanosecond_timestamps() {
    let scene = Scene::new();
    let mut spans = Vec::new();
    let subjects = [
        "strands.box.policy.resource",
        "file.path",
        "server.address",
        "process.command",
    ];
    for index in 0..subjects.len() {
        let mut span = decision(index as u64, "deny", "/fallback");
        span["startTimeUnixNano"] = json!("1735689600123456789");
        span["attributes"]
            .as_array_mut()
            .unwrap()
            .retain(|a| a["key"] != "file.path" && a["key"] != "strands.box.policy.resource");
        for key in subjects[index..].iter().rev() {
            span["attributes"].as_array_mut().unwrap().push(json!({
                "key": key, "value": {"stringValue": format!("value:{key}")}
            }));
        }
        span["attributes"].as_array_mut().unwrap().insert(
            0,
            json!({
                "key": "untrusted.file.path", "value": {"stringValue": "/wrong"}
            }),
        );
        spans.push(span);
    }
    // A valid last batch need not end in a newline.
    scene.write(&batch(spans).to_string());
    let output = scene.records(false);
    success(&output);
    let all = rows(&output);
    assert_eq!(all.len(), 4);
    for (row, subject) in all.iter().zip(subjects) {
        assert_eq!(row[0], "2025-01-01T00:00:00.123456789Z");
        assert_eq!(row[3], format!("value:{subject}"));
    }
}

#[test]
fn records_preserves_network_ports_and_http_paths() {
    let scene = Scene::new();
    let cases = [
        ("net:connect", "docs.rs", 443, "docs.rs:443"),
        ("net:connect", "docs.rs", 22, "docs.rs:22"),
        (
            "http:request",
            "api.github.com",
            443,
            "api.github.com:443/repos/x/y/pulls",
        ),
    ];
    let mut spans = Vec::new();
    for (index, (action, host, port, resource)) in cases.iter().enumerate() {
        let mut span = decision(index as u64, "deny", resource);
        span["name"] = json!(format!("policy {action}"));
        change(&mut span, "action", Some(action));
        let attributes = span["attributes"].as_array_mut().unwrap();
        attributes.retain(|attribute| attribute["key"] != "file.path");
        attributes.push(json!({"key": "server.address", "value": {"stringValue": host}}));
        attributes.push(json!({"key": "server.port", "value": {"intValue": port.to_string()}}));
        if *action == "http:request" {
            attributes.push(json!({"key": "http.request.method", "value": {"stringValue": "GET"}}));
        }
        spans.push(span);
    }
    scene.write(&line(&batch(spans)));
    let expected: Vec<_> = cases.iter().map(|case| case.3).collect();
    for deny in [false, true] {
        let output = scene.records(deny);
        success(&output);
        let resources: Vec<_> = rows(&output)
            .into_iter()
            .map(|row| row[3].clone())
            .collect();
        assert_eq!(resources, expected);
    }
}

fn json_rows(output: &Output) -> Vec<Value> {
    let value: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "records must emit one JSON value: {error}\nstdout: {}\nstderr: {}",
            text(&output.stdout),
            text(&output.stderr)
        )
    });
    let rows = value.as_array().expect("records emits a JSON array");
    for row in rows {
        let mut keys: Vec<_> = row
            .as_object()
            .expect("each decision is an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "action", "enforced", "reason", "resource", "result", "rule", "time"
            ]
        );
    }
    rows.clone()
}

fn json_resources(output: &Output) -> Vec<String> {
    json_rows(output)
        .into_iter()
        .map(|row| row["resource"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn records_text_format_is_the_default() {
    let scene = Scene::new();
    let mut span = decision(1, "deny", "/p/file\nnext");
    change(&mut span, "action", Some("Box::Action::\"fs:read\""));
    scene.write(&line(&batch(vec![span])));
    let default = scene.records(false);
    let explicit = scene.records_with(&["--format", "text"]);
    success(&default);
    success(&explicit);
    assert_eq!(explicit.stdout, default.stdout);
    assert_eq!(explicit.stderr, default.stderr);
    assert_eq!(rows(&explicit)[0][2], "fs:read");
    assert_eq!(rows(&explicit)[0][3], "/p/file\\nnext");
}

#[test]
fn records_json_distinguishes_missing_values_from_present_strings() {
    let scene = Scene::new();
    let mut missing = decision(1, "deny", "/p/missing");
    missing["attributes"] = json!([]);
    missing.as_object_mut().unwrap().remove("startTimeUnixNano");
    let mut wrong_types = decision(2, "deny", "/p/wrong-types");
    wrong_types["startTimeUnixNano"] = json!(1735689600000000000_u64);
    wrong_types["attributes"] = json!([
        {"key": "strands.box.policy.verdict", "value": {"stringValue": false}},
        {"key": "strands.box.policy.action", "value": {"stringValue": 3}},
        {"key": "strands.box.policy.resource", "value": {"stringValue": []}},
        {"key": "strands.box.policy.rule", "value": {"stringValue": {}}},
        {"key": "strands.box.policy.reason", "value": {"stringValue": null}},
        {"key": "file.path", "value": {"intValue": "7"}}
    ]);
    let mut empty = decision(3, "deny", "/fallback-must-not-replace-empty");
    for name in ["verdict", "action", "resource", "rule", "reason"] {
        change(&mut empty, name, Some(""));
    }
    empty["startTimeUnixNano"] = json!("");
    let mut literals = decision(4, "unknown", "-");
    change(&mut literals, "action", Some("-"));
    change(&mut literals, "rule", Some("unknown"));
    change(&mut literals, "reason", Some("-"));
    literals["startTimeUnixNano"] = json!("not a timestamp");
    let mut overflow = decision(5, "permit", "/p/overflow");
    overflow["startTimeUnixNano"] = json!("18446744073709551616");
    let mut epoch = decision(6, "permit", "/p/epoch");
    epoch["startTimeUnixNano"] = json!("0");
    scene.write(&line(&batch(vec![
        missing,
        wrong_types,
        empty,
        literals,
        overflow,
        epoch,
    ])));
    let output = scene.records_with(&["--format", "json"]);
    success(&output);
    assert!(output.stderr.is_empty());
    let actual = json_rows(&output);
    let nulls = json!({
        "time": null, "result": null, "action": null,
        "resource": null, "rule": null, "reason": null, "enforced": null
    });
    assert_eq!(actual[0], nulls);
    assert_eq!(actual[1], nulls);
    assert_eq!(
        actual[2],
        json!({
            "time": null, "result": "", "action": "", "resource": "", "rule": "", "reason": "", "enforced": null
        })
    );
    assert_eq!(
        actual[3],
        json!({
            "time": null, "result": "unknown", "action": "-",
            "resource": "-", "rule": "unknown", "reason": "-", "enforced": null
        })
    );
    assert_eq!(
        actual[4],
        json!({
            "time": null, "result": "permit", "action": "fs:read",
            "resource": "/p/overflow", "rule": "private_files", "reason": "outside the project", "enforced": null
        })
    );
    assert_eq!(actual[5]["time"], "1970-01-01T00:00:00.000000000Z");
    assert_eq!(actual.len(), 6);
}

#[test]
fn records_json_round_trips_controls_and_unicode_without_display_escaping() {
    let scene = Scene::new();
    let value = "日本語\tline\nnext\r\u{1b}[31m\0\u{9b}雪😀\\n";
    let mut span = decision(1, value, value);
    for name in ["action", "rule", "reason"] {
        change(&mut span, name, Some(value));
    }
    span["startTimeUnixNano"] = json!("1735689600123456789");
    scene.write(&line(&batch(vec![span])));
    let output = scene.records_with(&["--format", "json"]);
    success(&output);
    assert_eq!(
        json_rows(&output),
        [json!({
            "time": "2025-01-01T00:00:00.123456789Z", "result": value,
            "action": value, "resource": value, "rule": value, "reason": value, "enforced": null
        })]
    );
    let denied = scene.records_with(&["--format", "json", "--deny"]);
    success(&denied);
    assert!(json_rows(&denied).is_empty());
}

#[test]
fn records_json_uses_normalized_actions_and_canonical_resource_fallbacks() {
    let scene = Scene::new();
    let subjects = [
        "strands.box.policy.resource",
        "file.path",
        "server.address",
        "process.command",
    ];
    let mut spans = Vec::new();
    for index in 0..subjects.len() {
        let mut span = decision(index as u64, "deny", "/discard");
        change(&mut span, "action", Some("Box::Action::\"net:connect\""));
        span["attributes"]
            .as_array_mut()
            .unwrap()
            .retain(|a| a["key"] != "file.path" && a["key"] != "strands.box.policy.resource");
        for key in subjects[index..].iter().rev() {
            span["attributes"].as_array_mut().unwrap().push(json!({
                "key": key, "value": {"stringValue": format!("{key}:443/path")}
            }));
        }
        span["attributes"].as_array_mut().unwrap().insert(
            0,
            json!({
                "key": "untrusted.strands.box.policy.resource", "value": {"stringValue": "/wrong"}
            }),
        );
        spans.push(span);
    }
    let mut fallback = decision(9, "deny", "/p/nonstring-canonical-fallback");
    change(&mut fallback, "resource", None);
    fallback["attributes"].as_array_mut().unwrap().push(json!({
        "key": "strands.box.policy.resource", "value": {"stringValue": 42}
    }));
    spans.push(fallback);
    scene.write(&line(&batch(spans)));
    let output = scene.records_with(&["--format", "json"]);
    success(&output);
    let actual = json_rows(&output);
    assert_eq!(actual.len(), 5);
    for (row, key) in actual.iter().zip(subjects) {
        assert_eq!(row["action"], "net:connect");
        assert_eq!(row["resource"], format!("{key}:443/path"));
    }
    assert_eq!(actual[4]["resource"], "/p/nonstring-canonical-fallback");
}

#[test]
fn records_json_returns_an_empty_array_for_empty_or_filtered_history() {
    let scene = Scene::new();
    let empty = scene.records_with(&["--format", "json"]);
    success(&empty);
    assert!(empty.stderr.is_empty());
    assert!(json_rows(&empty).is_empty());
    scene.write(&line(&batch(vec![decision(1, "permit", "/p/allowed")])));
    for options in [
        vec!["--deny"],
        vec!["--would-deny"],
        vec!["--action", "net:connect"],
        vec!["--resource", "/absent"],
        vec!["--since", "2025-01-02T00:00:00Z"],
        vec!["--tail", "0"],
    ] {
        let output = scene
            .command(&["runs", "history", ID, "--format", "json"])
            .args(&options)
            .output()
            .unwrap();
        success(&output);
        assert!(
            output.stderr.is_empty(),
            "{options:?}: {}",
            text(&output.stderr)
        );
        assert!(json_rows(&output).is_empty(), "{options:?}");
    }
    let output = scene.records_with(&["--would-deny"]);
    success(&output);
    assert!(output.stderr.is_empty());
    assert_eq!(
        text(&output.stdout),
        "No would-deny policy decisions recorded.\n"
    );
}

#[test]
fn records_action_filter_is_exact_and_uses_the_normalized_recorded_action() {
    let scene = Scene::new();
    let mut spans = Vec::new();
    for (n, action) in [
        "fs:read",
        "Box::Action::\"fs:read\"",
        "FS:READ",
        "fs:reader",
    ]
    .iter()
    .enumerate()
    {
        let mut span = decision(n as u64, "permit", &format!("/p/{n}"));
        change(&mut span, "action", Some(action));
        spans.push(span);
    }
    let mut missing = decision(5, "permit", "/p/missing");
    change(&mut missing, "action", None);
    spans.push(missing);
    scene.write(&line(&batch(spans)));
    for (filter, expected) in [
        ("fs:read", vec!["/p/0", "/p/1"]),
        ("FS:READ", vec!["/p/2"]),
        ("read", vec![]),
        ("Box::Action::\"fs:read\"", vec![]),
        ("-", vec![]),
    ] {
        let output = scene.records_with(&["--format", "json", "--action", filter]);
        success(&output);
        assert_eq!(json_resources(&output), expected, "filter: {filter:?}");
    }
}

#[test]
fn records_resource_filter_uses_literal_case_sensitive_unescaped_substrings() {
    let scene = Scene::new();
    let resources = [
        "/Project/a/../B[1]*\n雪",
        "/Project/a/../B1suffix\n雪",
        "/Project/B[1]*\n雪",
        "/Project/a/../B[1]*\\n雪",
        "/project/a/../B[1]*\n雪",
    ];
    let mut spans: Vec<_> = resources
        .iter()
        .enumerate()
        .map(|(n, resource)| {
            let mut span = decision(n as u64, "deny", resource);
            span["attributes"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|a| a["key"] == "file.path")
                .unwrap()["value"]["stringValue"] = json!("/wrong/fallback");
            span
        })
        .collect();
    let mut fallback = decision(8, "deny", "/Project/fallback");
    change(&mut fallback, "resource", None);
    spans.push(fallback);
    let mut missing = decision(9, "deny", "/discard");
    change(&mut missing, "resource", None);
    missing["attributes"]
        .as_array_mut()
        .unwrap()
        .retain(|attribute| attribute["key"] != "file.path");
    spans.push(missing);
    scene.write(&line(&batch(spans)));
    for (filter, expected) in [
        ("/Project/a/../B[1]*\n雪", vec![resources[0]]),
        ("/Project/B[1]*\n雪", vec![resources[2]]),
        ("/Project/a/../B[1]*\\n雪", vec![resources[3]]),
        ("/project", vec![resources[4]]),
        ("/wrong/fallback", vec![]),
        ("fallback", vec!["/Project/fallback"]),
        ("-", vec![]),
    ] {
        let output = scene.records_with(&["--format", "json", "--resource", filter]);
        success(&output);
        assert_eq!(json_resources(&output), expected, "filter: {filter:?}");
    }
}

#[test]
fn records_since_compares_instants_inclusively_and_keeps_file_order() {
    let scene = Scene::new();
    let mut spans = Vec::new();
    for (n, resource, time) in [
        (1, "/p/after", Some("1735689600123456790")),
        (2, "/p/before", Some("1735689600123456788")),
        (3, "/p/equal", Some("1735689600123456789")),
        (4, "/p/absent-time", None),
        (5, "/p/invalid-time", Some("invalid")),
    ] {
        let mut span = decision(n, "deny", resource);
        if let Some(time) = time {
            span["startTimeUnixNano"] = json!(time);
        } else {
            span.as_object_mut().unwrap().remove("startTimeUnixNano");
        }
        spans.push(span);
    }
    scene.write(&line(&batch(spans)));
    let unfiltered = scene.records_with(&[
        "--format",
        "json",
        "--deny",
        "--action",
        "fs:read",
        "--resource",
        "/p/",
    ]);
    success(&unfiltered);
    assert_eq!(
        json_resources(&unfiltered),
        [
            "/p/after",
            "/p/before",
            "/p/equal",
            "/p/absent-time",
            "/p/invalid-time"
        ]
    );
    for since in [
        "2025-01-01T00:00:00.123456789Z",
        "2024-12-31T19:00:00.123456789-05:00",
        "2025-01-01T05:30:00.123456789+05:30",
    ] {
        let output = scene.records_with(&["--format", "json", "--since", since]);
        success(&output);
        assert_eq!(
            json_resources(&output),
            ["/p/after", "/p/equal"],
            "since: {since}"
        );
    }
}

#[test]
fn records_combines_all_filters_before_taking_the_tail() {
    let scene = Scene::new();
    let mut spans = Vec::new();
    for (n, verdict, action, resource, time) in [
        (1, "deny", "fs:read", "/keep/first", "1735689600000000000"),
        (
            2,
            "deny",
            "Box::Action::\"fs:read\"",
            "/keep/second",
            "1735689600000000001",
        ),
        (3, "deny", "fs:read", "/keep/third", "1735689600000000002"),
        (
            4,
            "permit",
            "fs:read",
            "/keep/wrong-verdict",
            "1735689600000000000",
        ),
        (
            5,
            "deny",
            "FS:READ",
            "/keep/wrong-action",
            "1735689600000000000",
        ),
        (
            6,
            "deny",
            "fs:read",
            "/other/wrong-resource",
            "1735689600000000000",
        ),
        (
            7,
            "deny",
            "fs:read",
            "/keep/too-early",
            "1735689599999999999",
        ),
        (8, "deny", "fs:read", "/keep/no-time", "invalid"),
    ] {
        let mut span = decision(n, verdict, resource);
        change(&mut span, "action", Some(action));
        span["startTimeUnixNano"] = json!(time);
        spans.push(span);
    }
    for (flag, enforcement, opposite_enforcement, display) in [
        ("--deny", None, false, "deny"),
        ("--would-deny", Some(false), true, "would deny"),
    ] {
        let mut selected = spans.clone();
        if let Some(enforced) = enforcement {
            for span in &mut selected {
                span["attributes"].as_array_mut().unwrap().push(json!({
                    "key": "strands.box.policy.enforced", "value": {"boolValue": enforced}
                }));
            }
        }
        let mut opposite = decision(9, "deny", "/keep/opposite-kind");
        opposite["attributes"].as_array_mut().unwrap().push(json!({
            "key": "strands.box.policy.enforced", "value": {"boolValue": opposite_enforcement}
        }));
        selected.push(opposite);
        scene.write(&line(&batch(selected)));
        let before = snapshot(&scene.home);
        for format in ["text", "json"] {
            let output = scene.records_with(&[
                "--format",
                format,
                flag,
                "--action",
                "fs:read",
                "--resource",
                "/keep/",
                "--since",
                "2025-01-01T00:00:00Z",
                "--tail",
                "2",
            ]);
            success(&output);
            assert!(output.stderr.is_empty());
            let resources = if format == "json" {
                let rows = json_rows(&output);
                assert!(rows.iter().all(|row| row["result"] == "deny"));
                assert!(rows.iter().all(|row| row["enforced"] == json!(enforcement)));
                json_resources(&output)
            } else {
                let rows = rows(&output);
                assert!(rows.iter().all(|row| row[1] == display));
                rows.into_iter().map(|row| row[3].clone()).collect()
            };
            assert_eq!(
                resources,
                ["/keep/second", "/keep/third"],
                "{flag}, format: {format}"
            );
        }
        assert_eq!(snapshot(&scene.home), before);
    }
}

#[test]
fn records_tail_keeps_repeated_matching_decisions_in_file_order_for_every_limit() {
    let scene = Scene::new();
    let mut newest = decision(1, "deny", "/p/newest-time");
    newest["startTimeUnixNano"] = json!("1735689609000000000");
    let repeated = decision(2, "deny", "/p/repeated");
    let mut oldest = decision(3, "deny", "/p/oldest-time");
    oldest["startTimeUnixNano"] = json!("1735689500000000000");
    scene.write(
        &(line(&batch(vec![newest, repeated.clone()]))
            + &line(&batch(vec![
                oldest,
                repeated,
                decision(4, "permit", "/p/ignored-last"),
            ]))),
    );
    let all = [
        "/p/newest-time",
        "/p/repeated",
        "/p/oldest-time",
        "/p/repeated",
    ];
    for limit in [0, 1, 3, 4, usize::MAX] {
        let limit_text = limit.to_string();
        let output = scene.records_with(&["--format", "json", "--deny", "--tail", &limit_text]);
        success(&output);
        assert_eq!(
            json_resources(&output),
            all[all.len().saturating_sub(limit)..],
            "tail: {limit}"
        );
    }
}

#[test]
fn records_json_stays_valid_and_reports_all_bad_lines_with_tail_or_no_matches() {
    let scene = Scene::new();
    let mut oversized = batch(vec![decision(2, "deny", "/p/oversized")]);
    oversized["padding"] = json!("x".repeat(8 * 1024 * 1024));
    scene.write(
        &(line(&batch(vec![decision(1, "deny", "/p/first")]))
            + "{bad json}\n"
            + &line(&oversized)
            + &line(&batch(vec![decision(3, "deny", "/p/later")]))
            + "{\"resourceSpans\":"),
    );
    for (options, expected) in [
        (vec!["--tail", "0"], vec![]),
        (vec!["--resource", "/no-match"], vec![]),
        (vec!["--tail", "1"], vec!["/p/later"]),
        (vec!["--tail", "99"], vec!["/p/first", "/p/later"]),
    ] {
        let output = scene
            .command(&["runs", "history", ID, "--format", "json"])
            .args(&options)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "{options:?}: {}",
            text(&output.stderr)
        );
        assert_eq!(json_resources(&output), expected, "{options:?}");
        for number in [2, 3, 5] {
            has_line_warning(&output, number);
        }
    }
}

#[test]
fn records_rejects_invalid_filter_values_as_usage_errors() {
    let scene = Scene::new();
    scene.write(&line(&batch(vec![decision(1, "deny", "/p/valid")])));
    let valid = scene.records_with(&[
        "--format",
        "json",
        "--action",
        "fs:read",
        "--resource",
        "/p/",
        "--since",
        "2025-01-01T00:00:00Z",
        "--tail",
        "0",
    ]);
    success(&valid);
    assert!(json_rows(&valid).is_empty());
    scene.write("{bad json}\n");
    let overflow = (usize::MAX as u128 + 1).to_string();
    for (flag, value) in [
        ("--format", "yaml"),
        ("--format", "JSON"),
        ("--format", ""),
        ("--action", ""),
        ("--resource", ""),
        ("--since", ""),
        ("--since", "2025-01-01"),
        ("--since", "2025-01-01T00:00:00"),
        ("--since", "2025-02-30T00:00:00Z"),
        ("--since", "2025-01-01T00:00:00+0000"),
        ("--since", "2025-01-01T00:00:00Z trailing"),
        ("--tail", "-1"),
        ("--tail", "1.5"),
        ("--tail", "many"),
        ("--tail", overflow.as_str()),
    ] {
        let output = scene.records_with(&[flag, value]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{flag} {value:?}: {}",
            text(&output.stderr)
        );
        assert!(output.stdout.is_empty(), "{flag} {value:?}");
        assert!(text(&output.stderr).contains("error:"), "{flag} {value:?}");
        assert!(
            !text(&output.stderr).contains("invalid JSON"),
            "usage is checked before reading the log"
        );
    }
}

fn control(n: u64, operation: &str, subject: &str, reason: Option<&str>) -> Value {
    let mut attributes = vec![
        json!({"key": "strands.box.control.operation", "value": {"stringValue": operation}}),
        json!({"key": "strands.box.control.subject", "value": {"stringValue": subject}}),
    ];
    if let Some(reason) = reason {
        attributes
            .push(json!({"key": "strands.box.control.reason", "value": {"stringValue": reason}}));
    }
    json!({
        "traceId": format!("{n:032x}"), "spanId": format!("{n:016x}"),
        "name": format!("control {operation}"), "kind": 1,
        "startTimeUnixNano": format!("17356896000000000{n:02}"),
        "endTimeUnixNano": format!("17356896000000000{n:02}"),
        "attributes": attributes
    })
}

fn decision_at(n: u64, verdict: &str, resource: &str) -> Value {
    let mut span = decision(n, verdict, resource);
    span["startTimeUnixNano"] = json!(format!("17356896000000000{n:02}"));
    span
}

/// One batch with the policy scope first, as Box Core can write it, so time alone orders the rows.
fn with_control(policy: Vec<Value>, control: Vec<Value>) -> Value {
    json!({"resourceSpans": [{
        "resource": {"attributes": [{"key": "strands.box.source", "value": {"stringValue": "box"}}]},
        "scopeSpans": [
            {"scope": {"name": "strands-box.policy"}, "spans": policy},
            {"scope": {"name": "strands-box.control"}, "spans": control}
        ]
    }]})
}

#[test]
fn records_show_each_installed_or_refused_policy_and_leave_out_other_control_records() {
    let scene = Scene::new();
    scene.write(&format!(
        "{}{}",
        line(&with_control(
            vec![
                decision_at(3, "deny", "/p/private"),
                decision_at(6, "permit", "/p/private"),
            ],
            vec![
                control(1, "box_started", "box", None),
                control(2, "policy_installed", "policy.dw", None),
                control(5, "policy_installed", "policy off", None),
            ],
        )),
        line(&with_control(
            vec![decision_at(7, "permit", "/p/other")],
            vec![control(8, "policy_refused", "policy.dw", Some("bad rule"))],
        )),
    ));
    let output = scene.records(false);
    success(&output);
    let shown: Vec<_> = rows(&output)
        .into_iter()
        .map(|row| {
            [
                row[1].clone(),
                row[2].clone(),
                row[3].clone(),
                row[5].clone(),
            ]
        })
        .collect();
    assert_eq!(
        shown,
        [
            ["installed", "policy", "policy.dw", "-"],
            ["deny", "fs:read", "/p/private", "outside the project"],
            ["installed", "policy", "policy off", "-"],
            ["permit", "fs:read", "/p/private", "outside the project"],
            ["permit", "fs:read", "/p/other", "outside the project"],
            ["refused", "policy", "policy.dw", "bad rule"],
        ]
        .map(|row| row.map(str::to_owned))
    );

    let denied = scene.records(true);
    success(&denied);
    assert_eq!(rows(&denied).len(), 1);
    let last = scene.records_with(&["--tail", "3"]);
    success(&last);
    assert_eq!(
        rows(&last)
            .iter()
            .map(|row| row[3].as_str())
            .collect::<Vec<_>>(),
        ["/p/private", "/p/other", "policy.dw"]
    );
    let changes = scene.records_with(&["--action", "policy", "--format", "json"]);
    success(&changes);
    let changes = json_rows(&changes);
    assert_eq!(
        changes
            .iter()
            .map(|row| (row["result"].as_str(), row["resource"].as_str()))
            .collect::<Vec<_>>(),
        [
            (Some("installed"), Some("policy.dw")),
            (Some("installed"), Some("policy off")),
            (Some("refused"), Some("policy.dw")),
        ]
    );
    assert!(changes.iter().all(|row| row["enforced"].is_null()));
}
