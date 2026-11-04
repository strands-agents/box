//! Working-directory restrictions through the configured shell and its decision records.

#[path = "support/fixture.rs"]
mod fixture;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Output;

use fixture::{Configured, Request};

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn shell_decisions(box_: &Configured, action: &str) -> Vec<BTreeMap<String, String>> {
    let text = std::fs::read_to_string(box_.operator_home().join("decisions.jsonl"))
        .expect("the configured decision records");
    let mut decisions = Vec::new();
    for line in text.lines() {
        let batch: serde_json::Value = serde_json::from_str(line).expect("a decision batch");
        for resource in batch["resourceSpans"].as_array().into_iter().flatten() {
            for scope in resource["scopeSpans"].as_array().into_iter().flatten() {
                if scope["scope"]["name"] != "strands-box.policy" {
                    continue;
                }
                for span in scope["spans"].as_array().into_iter().flatten() {
                    let attributes: BTreeMap<String, String> = span["attributes"]
                        .as_array()
                        .expect("decision attributes")
                        .iter()
                        .filter_map(|attribute| {
                            Some((
                                attribute["key"].as_str()?.to_string(),
                                attribute["value"]["stringValue"].as_str()?.to_string(),
                            ))
                        })
                        .collect();
                    if attributes
                        .get("strands.box.policy.action")
                        .map(String::as_str)
                        == Some(action)
                        && attributes
                            .get("process.command")
                            .is_some_and(|program| program == "pwd" || program.ends_with("/pwd"))
                    {
                        decisions.push(attributes);
                    }
                }
            }
        }
    }
    decisions
}

fn run_in(box_: &Configured, directory: &Path, program: &str) -> Output {
    box_.bash(&format!(
        "zsh -lc \"cd '{}' && {program}\"",
        directory.display()
    ))
}

fn expect_permitted(box_: &Configured, directory: &Path, program: &str) {
    let output = run_in(box_, directory, program);
    eprintln!(
        "allowed directory={} status={:?} stdout={:?}",
        directory.display(),
        output.status.code(),
        stdout(&output)
    );
    assert!(
        output.status.success(),
        "allowed control failed: {output:?}"
    );
    assert_eq!(
        stdout(&output).trim(),
        directory.to_string_lossy(),
        "the command must observe its actual directory: {output:?}"
    );
}

fn expect_refused(box_: &Configured, directory: &Path, program: &str) {
    let output = run_in(box_, directory, program);
    eprintln!(
        "protected directory={} status={:?} stdout={:?}",
        directory.display(),
        output.status.code(),
        stdout(&output)
    );
    eprintln!(
        "spawn decisions: {:?}",
        shell_decisions(box_, "shell:spawn")
    );
    eprintln!("exec decisions: {:?}", shell_decisions(box_, "shell:exec"));
    assert_eq!(output.status.code(), Some(126), "{output:?}");
    assert!(stderr(&output).contains("cwd_guard"), "{output:?}");
    assert!(
        stdout(&output).trim().is_empty(),
        "the protected command ran: {output:?}"
    );
}

fn check_working_directory_guard(action: &str, descendants: bool) {
    if !fixture::namespace_launcher_is_usable() {
        eprintln!(
            "SKIPPED: {action}, descendants={descendants}: namespace launcher is unavailable"
        );
        return;
    }
    let pwd = ["/usr/bin/pwd", "/bin/pwd"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .expect("the host pwd program");
    let program = if action == "shell:spawn" { pwd } else { "pwd" };
    let program_condition = if action == "shell:spawn" {
        format!("context.input.program_path == {pwd:?}")
    } else {
        "context.input.program == \"pwd\"".to_string()
    };
    let condition = if descendants {
        r#"context.input.cwd == "~/workspace/guarded" || context.input.cwd like "~/workspace/guarded/*""#
    } else {
        r#"context.input.cwd == "~/workspace""#
    };
    let policy = format!(
        r#"
permit(principal, action, resource);
@id("cwd_guard")
forbid(principal, action == Box::Action::"{action}", resource)
when {{ {program_condition} && ({condition}) }};
"#
    );
    let config = format!(
        r#"
[tool.pwd]
command = ["{pwd}"]
[tool.pwd.filesystem]
read = ["{{workspace}}"]
[telemetry.decisions]
kind = "file"
destination = "~/decisions.jsonl"
include = ["permit", "deny"]
"#
    );
    let box_ = Request::with_config("shell-cwd", &policy, &config).expect();
    let workspace = box_.workspace();
    let sibling = workspace.join("allowed");
    let protected = workspace.join("guarded");
    let child = protected.join("child");
    std::fs::create_dir_all(&sibling).expect("the allowed directory");
    std::fs::create_dir_all(&child).expect("the protected descendant");

    expect_permitted(&box_, &sibling, program);
    let expected_denials = if descendants {
        expect_refused(&box_, &protected, program);
        expect_refused(&box_, &child, program);
        vec![protected.clone(), child.clone()]
    } else {
        expect_refused(&box_, &workspace, program);
        vec![workspace.clone()]
    };
    let decisions = shell_decisions(&box_, action);
    eprintln!("{action} decisions: {decisions:?}");
    assert_eq!(decisions.len(), expected_denials.len() + 1, "{decisions:?}");
    let expected = std::iter::once((sibling, "permit")).chain(
        expected_denials
            .into_iter()
            .map(|directory| (directory, "deny")),
    );
    for (decision, (directory, verdict)) in decisions.iter().zip(expected) {
        assert_eq!(
            decision
                .get("process.working_directory")
                .map(String::as_str),
            Some(directory.to_string_lossy().as_ref()),
            "decision telemetry must retain the actual working directory: {decision:?}"
        );
        assert_eq!(
            decision
                .get("strands.box.policy.verdict")
                .map(String::as_str),
            Some(verdict),
            "the decision must match execution: {decision:?}"
        );
        if verdict == "deny" {
            assert_eq!(
                decision.get("strands.box.policy.rule").map(String::as_str),
                Some("cwd_guard"),
                "the authored restriction must cause the refusal: {decision:?}"
            );
        }
    }
}

#[test]
fn a_configured_spawn_respects_an_exact_working_directory_restriction() {
    check_working_directory_guard("shell:spawn", false);
}

#[test]
fn a_configured_spawn_respects_a_descendant_working_directory_restriction() {
    check_working_directory_guard("shell:spawn", true);
}

#[test]
fn a_configured_builtin_respects_an_exact_working_directory_restriction() {
    check_working_directory_guard("shell:exec", false);
}

#[test]
fn a_configured_builtin_respects_a_descendant_working_directory_restriction() {
    check_working_directory_guard("shell:exec", true);
}
