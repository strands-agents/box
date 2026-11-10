//! Working-directory restrictions through the configured shell and its decision records.

#[path = "support/fixture.rs"]
mod fixture;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Output;

use fixture::{Configured, Request};

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn host_pwd() -> PathBuf {
    let path = ["/usr/bin/pwd", "/bin/pwd"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .expect("the host pwd program");
    Path::new(path)
        .canonicalize()
        .expect("the native pwd executable identity")
}

fn install_pwd_alias(request: &Request, executable: &Path) -> String {
    let workspace = request.operator_home().join("workspace");
    std::fs::create_dir_all(&workspace).expect("the fixture workspace");
    let alias = workspace.join("native-pwd");
    std::os::unix::fs::symlink(executable, &alias).expect("a distinct alias of native pwd");
    assert_eq!(
        alias.canonicalize().expect("the native pwd alias resolves"),
        executable,
        "the fixture alias must retain the native executable identity"
    );
    alias.display().to_string()
}

fn shell_decisions(box_: &Configured, action: &str) -> Vec<BTreeMap<String, String>> {
    command_decisions(box_, action)
        .into_iter()
        .filter(|decision| {
            decision.get("process.command").is_some_and(|program| {
                program == "pwd"
                    || program == "native-pwd"
                    || program.ends_with("/pwd")
                    || program.ends_with("/native-pwd")
            })
        })
        .collect()
}

fn command_decisions(box_: &Configured, action: &str) -> Vec<BTreeMap<String, String>> {
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
    let pwd = host_pwd();
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
    let config = r#"
[tool.pwd]
command = ["{workspace}/native-pwd"]
[tool.pwd.filesystem]
read = ["{workspace}"]
[telemetry.decisions]
kind = "file"
destination = "~/decisions.jsonl"
include = ["permit", "deny"]
"#;
    let request = Request::with_config("shell-cwd", &policy, config);
    let alias = install_pwd_alias(&request, &pwd);
    let program = if action == "shell:spawn" {
        alias.as_str()
    } else {
        "pwd"
    };
    let box_ = request.expect();
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

fn tool_directory_fixture(
    name: &str,
    tool_workspace: Option<&str>,
    guarded_directory: &str,
) -> Option<(Configured, String)> {
    if !fixture::namespace_launcher_is_usable() {
        eprintln!("SKIPPED: {name}: namespace launcher is unavailable");
        return None;
    }
    let pwd = host_pwd();
    let policy = format!(
        r#"
@id("allowed_operations")
permit(principal, action, resource);
@id("cwd_guard")
forbid(principal, action == Box::Action::"shell:spawn", resource)
when {{ context.input.program_path == {pwd:?} && context.input.cwd == {guarded_directory:?} }};
"#
    );
    let workspace_setting = tool_workspace
        .map(|directory| format!("workspace = {directory:?}\n"))
        .unwrap_or_default();
    let config = format!(
        r#"
[tool.pwd]
command = ["{{workspace}}/native-pwd"]
{workspace_setting}[tool.pwd.filesystem]
read = ["{{workspace}}"]
[telemetry.decisions]
kind = "file"
destination = "~/decisions.jsonl"
include = ["permit", "deny"]
"#
    );
    let request = Request::with_config(name, &policy, &config);
    let program = install_pwd_alias(&request, &pwd);
    for directory in [
        "workspace/allowed",
        "workspace/guarded",
        "workspace/caller",
        "outside",
    ] {
        std::fs::create_dir_all(request.operator_home().join(directory))
            .expect("the configured tool directories");
    }
    Some((request.expect(), program))
}

fn expect_output_directory(output: &Output, directory: &Path) {
    assert!(
        output.status.success(),
        "the allowed tool failed: {output:?}"
    );
    assert_eq!(
        stdout(output).trim(),
        directory.to_string_lossy(),
        "the tool must execute in its selected directory: {output:?}"
    );
}

fn expect_spawn_decisions(box_: &Configured, expected: &[(&Path, &str)]) {
    expect_decision_directories(&shell_decisions(box_, "shell:spawn"), expected);
}

fn expect_decision_directories(decisions: &[BTreeMap<String, String>], expected: &[(&Path, &str)]) {
    assert_eq!(decisions.len(), expected.len(), "{decisions:?}");
    for (decision, (directory, verdict)) in decisions.iter().zip(expected) {
        assert_eq!(
            decision
                .get("process.working_directory")
                .map(String::as_str),
            Some(directory.to_string_lossy().as_ref()),
            "the decision must name the selected tool directory: {decision:?}"
        );
        assert_eq!(
            decision
                .get("strands.box.policy.verdict")
                .map(String::as_str),
            Some(*verdict),
            "the decision must agree with execution: {decision:?}"
        );
        let rule = if *verdict == "deny" {
            "cwd_guard"
        } else {
            "allowed_operations"
        };
        assert_eq!(
            decision.get("strands.box.policy.rule").map(String::as_str),
            Some(rule),
            "the authored rule must determine the decision: {decision:?}"
        );
    }
}

#[test]
fn an_explicit_tool_workspace_is_checked_before_the_tool_starts() {
    let Some((allowed, pwd)) = tool_directory_fixture(
        "explicit-cwd-control",
        Some("{workspace}/allowed"),
        "~/workspace/guarded",
    ) else {
        return;
    };
    let allowed_directory = allowed.workspace().join("allowed");
    for program in [pwd.as_str(), "native-pwd"] {
        let output = run_in(&allowed, &allowed.workspace().join("caller"), program);
        expect_output_directory(&output, &allowed_directory);
    }
    let (guarded, pwd) = tool_directory_fixture(
        "explicit-cwd-denial",
        Some("{workspace}/guarded"),
        "~/workspace/guarded",
    )
    .expect("the launcher was available for the control");
    for program in [pwd.as_str(), "native-pwd"] {
        expect_refused(&guarded, &guarded.workspace().join("allowed"), program);
    }
    expect_spawn_decisions(
        &allowed,
        &[
            (&allowed_directory, "permit"),
            (&allowed_directory, "permit"),
        ],
    );
    let guarded_directory = guarded.workspace().join("guarded");
    expect_spawn_decisions(
        &guarded,
        &[(&guarded_directory, "deny"), (&guarded_directory, "deny")],
    );
}

#[test]
fn an_allowed_tool_workspace_does_not_inherit_the_callers_directory_denial() {
    let Some((box_, pwd)) = tool_directory_fixture(
        "explicit-cwd-permit",
        Some("{workspace}/allowed"),
        "~/workspace/guarded",
    ) else {
        return;
    };
    let actual_directory = box_.workspace().join("allowed");
    let output = run_in(&box_, &box_.workspace().join("guarded"), &pwd);
    expect_output_directory(&output, &actual_directory);
    expect_spawn_decisions(&box_, &[(&actual_directory, "permit")]);
}

#[test]
fn a_fallback_workspace_is_checked_before_the_tool_starts() {
    let Some((box_, pwd)) = tool_directory_fixture("fallback-cwd-denial", None, "~/workspace")
    else {
        return;
    };
    let allowed_directory = box_.workspace().join("allowed");
    expect_permitted(&box_, &allowed_directory, &pwd);
    expect_refused(&box_, &box_.operator_home().join("outside"), &pwd);
    expect_spawn_decisions(
        &box_,
        &[(&allowed_directory, "permit"), (&box_.workspace(), "deny")],
    );
}

#[test]
fn an_allowed_fallback_workspace_does_not_inherit_the_callers_directory_denial() {
    let Some((box_, pwd)) = tool_directory_fixture("fallback-cwd-permit", None, "~/outside") else {
        return;
    };
    let output = run_in(&box_, &box_.operator_home().join("outside"), &pwd);
    expect_output_directory(&output, &box_.workspace());
    expect_spawn_decisions(&box_, &[(&box_.workspace(), "permit")]);
}

#[test]
fn a_denied_tool_directory_stops_every_pipeline_stage() {
    let Some((allowed, pwd)) = tool_directory_fixture(
        "pipeline-cwd-control",
        Some("{workspace}/allowed"),
        "~/workspace/guarded",
    ) else {
        return;
    };
    let allowed_marker = allowed.workspace().join("earlier-stage-ran");
    let output = run_in(
        &allowed,
        &allowed.workspace().join("caller"),
        &format!("mkdir '{}' | {pwd}", allowed_marker.display()),
    );
    expect_output_directory(&output, &allowed.workspace().join("allowed"));
    assert!(
        allowed_marker.is_dir(),
        "the permitted pipeline must execute its first stage: {output:?}"
    );
    let (guarded, pwd) = tool_directory_fixture(
        "pipeline-cwd-denial",
        Some("{workspace}/guarded"),
        "~/workspace/guarded",
    )
    .expect("the launcher was available for the control");
    let guarded_marker = guarded.workspace().join("earlier-stage-ran");
    expect_refused(
        &guarded,
        &guarded.workspace().join("allowed"),
        &format!("mkdir '{}' | {pwd}", guarded_marker.display()),
    );
    assert!(
        !guarded_marker.exists(),
        "a denied tool directory must prevent the earlier pipeline stage from running"
    );
    expect_spawn_decisions(
        &allowed,
        &[(&allowed.workspace().join("allowed"), "permit")],
    );
    expect_spawn_decisions(&guarded, &[(&guarded.workspace().join("guarded"), "deny")]);
}

#[test]
fn a_program_using_the_agent_spec_checks_the_agent_workspace() {
    if !fixture::namespace_launcher_is_usable() {
        eprintln!("SKIPPED: agent-spec workspace: namespace launcher is unavailable");
        return;
    }
    let pwd = host_pwd();
    let config = r#"
[telemetry.decisions]
kind = "file"
destination = "~/decisions.jsonl"
include = ["permit", "deny"]
"#;
    for (name, guarded, verdict) in [
        ("agent-spec-cwd-control", "~/workspace/caller", "permit"),
        ("agent-spec-cwd-denial", "~/workspace", "deny"),
    ] {
        let policy = format!(
            r#"
@id("allowed_operations")
permit(principal, action, resource);
@id("cwd_guard")
forbid(principal, action == Box::Action::"shell:spawn", resource)
when {{ context.input.program_path == {pwd:?} && context.input.cwd == {guarded:?} }};
"#
        );
        let request = Request::with_config(name, &policy, config).agent_list(
            "exec",
            &[pwd.to_str().expect("the native pwd path is UTF-8")],
        );
        let program = install_pwd_alias(&request, &pwd);
        std::fs::create_dir_all(request.operator_home().join("workspace/caller"))
            .expect("the caller directory");
        let box_ = request.expect();
        let caller = box_.workspace().join("caller");
        if verdict == "permit" {
            expect_output_directory(&run_in(&box_, &caller, &program), &box_.workspace());
        } else {
            expect_refused(&box_, &caller, &program);
        }
        expect_spawn_decisions(&box_, &[(&box_.workspace(), verdict)]);
    }
}

#[test]
fn the_longest_command_prefix_selects_the_checked_workspace() {
    let Some((box_, pwd)) = tool_directory_fixture(
        "command-prefix-cwd",
        Some("{workspace}/allowed"),
        "~/workspace/guarded",
    ) else {
        return;
    };
    let mut command = box_.command_for("/bin/bash");
    let mut config: toml::Value =
        toml::from_str(&std::fs::read_to_string(box_.config()).expect("the configured authority"))
            .expect("the configured TOML");
    let mut longer = config["tool"]["pwd"].clone();
    longer["command"] =
        toml::Value::try_from(vec![pwd.as_str(), "-P"]).expect("the longer command prefix");
    longer["workspace"] =
        toml::Value::String(box_.workspace().join("guarded").display().to_string());
    config["tool"]
        .as_table_mut()
        .expect("the configured tool tables")
        .insert("physical".to_string(), longer);
    std::fs::write(
        box_.config(),
        toml::to_string(&config).expect("the extended tool configuration"),
    )
    .expect("the extended configuration is installed before the run");
    let output = command
        .args([
            "-c",
            &format!(
                "zsh -lc \"cd '{}' && {pwd}\"; zsh -lc \"cd '{}' && {pwd} -P\"",
                box_.workspace().join("caller").display(),
                box_.workspace().join("caller").display(),
            ),
        ])
        .output()
        .expect("run both command prefixes");
    assert_eq!(output.status.code(), Some(126), "{output:?}");
    assert_eq!(
        stdout(&output).trim(),
        box_.workspace().join("allowed").to_string_lossy(),
        "the short prefix must run and the longer prefix must be refused: {output:?}"
    );
    assert!(stderr(&output).contains("cwd_guard"), "{output:?}");
    expect_spawn_decisions(
        &box_,
        &[
            (&box_.workspace().join("allowed"), "permit"),
            (&box_.workspace().join("guarded"), "deny"),
        ],
    );
}

#[cfg(unix)]
fn aliased_directory_fixture(name: &str) -> Option<Configured> {
    if !fixture::namespace_launcher_is_usable() {
        eprintln!("SKIPPED: {name}: namespace launcher is unavailable");
        return None;
    }
    let pwd = host_pwd();
    let policy = r#"
@id("allowed_operations")
permit(principal, action, resource);
"#;
    let config = r#"
[tool.alpha]
command = ["{workspace}/alpha-pwd"]
workspace = "{workspace}/alpha"
[tool.beta]
command = ["{workspace}/beta-pwd"]
workspace = "{workspace}/beta"
[telemetry.decisions]
kind = "file"
destination = "~/decisions.jsonl"
include = ["permit", "deny"]
"#;
    let request = Request::with_config(name, policy, config);
    let workspace = request.operator_home().join("workspace");
    for name in ["alpha", "beta", "caller"] {
        std::fs::create_dir_all(workspace.join(name)).expect("the selected tool directory");
    }
    for alias in ["alpha-pwd", "beta-pwd"] {
        std::os::unix::fs::symlink(&pwd, workspace.join(alias)).expect("an alias of pwd");
    }
    Some(request.expect())
}

#[cfg(unix)]
#[test]
fn configured_aliases_of_one_program_keep_their_checked_workspaces() {
    let Some(box_) = aliased_directory_fixture("aliased-tool-cwd") else {
        return;
    };
    let caller = box_.workspace().join("caller");
    for name in ["beta", "alpha"] {
        let program = box_.workspace().join(format!("{name}-pwd"));
        expect_output_directory(
            &run_in(&box_, &caller, &format!("'{}'", program.display())),
            &box_.workspace().join(name),
        );
    }
    expect_decision_directories(
        &command_decisions(&box_, "shell:spawn"),
        &[
            (&box_.workspace().join("beta"), "permit"),
            (&box_.workspace().join("alpha"), "permit"),
        ],
    );
}

#[test]
fn missing_slash_commands_keep_status127_and_the_caller_directory() {
    let Some((box_, _)) = tool_directory_fixture("missing-slash-cwd", None, "~/workspace/guarded")
    else {
        return;
    };
    let caller = box_.operator_home().join("outside");
    let absolute = caller.join("missing-command");
    for program in [
        absolute.display().to_string(),
        "./missing-command".to_string(),
    ] {
        let output = run_in(&box_, &caller, &program);
        assert_eq!(output.status.code(), Some(127), "{output:?}");
        assert!(stdout(&output).is_empty(), "{output:?}");
    }
    expect_decision_directories(
        &command_decisions(&box_, "shell:spawn"),
        &[(&caller, "permit"), (&caller, "permit")],
    );
}

#[test]
fn a_tool_workspace_does_not_change_the_callers_shell_directory() {
    let Some((box_, pwd)) = tool_directory_fixture(
        "caller-cwd-unchanged",
        Some("{workspace}/allowed"),
        "~/workspace/guarded",
    ) else {
        return;
    };
    let caller = box_.workspace().join("caller");
    let selected = box_.workspace().join("allowed");
    let output = run_in(&box_, &caller, &format!("pwd; {pwd}; pwd"));
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        stdout(&output).lines().collect::<Vec<_>>(),
        [
            caller.to_string_lossy().as_ref(),
            selected.to_string_lossy().as_ref(),
            caller.to_string_lossy().as_ref(),
        ],
        "the parent Shell must retain its directory before and after the tool: {output:?}"
    );
    expect_spawn_decisions(&box_, &[(&selected, "permit")]);
    expect_decision_directories(
        &shell_decisions(&box_, "shell:exec"),
        &[(&caller, "permit"), (&caller, "permit")],
    );
}

#[cfg(unix)]
#[test]
fn pipeline_tools_keep_distinct_checked_workspaces() {
    let Some(box_) = aliased_directory_fixture("pipeline-distinct-cwd") else {
        return;
    };
    let alpha = box_.workspace().join("alpha");
    let beta = box_.workspace().join("beta");
    let output = run_in(
        &box_,
        &box_.workspace().join("caller"),
        &format!(
            "'{}' 1>&2 | '{}'",
            box_.workspace().join("alpha-pwd").display(),
            box_.workspace().join("beta-pwd").display(),
        ),
    );
    expect_output_directory(&output, &beta);
    assert!(
        stderr(&output)
            .lines()
            .any(|line| line == alpha.to_string_lossy()),
        "the first pipeline stage must execute in its own directory: {output:?}"
    );
    expect_decision_directories(
        &command_decisions(&box_, "shell:spawn"),
        &[(&alpha, "permit"), (&beta, "permit")],
    );
}
