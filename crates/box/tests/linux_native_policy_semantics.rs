//! Native policy checks distinguish moving names, replacing files, and listing directories.
#![cfg(all(
    box_native_kernel_tests,
    target_os = "linux",
    target_arch = "aarch64",
    feature = "native-filesystem-policy",
    feature = "test-support"
))]

#[path = "support/bounded_output.rs"]
mod bounded_output;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn exercise(operation: &str, replacement: bool, policy: &str, allowed: bool) {
    let parent =
        PathBuf::from(std::env::var_os("NATIVE_TEST_ROOT").expect("short native fixture root"));
    let root = tempfile::tempdir_in(parent).unwrap().keep();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let source = workspace.join("source");
    let destination = workspace.join("destination");
    if operation == "Frename" {
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("child"), "original\n").unwrap();
        std::fs::write(&destination, "previous\n").unwrap();
    } else {
        std::fs::write(&source, "original\n").unwrap();
    }
    if replacement {
        std::fs::write(&destination, "previous\n").unwrap();
    }
    if operation == "Fopen" {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o400)).unwrap();
    }
    let workload = root.join("native-workload");
    std::fs::copy(env!("NATIVE_WORKLOAD"), &workload).unwrap();
    let q = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
    let args = vec![
        workload.display().to_string(),
        operation.to_string(),
        source.display().to_string(),
        destination.display().to_string(),
        if allowed { "allow" } else { "deny" }.to_string(),
    ];
    std::fs::write(
        root.join("box.toml"),
        format!(
            "name = \"native-policy-semantics\"\nbox_dir = {}\npolicy = \"policy.dw\"\n\
        [experimental-features]\nnative-filesystem-policy = true\n\
        [agent]\ncommand = {}\nworkspace = {}\n\
        [agent.filesystem]\nread = [{}]\nwrite = [{}]\n",
            q(&root.join("state")),
            toml::Value::Array(args.into_iter().map(toml::Value::String).collect()),
            q(&workspace),
            q(&workspace),
            q(&workspace),
        ),
    )
    .unwrap();
    std::fs::write(root.join("policy.dw"), policy).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box"));
    command
        .args(["run", "--config"])
        .arg(root.join("box.toml"))
        .env("HOME", &root)
        .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE")
        .env_remove("BOX_NATIVE_TEST_FAULT")
        .stdin(Stdio::null());
    let output = bounded_output::bounded_output(command);
    std::fs::write(root.join("stderr.log"), &output.stderr).unwrap();
    std::fs::write(root.join("stdout.log"), &output.stdout).unwrap();
    assert!(output.status.success(), "fixture={root:?}: {output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(if allowed {
            "NATIVE_ALLOWED"
        } else {
            "NATIVE_DENIED"
        }),
        "{stdout}"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("NATIVE_RESEARCH_EVENT="))
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let moves = operation
        .strip_prefix('R')
        .or_else(|| operation.strip_prefix('S'))
        .map_or(0, |count| count.parse::<usize>().unwrap());
    let prior_opens = usize::from(operation == "Double");
    let prior_attempts = usize::from(operation.starts_with('B') || operation.starts_with('F'));
    assert_eq!(
        events.len(),
        moves + prior_opens + prior_attempts + 1,
        "{stderr}"
    );
    if prior_attempts == 1 {
        let denied = operation.starts_with('B');
        assert_eq!(
            events[0]["outcome"],
            if denied { "denied" } else { "failed" },
            "{stderr}"
        );
        let decisions = events[0]["decisions"].as_array().unwrap();
        let operations: &[&str] = if operation.ends_with("open") {
            &["ReadContent", "WriteContent"]
        } else if replacement || operation == "Frename" {
            &[
                "Rename",
                "ReadContent",
                "RemoveFile",
                "Rename",
                "WriteContent",
            ]
        } else {
            &["Rename", "ReadContent", "Rename"]
        };
        assert_eq!(decisions.len(), operations.len(), "{stderr}");
        for (index, (decision, expected)) in decisions.iter().zip(operations).enumerate() {
            assert_eq!(decision["operation"], *expected, "{stderr}");
            assert_eq!(
                decision["allow"],
                !denied || index + 1 < decisions.len(),
                "{stderr}"
            );
        }
    }
    if prior_opens == 1 {
        assert_eq!(events[0]["outcome"], "descriptor_issued", "{stderr}");
        assert_eq!(events[0]["decisions"][0]["allow"], true, "{stderr}");
    }
    for event in &events[..moves] {
        assert_eq!(event["outcome"], "completed", "{stderr}");
        let decisions = event["decisions"].as_array().unwrap();
        let operations: &[&str] = if operation.starts_with('S') {
            &[
                "Rename",
                "ReadContent",
                "RemoveFile",
                "Rename",
                "WriteContent",
            ]
        } else {
            &["Rename", "ReadContent", "Rename"]
        };
        assert_eq!(decisions.len(), operations.len(), "{stderr}");
        for (decision, operation) in decisions.iter().zip(operations) {
            assert_eq!(decision["operation"], *operation, "{stderr}");
            assert_eq!(decision["allow"], true, "{stderr}");
        }
    }
    assert_eq!(
        events[moves + prior_opens + prior_attempts]["outcome"],
        if allowed {
            if operation == "move" {
                "completed"
            } else {
                "descriptor_issued"
            }
        } else {
            "denied"
        },
        "{stderr}"
    );
    if (operation == "move" && allowed) || (operation.starts_with('R') && moves % 2 == 1) {
        assert!(!source.exists());
        assert_eq!(std::fs::read(&destination).unwrap(), b"original\n");
    } else if operation == "Frename" {
        assert_eq!(std::fs::read(source.join("child")).unwrap(), b"original\n");
        assert_eq!(std::fs::read(&destination).unwrap(), b"previous\n");
    } else {
        assert_eq!(std::fs::read(&source).unwrap(), b"original\n");
        if replacement {
            assert_eq!(std::fs::read(&destination).unwrap(), b"previous\n");
        } else {
            assert!(!destination.exists());
        }
    }
}

fn destination_denial(action: &str) -> String {
    format!(
        r#"permit(principal, action, resource);
forbid(principal, action == Box::Action::"{action}", resource)
when {{ context.input.path == "~/workspace/destination" }};"#
    )
}

#[test]
fn rename_requires_move_permission_at_both_new_and_existing_destinations() {
    for replacement in [false, true] {
        exercise(
            "move",
            replacement,
            "permit(principal, action, resource);",
            true,
        );
        exercise("move", replacement, &destination_denial("fs:move"), false);
    }
}

#[test]
fn destination_write_and_delete_permissions_apply_only_to_replacement() {
    for action in ["fs:write", "fs:delete"] {
        exercise("move", false, &destination_denial(action), true);
        exercise("move", true, &destination_denial(action), false);
    }
}

#[test]
fn directory_listing_and_file_content_use_distinct_policy_operations() {
    let deny_content = r#"permit(principal, action, resource);
forbid(principal, action == Box::Action::"fs:read", resource)
when { context.input.operation == Box::FsReadOperation::"read_content" };"#;
    let deny_listing = r#"permit(principal, action, resource);
forbid(principal, action == Box::Action::"fs:read", resource)
when { context.input.operation == Box::FsReadOperation::"enumerate" };"#;
    exercise("enumerate", false, deny_content, true);
    exercise("Pread", false, deny_content, false);
    exercise("enumerate", false, deny_listing, false);
    exercise("Pread", false, deny_listing, true);
}

fn move_limit(limit: usize) -> String {
    format!(
        r#"permit(principal, action, resource);
forbid(principal, action == Box::Action::"fs:read", resource)
when {{ context.input.operation == Box::FsReadOperation::"read_content" }}
when temporal {{
    exists (total: Long). (
        (count for (t: Timepoint). where (
            formerly within 1h (
                Box::Action::"fs:move"::response{{
                    input.path: _, input.operation: Box::FsMoveOperation::"rename"
                }} && tp(t)
            )
        )) == total && total >= {limit}
    )
}};"#
    )
}

#[test]
fn one_rename_counts_as_one_completed_move() {
    exercise("R0", false, &move_limit(1), true);
    exercise("R1", false, &move_limit(2), true);
    exercise("R1", false, &move_limit(1), false);
}

#[test]
fn two_renames_reach_the_completed_move_limit() {
    exercise("R2", false, &move_limit(2), false);
}

#[test]
fn same_path_rename_retains_one_completed_move() {
    exercise("S1", false, &move_limit(2), true);
    exercise("S1", false, &move_limit(1), false);
}

fn deny_after_source_read(path: &str) -> String {
    format!(
        r#"permit(principal, action, resource);
forbid(principal, action == Box::Action::"fs:read", resource)
when {{ context.input.path == "~/workspace/{path}"
    && context.input.operation == Box::FsReadOperation::"read_content" }}
when temporal {{ formerly within 1h (
    Box::Action::"fs:read"::response{{
        input.path: "~/workspace/source",
        input.operation: Box::FsReadOperation::"read_content"
    }}
) }};"#
    )
}

#[test]
fn rename_outcome_uses_the_policy_path() {
    exercise("R1", false, &deny_after_source_read("destination"), false);
}

#[test]
fn open_outcome_uses_the_policy_path() {
    exercise("Double", false, &deny_after_source_read("source"), false);
}

fn deny_read_after_error(action: &str) -> String {
    format!(
        r#"permit(principal, action, resource);
forbid(principal, action == Box::Action::"fs:read", resource)
when {{ context.input.operation == Box::FsReadOperation::"read_content" }}
when temporal {{ formerly within 1h (
    Box::Action::"{action}"::error{{ input.path: _ }}
) }};"#
    )
}

#[test]
fn denied_rename_leaves_earlier_checks_request_only() {
    for (replacement, denied_action, prior_actions) in [
        (false, "fs:move", &["fs:move", "fs:read"][..]),
        (true, "fs:write", &["fs:move", "fs:read", "fs:delete"][..]),
    ] {
        for prior_action in prior_actions {
            let policy = format!(
                "{}\n{}",
                destination_denial(denied_action),
                deny_read_after_error(prior_action)
            );
            exercise("Brename", replacement, &policy, true);
        }
    }
}

#[test]
fn denied_open_leaves_earlier_read_request_only() {
    let policy = format!(
        r#"{}
forbid(principal, action == Box::Action::"fs:write", resource);"#,
        deny_read_after_error("fs:read")
    );
    exercise("Bopen", false, &policy, true);
}

#[test]
fn failed_rename_keeps_actual_failure_history() {
    for action in ["fs:move", "fs:read", "fs:delete", "fs:write"] {
        exercise("Frename", false, &deny_read_after_error(action), false);
    }
}

#[test]
fn failed_open_keeps_actual_failure_history() {
    for action in ["fs:read", "fs:write"] {
        exercise("Fopen", false, &deny_read_after_error(action), false);
    }
}
