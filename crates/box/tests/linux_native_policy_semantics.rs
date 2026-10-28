//! Native policy checks distinguish moving names, replacing files, and listing directories.
#![cfg(all(
    box_native_kernel_tests,
    box_native_adapter_tests,
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
    std::fs::write(&source, "original\n").unwrap();
    if replacement {
        std::fs::write(&destination, "previous\n").unwrap();
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
    assert_eq!(events.len(), 1, "{stderr}");
    assert_eq!(
        events[0]["outcome"],
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
    if operation == "move" && allowed {
        assert!(!source.exists());
        assert_eq!(std::fs::read(&destination).unwrap(), b"original\n");
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
