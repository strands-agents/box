//! Native directory and symbolic-link effects through Box and Dogwood.
#![cfg(all(
    box_native_kernel_tests,
    target_os = "linux",
    target_arch = "aarch64",
    feature = "native-filesystem-policy",
    feature = "test-support"
))]
use std::os::unix::fs::{PermissionsExt, symlink};
#[path = "support/bounded_output.rs"]
mod bounded_output;
use bounded_output::bounded_output;
use std::path::{Path, PathBuf};
use std::process::Command;

fn exercise(operation: &str, deny: bool, directory: bool, link: bool) {
    let parent = PathBuf::from(
        std::env::var_os("NATIVE_TEST_ROOT")
            .unwrap_or_else(|| std::env::temp_dir().into_os_string()),
    );
    let root = tempfile::tempdir_in(parent).unwrap().keep();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let source = workspace.join("source");
    let destination = workspace.join("destination");
    let target = workspace.join("target");
    std::fs::write(&target, "target remains\n").unwrap();
    if directory {
        std::fs::create_dir(&source).unwrap();
    }
    if link {
        symlink("target", &source).unwrap();
    }
    let staged = root.join("native-workload");
    std::fs::copy(
        std::env::var_os("NATIVE_WORKLOAD").unwrap_or_else(|| env!("NATIVE_WORKLOAD").into()),
        &staged,
    )
    .unwrap();
    let q = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
    let args = vec![
        staged.display().to_string(),
        operation.into(),
        source.display().to_string(),
        if operation == "symlink" {
            "target".into()
        } else {
            destination.display().to_string()
        },
        if deny { "deny".into() } else { "allow".into() },
    ];
    std::fs::write(
        root.join("box.toml"),
        format!(
            "name = \"native-directory-test\"\nbox_dir = {}\npolicy = \"policy.dw\"\n\
        [experimental-features]\nnative-filesystem-policy = true\n\
        [agent]\ncommand = {}\nworkspace = {}\nnative-filesystem-policy = true\n\
        [agent.filesystem]\nread = [{}]\nwrite = [{}]\n",
            q(&root.join("state")),
            toml::Value::Array(args.into_iter().map(toml::Value::String).collect()),
            q(&workspace),
            q(&workspace),
            q(&workspace)
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("policy.dw"),
        if deny {
            "forbid(principal, action, resource);\n"
        } else {
            "permit(principal, action, resource);\n"
        },
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box"));
    command
        .args(["run", "--config"])
        .arg(root.join("box.toml"))
        .env("HOME", &root)
        .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE")
        .env_remove("BOX_NATIVE_TEST_FAULT");
    command.stdin(std::process::Stdio::null());
    let output = bounded_output(command);
    std::fs::write(root.join("stderr.log"), &output.stderr).unwrap();
    std::fs::write(root.join("stdout.log"), &output.stdout).unwrap();
    println!("fixture={}", root.display());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read(&target).unwrap(), b"target remains\n");
    if deny {
        assert_eq!(
            std::fs::symlink_metadata(&source).is_ok(),
            directory || link
        );
        assert!(!destination.exists());
    } else if operation == "jmkdir" {
        assert!(source.is_dir());
        assert_eq!(
            std::fs::metadata(source).unwrap().permissions().mode() & 0o777,
            0o750
        );
    } else if operation == "symlink" {
        assert_eq!(std::fs::read_link(source).unwrap(), Path::new("target"));
    } else if operation == "move" {
        assert!(std::fs::symlink_metadata(&source).is_err());
        if link {
            assert_eq!(
                std::fs::read_link(destination).unwrap(),
                Path::new("target")
            );
        } else {
            assert!(destination.is_dir());
        }
    } else {
        assert!(std::fs::symlink_metadata(source).is_err());
    }
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("NATIVE_RESEARCH_EVENT="), "{stderr}");
    let expected = if deny {
        "\"outcome\":\"denied\""
    } else {
        "\"outcome\":\"completed\""
    };
    assert!(stderr.contains(expected), "{stderr}");
}
#[test]
fn creating_a_directory_uses_the_workload_umask() {
    exercise("jmkdir", false, false, false);
}
#[test]
fn policy_can_deny_directory_creation() {
    exercise("jmkdir", true, false, false);
}
#[test]
fn removing_an_empty_directory_completes() {
    exercise("krmdir", false, true, false);
}
#[test]
fn policy_can_deny_directory_removal() {
    exercise("krmdir", true, true, false);
}
#[test]
fn creating_a_link_keeps_its_relative_target() {
    exercise("symlink", false, false, false);
}
#[test]
fn policy_can_deny_link_creation() {
    exercise("symlink", true, false, false);
}
#[test]
fn unlink_removes_the_link_and_preserves_its_target() {
    exercise("delete", false, false, true);
}
#[test]
fn policy_can_deny_unlinking_a_link() {
    exercise("delete", true, false, true);
}
#[test]
fn rename_moves_the_link_and_preserves_its_target() {
    exercise("move", false, false, true);
}
#[test]
fn policy_can_deny_renaming_a_link() {
    exercise("move", true, false, true);
}
#[test]
fn rename_moves_a_directory_to_an_absent_name() {
    exercise("move", false, true, false);
}
#[test]
fn policy_can_deny_renaming_a_directory() {
    exercise("move", true, true, false);
}

fn private_temporary_operations(operation: &str) {
    let parent = PathBuf::from(
        std::env::var_os("NATIVE_TEST_ROOT")
            .unwrap_or_else(|| std::env::temp_dir().into_os_string()),
    );
    let root = tempfile::tempdir_in(parent).unwrap().keep();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let (host_file, host_path) = tempfile::NamedTempFile::new_in("/tmp")
        .unwrap()
        .keep()
        .unwrap();
    drop(host_file);
    std::fs::write(&host_path, "host bytes remain\n").unwrap();
    let destination = host_path.with_extension("moved");
    assert!(!destination.exists());
    let staged = root.join("native-workload");
    std::fs::copy(
        std::env::var_os("NATIVE_WORKLOAD").unwrap_or_else(|| env!("NATIVE_WORKLOAD").into()),
        &staged,
    )
    .unwrap();
    let q = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
    let args = vec![
        staged.display().to_string(),
        operation.into(),
        host_path.display().to_string(),
        destination.display().to_string(),
        if operation == "tmp" { "allow" } else { "deny" }.into(),
    ];
    std::fs::write(
        root.join("box.toml"),
        format!(
            "name = \"native-private-tmp\"\nbox_dir = {}\npolicy = \"policy.dw\"\n\
        [experimental-features]\nnative-filesystem-policy = true\n\
        [agent]\ncommand = {}\nworkspace = {}\nnative-filesystem-policy = true\n\
        [agent.filesystem]\nread = [{}]\nwrite = [{}]\n",
            q(&root.join("state")),
            toml::Value::Array(args.into_iter().map(toml::Value::String).collect()),
            q(&workspace),
            q(&workspace),
            q(&workspace)
        ),
    )
    .unwrap();
    let denied_action = match operation {
        "tmpw" => Some("fs:write"),
        "tmpr" => Some("fs:read"),
        _ => None,
    };
    let mut policy = "permit(principal, action, resource);\n".to_owned();
    if let Some(action) = denied_action {
        policy.push_str(&format!(
            "forbid(principal, action == Box::Action::\"{action}\", resource);\n"
        ));
    }
    std::fs::write(root.join("policy.dw"), policy).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box"));
    command
        .args(["run", "--config"])
        .arg(root.join("box.toml"))
        .env("HOME", &root)
        .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE")
        .env_remove("BOX_NATIVE_TEST_FAULT");
    command.stdin(std::process::Stdio::null());
    let output = bounded_output(command);
    std::fs::write(root.join("stderr.log"), &output.stderr).unwrap();
    std::fs::write(root.join("stdout.log"), &output.stdout).unwrap();
    std::fs::write(
        root.join("host-path.txt"),
        host_path.as_os_str().as_encoded_bytes(),
    )
    .unwrap();
    println!("fixture={}", root.display());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read(&host_path).unwrap(), b"host bytes remain\n");
    assert!(!destination.exists());
    let stderr = String::from_utf8(output.stderr).unwrap();
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("NATIVE_RESEARCH_EVENT="))
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events[0]["broker_errno"], libc::ENOENT, "{stderr}");
    if operation == "tmp" {
        assert_eq!(events.len(), 9, "{stderr}");
        assert!(
            events.iter().skip(1).all(|event| matches!(
                event["outcome"].as_str(),
                Some("completed" | "descriptor_issued")
            )),
            "{stderr}"
        );
    } else {
        assert_eq!(
            events.len(),
            if operation == "tmpr" { 3 } else { 2 },
            "{stderr}"
        );
        assert_eq!(events.last().unwrap()["outcome"], "denied", "{stderr}");
        if operation == "tmpr" {
            assert_eq!(events[1]["outcome"], "descriptor_issued", "{stderr}");
        }
    }
}
#[test]
fn private_tmp_operations_do_not_change_host_files_at_the_same_names() {
    private_temporary_operations("tmp");
}
#[test]
fn policy_can_deny_private_tmp_creation() {
    private_temporary_operations("tmpw");
}
#[test]
fn policy_can_deny_reopening_a_private_tmp_file() {
    private_temporary_operations("tmpr");
}

fn directory_error(existing: bool, expected_errno: i32) {
    let parent = PathBuf::from(
        std::env::var_os("NATIVE_TEST_ROOT")
            .unwrap_or_else(|| std::env::temp_dir().into_os_string()),
    );
    let root = tempfile::tempdir_in(parent).unwrap().keep();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let target = if existing {
        workspace.clone()
    } else {
        workspace.join("missing/child")
    };
    let staged = root.join("native-workload");
    std::fs::copy(
        std::env::var_os("NATIVE_WORKLOAD").unwrap_or_else(|| env!("NATIVE_WORKLOAD").into()),
        &staged,
    )
    .unwrap();
    let q = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
    let args = vec![
        staged.display().to_string(),
        "jerrno".into(),
        target.display().to_string(),
        expected_errno.to_string(),
        "allow".into(),
    ];
    std::fs::write(root.join("box.toml"), format!(
        "name = \"native-directory-errno\"\nbox_dir = {}\npolicy = \"policy.dw\"\n[experimental-features]\nnative-filesystem-policy = true\n[agent]\ncommand = {}\nworkspace = {}\nnative-filesystem-policy = true\n[agent.filesystem]\nread = [{}]\nwrite = [{}]\n",
        q(&root.join("state")), toml::Value::Array(args.into_iter().map(toml::Value::String).collect()), q(&workspace), q(&workspace), q(&workspace)
    )).unwrap();
    std::fs::write(
        root.join("policy.dw"),
        "permit(principal, action, resource);\n",
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box"));
    command
        .args(["run", "--config"])
        .arg(root.join("box.toml"))
        .env("HOME", &root)
        .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE")
        .env_remove("BOX_NATIVE_TEST_FAULT");
    command.stdin(std::process::Stdio::null());
    let output = bounded_output(command);
    std::fs::write(root.join("stderr.log"), &output.stderr).unwrap();
    std::fs::write(root.join("stdout.log"), &output.stdout).unwrap();
    println!("fixture={}", root.display());
    assert!(output.status.success(), "{output:?}");
    assert!(workspace.is_dir());
    assert!(!workspace.join("missing").exists());
}

#[test]
fn creating_the_existing_workspace_returns_exists() {
    directory_error(true, libc::EEXIST);
}

#[test]
fn creating_a_directory_without_its_parent_returns_not_found() {
    directory_error(false, libc::ENOENT);
}
