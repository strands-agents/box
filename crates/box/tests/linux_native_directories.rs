//! Native directory and symbolic-link effects through Box and Dogwood.
#![cfg(all(
    box_native_kernel_tests,
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64"),
    target_pointer_width = "64",
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
    let workload_operation = operation;
    let operation = operation.strip_prefix('L').unwrap_or(operation);
    let operation = operation.strip_prefix('R').unwrap_or(operation);
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
        workload_operation.into(),
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
    if workload_operation.starts_with('L') {
        assert_eq!(
            output.stdout,
            if deny {
                b"NATIVE_DENIED\n".as_slice()
            } else {
                b"NATIVE_ALLOWED\n".as_slice()
            }
        );
        let events: Vec<serde_json::Value> = stderr
            .lines()
            .filter_map(|line| line.strip_prefix("NATIVE_RESEARCH_EVENT="))
            .map(|line| serde_json::from_str(line).expect("native policy event"))
            .collect();
        assert_eq!(events.len(), 1, "{stderr}");
        let event = &events[0];
        assert_eq!(
            event["outcome"],
            if deny { "denied" } else { "completed" },
            "{event}"
        );
        let operations: &[&str] = match operation {
            "jmkdir" => &["CreateDir"],
            "krmdir" => &["RemoveDir"],
            "symlink" => &["Symlink"],
            "delete" => &["RemoveFile"],
            "move" if !deny => &["Rename", "ReadContent", "Rename"],
            "move" => &["Rename"],
            _ => panic!("unexpected legacy operation: {operation}"),
        };
        let decisions = event["decisions"].as_array().expect("policy decisions");
        assert_eq!(decisions.len(), operations.len(), "{event}");
        for (decision, operation) in decisions.iter().zip(operations) {
            assert_eq!(decision["operation"], *operation, "{event}");
            assert_eq!(decision["allow"], !deny, "{event}");
        }
    }
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

#[derive(Clone, Copy)]
enum EntryExpectation {
    Completed,
    PolicyDenied,
    BaselineRefused,
    Unsupported(&'static str),
}

/// The inode and bytes distinguish a refused operation from an effect followed by an error.
fn entry_state(path: &Path) -> Option<(u64, bool, Vec<u8>)> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(metadata) => Some((
            metadata.ino(),
            metadata.is_dir(),
            if metadata.is_dir() {
                Vec::new()
            } else {
                std::fs::read(path).unwrap()
            },
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("inspect {}: {error}", path.display()),
    }
}

fn narrower_entry_case(
    operation: &str,
    directory: bool,
    destination_exists: bool,
    expected: EntryExpectation,
) {
    let parent = PathBuf::from(std::env::var_os("NATIVE_TEST_ROOT").expect("short fixture root"));
    let root = tempfile::tempdir_in(parent).unwrap().keep();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let source = workspace.join("source");
    let destination = workspace.join("destination");
    let unrelated = workspace.join("unrelated");
    std::fs::write(&unrelated, "unrelated bytes\n").unwrap();
    if operation.starts_with('m') {
        if directory {
            std::fs::create_dir(&source).unwrap();
        } else {
            std::fs::write(&source, "source bytes\n").unwrap();
        }
    }
    if destination_exists {
        if directory {
            std::fs::create_dir(&destination).unwrap();
        } else {
            std::fs::write(&destination, "destination bytes\n").unwrap();
        }
    }
    let before = (
        entry_state(&source),
        entry_state(&destination),
        entry_state(&unrelated),
    );
    let workload = root.join("native-workload");
    std::fs::copy(
        std::env::var_os("NATIVE_WORKLOAD").unwrap_or_else(|| env!("NATIVE_WORKLOAD").into()),
        &workload,
    )
    .unwrap();
    let denied = !matches!(expected, EntryExpectation::Completed);
    let args = [
        workload.display().to_string(),
        operation.into(),
        source.display().to_string(),
        destination.display().to_string(),
        match expected {
            EntryExpectation::Completed => "allow",
            EntryExpectation::BaselineRefused => "E",
            _ => "deny",
        }
        .into(),
    ];
    let q = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
    std::fs::write(
        root.join("box.toml"),
        format!(
            "name = \"native-entry-contract\"\nbox_dir = {}\npolicy = \"policy.dw\"\n\
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
    std::fs::write(
        root.join("policy.dw"),
        if matches!(expected, EntryExpectation::PolicyDenied) {
            "permit(principal, action, resource);\n\
             forbid(principal, action == Box::Action::\"fs:move\", resource);\n"
        } else {
            "permit(principal, action, resource);\n"
        },
    )
    .unwrap();
    let mut command = Command::new(
        std::env::var_os("NATIVE_BOX").unwrap_or_else(|| env!("CARGO_BIN_EXE_strands-box").into()),
    );
    command
        .args(["run", "--config"])
        .arg(root.join("box.toml"))
        .env("HOME", &root)
        .env_remove("BOX_NATIVE_TEST_FAULT")
        .stdin(std::process::Stdio::null());
    let output = bounded_output(command);
    std::fs::write(root.join("stderr.log"), &output.stderr).unwrap();
    std::fs::write(root.join("stdout.log"), &output.stdout).unwrap();
    println!("fixture={}", root.display());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        output.stdout,
        if denied {
            b"NATIVE_DENIED\n".as_slice()
        } else {
            b"NATIVE_ALLOWED\n".as_slice()
        }
    );
    assert_eq!(entry_state(&unrelated), before.2);
    match expected {
        EntryExpectation::Completed => {
            assert!(entry_state(&source).is_none());
            assert_eq!(entry_state(&destination), before.0);
        }
        EntryExpectation::PolicyDenied
        | EntryExpectation::BaselineRefused
        | EntryExpectation::Unsupported(_) => {
            assert_eq!(entry_state(&source), before.0);
            assert_eq!(entry_state(&destination), before.1);
        }
    }
    let stderr = String::from_utf8(output.stderr).unwrap();
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("NATIVE_RESEARCH_EVENT="))
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    if matches!(expected, EntryExpectation::BaselineRefused) {
        assert!(
            events.is_empty(),
            "baseline refusal must precede native dispatch: {stderr}"
        );
        return;
    }
    assert_eq!(events.len(), 1, "{stderr}");
    let event = &events[0];
    match expected {
        EntryExpectation::Completed => {
            assert_eq!(event["outcome"], "completed", "{stderr}");
            let decisions = event["decisions"].as_array().unwrap();
            assert!(!decisions.is_empty() && decisions.iter().all(|d| d["allow"] == true));
        }
        EntryExpectation::PolicyDenied => {
            assert_eq!(event["outcome"], "denied", "{stderr}");
            assert!(
                event["decisions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|d| d["allow"] == false
                        && d["operation"] == "Rename"
                        && d["path"] == source.as_os_str().to_str().unwrap())
            );
        }
        EntryExpectation::BaselineRefused => unreachable!("checked before reading the event"),
        EntryExpectation::Unsupported(reason) => {
            assert_eq!(event["refusal"], reason, "{stderr}");
            assert_eq!(event["broker_errno"], libc::EACCES, "{stderr}");
            assert_eq!(event["decisions"], serde_json::json!([]), "{stderr}");
        }
    }
}

#[test]
fn renameat2_without_flags_uses_native_move_policy() {
    narrower_entry_case("m2", false, false, EntryExpectation::Completed);
    narrower_entry_case("m2", false, false, EntryExpectation::PolicyDenied);
}

#[test]
fn renameat2_noreplace_is_refused_before_policy_and_preserves_both_entries() {
    for destination_exists in [false, true] {
        narrower_entry_case(
            "m2n",
            false,
            destination_exists,
            EntryExpectation::Unsupported("unsupported entry flags or mode"),
        );
    }
}

#[test]
fn file_creation_refuses_each_special_permission_bit_before_policy() {
    narrower_entry_case(
        "c1",
        false,
        false,
        EntryExpectation::Unsupported("unsupported entry flags or mode"),
    );
    for operation in ["c2", "c4"] {
        narrower_entry_case(operation, false, false, EntryExpectation::BaselineRefused);
    }
}

#[test]
fn directory_creation_refuses_each_special_permission_bit_before_policy() {
    narrower_entry_case(
        "j1",
        false,
        false,
        EntryExpectation::Unsupported("unsupported entry flags or mode"),
    );
    for operation in ["j2", "j4"] {
        narrower_entry_case(operation, false, false, EntryExpectation::BaselineRefused);
    }
}

#[test]
fn rename_refuses_an_existing_directory_before_policy_and_preserves_both_entries() {
    narrower_entry_case(
        "move",
        true,
        true,
        EntryExpectation::Unsupported("replacing an existing directory is not supported"),
    );
}

#[cfg(target_arch = "x86_64")]
mod legacy {
    fn exercise(operation: &str, deny: bool, directory: bool, link: bool) {
        for prefix in ["L", "LR"] {
            let operation = format!("{prefix}{}", &operation[1..]);
            super::exercise(&operation, deny, directory, link);
        }
    }

    #[test]
    fn mkdir_obeys_policy_and_preserves_the_workload_umask() {
        for deny in [false, true] {
            exercise("Ljmkdir", deny, false, false);
        }
    }

    #[test]
    fn rmdir_obeys_policy_and_preserves_a_denied_directory() {
        for deny in [false, true] {
            exercise("Lkrmdir", deny, true, false);
        }
    }

    #[test]
    fn symlink_obeys_policy_and_keeps_the_relative_target() {
        for deny in [false, true] {
            exercise("Lsymlink", deny, false, false);
        }
    }

    #[test]
    fn unlink_obeys_policy_for_a_link_and_preserves_its_target() {
        for deny in [false, true] {
            exercise("Ldelete", deny, false, true);
        }
    }

    #[test]
    fn rename_obeys_policy_for_a_link_and_preserves_its_target() {
        for deny in [false, true] {
            exercise("Lmove", deny, false, true);
        }
    }

    #[test]
    fn rename_obeys_policy_for_a_directory() {
        for deny in [false, true] {
            exercise("Lmove", deny, true, false);
        }
    }
}
