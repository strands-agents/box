//! Path compatibility through the contained native syscall path.
#![cfg(all(
    box_native_kernel_tests,
    target_os = "linux",
    target_arch = "aarch64",
    feature = "native-filesystem-policy",
    feature = "test-support"
))]
use std::os::unix::fs::symlink;
#[path = "support/bounded_output.rs"]
mod bounded_output;
use bounded_output::bounded_output;
use std::path::{Path, PathBuf};
use std::process::Command;

fn exercise(operation: &str, spelling: &str, expected: &str, deny: bool) {
    let parent =
        PathBuf::from(std::env::var_os("NATIVE_TEST_ROOT").expect("short native fixture root"));
    let root = tempfile::tempdir_in(parent).unwrap().keep();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::create_dir(workspace.join("directory")).unwrap();
    std::fs::write(workspace.join("target"), "original\n").unwrap();
    std::fs::write(root.join("outside"), "original\n").unwrap();
    symlink("target", workspace.join("relative")).unwrap();
    symlink(workspace.join("target"), workspace.join("absolute")).unwrap();
    symlink("../target", workspace.join("directory/link")).unwrap();
    symlink("loop", workspace.join("loop")).unwrap();
    symlink("directory", workspace.join("alias")).unwrap();
    symlink("directory/created", workspace.join("dangling")).unwrap();
    symlink(root.join("outside"), workspace.join("outside")).unwrap();
    let workload = root.join("native-workload");
    std::fs::copy(env!("NATIVE_WORKLOAD"), &workload).unwrap();
    let q = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
    let args = vec![
        workload.display().to_string(),
        operation.into(),
        workspace.join(spelling).display().to_string(),
        "unused".into(),
        expected.into(),
    ];
    std::fs::write(root.join("box.toml"), format!(
        "name = \"native-paths\"\nbox_dir = {}\npolicy = \"policy.dw\"\n[experimental-features]\nnative-filesystem-policy = true\n[agent]\ncommand = {}\nworkspace = {}\n[agent.filesystem]\nread = [{}]\nwrite = [{}]\n",
        q(&root.join("state")), toml::Value::Array(args.into_iter().map(toml::Value::String).collect()), q(&workspace), q(&workspace), q(&workspace)
    )).unwrap();
    std::fs::write(
        root.join("policy.dw"),
        if operation == "Ptarget" {
            r#"permit(principal, action, resource);
forbid(principal, action == Box::Action::"fs:read", resource)
when { context.input.path == "~/workspace/target" };"#
        } else if deny {
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
    println!("fixture={}", root.display());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        std::fs::read(workspace.join("target")).unwrap(),
        b"original\n"
    );
    assert_eq!(std::fs::read(root.join("outside")).unwrap(), b"original\n");
    if operation == "Pcreate" || operation == "Pdangling" {
        if expected == "allow" {
            assert_eq!(
                std::fs::read(workspace.join("directory/created")).unwrap(),
                b"created\n"
            );
        } else {
            assert!(!workspace.join("directory/created").exists());
        }
    }
    let stderr = String::from_utf8(output.stderr).unwrap();
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("NATIVE_RESEARCH_EVENT="))
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 1, "{stderr}");
    let unsupported = stderr.contains("this kernel cannot transfer O_PATH");
    if expected == "probe" && unsupported {
        assert_eq!(
            events[0]["refusal"], "kernel cannot transfer path-only handles",
            "{stderr}"
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("NATIVE_DENIED"));
    } else if expected == "allow" || expected == "probe" {
        assert_eq!(events[0]["outcome"], "descriptor_issued", "{stderr}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("NATIVE_ALLOWED"));
    } else {
        assert!(String::from_utf8_lossy(&output.stdout).contains("NATIVE_DENIED"));
        assert_ne!(events[0]["outcome"], "descriptor_issued", "{stderr}");
    }
}
#[test]
fn relative_link_reads_the_target() {
    exercise("Pread", "relative", "allow", false);
}
#[test]
fn absolute_link_reads_the_target() {
    exercise("Pread", "absolute", "allow", false);
}
#[test]
fn parent_components_follow_kernel_path_order() {
    exercise("Pread", "directory/../directory/link", "allow", false);
}
#[test]
fn policy_denies_a_link_target_read() {
    exercise("Pread", "relative", "deny", true);
}
#[test]
fn a_link_cannot_reach_outside_the_grant() {
    exercise("Pread", "outside", "deny", false);
}
#[test]
fn a_link_loop_is_refused() {
    exercise("Pread", "loop", "deny", false);
}
#[test]
fn a_nofollow_content_open_refuses_a_link() {
    exercise("Pnofollow", "relative", "deny", false);
}
#[test]
fn path_only_file_open_uses_the_probed_capability() {
    exercise("Phandle", "target", "probe", false);
}
#[test]
fn path_only_link_open_keeps_nofollow() {
    exercise("Psymlink", "relative", "probe", false);
}
#[test]
fn policy_denies_path_only_opens_when_supported() {
    exercise("Phandle", "target", "deny", true);
}

#[test]
fn creation_follows_parent_links_and_parent_components() {
    exercise("Pcreate", "directory/../alias/created", "allow", false);
}
#[test]
fn creation_follows_a_dangling_final_link() {
    exercise("Pdangling", "dangling", "allow", false);
}
#[test]
fn policy_denies_creation_through_a_dangling_link() {
    exercise("Pdangling", "dangling", "deny", true);
}

#[test]
fn a_permitted_link_name_cannot_hide_a_denied_target() {
    exercise("Ptarget", "relative", "deny", false);
}

fn entry_suffix(
    operation: &str,
    kind: &str,
    suffix: &str,
    destination_suffix: &str,
    allowed: bool,
) {
    let root = tempfile::tempdir_in(std::env::var_os("NATIVE_TEST_ROOT").unwrap())
        .unwrap()
        .keep();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let source = workspace.join("source");
    let target = workspace.join("target");
    let destination = workspace.join("destination");
    std::fs::write(&target, "target remains").unwrap();
    match kind {
        "file" => std::fs::write(&source, "source remains").unwrap(),
        "directory" => std::fs::create_dir(&source).unwrap(),
        "link" => symlink("target", &source).unwrap(),
        "missing" => (),
        _ => unreachable!(),
    }
    let workload = root.join("native-workload");
    std::fs::copy(env!("NATIVE_WORKLOAD"), &workload).unwrap();
    let args = vec![
        workload.display().to_string(),
        operation.into(),
        format!("{}{suffix}", source.display()),
        format!("{}{destination_suffix}", destination.display()),
        if allowed { "allow" } else { "deny" }.into(),
    ];
    let q = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
    std::fs::write(root.join("box.toml"), format!(
        "name = \"native-suffix\"\nbox_dir = {}\npolicy = \"policy.dw\"\n[experimental-features]\nnative-filesystem-policy = true\n[agent]\ncommand = {}\nworkspace = {}\n[agent.filesystem]\nread = [{}]\nwrite = [{}]\n",
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
    println!("fixture={}", root.display());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read(&target).unwrap(), b"target remains");
    if !allowed {
        assert!(!destination.exists());
        match kind {
            "file" => assert_eq!(std::fs::read(&source).unwrap(), b"source remains"),
            "directory" => assert!(source.is_dir()),
            "link" => assert_eq!(std::fs::read_link(&source).unwrap(), Path::new("target")),
            "missing" => assert!(!source.exists()),
            _ => unreachable!(),
        }
    } else if operation == "jmkdir" {
        assert!(source.is_dir());
    } else if operation == "krmdir" {
        assert!(!source.exists());
    } else {
        assert!(!source.exists());
        assert!(destination.is_dir());
    }
}
#[test]
fn unlink_with_a_trailing_slash_preserves_the_file() {
    entry_suffix("delete", "file", "/", "", false);
}
#[test]
fn unlink_with_a_trailing_slash_preserves_the_link() {
    entry_suffix("delete", "link", "/", "", false);
}
#[test]
fn rmdir_with_a_final_dot_preserves_the_directory() {
    entry_suffix("krmdir", "directory", "/.", "", false);
}
#[test]
fn rename_with_a_trailing_slash_preserves_the_file() {
    entry_suffix("move", "file", "/", "", false);
}
#[test]
fn rename_with_a_trailing_slash_preserves_the_link() {
    entry_suffix("move", "link", "/", "", false);
}
#[test]
fn rename_to_a_missing_directory_spelling_preserves_the_file() {
    entry_suffix("move", "file", "", "/", false);
}
#[test]
fn file_creation_with_a_trailing_slash_creates_nothing() {
    entry_suffix("Pcreate", "missing", "/", "", false);
}
#[test]
fn file_creation_with_a_final_dot_creates_nothing() {
    entry_suffix("Pcreate", "missing", "/.", "", false);
}
#[test]
fn mkdir_with_a_trailing_slash_creates_a_directory() {
    entry_suffix("jmkdir", "missing", "/", "", true);
}
#[test]
fn rmdir_with_a_trailing_slash_removes_the_directory() {
    entry_suffix("krmdir", "directory", "/", "", true);
}
#[test]
fn rename_with_a_trailing_slash_moves_the_directory() {
    entry_suffix("move", "directory", "/", "", true);
}

#[test]
fn filesystem_queries_remain_sanitized_beside_an_allowed_native_read() {
    exercise("Qread", "target", "allow", false);
}

#[test]
fn filesystem_queries_remain_sanitized_beside_a_denied_native_read() {
    exercise("Qread", "target", "deny", true);
}

#[derive(Clone, Copy)]
enum HardLinkAccess {
    Allowed,
    PolicyDenied,
    OutsideGrant,
}

fn hard_link_case(operation: &str, access: HardLinkAccess) {
    use std::os::unix::fs::MetadataExt;

    let root = tempfile::tempdir_in(std::env::var_os("NATIVE_TEST_ROOT").unwrap())
        .unwrap()
        .keep();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let allowed = workspace.join("allowed");
    let denied = workspace.join("denied");
    let outside = root.join("outside");
    let unrelated = workspace.join("unrelated");
    std::fs::write(&allowed, "original\n").unwrap();
    std::fs::hard_link(&allowed, &denied).unwrap();
    std::fs::hard_link(&allowed, &outside).unwrap();
    std::fs::write(&unrelated, "unrelated\n").unwrap();
    let original = std::fs::metadata(&allowed).unwrap();
    let identity = (original.dev(), original.ino());
    for path in [&allowed, &denied, &outside] {
        let metadata = std::fs::metadata(path).unwrap();
        assert_eq!((metadata.dev(), metadata.ino()), identity);
        assert_eq!(metadata.nlink(), 3);
    }
    let requested = match access {
        HardLinkAccess::Allowed => &allowed,
        HardLinkAccess::PolicyDenied => &denied,
        HardLinkAccess::OutsideGrant => &outside,
    };
    let permitted = matches!(access, HardLinkAccess::Allowed);
    let workload = root.join("native-workload");
    std::fs::copy(
        std::env::var_os("NATIVE_WORKLOAD").unwrap_or_else(|| env!("NATIVE_WORKLOAD").into()),
        &workload,
    )
    .unwrap();
    let args = [
        workload.display().to_string(),
        operation.into(),
        requested.display().to_string(),
        "unused".into(),
        if permitted { "allow" } else { "deny" }.into(),
    ];
    let q = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
    std::fs::write(
        root.join("box.toml"),
        format!(
            "name = \"native-hard-links\"\nbox_dir = {}\npolicy = \"policy.dw\"\n\
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
        r#"permit(principal, action, resource);
forbid(principal, action in [Box::Action::"fs:read", Box::Action::"fs:write"], resource)
when { context.input.path == "~/workspace/denied" };"#,
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
        if permitted {
            b"NATIVE_ALLOWED\n".as_slice()
        } else {
            b"NATIVE_DENIED\n".as_slice()
        }
    );
    // A permitted write changes this inode through every link. Policy controls the requested
    // name; it does not revoke other names or give each hard link independent file contents.
    let expected = if permitted && operation == "w" {
        b"native workload wrote\n".as_slice()
    } else {
        b"original\n".as_slice()
    };
    for path in [&allowed, &denied, &outside] {
        let metadata = std::fs::metadata(path).unwrap();
        assert_eq!((metadata.dev(), metadata.ino()), identity);
        assert_eq!(metadata.nlink(), 3);
        assert_eq!(std::fs::read(path).unwrap(), expected);
    }
    assert_eq!(std::fs::read(&unrelated).unwrap(), b"unrelated\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("NATIVE_RESEARCH_EVENT="))
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 1, "{stderr}");
    let event = &events[0];
    match access {
        HardLinkAccess::Allowed | HardLinkAccess::PolicyDenied => {
            assert_eq!(
                event["outcome"],
                if permitted {
                    "descriptor_issued"
                } else {
                    "denied"
                },
                "{stderr}"
            );
            let decisions = event["decisions"].as_array().unwrap();
            assert_eq!(decisions.len(), 1, "{stderr}");
            assert_eq!(decisions[0]["allow"], permitted, "{stderr}");
            assert_eq!(
                decisions[0]["operation"],
                if operation == "r" {
                    "ReadContent"
                } else {
                    "WriteContent"
                },
                "{stderr}"
            );
            assert_eq!(
                decisions[0]["resource"],
                if permitted {
                    "~/workspace/allowed"
                } else {
                    "~/workspace/denied"
                },
                "{stderr}"
            );
        }
        HardLinkAccess::OutsideGrant => {
            assert_eq!(event["path"], requested.to_str().unwrap(), "{stderr}");
            assert_eq!(event["broker_errno"], libc::ENOENT, "{stderr}");
            assert_eq!(event["decisions"], serde_json::json!([]), "{stderr}");
        }
    }
}

#[test]
fn hard_link_access_uses_the_allowed_name_and_preserves_shared_inode_semantics() {
    for operation in ["r", "w"] {
        hard_link_case(operation, HardLinkAccess::Allowed);
    }
}

#[test]
fn a_policy_denied_hard_link_alias_cannot_read_or_write_the_shared_inode() {
    for operation in ["r", "w"] {
        hard_link_case(operation, HardLinkAccess::PolicyDenied);
    }
}

#[test]
fn a_hard_link_alias_outside_the_grant_cannot_read_or_write_the_shared_inode() {
    for operation in ["r", "w"] {
        hard_link_case(operation, HardLinkAccess::OutsideGrant);
    }
}
