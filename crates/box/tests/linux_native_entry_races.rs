//! Controlled entry replacement through the Linux native launch path.
#![cfg(all(
    box_native_kernel_tests,
    box_native_adapter_tests,
    target_os = "linux",
    target_arch = "aarch64",
    feature = "native-filesystem-policy",
    feature = "test-support",
    box_native_test_faults
))]

use std::io::{BufRead, BufReader};
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

fn exercise(operation: &str, replacement: Option<&str>, deny: bool) {
    exercise_at(operation, replacement, deny, false);
}

fn exercise_at(operation: &str, replacement: Option<&str>, deny: bool, final_interval: bool) {
    exercise_kind(operation, replacement, deny, final_interval, "file");
}

fn exercise_kind(
    operation: &str,
    replacement: Option<&str>,
    deny: bool,
    final_interval: bool,
    kind: &str,
) {
    let parent = PathBuf::from(
        std::env::var_os("NATIVE_TEST_ROOT")
            .unwrap_or_else(|| std::env::temp_dir().into_os_string()),
    );
    let root = tempfile::tempdir_in(parent).unwrap().keep();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let source = workspace.join("source.txt");
    let destination = workspace.join("destination.txt");
    let make_entry = |path: &std::path::Path, content: &str| match kind {
        "directory" => std::fs::create_dir(path).unwrap(),
        "link" => symlink(content, path).unwrap(),
        _ => std::fs::write(path, content).unwrap(),
    };
    make_entry(&source, "approved source\n");
    if kind != "directory" {
        make_entry(&destination, "approved destination\n");
    }
    let staged = root.join("native-workload");
    std::fs::copy(
        std::env::var_os("NATIVE_WORKLOAD").unwrap_or_else(|| env!("NATIVE_WORKLOAD").into()),
        &staged,
    )
    .unwrap();
    let q = |path: &std::path::Path| toml::Value::String(path.display().to_string()).to_string();
    let args = vec![
        staged.display().to_string(),
        operation.into(),
        source.display().to_string(),
        destination.display().to_string(),
        if deny || (replacement.is_some() && operation != "xtruncate") {
            "deny"
        } else {
            "allow"
        }
        .into(),
    ];
    std::fs::write(
        root.join("box.toml"),
        format!(
            "name = \"native-entry-race\"\nbox_dir = {}\npolicy = \"policy.dw\"\n\
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
    let mut policy = "permit(principal, action, resource);\n".to_owned();
    if deny {
        policy.push_str("forbid(principal, action in [Box::Action::\"fs:delete\", Box::Action::\"fs:move\"], resource);\n");
    }
    std::fs::write(root.join("policy.dw"), policy).unwrap();
    let release = root.join("release");
    let mut child = Command::new(env!("CARGO_BIN_EXE_strands-box"))
        .args(["run", "--config"])
        .arg(root.join("box.toml"))
        .env("HOME", &root)
        .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE")
        .env(
            "BOX_NATIVE_TEST_FAULT",
            format!(
                "{}:{}",
                if final_interval {
                    "entry-final-race"
                } else {
                    "entry-race"
                },
                release.display()
            ),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (send, receive) = mpsc::channel();
    let stream = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut log = String::new();
        for line in BufReader::new(stream).lines() {
            let line = line.unwrap();
            if line == "NATIVE_RACE_ENTRY_CHECKED" {
                let _ = send.send(());
            }
            log.push_str(&line);
            log.push('\n');
        }
        log
    });
    if !deny && receive.recv_timeout(Duration::from_secs(10)).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("missing checked marker: {}", reader.join().unwrap());
    }
    let replaced = replacement.map(|which| {
        if which == "source" {
            source.clone()
        } else {
            destination.clone()
        }
    });
    let saved = workspace.join("approved.saved");
    let approved_identity = replaced
        .as_ref()
        .and_then(|path| std::fs::symlink_metadata(path).ok())
        .map(|m| (m.dev(), m.ino()));
    let replacement_identity = replaced.as_ref().map(|path| {
        if approved_identity.is_some() {
            std::fs::rename(path, &saved).unwrap();
        }
        make_entry(path, "replacement\n");
        let m = std::fs::symlink_metadata(path).unwrap();
        (m.dev(), m.ino())
    });
    std::fs::write(release, "release").unwrap();
    let output = child.wait_with_output().unwrap();
    let log = reader.join().unwrap();
    std::fs::write(root.join("stderr.log"), &log).unwrap();
    std::fs::write(root.join("stdout.log"), &output.stdout).unwrap();
    let replacement_survives = replaced.as_ref().map(|path| {
        std::fs::symlink_metadata(path)
            .ok()
            .map(|m| (m.dev(), m.ino()))
            == replacement_identity
    });
    let receipt = serde_json::json!({"kind":kind,"operation":operation,"replacement":replacement,"deny":deny,"final_interval":final_interval,"replacement_survives":replacement_survives,"exit":output.status.code(),"fixture":root,"scope":"The host test driver replaces an entry after authorization. This checks object identity, not an untrusted-process escape."});
    std::fs::write(
        root.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    println!("RACE_RECEIPT={receipt}");
    assert!(output.status.success(), "{output:?}\n{log}");
    if replacement.is_some() {
        assert_eq!(
            replacement_survives,
            Some(true),
            "the operation affected the replacement: {receipt}"
        );
        if let Some(identity) = approved_identity {
            if operation == "xtruncate" {
                assert_eq!(std::fs::read(&saved).unwrap(), b"app");
            }
            let saved = std::fs::symlink_metadata(saved).unwrap();
            assert_eq!((saved.dev(), saved.ino()), identity);
        }
        if kind == "file" {
            assert_eq!(
                std::fs::read(replaced.as_ref().unwrap()).unwrap(),
                b"replacement\n"
            );
        }
    } else if deny {
        assert_eq!(std::fs::read(source).unwrap(), b"approved source\n");
        assert_eq!(
            std::fs::read(destination).unwrap(),
            b"approved destination\n"
        );
    } else if operation == "delete" {
        assert!(!source.exists());
    } else {
        assert!(!source.exists());
        assert_eq!(std::fs::read(destination).unwrap(), b"approved source\n");
    }
}

#[test]
fn unlink_must_not_remove_a_replacement_after_authorization() {
    exercise("delete", Some("source"), false);
}
#[test]
fn rename_must_not_move_a_replacement_source_after_authorization() {
    exercise("move", Some("source"), false);
}
#[test]
fn rename_must_not_overwrite_a_replacement_destination_after_authorization() {
    exercise("move", Some("destination"), false);
}
#[test]
fn unchanged_unlink_target_completes() {
    exercise("delete", None, false);
}
#[test]
fn unchanged_rename_target_completes() {
    exercise("move", None, false);
}
#[test]
fn temporary_policy_refuses_native_unlink() {
    exercise("delete", None, true);
}
#[test]
fn temporary_policy_refuses_native_rename() {
    exercise("move", None, true);
}

#[test]
fn unlink_must_not_remove_a_replacement_after_final_verification() {
    exercise_at("delete", Some("source"), false, true);
}
#[test]
fn rename_must_not_move_a_replacement_source_after_final_verification() {
    exercise_at("move", Some("source"), false, true);
}
#[test]
fn rename_must_not_overwrite_a_replacement_destination_after_final_verification() {
    exercise_at("move", Some("destination"), false, true);
}

#[test]
fn rmdir_must_not_remove_a_replacement_after_final_verification() {
    exercise_kind("krmdir", Some("source"), false, true, "directory");
}
#[test]
fn directory_rename_must_not_move_a_replacement_after_final_verification() {
    exercise_kind("move", Some("source"), false, true, "directory");
}
#[test]
fn directory_rename_must_not_overwrite_a_new_destination_after_final_verification() {
    exercise_kind("move", Some("destination"), false, true, "directory");
}
#[test]
fn unlink_must_not_remove_a_replacement_link_after_final_verification() {
    exercise_kind("delete", Some("source"), false, true, "link");
}
#[test]
fn rename_must_not_move_a_replacement_link_after_final_verification() {
    exercise_kind("move", Some("source"), false, true, "link");
}
#[test]
fn rename_must_not_overwrite_a_replacement_link_after_final_verification() {
    exercise_kind("move", Some("destination"), false, true, "link");
}

#[test]
fn path_truncate_changes_the_pinned_file_and_preserves_a_replacement() {
    exercise_at("xtruncate", Some("source"), false, true);
}
