//! Actual filesystem effects beneath Box's internal state protection.

#![cfg(unix)]

#[path = "support/fixture.rs"]
mod fixture;

use std::path::Path;

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn mutation(interface: &str, operation: &str, source: &Path, destination: &Path) -> String {
    let source = source.to_str().unwrap();
    let destination = destination.to_str().unwrap();
    if interface == "shell" {
        let source = quote(source);
        let destination = quote(destination);
        let command = match operation {
            "write" => format!("printf changed > {source}"),
            "delete" => format!("rm -r {source}"),
            "rename" | "replace" => format!("mv {source} {destination}"),
            _ => unreachable!(),
        };
        format!("zsh -lc {}", quote(&command))
    } else {
        let command = match operation {
            "write" => format!("from pathlib import Path\nPath({source:?}).write_text('changed')"),
            "delete" => format!("import os\nos.remove({source:?})"),
            "rename" | "replace" => format!("import os\nos.rename({source:?}, {destination:?})"),
            _ => unreachable!(),
        };
        format!("python3 -c {}", quote(&command))
    }
}

fn command_at(box_: &fixture::Configured, root: &Path, program: &str) -> std::process::Command {
    let command = box_.command_for(program);
    let mut config: toml::Value =
        toml::from_str(&std::fs::read_to_string(box_.config()).unwrap()).unwrap();
    config["box_dir"] = toml::Value::String(root.display().to_string());
    std::fs::write(box_.config(), toml::to_string(&config).unwrap()).unwrap();
    command
}

fn protected_case(interface: &str) {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ =
        fixture::Request::with_policy("protected", "permit(principal, action, resource);").expect();
    // Keep both ancestors separate from the authored configuration and policy.
    let grandparent = box_.operator_home().join("state");
    let parent = grandparent.join("parent");
    let root = parent.join("box");
    std::fs::create_dir_all(&parent).unwrap();
    let prepared = command_at(&box_, &root, fixture::no_op_program())
        .output()
        .unwrap();
    assert!(prepared.status.success(), "{prepared:?}");
    let sentinel = root.join("private/sentinel");
    std::fs::write(&sentinel, b"original").unwrap();
    let replacement = box_.operator_home().join("replacement");
    let destination = box_.operator_home().join("moved");
    let cases = [
        ("write", sentinel.clone(), destination.clone()),
        ("delete", sentinel.clone(), destination.clone()),
        ("rename", sentinel.clone(), destination.clone()),
        ("replace", replacement.clone(), sentinel.clone()),
        ("rename", root.clone(), destination.clone()),
        ("rename", parent.clone(), destination.clone()),
        ("rename", grandparent.clone(), destination.clone()),
    ];
    for (operation, source, destination) in cases {
        std::fs::write(&replacement, b"replacement").unwrap();
        let script = mutation(interface, operation, &source, &destination);
        let mut command = command_at(&box_, &root, "/bin/bash");
        let output = command.args(["-c", &script]).output().unwrap();
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "{interface} {operation} {source:?}: {output:?}"
        );
        let hidden = source.starts_with(&root)
            && (error.contains("No such file or directory") || error.contains("does not exist"));
        assert!(
            error.contains("trusted Box state") || hidden,
            "{interface} {operation} {source:?}: {error}"
        );
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"original");
        assert_eq!(std::fs::read(&replacement).unwrap(), b"replacement");
        assert!(root.is_dir() && parent.is_dir() && grandparent.is_dir());
        assert!(!box_.operator_home().join("moved").exists());
    }
    if interface == "shell" {
        for target in [&root, &parent, &grandparent] {
            let script = mutation(interface, "delete", target, &destination);
            let mut command = command_at(&box_, &root, "/bin/bash");
            let output = command.args(["-c", &script]).output().unwrap();
            assert!(!output.status.success(), "{output:?}");
            let error = String::from_utf8_lossy(&output.stderr);
            let hidden = target == &root
                && (error.contains("No such file or directory")
                    || error.contains("does not exist"));
            assert!(error.contains("trusted Box state") || hidden, "{output:?}");
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"original");
        }
    }
}

fn siblings_case(interface: &str) {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let box_ =
        fixture::Request::with_policy("siblings", "permit(principal, action, resource);").expect();
    let sibling = box_.root().parent().unwrap().join("sibling");
    std::fs::create_dir(&sibling).unwrap();
    let file = sibling.join("file");
    let moved = sibling.join("moved");
    for operation in ["write", "rename", "replace", "delete"] {
        let (source, destination) = match operation {
            "rename" => (&file, &moved),
            "replace" => {
                std::fs::write(&file, b"replacement").unwrap();
                (&file, &moved)
            }
            "delete" => (&moved, &file),
            _ => (&file, &moved),
        };
        let output = box_.bash(&mutation(interface, operation, source, destination));
        assert!(
            output.status.success(),
            "{interface} {operation}: {output:?}"
        );
        match operation {
            "write" => assert_eq!(std::fs::read(&file).unwrap(), b"changed"),
            "rename" => {
                assert!(!file.exists());
                assert_eq!(std::fs::read(&moved).unwrap(), b"changed");
            }
            "replace" => {
                assert!(!file.exists());
                assert_eq!(std::fs::read(&moved).unwrap(), b"replacement");
            }
            "delete" => assert!(!moved.exists()),
            _ => unreachable!(),
        }
    }
    let renamed = sibling.with_file_name("renamed-sibling");
    let output = box_.bash(&mutation(interface, "rename", &sibling, &renamed));
    assert!(output.status.success(), "{output:?}");
    assert!(!sibling.exists() && renamed.is_dir());
}

#[test]
fn shell_cannot_mutate_box_state_or_its_ancestors() {
    protected_case("shell");
}

#[test]
fn python_cannot_mutate_box_state_or_its_ancestors() {
    protected_case("python");
}

#[test]
fn shell_can_mutate_sibling_files_and_directories() {
    siblings_case("shell");
}

#[test]
fn python_can_mutate_sibling_files_and_directories() {
    siblings_case("python");
}
