//! Production execution refuses a denied subtree after a brokered rename.

#![cfg(unix)]

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::Path;

#[path = "support/fixture.rs"]
mod fixture;

const POLICY: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"shell:spawn", resource);
permit(principal, action == Box::Action::"fs:read", resource);
permit(principal, action == Box::Action::"fs:write", resource);
permit(principal, action == Box::Action::"fs:move", resource);
"#;

#[derive(Clone, Copy, Debug)]
enum Replacement {
    Directory,
    Missing,
    Symlink,
}

fn marker(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("cannot inspect {}: {error}", path.display()),
    }
}

fn identity(path: &Path) -> Option<(u64, u64)> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Some((metadata.dev(), metadata.ino())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("cannot inspect {}: {error}", path.display()),
    }
}

fn relocation(replacement: Replacement, script: bool, listed: bool, linked: bool) {
    if !fixture::namespace_launcher_is_usable() {
        eprintln!("skipping: this platform cannot run the namespace launcher");
        return;
    }
    let mut request = fixture::Request::with_policy("deny-exec", POLICY)
        .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE");
    let tools = request.operator_home().join("tools");
    let denied = tools.join("denied");
    let moved = tools.join("moved");
    std::fs::create_dir_all(&denied).unwrap();
    std::fs::create_dir(tools.join("empty")).unwrap();
    std::fs::write(tools.join("unrelated-a"), "RENAME_CONTROL").unwrap();
    let interpreter = Path::new("/bin/bash").canonicalize().unwrap();
    let program = denied.join("program");
    if script {
        std::fs::write(
            &program,
            format!(
                "#!{}\nprintf 'EXECUTED\\n' > \"$2\"\n",
                interpreter.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    } else {
        std::fs::copy("/bin/cp", &program).unwrap();
    }
    std::fs::copy("/bin/cp", tools.join("permitted")).unwrap();
    if script {
        std::fs::copy(&program, tools.join("permitted-script")).unwrap();
    }
    if linked {
        symlink(moved.join("program"), tools.join("linked-program")).unwrap();
    }
    let denied_identity = identity(&denied).unwrap();
    let program_identity = identity(&program).unwrap();
    request = request
        .agent_read(&[&tools])
        .agent_list("exec", &[tools.to_str().unwrap()])
        .agent_list("deny", &[denied.to_str().unwrap()]);
    if listed {
        request = request.agent_list("exec", &[interpreter.to_str().unwrap()]);
    }
    let box_ = request.expect();
    let home = box_.box_home();
    let seed = home.join("seed");
    std::fs::write(&seed, "EXECUTED\n").unwrap();
    let replacement_code = match replacement {
        Replacement::Directory => format!("Path('{}/denied').mkdir()", tools.display()),
        Replacement::Missing => String::new(),
        Replacement::Symlink => String::new(),
    };
    let replace_link = if matches!(replacement, Replacement::Symlink) {
        format!(
            "zsh -c \"ln -s empty '{}/denied'\"; printf 'LINK_STATUS=%s\\n' \"$?\"",
            tools.display()
        )
    } else {
        String::new()
    };
    let called = if linked {
        tools.join("linked-program")
    } else {
        moved.join("program")
    };
    let script_control = if script {
        format!(
            "zsh -c \"'{}/permitted-script' '{}' '{}/allowed-script'\"; printf 'SCRIPT_CONTROL=%s\\n' \"$?\"",
            tools.display(),
            seed.display(),
            home.display()
        )
    } else {
        String::new()
    };
    let output = box_.bash(&format!(r#"
printf 'WORKLOAD_STARTED\n'
zsh -c "'{program}' '{seed}' '{home}/blocked-before'"
printf 'DENIED_BEFORE=%s\n' "$?"
zsh -c "'{tools}/permitted' '{seed}' '{home}/allowed-before'"
printf 'PERMITTED_BEFORE=%s\n' "$?"
python3 -c "from pathlib import Path; Path('{tools}/unrelated-a').rename('{tools}/unrelated-b')"
printf 'UNRELATED_BEFORE=%s\n' "$?"
zsh -c "'{tools}/permitted' '{seed}' '{home}/allowed-after-unrelated'"
printf 'PERMITTED_AFTER_UNRELATED=%s\n' "$?"
{script_control}
python3 -c "from pathlib import Path; Path('{tools}/denied').rename('{tools}/moved'); {replacement_code}"
printf 'MOVE_STATUS=%s\n' "$?"
{replace_link}
zsh -c "'{called}' '{seed}' '{home}/blocked-after'"
printf 'DENIED_AFTER=%s\n' "$?"
zsh -c "'{tools}/permitted' '{seed}' '{home}/allowed-after-mutation'"
printf 'PERMITTED_AFTER_MUTATION=%s\n' "$?"
python3 -c "from pathlib import Path; Path('{tools}/unrelated-b').rename('{tools}/unrelated-c')"
printf 'UNRELATED_AFTER=%s\n' "$?"
"#,
        program=program.display(), seed=seed.display(), home=home.display(),
        tools=tools.display(), called=called.display()));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let evidence = serde_json::json!({
        "replacement": format!("{replacement:?}"), "script": script,
        "interpreter_listed": listed, "invoked_through_symlink": linked,
        "exit": output.status.code(), "stdout": stdout, "stderr": stderr,
        "denied_identity_before": denied_identity, "denied_identity_after": identity(&denied),
        "moved_identity": identity(&moved), "program_identity_before": program_identity,
        "program_identity_after": identity(&moved.join("program")),
        "blocked_before": marker(&home.join("blocked-before")),
        "blocked_after": marker(&home.join("blocked-after")),
        "allowed_before": marker(&home.join("allowed-before")),
        "allowed_script": marker(&home.join("allowed-script")),
        "allowed_after_mutation": marker(&home.join("allowed-after-mutation")),
        "allowed_after_unrelated": marker(&home.join("allowed-after-unrelated")),
        "unrelated_source_exists": tools.join("unrelated-a").exists(),
        "unrelated_intermediate_exists": tools.join("unrelated-b").exists(),
        "unrelated_result": marker(&tools.join("unrelated-c")),
    });
    eprintln!("DENIED_EXECUTABLE_EVIDENCE={evidence}");
    assert!(output.status.success(), "{evidence}");
    for line in [
        "WORKLOAD_STARTED",
        "DENIED_BEFORE=126",
        "PERMITTED_BEFORE=0",
        "UNRELATED_BEFORE=0",
        "PERMITTED_AFTER_UNRELATED=0",
        "MOVE_STATUS=0",
        "DENIED_AFTER=126",
        "UNRELATED_AFTER=0",
    ] {
        assert!(
            stdout.lines().any(|actual| actual == line),
            "missing {line}: {evidence}"
        );
    }
    assert_eq!(marker(&home.join("blocked-before")), None, "{evidence}");
    assert_eq!(marker(&home.join("blocked-after")), None, "{evidence}");
    for name in ["allowed-before", "allowed-after-unrelated"] {
        assert_eq!(
            marker(&home.join(name)).as_deref(),
            Some("EXECUTED\n"),
            "{evidence}"
        );
    }
    assert_eq!(identity(&moved), Some(denied_identity), "{evidence}");
    assert_eq!(
        identity(&moved.join("program")),
        Some(program_identity),
        "{evidence}"
    );
    assert_eq!(
        marker(&tools.join("unrelated-c")).as_deref(),
        Some("RENAME_CONTROL"),
        "{evidence}"
    );
    assert!(!tools.join("unrelated-a").exists(), "{evidence}");
    assert!(!tools.join("unrelated-b").exists(), "{evidence}");
    if script {
        let status = if listed {
            "SCRIPT_CONTROL=0"
        } else {
            "SCRIPT_CONTROL=126"
        };
        assert!(stdout.lines().any(|line| line == status), "{evidence}");
        assert_eq!(
            marker(&home.join("allowed-script")).as_deref(),
            listed.then_some("EXECUTED\n"),
            "{evidence}"
        );
    }
    match replacement {
        Replacement::Directory => {
            assert!(denied.is_dir(), "{evidence}");
            assert_eq!(std::fs::read_dir(&denied).unwrap().count(), 0, "{evidence}");
            assert_ne!(identity(&denied), Some(denied_identity), "{evidence}");
            assert!(stderr.contains("was replaced"), "{evidence}");
        }
        Replacement::Missing => {
            assert_eq!(identity(&denied), None, "{evidence}");
            assert!(stderr.contains("cannot be read"), "{evidence}");
        }
        Replacement::Symlink => {
            assert!(
                stdout.lines().any(|line| line == "LINK_STATUS=0"),
                "{evidence}"
            );
            assert!(denied.is_symlink(), "{evidence}");
            assert_eq!(
                std::fs::read_link(&denied).unwrap(),
                Path::new("empty"),
                "{evidence}"
            );
            assert!(stderr.contains("was replaced"), "{evidence}");
        }
    }
}

#[test]
fn a_denied_binary_stays_refused_after_rename_and_directory_replacement() {
    relocation(Replacement::Directory, false, false, false);
}

#[test]
fn a_denied_binary_stays_refused_when_its_original_name_vanishes() {
    relocation(Replacement::Missing, false, false, false);
}

#[test]
fn a_denied_binary_stays_refused_after_symlink_replacement() {
    relocation(Replacement::Symlink, false, false, false);
}

#[test]
fn a_link_to_the_relocated_denied_binary_stays_refused() {
    relocation(Replacement::Directory, false, false, true);
}

#[test]
fn a_denied_script_with_a_listed_interpreter_stays_refused_after_relocation() {
    relocation(Replacement::Directory, true, true, false);
}

#[test]
fn a_denied_script_with_an_unlisted_interpreter_stays_refused_after_relocation() {
    relocation(Replacement::Directory, true, false, false);
}
