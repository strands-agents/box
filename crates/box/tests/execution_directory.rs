//! Native launches retain the execution directory approved when the run started.

#![cfg(unix)]

use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

#[path = "support/fixture.rs"]
mod fixture;

const POLICY: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"shell:spawn", resource)
when { context.input.program_path like "~/toolchain/bin/*" };
permit(principal, action == Box::Action::"fs:read", resource);
permit(principal, action == Box::Action::"fs:write", resource);
permit(principal, action == Box::Action::"fs:move", resource);
"#;

#[derive(Clone, Copy, Debug)]
enum Replacement {
    Directory,
    Ancestor,
}

fn marker(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("cannot inspect {}: {error}", path.display()),
    }
}

fn identity(path: &Path) -> (u64, u64) {
    let metadata = std::fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", path.display()));
    (metadata.dev(), metadata.ino())
}

fn replaced_execution_directory(replacement: Replacement) {
    if !fixture::namespace_launcher_is_usable() {
        eprintln!("skipping: this platform cannot run the namespace launcher");
        return;
    }
    let request = fixture::Request::with_policy("exec-directory", POLICY)
        .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE");
    let toolchain = request.operator_home().join("toolchain");
    let tools = toolchain.join("bin");
    std::fs::create_dir_all(&tools).unwrap();
    let program = tools.join("program");
    std::fs::copy("/bin/cp", &program).unwrap();
    let original_directory = identity(&tools);
    let original_program = identity(&program);
    let box_ = request
        .agent_read(&[&tools])
        .agent_list("exec", &[tools.to_str().unwrap()])
        .expect();
    let home = box_.box_home();
    let staged = home.join("replacement");
    let staged_tools = match replacement {
        Replacement::Directory => staged.clone(),
        Replacement::Ancestor => staged.join("bin"),
    };
    std::fs::create_dir_all(&staged_tools).unwrap();
    std::fs::copy("/bin/cp", staged_tools.join("program")).unwrap();
    let replacement_directory = identity(&staged_tools);
    let replacement_program = identity(&staged_tools.join("program"));
    assert_ne!(original_directory, replacement_directory);
    assert_ne!(original_program, replacement_program);
    let source = match replacement {
        Replacement::Directory => &tools,
        Replacement::Ancestor => &toolchain,
    };
    let parked = source.with_file_name("original");
    let parked_tools = match replacement {
        Replacement::Directory => parked.clone(),
        Replacement::Ancestor => parked.join("bin"),
    };
    std::fs::write(home.join("seed"), "EXECUTED\n").unwrap();
    std::fs::write(home.join("unrelated-a"), "RENAME_CONTROL\n").unwrap();

    let configuration: toml::Value =
        toml::from_str(&std::fs::read_to_string(box_.config()).unwrap()).unwrap();
    let writes = configuration["agent"]["filesystem"]["write"]
        .as_array()
        .unwrap();
    assert_eq!(writes.len(), 1);
    let write = Path::new(writes[0].as_str().unwrap());
    assert_eq!(write, home);
    assert!(!tools.starts_with(write));
    assert!(!write.starts_with(&tools));

    let output = box_.bash(&format!(
        r#"
printf 'WORKLOAD_STARTED\n'
zsh -c "'{program}' '{home}/seed' '{home}/allowed-before'"
printf 'PERMITTED_BEFORE=%s\n' "$?"
python3 -c "import os; os.rename('{home}/unrelated-a', '{home}/unrelated-b')"
printf 'UNRELATED_BEFORE=%s\n' "$?"
zsh -c "'{program}' '{home}/seed' '{home}/allowed-after-unrelated'"
printf 'PERMITTED_AFTER_UNRELATED=%s\n' "$?"
python3 -c "import os; os.rename('{source}', '{parked}'); os.rename('{staged}', '{source}')"
printf 'REPLACEMENT_STATUS=%s\n' "$?"
zsh -c "'{program}' '{home}/seed' '{home}/blocked-after-replacement'"
printf 'REPLACED_PROGRAM=%s\n' "$?"
python3 -c "import os; os.rename('{home}/unrelated-b', '{home}/unrelated-c')"
printf 'UNRELATED_AFTER=%s\n' "$?"
"#,
        program = program.display(),
        home = home.display(),
        source = source.display(),
        parked = parked.display(),
        staged = staged.display(),
    ));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let evidence = serde_json::json!({
        "replacement": format!("{replacement:?}"),
        "exit": output.status.code(), "stdout": stdout, "stderr": stderr,
        "original_directory": original_directory,
        "replacement_directory": replacement_directory,
        "directory_after": identity(&tools),
        "original_program": original_program,
        "replacement_program": replacement_program,
        "program_after": identity(&program),
        "parked_directory": identity(&parked_tools),
        "parked_program": identity(&parked_tools.join("program")),
        "allowed_before": marker(&home.join("allowed-before")),
        "allowed_after_unrelated": marker(&home.join("allowed-after-unrelated")),
        "blocked_after_replacement": marker(&home.join("blocked-after-replacement")),
        "unrelated_result": marker(&home.join("unrelated-c")),
    });
    eprintln!("EXECUTION_DIRECTORY_EVIDENCE={evidence}");
    assert!(output.status.success(), "{evidence}");
    for line in [
        "WORKLOAD_STARTED",
        "PERMITTED_BEFORE=0",
        "UNRELATED_BEFORE=0",
        "PERMITTED_AFTER_UNRELATED=0",
        "REPLACEMENT_STATUS=0",
        "REPLACED_PROGRAM=126",
        "UNRELATED_AFTER=0",
    ] {
        assert!(
            stdout.lines().any(|actual| actual == line),
            "missing {line}: {evidence}"
        );
    }
    assert_eq!(identity(&tools), replacement_directory, "{evidence}");
    assert_eq!(identity(&program), replacement_program, "{evidence}");
    assert_eq!(identity(&parked_tools), original_directory, "{evidence}");
    assert_eq!(
        identity(&parked_tools.join("program")),
        original_program,
        "{evidence}"
    );
    for name in ["allowed-before", "allowed-after-unrelated"] {
        assert_eq!(
            marker(&home.join(name)).as_deref(),
            Some("EXECUTED\n"),
            "{evidence}"
        );
    }
    assert_eq!(
        marker(&home.join("blocked-after-replacement")),
        None,
        "{evidence}"
    );
    assert_eq!(
        marker(&home.join("unrelated-c")).as_deref(),
        Some("RENAME_CONTROL\n"),
        "{evidence}"
    );
    assert!(!home.join("unrelated-a").exists(), "{evidence}");
    assert!(!home.join("unrelated-b").exists(), "{evidence}");
    assert!(stderr.contains("was replaced"), "{evidence}");
    assert!(
        !stderr.contains("lies inside the writable grant"),
        "{evidence}"
    );

    let restarted = box_.bash(&format!(
        "zsh -c \"'{}' '{}/seed' '{}/allowed-after-restart'\"",
        program.display(),
        home.display(),
        home.display(),
    ));
    assert!(
        restarted.status.success(),
        "a new run approves the replacement directory: stdout={} stderr={}",
        String::from_utf8_lossy(&restarted.stdout),
        String::from_utf8_lossy(&restarted.stderr),
    );
    assert_eq!(
        marker(&home.join("allowed-after-restart")).as_deref(),
        Some("EXECUTED\n")
    );
}

#[test]
fn a_replaced_execution_directory_cannot_supply_a_program_to_the_current_run() {
    replaced_execution_directory(Replacement::Directory);
}

#[test]
fn a_replaced_execution_ancestor_cannot_supply_a_program_to_the_current_run() {
    replaced_execution_directory(Replacement::Ancestor);
}
