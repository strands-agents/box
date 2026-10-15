//! Real Endpoint Security enforcement by the signed product, never the mapper alone.
#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "../../crates/box/tests/support/bounded_output.rs"]
mod bounded_output;
use bounded_output::bounded_output;

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    workspace: PathBuf,
    binary: PathBuf,
    probe: PathBuf,
    policy: String,
    writable: bool,
}

impl Fixture {
    fn new(policy: &str, writable: bool) -> Self {
        let directory = tempfile::Builder::new()
            .prefix("esbox")
            .tempdir_in("/private/var/tmp")
            .unwrap();
        let root = directory.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let probe = root.join("probe");
        let compiled = Command::new("/usr/bin/clang")
            .args(["-Wall", "-Wextra", "-Werror"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../crates/box/tests/support/macos_file_probe.c"
            ))
            .arg("-o")
            .arg(&probe)
            .output()
            .unwrap();
        assert!(compiled.status.success(), "{compiled:?}");
        let binary = std::env::var_os("STRANDS_BOX_SIGNED_TEST_BINARY")
            .map(PathBuf::from)
            .expect("set STRANDS_BOX_SIGNED_TEST_BINARY to the signed product bundle executable");
        Self {
            _directory: directory,
            root,
            workspace,
            binary,
            probe,
            policy: policy.into(),
            writable,
        }
    }

    fn command(
        &self,
        operation: &str,
        from: &str,
        to: &str,
        expected: &str,
        child: bool,
    ) -> Command {
        std::fs::write(self.root.join("policy.dw"), &self.policy).unwrap();
        let quote = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
        let config = format!(
            r#"name = "mac-native"
box_dir = {}
policy = "policy.dw"
[experimental-features]
native-filesystem-policy = true
[agent]
command = [{}]
workspace = {}
env = {{ HOME = {}, TMPDIR = {} }}
[agent.filesystem]
read = [{}]
write = [{}]
"#,
            quote(&self.root.join("box")),
            quote(&self.probe),
            quote(&self.workspace),
            quote(&self.workspace),
            quote(&self.workspace),
            quote(&self.workspace),
            if self.writable {
                quote(&self.workspace)
            } else {
                String::new()
            },
        );
        let config_path = self.root.join("box.toml");
        std::fs::write(&config_path, config).unwrap();
        let mut command = Command::new(&self.binary);
        command
            .arg("run")
            .arg("--config")
            .arg(config_path)
            .arg("--")
            .args([
                operation,
                from,
                to,
                expected,
                if child { "child" } else { "self" },
            ])
            .env("HOME", &self.root)
            .current_dir(&self.workspace);
        command
    }

    fn run(&self, operation: &str, from: &str, to: &str, expected: &str, child: bool) -> Output {
        let output = bounded_output(self.command(operation, from, to, expected, child));
        assert!(
            output.status.success(),
            "{operation} {from} -> {to}: {output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("NATIVE_RESULT="),
            "{output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("macOS file enforcement ready"),
            "{output:?}"
        );
        if expected == "deny" && self.writable {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("macOS file request denied"),
                "a policy denial must reach the adapter: {output:?}"
            );
        }
        eprintln!(
            "native case: {operation} {from} -> {to}, expected={expected}, grandchild={child}; {}",
            String::from_utf8_lossy(&output.stdout).trim()
        );
        output
    }
}

const PERMIT: &str = "permit(principal, action, resource);";

#[test]
fn direct_open_truncate_and_grandchild_obey_dogwood() {
    let fixture = Fixture::new(
        r#"permit(principal, action, resource);
@id("native_protected")
forbid(principal, action in [Box::Action::"fs:write", Box::Action::"fs:read"], resource)
when { context.input.path like "*/protected" };
"#,
        true,
    );
    std::fs::write(fixture.workspace.join("allowed"), "original").unwrap();
    std::fs::write(fixture.workspace.join("protected"), "original").unwrap();
    for operation in ["read", "write", "append", "truncate"] {
        fixture.run(operation, "allowed", "-", "allow", false);
        fixture.run(operation, "protected", "-", "deny", false);
    }
    fixture.run("write", "protected", "-", "deny", true);
    fixture.run("write", "allowed", "-", "allow", true);
    assert_eq!(
        std::fs::read(fixture.workspace.join("protected")).unwrap(),
        b"original"
    );
    assert_eq!(
        std::fs::read(fixture.workspace.join("allowed")).unwrap(),
        b"changed"
    );
}

#[test]
fn native_mutations_preserve_denied_paths() {
    let fixture = Fixture::new(
        r#"permit(principal, action, resource);
@id("native_mutation")
forbid(principal, action in [Box::Action::"fs:write", Box::Action::"fs:delete", Box::Action::"fs:move"], resource)
when { context.input.path like "*/protected*" };
forbid(principal, action == Box::Action::"fs:read", resource)
when { context.input.path like "*/unreadable" };
"#,
        true,
    );
    for name in [
        "source",
        "destination",
        "protected",
        "protected-source",
        "unreadable",
    ] {
        std::fs::write(fixture.workspace.join(name), name).unwrap();
    }
    std::fs::create_dir(fixture.workspace.join("protected-directory")).unwrap();
    for (op, from, to, expected) in [
        ("create", "new", "-", "allow"),
        ("rename", "new", "moved", "allow"),
        ("unlink", "moved", "-", "allow"),
        ("mkdir", "directory", "-", "allow"),
        ("rmdir", "directory", "-", "allow"),
        ("symlink", "source", "link", "allow"),
        ("unlink", "link", "-", "allow"),
        ("create", "protected-new", "-", "deny"),
        ("mkdir", "protected-new-directory", "-", "deny"),
        ("symlink", "source", "protected-link", "deny"),
        ("unlink", "protected", "-", "deny"),
        ("rmdir", "protected-directory", "-", "deny"),
        ("rename", "source", "protected-destination", "deny"),
        ("rename", "protected-source", "new-destination", "deny"),
        ("rename", "unreadable", "new-destination", "deny"),
    ] {
        fixture.run(op, from, to, expected, false);
    }
    for name in [
        "source",
        "destination",
        "protected",
        "protected-source",
        "unreadable",
    ] {
        assert_eq!(
            std::fs::read_to_string(fixture.workspace.join(name)).unwrap(),
            name
        );
    }
    for name in [
        "new",
        "moved",
        "directory",
        "link",
        "protected-new",
        "protected-new-directory",
        "protected-link",
        "protected-destination",
        "new-destination",
    ] {
        assert!(
            fixture.workspace.join(name).symlink_metadata().is_err(),
            "{name}"
        );
    }
    assert!(fixture.workspace.join("protected-directory").is_dir());
}

#[test]
fn replacement_requires_source_move_and_destination_move_delete_write() {
    for (action, path) in [
        ("fs:read", "source"),
        ("fs:move", "source"),
        ("fs:move", "destination"),
        ("fs:delete", "destination"),
        ("fs:write", "destination"),
    ] {
        let fixture = Fixture::new(
            &format!(
                r#"permit(principal, action, resource);
forbid(principal, action == Box::Action::"{action}", resource)
when {{ context.input.path == "~/workspace/{path}" }};"#
            ),
            true,
        );
        std::fs::write(fixture.workspace.join("source"), "new").unwrap();
        std::fs::write(fixture.workspace.join("destination"), "old").unwrap();
        let output = fixture.run("rename", "source", "destination", "deny", false);
        assert!(String::from_utf8_lossy(&output.stderr).contains("\"origin\":\"dogwood\""));
        assert_eq!(
            std::fs::read_to_string(fixture.workspace.join("source")).unwrap(),
            "new"
        );
        assert_eq!(
            std::fs::read_to_string(fixture.workspace.join("destination")).unwrap(),
            "old"
        );
    }
    let fixture = Fixture::new(PERMIT, true);
    std::fs::write(fixture.workspace.join("source"), "new").unwrap();
    std::fs::write(fixture.workspace.join("destination"), "old").unwrap();
    fixture.run("rename", "source", "destination", "allow", false);
    assert!(!fixture.workspace.join("source").exists());
    assert_eq!(
        std::fs::read_to_string(fixture.workspace.join("destination")).unwrap(),
        "new"
    );
}

#[test]
fn event_only_descriptors_read_bytes_and_require_content_permission() {
    let fixture = Fixture::new(PERMIT, true);
    std::fs::write(fixture.workspace.join("file"), "original").unwrap();
    let output = fixture.run("event-only", "file", "-", "allow", false);
    assert!(String::from_utf8_lossy(&output.stdout).contains("EVENT_ONLY_READ=1"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("EVENT_ONLY_WRITE=-1"));
    let fixture = Fixture::new(
        r#"permit(principal, action, resource);
forbid(principal, action == Box::Action::"fs:read", resource)
when { context.input.path == "~/workspace/file" &&
       context.input.operation == Box::FsReadOperation::"read_content" };"#,
        true,
    );
    std::fs::write(fixture.workspace.join("file"), "original").unwrap();
    fixture.run("event-only", "file", "-", "deny", false);
}

#[test]
fn unsupported_directory_replacement_emits_adapter_diagnostics() {
    let fixture = Fixture::new(PERMIT, true);
    std::fs::create_dir(fixture.workspace.join("source")).unwrap();
    std::fs::create_dir(fixture.workspace.join("destination")).unwrap();
    let output = fixture.run("rename", "source", "destination", "deny", false);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let line = stderr
        .lines()
        .find_map(|line| line.strip_prefix("MACOS_FILE_DIAGNOSTIC "))
        .unwrap();
    let record: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(record["origin"], "adapter");
    assert_eq!(record["event"], "rename");
    assert_eq!(record["path"], "~/workspace/source");
    assert_eq!(record["destination"], "~/workspace/destination");
    assert!(record["sequence"].is_u64());
    assert!(record["flags"].is_u64());
    assert!(fixture.workspace.join("source").is_dir());
    assert!(fixture.workspace.join("destination").is_dir());
}

#[test]
fn execute_only_open_cannot_read_or_write_and_obeys_exec_policy() {
    let fixture = Fixture::new(PERMIT, true);
    fixture.run("exec-only", "/usr/bin/true", "-", "allow", false);
    let fixture = Fixture::new(
        r#"permit(principal, action, resource);
forbid(principal, action == Box::Action::"fs:read", resource)
when { context.input.path == "/usr/bin/true" &&
       context.input.operation == Box::FsReadOperation::"exec" };"#,
        true,
    );
    fixture.run("exec-only", "/usr/bin/true", "-", "deny", false);
}

#[test]
fn replacement_of_a_symlink_does_not_change_its_referent() {
    let fixture = Fixture::new(PERMIT, true);
    std::fs::write(fixture.workspace.join("source"), "new").unwrap();
    std::fs::write(fixture.workspace.join("referent"), "keep").unwrap();
    std::os::unix::fs::symlink("referent", fixture.workspace.join("destination")).unwrap();
    fixture.run("rename", "source", "destination", "allow", false);
    assert_eq!(
        std::fs::read_to_string(fixture.workspace.join("destination")).unwrap(),
        "new"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.workspace.join("referent")).unwrap(),
        "keep"
    );
    assert!(!fixture.workspace.join("destination").is_symlink());
}

#[test]
fn containment_and_default_deny_remain_independent_restrictions() {
    for (policy, writable) in [
        (PERMIT, false),
        (
            r#"permit(principal, action == Box::Action::"fs:read", resource);"#,
            true,
        ),
    ] {
        let fixture = Fixture::new(policy, writable);
        std::fs::write(fixture.workspace.join("file"), "original").unwrap();
        fixture.run("write", "file", "-", "deny", false);
        fixture.run("truncate", "file", "-", "deny", false);
        fixture.run("create", "new", "-", "deny", false);
        assert_eq!(
            std::fs::read(fixture.workspace.join("file")).unwrap(),
            b"original"
        );
        assert!(!fixture.workspace.join("new").exists());
    }
}

#[test]
fn native_history_changes_the_next_decision_without_a_cached_allow() {
    let fixture = Fixture::new(
        r#"
permit(principal, action, resource);
@id("one_native_write")
forbid(principal, action == Box::Action::"fs:write", resource)
when { context.input.path == "~/workspace/once" }
when temporal {
    formerly within 300s (
        Box::Action::"fs:write"::response{
            input.path: "~/workspace/once",
            output.result: Box::FsResponseResult::"indeterminate"
        }
    )
};
"#,
        true,
    );
    std::fs::write(fixture.workspace.join("once"), "original").unwrap();
    let output = fixture.run("write-twice", "once", "-", "allow", false);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("SECOND_WRITE_RESULT=-1"),
        "{output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Dogwood denied"),
        "{output:?}"
    );
}

#[test]
fn retired_benchmark_environment_cannot_disable_policy_checks() {
    let fixture = Fixture::new(
        r#"permit(principal, action, resource);
forbid(principal, action == Box::Action::"fs:write", resource)
when { context.input.path like "*/protected" };"#,
        true,
    );
    std::fs::write(fixture.workspace.join("protected"), "original").unwrap();
    let mut command = fixture.command("write", "protected", "-", "deny", false);
    command
        .env("BOX_FS_BENCH", "off")
        .env("BOX_HISTORY_BENCH", "memory");
    let output = bounded_output(command);
    assert!(output.status.success(), "{output:?}");
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(
        diagnostic.contains("macOS file enforcement ready"),
        "{output:?}"
    );
    assert!(
        diagnostic.contains("macOS file request denied"),
        "{output:?}"
    );
    assert_eq!(
        std::fs::read(fixture.workspace.join("protected")).unwrap(),
        b"original"
    );
}

#[test]
fn shutdown_ends_a_descendant_outside_the_original_process_group() {
    for enabled in [true, false] {
        let fixture = Fixture::new(PERMIT, true);
        let command = fixture.command("detached", "detached.pid", "-", "allow", false);
        process_selection(&fixture, enabled, "");
        let output = bounded_output(command);
        assert!(output.status.success(), "mode={enabled}: {output:?}");
        let pid: u32 = std::fs::read_to_string(fixture.workspace.join("detached.pid"))
            .unwrap()
            .parse()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let alive = Command::new("/bin/kill")
                .args(["-0", &pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap()
                .success();
            if !alive {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "descendant {pid} outlived Box"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

#[test]
fn disabling_and_reenabling_native_checks_preserves_history() {
    let fixture = Fixture::new(
        r#"
permit(principal, action, resource);
forbid(principal, action == Box::Action::"fs:write", resource)
when { context.input.path == "~/workspace/once" }
when temporal {
    formerly within 300s (
        Box::Action::"fs:write"::response{
            input.path: "~/workspace/once",
            output.result: Box::FsResponseResult::"indeterminate"
        }
    )
};
"#,
        true,
    );
    std::fs::write(fixture.workspace.join("once"), "original").unwrap();
    fixture.run("write", "once", "-", "allow", false);
    let record_path = fixture.root.join("box/private/box.toml");
    let version = || {
        let value: toml::Value = std::fs::read_to_string(&record_path)
            .unwrap()
            .parse()
            .unwrap();
        value["version"].as_integer().unwrap()
    };
    assert_eq!(version(), 22);
    let command = fixture.command("read", "once", "-", "allow", false);
    let config_path = fixture.root.join("box.toml");
    let text = std::fs::read_to_string(&config_path).unwrap();
    std::fs::write(
        config_path,
        text.replace(
            "native-filesystem-policy = true",
            "native-filesystem-policy = false",
        ),
    )
    .unwrap();
    let output = bounded_output(command);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(version(), 21);
    fixture.run("write", "once", "-", "deny", false);
    assert_eq!(version(), 22);
}

fn process_selection(fixture: &Fixture, agent: bool, tools: &str) {
    let config_path = fixture.root.join("box.toml");
    let text = std::fs::read_to_string(&config_path).unwrap();
    std::fs::write(
        config_path,
        format!(
            "{}\n{tools}",
            text.replace(
                "[agent]\n",
                &format!("[agent]\nnative-filesystem-policy = {agent}\n")
            )
        ),
    )
    .unwrap();
}

fn tool_selection(fixture: &Fixture, name: &str, operation: &str, mode: Option<bool>) -> String {
    let quote = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
    let selected = mode
        .map(|v| format!("native-filesystem-policy = {v}\n"))
        .unwrap_or_default();
    format!(
        "[tool.{name}]\ncommand = [{}, \"{operation}\"]\n{selected}[tool.{name}.filesystem]\nread = [{}]\nwrite = [{}]\n",
        quote(&fixture.probe),
        quote(&fixture.workspace),
        quote(&fixture.workspace)
    )
}

#[test]
fn disabled_agent_starts_under_a_restrictive_bootstrap_policy() {
    let fixture = Fixture::new(
        r#"permit(principal, action, resource);
forbid(principal, action == Box::Action::"fs:read", resource)
when { context.input.path == "/" || context.input.path like "*/protected" };"#,
        true,
    );
    std::fs::write(fixture.workspace.join("protected"), "original").unwrap();
    let command = fixture.command("read", "protected", "-", "allow", false);
    process_selection(&fixture, false, "");
    let output = bounded_output(command);
    assert!(output.status.success(), "{output:?}");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("macOS file request denied"),
        "{output:?}"
    );
    let output = bounded_output(fixture.command("read", "protected", "-", "deny", false));
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("macOS file request denied"),
        "{output:?}"
    );
}

#[test]
fn disabled_tools_start_under_a_restrictive_bootstrap_policy() {
    let fixture = Fixture::new(
        r#"permit(principal, action, resource);
forbid(principal, action == Box::Action::"fs:read", resource)
when { context.input.path == "/" || context.input.path like "*/protected" };"#,
        true,
    );
    std::fs::write(fixture.workspace.join("protected"), "original").unwrap();
    let read = format!(
        "'{}' read protected - allow child-exec",
        fixture.probe.display()
    );
    let command = fixture.command("shells", &read, &read, "allow", false);
    process_selection(
        &fixture,
        false,
        &tool_selection(&fixture, "read", "read", Some(false)),
    );
    let output = bounded_output(command);
    assert!(output.status.success(), "{output:?}");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("macOS file request denied"),
        "{output:?}"
    );
}

#[test]
fn independent_agent_and_tool_modes_survive_concurrent_forks_and_exec() {
    let fixture = Fixture::new(
        r#"permit(principal, action, resource);
forbid(principal, action == Box::Action::"fs:write", resource)
when { context.input.path like "*/protected" };"#,
        true,
    );
    std::fs::write(fixture.workspace.join("protected"), "original").unwrap();
    let off = format!(
        "'{}' write protected - allow child-exec",
        fixture.probe.display()
    );
    let on = format!(
        "'{}' append protected - deny child-exec",
        fixture.probe.display()
    );
    let tools = format!(
        "{}\n{}",
        tool_selection(&fixture, "off", "write", Some(false)),
        tool_selection(&fixture, "on", "append", None)
    );
    for agent in [true, false] {
        let command = fixture.command("shells", &off, &on, "allow", false);
        process_selection(&fixture, agent, &tools);
        let output = bounded_output(command);
        assert!(output.status.success(), "agent={agent}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("macOS file request denied"),
            "{output:?}"
        );
        assert_eq!(
            std::fs::read(fixture.workspace.join("protected")).unwrap(),
            b"changedl"
        );
    }
}

#[test]
fn a_disabled_agent_retains_containment_and_does_not_record_native_history() {
    let fixture = Fixture::new(
        r#"permit(principal, action, resource);
forbid(principal, action == Box::Action::"fs:write", resource)
when { context.input.path == "~/workspace/once" }
when temporal {
    formerly within 300s (
        Box::Action::"fs:write"::response{
            input.path: "~/workspace/once",
            output.result: Box::FsResponseResult::"indeterminate"
        }
    )
};"#,
        true,
    );
    std::fs::write(fixture.workspace.join("once"), "original").unwrap();
    let command = fixture.command("write", "once", "-", "allow", true);
    process_selection(&fixture, false, "");
    let output = bounded_output(command);
    assert!(output.status.success(), "{output:?}");
    // The disabled access must not consume the temporal rule's one permitted write.
    fixture.run("write", "once", "-", "allow", false);
    fixture.run("write", "once", "-", "deny", false);

    let restricted = Fixture::new(PERMIT, false);
    std::fs::write(restricted.workspace.join("protected"), "original").unwrap();
    let command = restricted.command("write", "protected", "-", "deny", true);
    process_selection(&restricted, false, "");
    let output = bounded_output(command);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        std::fs::read(restricted.workspace.join("protected")).unwrap(),
        b"original"
    );
}

#[test]
fn local_mcp_selection_is_independent_of_the_agent() {
    for enabled in [false, true] {
        let fixture = Fixture::new(
            r#"permit(principal, action, resource);
forbid(principal, action == Box::Action::"fs:write", resource)
when { context.input.path like "*/protected" };"#,
            true,
        );
        std::fs::write(fixture.workspace.join("protected"), "original").unwrap();
        let command = fixture.command("mcp-client", "probe", "-", "allow", false);
        let quote = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
        let server = format!(
            "[mcp.files]\ntype = \"stdio\"\ncommand = [\"probe\", \"mcp-server\", \"protected\", \"mcp-result\", \"allow\", \"self\"]\nnative-filesystem-policy = {enabled}\nenv = {{ PATH = {} }}\nworkspace = {}\n[mcp.files.filesystem]\nread = [{}]\nwrite = [{}]\n",
            quote(&fixture.root),
            quote(&fixture.workspace),
            quote(&fixture.workspace),
            quote(&fixture.workspace)
        );
        process_selection(&fixture, !enabled, &server);
        let output = bounded_output(command);
        assert!(output.status.success(), "server={enabled}: {output:?}");
        assert_eq!(
            std::fs::read_to_string(fixture.workspace.join("mcp-result")).unwrap(),
            if enabled { "-1" } else { "0" }
        );
    }
}
