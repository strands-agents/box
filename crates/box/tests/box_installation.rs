//! Installed Box executables stay outside workload write authority.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "support/bounded_output.rs"]
mod bounded_output;
#[path = "support/fixture.rs"]
mod fixture;

const BOX: &str = "strands-box";
const LAUNCHER: &str = "strands-box-contain-trampoline";
const ALIAS: &str = "strands-box-sock-alias";
const ENTERED: &str = "INSTALLATION_WORKLOAD_ENTERED";

static INSTALLATION_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Installation {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    bundle: PathBuf,
    binaries: PathBuf,
    workspace: PathBuf,
    config: PathBuf,
}

impl Installation {
    fn new() -> Self {
        let temporary = fixture::short_temporary_home();
        let root = temporary.path().canonicalize().unwrap();
        let bundle = root.join("bundle");
        let binaries = bundle.join("release/bin");
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&binaries).unwrap();
        std::fs::create_dir(&workspace).unwrap();
        let source = fixture::box_binary();
        let source = source.parent().unwrap();
        for name in [BOX, LAUNCHER, ALIAS] {
            std::fs::copy(source.join(name), binaries.join(name))
                .unwrap_or_else(|error| panic!("copy legitimate {name}: {error}"));
        }
        let config = root.join("box.toml");
        std::fs::write(
            root.join("policy.dw"),
            "permit(principal, action, resource);",
        )
        .unwrap();
        Self {
            _temporary: temporary,
            root,
            bundle,
            binaries,
            workspace,
            config,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.binaries.join(name)
    }

    fn run(&self, script: &str, tables: &str) -> Output {
        let command = ["/bin/bash", "-c", script];
        std::fs::write(
            &self.config,
            format!(
                "name = 'installation'\nbox_dir = {state:?}\npolicy = {policy:?}\n\
                 [agent]\ncommand = {command:?}\nworkspace = {workspace:?}\n{tables}\n",
                state = self.root.join("state").display().to_string(),
                policy = self.root.join("policy.dw").display().to_string(),
                workspace = self.workspace.display().to_string(),
            ),
        )
        .unwrap();
        let mut command = Command::new(self.path(BOX));
        command
            .args(["run", "--config"])
            .arg(&self.config)
            .env("HOME", &self.root)
            .env("PATH", "/usr/bin:/bin")
            .env("EXPERIMENTAL_LINUX_SUPPORT", "TRUE");
        bounded_output::bounded_output(command)
    }

    fn write_grant(&self, owner: &str, path: &Path, file: bool) -> String {
        let suffix = if file { "_file" } else { "" };
        let process = if owner == "agent" {
            String::new()
        } else if owner == "tool.writer" {
            format!(
                "[tool.writer]\ncommand = [{:?}]\n",
                fixture::no_op_program(),
            )
        } else {
            "[mcp.writer]\ntype = 'stdio'\ncommand = ['true']\n".to_string()
        };
        format!(
            "{process}[{owner}.filesystem]\nread{suffix} = [{path:?}]\n\
             write{suffix} = [{path:?}]\n",
            path = path.display().to_string(),
        )
    }

    fn read_grant(&self) -> String {
        format!(
            "[agent.filesystem]\nread = [{:?}]\n",
            self.binaries.display().to_string(),
        )
    }
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}

fn quoted(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn assert_installation_refusal(output: &Output, label: &str) {
    let seen = text(output);
    assert!(!output.status.success(), "{label} must refuse: {seen}");
    assert!(
        seen.contains("trusted Box executable"),
        "{label} must name the installed executable protection: {seen}",
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains(ENTERED),
        "{label} must refuse before the workload starts: {seen}",
    );
}

#[test]
fn every_process_table_refuses_writes_to_installed_executables_and_their_ancestors() {
    let _serial = INSTALLATION_TEST
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let installation = Installation::new();
    let targets = [
        (installation.path(BOX), true),
        (installation.path(LAUNCHER), true),
        (installation.binaries.clone(), false),
        (installation.bundle.clone(), false),
    ];
    for owner in ["agent", "tool.writer", "mcp.writer"] {
        for (target, file) in &targets {
            let tables = installation.write_grant(owner, target, *file);
            let output = installation.run(&format!("printf {ENTERED}"), &tables);
            let label = format!("{owner}: {}", target.display());
            assert_installation_refusal(&output, &label);
            assert!(
                text(&output).contains(&format!("[{owner}]")),
                "the refusal must name the process table: {}",
                text(&output),
            );
        }
    }
}

#[test]
fn installed_executables_remain_readable_and_an_unrelated_sibling_remains_writable() {
    let _serial = INSTALLATION_TEST
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let installation = Installation::new();
    let sibling = installation.binaries.join("ordinary-output");
    std::fs::write(&sibling, "ORIGINAL").unwrap();
    let tables = format!(
        "{}write_file = [{:?}]\n",
        installation.read_grant(),
        sibling.display().to_string(),
    );
    let script = format!(
        "IFS= read -r -n 1 first < {} && IFS= read -r -n 1 second < {} && printf SIBLING_WRITE_OK > {} && printf {ENTERED}",
        quoted(&installation.path(BOX)),
        quoted(&installation.path(LAUNCHER)),
        quoted(&sibling),
    );
    let output = installation.run(&script, &tables);
    assert!(output.status.success(), "{}", text(&output));
    assert!(String::from_utf8_lossy(&output.stdout).contains(ENTERED));
    assert_eq!(
        std::fs::read_to_string(sibling).unwrap(),
        "SIBLING_WRITE_OK"
    );
}

#[test]
fn an_operator_can_replace_installed_executables_between_runs() {
    let _serial = INSTALLATION_TEST
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let installation = Installation::new();
    let script = format!("printf {ENTERED}");
    let before = installation.run(&script, &installation.read_grant());
    assert!(before.status.success(), "{}", text(&before));
    for name in [BOX, LAUNCHER] {
        let replacement = installation.binaries.join("operator-update");
        std::fs::copy(installation.path(name), &replacement).unwrap();
        std::fs::rename(&replacement, installation.path(name)).unwrap();
    }
    let after = installation.run(&script, &installation.read_grant());
    assert!(after.status.success(), "{}", text(&after));
    assert!(String::from_utf8_lossy(&after.stdout).contains(ENTERED));
}

#[test]
fn installed_executables_with_existing_hard_links_refuse_before_the_workload_starts() {
    let _serial = INSTALLATION_TEST
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    for name in [BOX, LAUNCHER] {
        let installation = Installation::new();
        let alias = installation.workspace.join("existing-link");
        std::fs::hard_link(installation.path(name), &alias).unwrap();
        let output = installation.run(&format!("printf {ENTERED}"), "");
        assert_installation_refusal(&output, name);
        let seen = text(&output);
        assert!(
            seen.contains("hard link") || seen.contains("filesystem name"),
            "the refusal must explain the extra name: {seen}",
        );
    }
}

#[test]
fn the_hosted_shell_cannot_rename_installed_executables_or_their_ancestors() {
    let _serial = INSTALLATION_TEST
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let installation = Installation::new();
    let targets = [
        installation.path(BOX),
        installation.path(LAUNCHER),
        installation.binaries.clone(),
        installation.bundle.clone(),
    ];
    for source in targets {
        let destination = installation.workspace.join("renamed-installation");
        let hosted = format!("mv {} {}", quoted(&source), quoted(&destination));
        let script = format!("zsh -c '{}'", hosted.replace('\'', "'\\''"));
        let output = installation.run(&script, "");
        assert!(!output.status.success(), "{}", text(&output));
        assert!(
            text(&output).contains("trusted Box executable"),
            "the broker must name the installation protection: {}",
            text(&output),
        );
        assert!(source.exists(), "{} must remain", source.display());
        assert!(!destination.exists(), "the rename must not happen");
    }
}

#[test]
fn monty_cannot_remove_installed_executables_through_their_paths_or_symlinks() {
    let _serial = INSTALLATION_TEST
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let installation = Installation::new();
    for name in [BOX, LAUNCHER] {
        let installed = installation.path(name);
        let alias = installation.workspace.join(format!("{name}-link"));
        std::os::unix::fs::symlink(&installed, &alias).unwrap();
        for path in [&installed, &alias] {
            let python = format!(
                "from pathlib import Path\nPath({:?}).unlink()",
                path.display().to_string(),
            );
            let script = format!("python3 -c '{}'", python.replace('\'', "'\\''"));
            let output = installation.run(&script, "");
            assert!(!output.status.success(), "{}", text(&output));
            assert!(
                text(&output).contains("trusted Box executable"),
                "Monty must name the installation protection: {}",
                text(&output),
            );
            assert!(installed.exists(), "the installed binary must remain");
            assert!(alias.exists(), "the alias must remain");
        }
    }
}

#[test]
fn native_hard_links_cannot_turn_a_read_only_source_into_writable_output() {
    let _serial = INSTALLATION_TEST
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let installation = Installation::new();
    let source = installation.root.join("read-only-source");
    let destination = installation.workspace.join("linked-output");
    let control = installation.workspace.join("ordinary-output");
    std::fs::write(&source, "READ_ONLY_SOURCE").unwrap();
    let link_program = ["/usr/bin/ln", "/bin/ln"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("this platform ships ln");
    let tables = format!(
        "[agent.filesystem]\nread_file = [{source:?}]\nread = [{workspace:?}]\n\
         write = [{workspace:?}]\nexec = [{program:?}]\n",
        source = source.display().to_string(),
        workspace = installation.workspace.display().to_string(),
        program = link_program.display().to_string(),
    );
    let script = format!(
        "if {} {} {}; then printf NATIVE_LINK_ALLOWED; else printf NATIVE_LINK_REFUSED; fi; \
         printf WRITE_CONTROL_OK > {}",
        quoted(&link_program),
        quoted(&source),
        quoted(&destination),
        quoted(&control),
    );
    let output = installation.run(&script, &tables);
    let seen = text(&output);
    assert!(output.status.success(), "{seen}");
    assert!(seen.contains("NATIVE_LINK_REFUSED"), "{seen}");
    assert!(!seen.contains("NATIVE_LINK_ALLOWED"), "{seen}");
    assert!(
        [
            "Operation not permitted",
            "Permission denied",
            "Read-only file system",
            "Invalid cross-device link",
        ]
        .iter()
        .any(|reason| seen.contains(reason)),
        "ln must reach a filesystem refusal: {seen}",
    );
    assert!(!destination.exists(), "a new link must not exist");
    assert_eq!(std::fs::read_to_string(source).unwrap(), "READ_ONLY_SOURCE");
    assert_eq!(
        std::fs::read_to_string(control).unwrap(),
        "WRITE_CONTROL_OK"
    );
}
