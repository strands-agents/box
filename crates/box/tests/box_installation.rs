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
    main: PathBuf,
    workspace: PathBuf,
    config: PathBuf,
}

impl Installation {
    fn new() -> Self {
        Self::with_layout("release/bin", BOX)
    }

    #[cfg(target_os = "macos")]
    fn macos_package() -> Self {
        use std::os::unix::fs::PermissionsExt as _;

        let installation = Self::with_layout("Box.app/Contents/MacOS", "box");
        let release_script = include_str!("../../../scripts/macos-release.py");
        let wrapper = release_script
            .split_once("LAUNCHER = '''")
            .expect("the release script defines the shipped wrapper")
            .1
            .split_once("'''")
            .expect("the shipped wrapper has a closing delimiter")
            .0;
        let wrapper_path = installation.bundle.join("box");
        std::fs::write(&wrapper_path, wrapper).unwrap();
        std::fs::set_permissions(&wrapper_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        for name in [LAUNCHER, ALIAS] {
            std::os::unix::fs::symlink(
                format!("Box.app/Contents/MacOS/{name}"),
                installation.bundle.join(name),
            )
            .unwrap();
        }
        installation
    }

    fn with_layout(directory: &str, main_name: &str) -> Self {
        let temporary = fixture::short_temporary_home();
        let root = temporary.path().canonicalize().unwrap();
        let bundle = root.join("bundle");
        let binaries = bundle.join(directory);
        let main = binaries.join(main_name);
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&binaries).unwrap();
        std::fs::create_dir(&workspace).unwrap();
        let source = fixture::box_binary();
        let source = source.parent().unwrap();
        for (source_name, installed_name) in
            [(BOX, main_name), (LAUNCHER, LAUNCHER), (ALIAS, ALIAS)]
        {
            std::fs::copy(source.join(source_name), binaries.join(installed_name))
                .unwrap_or_else(|error| panic!("copy legitimate {source_name}: {error}"));
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
            main,
            workspace,
            config,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        if name == BOX {
            self.main.clone()
        } else {
            self.binaries.join(name)
        }
    }

    fn run(&self, script: &str, tables: &str) -> Output {
        self.run_from(&self.main, script, tables)
    }

    fn run_from(&self, executable: &Path, script: &str, tables: &str) -> Output {
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
        let mut command = Command::new(executable);
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
        (installation.path(ALIAS), true),
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
        "IFS= read -r -n 1 first < {} && IFS= read -r -n 1 second < {} && \
         IFS= read -r -n 1 third < {} && printf SIBLING_WRITE_OK > {} && printf {ENTERED}",
        quoted(&installation.path(BOX)),
        quoted(&installation.path(LAUNCHER)),
        quoted(&installation.path(ALIAS)),
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
    for name in [BOX, LAUNCHER, ALIAS] {
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
    for name in [BOX, LAUNCHER, ALIAS] {
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
        installation.path(ALIAS),
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
    for name in [BOX, LAUNCHER, ALIAS] {
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

fn assert_hosted_mutations_refused(installation: &Installation, target: &Path) {
    let original = std::fs::read(target).unwrap();
    let destination = installation.workspace.join("renamed-program");
    let replacement = installation.workspace.join("ordinary-replacement");
    std::fs::write(&replacement, "ORDINARY_REPLACEMENT_TEXT").unwrap();
    let python_source = format!("Path({:?})", target.display().to_string());
    let python_destination = format!("Path({:?})", destination.display().to_string());
    let python_replacement = format!("Path({:?})", replacement.display().to_string());
    let operations = [
        (
            "zsh",
            "rewrite",
            format!("printf INSTALLATION_MUTATION_TEXT > {}", quoted(target)),
        ),
        ("zsh", "delete", format!("rm {}", quoted(target))),
        (
            "zsh",
            "rename",
            format!("mv {} {}", quoted(target), quoted(&destination)),
        ),
        (
            "zsh",
            "replace",
            format!("mv {} {}", quoted(&replacement), quoted(target)),
        ),
        (
            "python3",
            "rewrite",
            format!(
                "from pathlib import Path\n{python_source}.write_text('INSTALLATION_MUTATION_TEXT')"
            ),
        ),
        (
            "python3",
            "delete",
            format!("from pathlib import Path\n{python_source}.unlink()"),
        ),
        (
            "python3",
            "rename",
            format!("from pathlib import Path\n{python_source}.rename({python_destination})"),
        ),
        (
            "python3",
            "replace",
            format!("from pathlib import Path\n{python_replacement}.rename({python_source})"),
        ),
    ];
    for (interpreter, operation, hosted) in operations {
        let script = format!("{interpreter} -c '{}'", hosted.replace('\'', "'\\''"));
        let output = installation.run(&script, "");
        let label = format!("{interpreter} {operation}: {}", target.display());
        assert!(!output.status.success(), "{label}: {}", text(&output));
        assert!(
            text(&output).contains("trusted Box executable"),
            "{label} must reach the installation protection: {}",
            text(&output),
        );
        assert!(
            std::fs::read(target).unwrap() == original,
            "{label} must preserve the installed bytes",
        );
        assert!(!destination.exists(), "{label} must not rename the program");
        assert_eq!(
            std::fs::read_to_string(&replacement).unwrap(),
            "ORDINARY_REPLACEMENT_TEXT",
            "{label} must retain the replacement source",
        );
    }
}

#[test]
fn hosted_interpreters_cannot_mutate_the_installed_alias_image() {
    let _serial = INSTALLATION_TEST
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let installation = Installation::new();
    assert_hosted_mutations_refused(&installation, &installation.path(ALIAS));
}

#[cfg(target_os = "macos")]
#[test]
fn every_process_table_refuses_writes_to_the_macos_package_wrapper_and_alias_image() {
    let _serial = INSTALLATION_TEST
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let installation = Installation::macos_package();
    for owner in ["agent", "tool.writer", "mcp.writer"] {
        for target in [installation.bundle.join("box"), installation.path(ALIAS)] {
            let tables = installation.write_grant(owner, &target, true);
            let output = installation.run(&format!("printf {ENTERED}"), &tables);
            assert_installation_refusal(&output, &format!("{owner}: {}", target.display()));
            assert!(
                text(&output).contains(&format!("[{owner}]")),
                "the refusal must name the process table: {}",
                text(&output),
            );
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn hosted_interpreters_cannot_mutate_the_macos_package_wrapper_or_alias_image() {
    let _serial = INSTALLATION_TEST
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let installation = Installation::macos_package();
    for target in [installation.bundle.join("box"), installation.path(ALIAS)] {
        assert_hosted_mutations_refused(&installation, &target);
    }
}

#[cfg(target_os = "macos")]
#[test]
fn the_macos_package_wrapper_launches_with_ordinary_sibling_writes() {
    let _serial = INSTALLATION_TEST
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let installation = Installation::macos_package();
    let wrapper = installation.bundle.join("box");
    let original = std::fs::read(&wrapper).unwrap();
    let native = installation.bundle.join("native-output");
    let shell = installation.bundle.join("shell-output");
    let monty = installation.bundle.join("monty-output");
    std::fs::write(&native, "ORIGINAL").unwrap();
    let tables = installation.write_grant("agent", &native, true);
    let hosted_shell = format!("printf SHELL_SIBLING_WRITE_OK > {}", quoted(&shell));
    let hosted_monty = format!(
        "from pathlib import Path\nPath({:?}).write_text('MONTY_SIBLING_WRITE_OK')",
        monty.display().to_string(),
    );
    let script = format!(
        "printf NATIVE_SIBLING_WRITE_OK > {} && zsh -c '{}' && python3 -c '{}' && printf {ENTERED}",
        quoted(&native),
        hosted_shell.replace('\'', "'\\''"),
        hosted_monty.replace('\'', "'\\''"),
    );
    let output = installation.run_from(&wrapper, &script, &tables);
    assert!(output.status.success(), "{}", text(&output));
    assert!(String::from_utf8_lossy(&output.stdout).contains(ENTERED));
    for (path, expected) in [
        (&native, "NATIVE_SIBLING_WRITE_OK"),
        (&shell, "SHELL_SIBLING_WRITE_OK"),
        (&monty, "MONTY_SIBLING_WRITE_OK"),
    ] {
        assert_eq!(std::fs::read_to_string(path).unwrap(), expected);
    }
    assert_eq!(std::fs::read(wrapper).unwrap(), original);
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
