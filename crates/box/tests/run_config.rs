mod support {
    pub mod fixture;
}

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use support::fixture::{box_binary, namespace_launcher_is_usable, no_op_program};

#[test]
fn init_is_an_unknown_subcommand() {
    let output = Command::new(box_binary())
        .arg("init")
        .output()
        .expect("run the removed command");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand 'init'"),
        "the CLI must reject init: {output:?}"
    );
}

/// One operator home holding a workspace, a caller-selected box directory, and the two authority
/// sources `run` reads.
struct ContractFixture {
    home: tempfile::TempDir,
    workspace: PathBuf,
    box_directory: PathBuf,
    config: PathBuf,
    policy: PathBuf,
}

impl ContractFixture {
    fn new() -> Self {
        let home = support::fixture::short_temporary_home();
        let root = home.path().canonicalize().expect("fixture home resolves");
        let workspace = root.join("workspace");
        let box_directory = root.join("state");
        std::fs::create_dir(&workspace).expect("workspace");
        std::fs::create_dir(&box_directory).expect("box directory");
        make_private(&box_directory);
        Self {
            config: workspace.join("control.any"),
            policy: workspace.join("rules.any"),
            home,
            workspace,
            box_directory,
        }
    }

    /// A configuration whose agent is the no-op program, with `policy` beside it when given.
    fn write(&self, policy: Option<&str>) -> String {
        self.write_document(policy, no_op_program(), "", "")
    }

    /// A configuration whose agent is `program`; a `run` argv is appended to it.
    fn write_for(&self, policy: Option<&str>, program: &str) -> String {
        self.write_document(policy, program, "", "")
    }

    /// Write the configuration and answer with its text: `agent_keys` joins the `[agent]` table,
    /// and `tail` follows it, for `[agent.filesystem]` and `[tool.<name>]` tables.
    fn write_document(
        &self,
        policy: Option<&str>,
        program: &str,
        agent_keys: &str,
        tail: &str,
    ) -> String {
        if let Some(text) = policy {
            std::fs::write(&self.policy, text).expect("policy");
        }
        let policy_line = policy
            .map(|_| "policy = \"rules.any\"\n")
            .unwrap_or_default();
        let text = format!(
            "name = \"contract\"\nbox_dir = {:?}\n{policy_line}\n\
             [agent]\ncommand = [{:?}]\nworkspace = {:?}\n{agent_keys}\n{tail}",
            self.box_directory.display().to_string(),
            program,
            self.workspace
                .canonicalize()
                .expect("workspace resolves")
                .display()
                .to_string(),
        );
        std::fs::write(&self.config, &text).expect("configuration");
        text
    }

    /// The workspace's canonical spelling, as a filesystem entry names it.
    fn workspace_text(&self) -> String {
        self.workspace
            .canonicalize()
            .expect("workspace resolves")
            .display()
            .to_string()
    }

    /// Run the box from the workspace; `argv` follows `--` and appends to `[agent] command`.
    fn run(&self, config: &Path, argv: &[&str]) -> Output {
        self.run_with_home(self.home.path(), &self.workspace, config, argv)
    }

    fn run_with_home(&self, home: &Path, working: &Path, config: &Path, argv: &[&str]) -> Output {
        let mut command = Command::new(box_binary());
        command.arg("run").arg("--config").arg(config);
        if !argv.is_empty() {
            command.arg("--").args(argv);
        }
        command
            .current_dir(working)
            .env("HOME", home)
            .output()
            .expect("spawn strands-box run")
    }

    fn record(&self) -> PathBuf {
        self.box_directory.join("private/box.toml")
    }
}

#[cfg(unix)]
fn make_private(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("private directory");
}

#[cfg(not(unix))]
fn make_private(_path: &Path) {}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// **A box survives its first use, and a later run recovers from a partial private record.**
///
/// The interrupted shapes are a `private/` left at each mode an earlier build wrote, holding a
/// record that never finished. Each run must still reach the agent, with `[agent] env` composed and
/// both authority sources unchanged.
#[cfg(unix)]
#[test]
fn a_box_survives_first_use_and_recovery_from_a_partial_record() {
    use std::os::unix::fs::PermissionsExt as _;

    if !namespace_launcher_is_usable() {
        return;
    }
    for interrupted_mode in [None, Some(0o1700), Some(0o700)] {
        let fixture = ContractFixture::new();
        let config = fixture.write_document(
            Some(""),
            "/bin/bash",
            "env = { IS_SANDBOX = \"true\" }\n",
            "",
        );
        if let Some(mode) = interrupted_mode {
            let private = fixture.box_directory.join("private");
            std::fs::create_dir(&private).expect("interrupted private directory");
            std::fs::set_permissions(&private, std::fs::Permissions::from_mode(mode))
                .expect("interrupted state mode");
            std::fs::write(private.join("box.toml"), "version =").expect("partial record");
            std::fs::set_permissions(
                private.join("box.toml"),
                std::fs::Permissions::from_mode(0o600),
            )
            .expect("private record mode");
        }
        for _ in 0..2 {
            let output = fixture.run(
                &fixture.config,
                &["-c", "printf '%s|%s\\n' \"$IS_SANDBOX\" \"$USER\""],
            );
            assert!(output.status.success(), "{}", text(&output));
            assert_eq!(
                String::from_utf8_lossy(&output.stdout).trim(),
                "true|strands-box"
            );
        }
        assert_eq!(std::fs::read_to_string(&fixture.config).unwrap(), config);
        assert_eq!(std::fs::read_to_string(&fixture.policy).unwrap(), "");
        assert!(fixture.record().is_file(), "{interrupted_mode:?}");
    }
}

#[test]
fn a_relative_config_path_selects_the_box() {
    if !namespace_launcher_is_usable() {
        return;
    }
    let fixture = ContractFixture::new();
    fixture.write(None);

    let output = fixture.run(Path::new("control.any"), &[]);
    assert!(output.status.success(), "{}", text(&output));
    assert!(fixture.record().is_file());
}

/// **An absent `box_dir` is refused, and Box sites no box for the caller.**
///
/// It used to select `~/.strands-box/b/<name>` and create the namespace on first use. Box now owns
/// no namespace, so there is nothing to default to.
///
/// Three things are asserted, because the first two alone would pass against a box that refused for
/// an unrelated reason and still wrote state: the refusal fires, it names the missing key, and
/// neither the product directory nor any part of it exists afterwards.
#[test]
fn an_absent_box_dir_is_refused_and_sites_no_box() {
    if !namespace_launcher_is_usable() {
        return;
    }
    let fixture = ContractFixture::new();
    std::fs::write(
        &fixture.config,
        format!(
            "name = \"defaulted\"\n[agent]\ncommand = [{:?}]\nworkspace = {:?}\n",
            no_op_program(),
            fixture.workspace_text()
        ),
    )
    .expect("configuration");

    let output = fixture.run(&fixture.config, &[]);
    let reported = text(&output);

    assert!(
        !output.status.success(),
        "a configuration naming no `box_dir` must be refused: {reported}"
    );
    assert!(
        reported.contains("missing field `box_dir`"),
        "the refusal must name the missing key: {reported}"
    );
    assert!(
        !fixture.home.path().join(".strands-box").exists(),
        "Box must create no product directory under the operator's home: {reported}"
    );
}

/// **A trailing `run` argv appends to `[agent] command`, so a stored program keeps its lead.**
#[test]
fn a_trailing_argv_appends_to_the_stored_command() {
    if !namespace_launcher_is_usable() {
        return;
    }
    let fixture = ContractFixture::new();
    fixture.write_document(None, "/bin/bash", "", "");
    // `[agent] command` is `["/bin/bash"]`; the argv supplies `-c` and the script, so a fixed
    // leading argument the operator stored is never displaced by what the caller types.
    let output = fixture.run(&fixture.config, &["-c", "printf appended:%s \"$#\""]);
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "appended:0");
}

#[test]
fn direct_filesystem_grants_preserve_loaded_authority() {
    if !namespace_launcher_is_usable() {
        return;
    }
    let fixture = ContractFixture::new();
    // Project reach is a pair of `[agent.filesystem]` entries naming the workspace's own canonical
    // path, because `write` no longer implies `read`.
    let workspace = fixture.workspace_text();
    let config = fixture.write_document(
        None,
        "/bin/bash",
        "",
        &format!("[agent.filesystem]\nread = [{workspace:?}]\nwrite = [{workspace:?}]\n"),
    );
    let output = fixture.run(
        &fixture.config,
        &[
            "-c",
            "printf changed > control.any; \
             printf sibling > ordinary.txt; printf finished",
        ],
    );

    assert!(output.status.success(), "{}", text(&output));
    assert!(text(&output).contains("finished"), "{}", text(&output));
    assert_eq!(
        std::fs::read_to_string(&fixture.config).expect("configuration"),
        config
    );
    assert_eq!(
        std::fs::read_to_string(fixture.workspace.join("ordinary.txt")).expect("sibling write"),
        "sibling"
    );
}

#[test]
fn tool_grants_preserve_loaded_authority_outside_workspace() {
    if !namespace_launcher_is_usable() {
        return;
    }
    for relative in ["control", ".aws/control"] {
        tool_grant_preserves_loaded_authority(relative);
    }
}

/// A `[tool.<name>]` granted the directory that holds the loaded sources writes beside them and
/// not over them. `~/.aws/control` sits under a credential store's anchor, which the exact-anchor
/// rule admits by name.
fn tool_grant_preserves_loaded_authority(relative: &str) {
    let mut fixture = ContractFixture::new();
    let authority = fixture.home.path().join(relative);
    std::fs::create_dir_all(&authority).expect("authority directory");
    let authority = authority
        .canonicalize()
        .expect("authority directory resolves");
    fixture.config = authority.join("control.any");
    fixture.policy = authority.join("rules.any");
    let workspace = fixture.workspace_text();
    let path = authority.display().to_string();
    // The write grant encloses the loaded policy, which the guard admits only when a `deny`
    // subtracts it; the configuration beside it is protected by identity instead.
    let policy_entry = fixture.policy.display().to_string();
    let config = fixture.write_document(
        Some("permit(principal, action, resource);"),
        "/bin/bash",
        "",
        &format!(
            "[tool.writer]\ncommand = [\"dd\"]\n[tool.writer.filesystem]\n\
             read = [{workspace:?}, {path:?}]\nwrite = [{path:?}]\ndeny = [{policy_entry:?}]\n"
        ),
    );
    let policy = std::fs::read(&fixture.policy).expect("policy");
    let seed = fixture.workspace.join("seed");
    std::fs::write(&seed, "changed").expect("write source");
    let ordinary = authority.join("ordinary.txt");
    let script = format!(
        "zsh -c 'dd if={seed} of={ordinary}'; \
         zsh -c 'dd if={seed} of={config}'; \
         zsh -c 'dd if={seed} of={policy}'; printf finished",
        seed = seed.display(),
        ordinary = ordinary.display(),
        config = fixture.config.display(),
        policy = fixture.policy.display()
    );

    let output = fixture.run(&fixture.config, &["-c", &script]);

    assert!(output.status.success(), "{}", text(&output));
    assert!(text(&output).contains("finished"), "{}", text(&output));
    assert_eq!(
        std::fs::read_to_string(&fixture.config).expect("configuration"),
        config,
        "{}",
        text(&output)
    );
    assert_eq!(std::fs::read(&fixture.policy).expect("policy"), policy);
    assert_eq!(
        std::fs::read_to_string(&ordinary).expect("sibling write"),
        "changed",
        "{}",
        text(&output)
    );
}

/// **A configuration loaded from outside the workspace is protected the same way as one inside
/// it.** The directory `--config` named is subtracted from the grant that encloses it, by path: the
/// workload writes beside it and not into it, and the sources keep their bytes on the host.
#[test]
fn a_config_outside_the_workspace_is_protected_by_path() {
    if !namespace_launcher_is_usable() {
        return;
    }
    let mut fixture = ContractFixture::new();
    let elsewhere = fixture
        .home
        .path()
        .canonicalize()
        .expect("the fixture home resolves")
        .join("elsewhere");
    let authority = elsewhere.join("authority");
    std::fs::create_dir_all(&authority).expect("the authority directory");
    fixture.config = authority.join("control.any");
    fixture.policy = authority.join("rules.any");
    let config = fixture.write_document(
        Some("permit(principal, action, resource);"),
        "/bin/bash",
        "",
        &format!(
            "[agent.filesystem]\nread = [{0:?}]\nwrite = [{0:?}]\n",
            elsewhere.display().to_string()
        ),
    );

    let output = fixture.run(
        &fixture.config,
        &[
            "-c",
            &format!(
                "printf changed > {authority}/control.any 2>/dev/null && printf CONFIG_WRITTEN; \
                 printf planted > {authority}/planted 2>/dev/null && printf PLANTED; \
                 read -r v < {authority}/rules.any 2>/dev/null && printf 'POLICY=%s' \"$v\"; \
                 printf beside > {elsewhere}/ordinary.txt && printf BESIDE_WRITTEN; \
                 printf ' finished'",
                authority = authority.display(),
                elsewhere = elsewhere.display()
            ),
        ],
    );

    let reported = text(&output);
    assert!(output.status.success(), "{reported}");
    assert!(reported.contains("BESIDE_WRITTEN finished"), "{reported}");
    assert!(
        !reported.contains("CONFIG_WRITTEN")
            && !reported.contains("PLANTED")
            && !reported.contains("POLICY="),
        "the directory holding the loaded sources must be unreachable: {reported}"
    );
    assert!(
        reported.contains(&format!("  write       {}", elsewhere.display())),
        "the grant that encloses the authority is disclosed: {reported}"
    );
    assert_eq!(
        std::fs::read_to_string(&fixture.config).expect("configuration"),
        config
    );
    assert!(!authority.join("planted").exists());
    assert_eq!(
        std::fs::read_to_string(elsewhere.join("ordinary.txt")).expect("the beside write"),
        "beside"
    );
}

/// **A declared tool is selected with nothing else naming it**: the file declaring a
/// `[tool.<name>]` is what puts it in the agent's reach.
#[test]
fn a_declared_tool_is_selected_without_naming_it() {
    if !namespace_launcher_is_usable() {
        return;
    }
    let fixture = ContractFixture::new();
    let workspace = fixture.workspace_text();
    let policy_entry = fixture.policy.display().to_string();
    fixture.write_document(
        Some("permit(principal, action, resource);"),
        "/bin/bash",
        "",
        &format!(
            "[tool.copier]\ncommand = [\"dd\"]\n[tool.copier.filesystem]\n\
             read = [{workspace:?}]\nwrite = [{workspace:?}]\ndeny = [{policy_entry:?}]\n"
        ),
    );
    std::fs::write(fixture.workspace.join("seed"), "bytes").expect("a seed");

    let output = fixture.run(
        &fixture.config,
        &[
            "-c",
            &format!(
                "zsh -c 'dd if={ws}/seed of={ws}/copied' 2>&1; printf finished",
                ws = fixture.workspace_text()
            ),
        ],
    );

    assert!(text(&output).contains("finished"), "{}", text(&output));
    assert_eq!(
        std::fs::read_to_string(fixture.workspace.join("copied"))
            .ok()
            .as_deref(),
        Some("bytes"),
        "a declared tool runs: {}",
        text(&output)
    );
}

#[test]
fn a_tool_grant_cannot_expose_private_state() {
    if !namespace_launcher_is_usable() {
        return;
    }
    let fixture = ContractFixture::new();
    fixture.write(Some("permit(principal, action, resource);"));
    let first = fixture.run(&fixture.config, &[]);
    assert!(first.status.success(), "{}", text(&first));
    fixture.write_document(
        Some("permit(principal, action, resource);"),
        no_op_program(),
        "",
        &format!(
            "[tool.reader]\ncommand = [\"dd\"]\n[tool.reader.filesystem]\nread = [{:?}]\n",
            fixture.box_directory.join("private").display().to_string()
        ),
    );

    // Every tool is translated before the agent starts, so the refusal needs no invocation.
    let output = fixture.run(&fixture.config, &[]);

    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        text(&output).contains("private Box state"),
        "{}",
        text(&output)
    );
}

/// **An `[agent.filesystem]` entry naming a child of the box directory is refused by name.**
///
/// `box_dir` is a caller-selected absolute with no `.strands-box` component, so the component rule
/// does not see it, and `bin/` and `trust/` sit beside `private/` rather than inside it. A write
/// grant over `bin/` is a program the workload plants beside the aliases.
#[test]
fn an_agent_entry_naming_a_box_directory_child_is_refused() {
    if !namespace_launcher_is_usable() {
        return;
    }
    for child in ["bin", "trust"] {
        let fixture = ContractFixture::new();
        fixture.write(None);
        // The first run creates the box directory's children, so the entry exists to validate.
        let first = fixture.run(&fixture.config, &[]);
        assert!(first.status.success(), "{}", text(&first));
        let entry = fixture
            .box_directory
            .join(child)
            .canonicalize()
            .expect("the child resolves");
        fixture.write_document(
            None,
            no_op_program(),
            "",
            &format!(
                "[agent.filesystem]\nwrite = [{:?}]\n",
                entry.display().to_string()
            ),
        );

        let output = fixture.run(&fixture.config, &[]);

        assert!(!output.status.success(), "{child}: {}", text(&output));
        assert!(
            text(&output).contains("Box's own directory")
                && text(&output).contains(&entry.display().to_string()),
            "the refusal must name the box directory and the entry for {child}: {}",
            text(&output)
        );
    }
}

/// **The box-directory guard judges the canonical identity, so a symlinked `box_dir` spelling
/// cannot step around it.**
///
/// `box_dir` is authored through a symlinked ancestor while the entry names the canonical
/// spelling; a raw comparison shares no prefix with it and accepts the grant.
#[cfg(unix)]
#[test]
fn a_symlinked_box_directory_still_guards_its_children() {
    if !namespace_launcher_is_usable() {
        return;
    }
    let mut fixture = ContractFixture::new();
    let real = fixture.home.path().join("real");
    std::fs::create_dir(&real).expect("the real ancestor");
    let link = fixture.home.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("link -> real");
    fixture.box_directory = link.join("state");
    std::fs::create_dir(&fixture.box_directory).expect("the box directory");
    make_private(&fixture.box_directory);
    fixture.write(None);
    // The first run creates the box directory's children, so the entry exists to validate.
    let first = fixture.run(&fixture.config, &[]);
    assert!(first.status.success(), "{}", text(&first));
    // The entry names the CANONICAL child, which shares no prefix with the authored spelling.
    let entry = real
        .join("state")
        .join("bin")
        .canonicalize()
        .expect("the canonical child resolves");
    fixture.write_document(
        None,
        no_op_program(),
        "",
        &format!(
            "[agent.filesystem]\nwrite = [{:?}]\n",
            entry.display().to_string()
        ),
    );

    let output = fixture.run(&fixture.config, &[]);

    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        text(&output).contains("Box's own directory")
            && text(&output).contains(&entry.display().to_string()),
        "the guard must judge the canonical identity: {}",
        text(&output)
    );
}

/// A tool grant naming a child of the box directory is refused on the same guard.
#[test]
fn a_tool_grant_cannot_expose_the_box_directory() {
    if !namespace_launcher_is_usable() {
        return;
    }
    for child in ["bin", "trust"] {
        let fixture = ContractFixture::new();
        fixture.write(Some("permit(principal, action, resource);"));
        let first = fixture.run(&fixture.config, &[]);
        assert!(first.status.success(), "{}", text(&first));
        let entry = fixture
            .box_directory
            .join(child)
            .canonicalize()
            .expect("the child resolves");
        fixture.write_document(
            Some("permit(principal, action, resource);"),
            no_op_program(),
            "",
            &format!(
                "[tool.reader]\ncommand = [\"dd\"]\n[tool.reader.filesystem]\nread = [{:?}]\n",
                entry.display().to_string()
            ),
        );

        let output = fixture.run(&fixture.config, &[]);

        assert!(!output.status.success(), "{child}: {}", text(&output));
        assert!(
            text(&output).contains("Box's own directory"),
            "the refusal must name the box directory for {child}: {}",
            text(&output)
        );
    }
}

/// **A declared home inside trusted Box state is refused, for the agent and for a tool.**
///
/// The box directory holds `bin`, `run`, `trust`, and `private`, and none of them is a home. A home
/// there would be state this box's own interpreters could name, so `run` refuses before it starts.
#[test]
fn a_declared_home_inside_the_box_directory_is_refused() {
    let fixture = ContractFixture::new();
    let inside_box_directory = fixture.box_directory.join("home");

    for (home, table, keys, tail) in [
        (
            inside_box_directory.clone(),
            "[agent]",
            format!(
                "env = {{ HOME = {:?} }}\n",
                inside_box_directory.display().to_string()
            ),
            String::new(),
        ),
        (
            inside_box_directory.clone(),
            "[tool.reader]",
            String::new(),
            format!(
                "[tool.reader]\ncommand = [\"dd\"]\nenv = {{ HOME = {:?} }}\n",
                inside_box_directory.display().to_string()
            ),
        ),
    ] {
        fixture.write_document(
            Some("permit(principal, action, resource);"),
            no_op_program(),
            &keys,
            &tail,
        );

        let output = fixture.run(&fixture.config, &[]);

        let reported = text(&output);
        assert!(
            !output.status.success(),
            "{home:?} must refuse the run: {reported}"
        );
        assert!(
            reported.contains(table) && reported.contains("trusted Box state"),
            "the refusal must name {table} and why: {reported}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn aliases_connect_through_a_symlinked_box_directory_ancestor() {
    if !namespace_launcher_is_usable() {
        return;
    }
    let mut fixture = ContractFixture::new();
    let alias = fixture.home.path().join("alias");
    std::os::unix::fs::symlink(fixture.home.path(), &alias).expect("ancestor alias");
    fixture.box_directory = alias.join("state");
    fixture.write_for(
        Some(r#"permit(principal, action == Box::Action::"shell:exec", resource);"#),
        "/bin/bash",
    );

    let output = fixture.run(&fixture.config, &["-c", "zsh -c 'echo broker-route-ok'"]);
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "broker-route-ok"
    );
}

/// **`name` is required, both paths must be absolute, and every key an earlier build read is
/// refused by name with its replacement.**
#[test]
fn name_is_required_and_every_removed_key_is_refused_by_name() {
    let fixture = ContractFixture::new();
    let box_dir = fixture.box_directory.display().to_string();
    // `name` and `box_dir` are both required, so a case about any other key has to carry both or it
    // is refused for the wrong reason. Each document below states only what it is about; `with_box_dir`
    // supplies the key when the case is not about `box_dir` itself.
    let with_box_dir = |document: &str| -> String {
        if document.contains("box_dir") {
            document.to_string()
        } else {
            format!("box_dir = {box_dir:?}\n{document}")
        }
    };
    let cases = [
        (
            format!("box_dir = {box_dir:?}\n[agent]\ncommand = [\"x\"]\n"),
            "missing field `name`",
        ),
        (
            "name = \"x\"\n[agent]\ncommand = [\"x\"]\n".to_string(),
            "missing field `box_dir`",
        ),
        (
            "name = \"x\"\nbox_dir = \"state\"\n[agent]\ncommand = [\"x\"]\n".to_string(),
            "`box_dir` must be absolute",
        ),
        (
            with_box_dir("name = \"x\"\n[agent]\ncommand = [\"x\"]\nworkspace = \"work\"\n"),
            "`workspace` must be absolute",
        ),
        (
            with_box_dir("name = \"x\"\nworkspace = \"/tmp\"\n"),
            "`[agent] workspace`",
        ),
        (
            with_box_dir("name = \"x\"\n[env]\nA = \"b\"\n"),
            "`[agent] env`",
        ),
        (
            with_box_dir("name = \"x\"\n[filesystem]\nworkspace = \"read-write\"\n"),
            "`[agent.filesystem]`",
        ),
        (
            with_box_dir("name = \"x\"\n[agent]\ndefault_command = [\"x\"]\n"),
            "`[agent] command`",
        ),
        (
            with_box_dir("name = \"x\"\n[agent]\ncommand = [\"x\"]\nread = [\"/a\"]\n"),
            "`[agent.filesystem] read`",
        ),
        (
            with_box_dir("name = \"x\"\n[agent]\ncommand = [\"x\"]\npacks = [\"node\"]\n"),
            "packs",
        ),
        (
            with_box_dir("name = \"x\"\n[tool.t]\nexec = [\"x\"]\n"),
            "`[tool.<name>] command`",
        ),
        (
            with_box_dir("name = \"x\"\n[tool.t.filesystem]\nmetadata = [\"/a\"]\n"),
            "`[tool.<name>.filesystem] metadata`",
        ),
        (
            with_box_dir("name = \"x\"\n[tool.t.filesystem]\nexec = [\"/a\"]\n"),
            "`[tool.<name>.filesystem] exec`",
        ),
        (
            with_box_dir(
                "name = \"x\"\n[mcp.m]\ntype = \"stdio\"\ncommand = [\"m\"]\n\
                 [mcp.m.filesystem]\nmetadata = [\"/a\"]\n",
            ),
            "`[mcp.<name>.filesystem] metadata`",
        ),
        (
            with_box_dir(
                "name = \"x\"\n[mcp.m]\ntype = \"stdio\"\ncommand = [\"m\"]\n\
                 [mcp.m.filesystem]\nexec = [\"/a\"]\n",
            ),
            "`[mcp.<name>.filesystem] exec`",
        ),
        (
            "name = \"x\"\n[telemetry.decisions]\nkind = \"file\"\ndestination = \"~/r.jsonl\"\n\
             signals = [\"policy_denied\"]\n"
                .to_string(),
            "`[telemetry.<label>] include`",
        ),
    ];
    for (document, expected) in cases {
        std::fs::write(&fixture.config, &document).expect("configuration");
        let output = fixture.run(&fixture.config, &[]);
        assert!(!output.status.success(), "{document}");
        assert!(
            text(&output).contains(expected),
            "{document} must be refused with {expected:?}: {}",
            text(&output)
        );
    }
    assert!(
        !fixture.box_directory.join("private").exists(),
        "a refused document must create no box state"
    );
}

#[test]
fn path_relationship_refusals_create_no_box_state() {
    let fixture = ContractFixture::new();
    let nested = fixture.workspace.join("state");
    std::fs::remove_dir(&fixture.box_directory).expect("remove old box directory");
    std::fs::create_dir(&nested).expect("nested box directory");
    make_private(&nested);
    std::fs::write(
        &fixture.config,
        format!(
            "name = \"contract\"\nbox_dir = {:?}\n[agent]\ncommand = [{:?}]\nworkspace = {:?}\n",
            nested.display().to_string(),
            no_op_program(),
            fixture.workspace_text()
        ),
    )
    .expect("configuration");

    let output = fixture.run(&fixture.config, &[]);
    assert!(!output.status.success());
    assert!(
        text(&output).contains("equal to or below"),
        "{}",
        text(&output)
    );
    assert_eq!(std::fs::read_dir(&nested).expect("box reads").count(), 0);
}

#[test]
fn authority_sources_cannot_live_inside_the_box_directory() {
    let fixture = ContractFixture::new();
    let inside_config = fixture.box_directory.join("control.any");
    let head = format!(
        "name = \"contract\"\nbox_dir = {:?}\n[agent]\ncommand = [{:?}]\nworkspace = {:?}\n",
        fixture.box_directory.display().to_string(),
        no_op_program(),
        fixture.workspace.display().to_string()
    );
    std::fs::write(&inside_config, &head).expect("inside configuration");
    let config_output = fixture.run(&inside_config, &[]);
    assert!(
        text(&config_output).contains("configuration source")
            && text(&config_output).contains("inside `box_dir`"),
        "{}",
        text(&config_output)
    );
    assert!(!fixture.box_directory.join("private").exists());

    std::fs::remove_file(&inside_config).expect("clear root");
    let inside_policy = fixture.box_directory.join("rules.any");
    std::fs::write(&inside_policy, "").expect("inside policy");
    std::fs::write(
        &fixture.config,
        format!(
            "name = \"contract\"\nbox_dir = {:?}\npolicy = {:?}\n[agent]\ncommand = [{:?}]\n\
             workspace = {:?}\n",
            fixture.box_directory.display().to_string(),
            inside_policy.display().to_string(),
            no_op_program(),
            fixture.workspace.display().to_string(),
        ),
    )
    .expect("configuration");
    let policy_output = fixture.run(&fixture.config, &[]);
    assert!(
        text(&policy_output).contains("policy source")
            && text(&policy_output).contains("inside `box_dir`"),
        "{}",
        text(&policy_output)
    );
    assert!(!fixture.box_directory.join("private").exists());
}

#[cfg(unix)]
#[test]
fn unsafe_box_directory_shapes_are_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = ContractFixture::new();
    fixture.write(None);
    std::fs::set_permissions(
        &fixture.box_directory,
        std::fs::Permissions::from_mode(0o755),
    )
    .expect("unsafe mode");
    let mode = fixture.run(&fixture.config, &[]);
    assert!(text(&mode).contains("mode is not 0700"), "{}", text(&mode));

    std::fs::set_permissions(
        &fixture.box_directory,
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("restore mode");
    std::fs::write(fixture.box_directory.join("stray"), "x").expect("stray file");
    let nonempty = fixture.run(&fixture.config, &[]);
    assert!(
        text(&nonempty).contains("contains no valid private record"),
        "{}",
        text(&nonempty)
    );
}

#[cfg(unix)]
#[test]
fn a_final_component_symlink_is_refused() {
    let fixture = ContractFixture::new();
    fixture.write(None);
    let real = fixture.home.path().join("real-state");
    std::fs::remove_dir(&fixture.box_directory).expect("remove box directory");
    std::fs::create_dir(&real).expect("real directory");
    make_private(&real);
    std::os::unix::fs::symlink(&real, &fixture.box_directory).expect("box symlink");

    let output = fixture.run(&fixture.config, &[]);
    assert!(!output.status.success());
    assert!(
        text(&output).contains("not a directory"),
        "{}",
        text(&output)
    );
    assert_eq!(std::fs::read_dir(&real).expect("real reads").count(), 0);
}

#[cfg(unix)]
#[test]
fn an_ancestor_symlink_spelling_starts_the_box_and_stays_visible() {
    if !namespace_launcher_is_usable() {
        return;
    }
    let mut fixture = ContractFixture::new();
    std::fs::remove_dir(&fixture.box_directory).expect("remove initial box directory");
    let real_parent = fixture.home.path().join("real");
    let visible_parent = fixture.home.path().join("visible");
    std::fs::create_dir(&real_parent).expect("real parent");
    std::fs::create_dir(real_parent.join("state")).expect("real box directory");
    make_private(&real_parent.join("state"));
    std::os::unix::fs::symlink(&real_parent, &visible_parent).expect("visible parent");
    fixture.box_directory = visible_parent.join("state");
    fixture.write(None);

    let output = fixture.run(&fixture.config, &[]);
    assert!(output.status.success(), "{}", text(&output));
    let record: toml::Value =
        toml::from_str(&std::fs::read_to_string(fixture.record()).expect("record"))
            .expect("record parses");
    assert_eq!(
        record["box_dir"].as_str(),
        Some(fixture.box_directory.to_string_lossy().as_ref())
    );
}

#[test]
fn box_identity_is_stable_and_does_not_locate_state() {
    if !namespace_launcher_is_usable() {
        return;
    }
    let fixture = ContractFixture::new();
    fixture.write(None);
    let first = fixture.run(&fixture.config, &[]);
    assert!(first.status.success(), "{}", text(&first));
    let first_record: toml::Value =
        toml::from_str(&std::fs::read_to_string(fixture.record()).expect("first record"))
            .expect("record parses");
    let box_id = first_record["box_id"].as_str().expect("box id").to_string();
    assert_eq!(first_record["version"].as_integer(), Some(21));
    assert_eq!(
        first_record["box_dir"].as_str(),
        Some(fixture.box_directory.to_string_lossy().as_ref())
    );
    assert_eq!(first_record["name"].as_str(), Some("contract"));
    assert!(box_id.starts_with("box-"));

    let other_home = support::fixture::short_temporary_home();
    let second = fixture.run_with_home(other_home.path(), other_home.path(), &fixture.config, &[]);
    assert!(second.status.success(), "{}", text(&second));
    let second_record: toml::Value =
        toml::from_str(&std::fs::read_to_string(fixture.record()).expect("second record"))
            .expect("record parses");
    assert_eq!(second_record["box_id"].as_str(), Some(box_id.as_str()));
}

#[cfg(unix)]
#[test]
fn interpreters_protect_loaded_sources_by_identity_not_filename() {
    if !namespace_launcher_is_usable() {
        return;
    }
    const POLICY: &str = r#"
permit (principal, action == Box::Action::"shell:exec", resource);
permit (principal, action == Box::Action::"fs:read", resource);
permit (principal, action == Box::Action::"fs:write", resource);
permit (principal, action == Box::Action::"fs:delete", resource);
"#;
    let fixture = ContractFixture::new();
    fixture.write_for(Some(POLICY), "/bin/bash");
    let config_symlink = fixture.workspace.join("control-symlink");
    std::os::unix::fs::symlink(&fixture.config, &config_symlink).expect("config symlink");

    // The loaded config is an authority source, so an interpreter cannot read it by any name, not
    // only cannot write it. Protection is by identity, so the odd filename does not exempt it.
    let read = fixture.run(
        &fixture.config,
        &["-c", &format!("zsh -c 'cat {}'", fixture.config.display())],
    );
    assert!(!read.status.success(), "{}", text(&read));
    assert!(
        text(&read).contains("authority source that this run loaded"),
        "the loaded config must be refused by identity: {}",
        text(&read)
    );

    for (path, command) in [
        (
            &fixture.config,
            format!(
                "zsh -c 'printf changed > {}' 2>&1",
                fixture.config.display()
            ),
        ),
        (
            &config_symlink,
            format!(
                "zsh -c 'printf changed > {}' 2>&1",
                config_symlink.display()
            ),
        ),
    ] {
        let before = std::fs::read(path).expect("protected source reads");
        let output = fixture.run(&fixture.config, &["-c", &command]);
        assert!(
            !output.status.success(),
            "{}: {}",
            path.display(),
            text(&output)
        );
        assert_eq!(
            std::fs::read(path).expect("protected source remains"),
            before,
            "{} changed",
            path.display()
        );
    }

    let ordinary = fixture.workspace.join("box.toml");
    std::fs::write(&ordinary, "before").expect("ordinary file");
    let output = fixture.run(
        &fixture.config,
        &[
            "-c",
            &format!("zsh -c 'printf ordinary > {}'", ordinary.display()),
        ],
    );
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(
        std::fs::read_to_string(ordinary).expect("ordinary file reads"),
        "ordinary"
    );
}

#[cfg(unix)]
#[test]
fn an_authority_source_with_a_hard_link_alias_is_refused() {
    let fixture = ContractFixture::new();
    fixture.write(Some("permit(principal, action, resource);"));
    let alias = fixture.workspace.join("control-link");
    std::fs::hard_link(&fixture.config, &alias).expect("config hard link");

    let output = fixture.run(&fixture.config, &[]);

    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        text(&output).contains("more than one filesystem name"),
        "{}",
        text(&output)
    );
    assert_eq!(
        std::fs::read(&alias).expect("the alias remains"),
        std::fs::read(&fixture.config).expect("the config remains")
    );
}
