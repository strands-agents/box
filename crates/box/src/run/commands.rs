//! The configured tool programs whose identities belong to one run.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use containment::{Operation, Scope};

use crate::error::{BoxError, ConfigError};
use crate::record::config::Record;
use crate::record::config::filesystem::DirectReach;
use crate::record::layout::{disk_identity, lies_within, open_without_following};

#[derive(Debug, Default)]
pub(crate) struct ConfiguredCommands {
    tools: BTreeMap<String, Arc<ConfiguredCommand>>,
    apple_git: Option<PathBuf>,
}

#[derive(Debug)]
pub(crate) struct ConfiguredCommand {
    table: String,
    path: PathBuf,
    invoked: PathBuf,
    routes: Vec<PathBuf>,
    opened: File,
    identity: (u64, u64),
}

impl ConfiguredCommands {
    pub(crate) fn load(record: &Record) -> Result<Self, BoxError> {
        let tools = record
            .tool
            .iter()
            .map(|(label, spec)| {
                let table = format!("[tool.{label}]");
                let resolved =
                    super::contain::executable::resolve(spec.program(), &spec.search_path())?;
                let path = resolved.granted_path().to_path_buf();
                let opened = open_without_following(&path).map_err(|error| {
                    refusal(&table, &path, &format!("cannot be opened: {error}"))
                })?;
                let metadata = opened.metadata().map_err(|error| {
                    refusal(&table, &path, &format!("cannot be inspected: {error}"))
                })?;
                use std::os::unix::fs::MetadataExt as _;
                if !metadata.is_file() || metadata.nlink() != 1 {
                    let reason = if cfg!(target_os = "macos") && path == Path::new("/usr/bin/git") {
                        "must be a regular file with exactly one hard link; \
                         use the path from `/usr/bin/xcrun --find git` in the tool's command"
                    } else {
                        "must be a regular file with exactly one hard link"
                    };
                    return Err(refusal(&table, &path, reason));
                }
                let invoked = resolved.invoked().to_path_buf();
                let mut routes = vec![invoked.clone()];
                let authored = Path::new(spec.program());
                if authored.is_absolute() && !routes.iter().any(|route| route == authored) {
                    routes.push(authored.to_path_buf());
                }
                let command = ConfiguredCommand {
                    table,
                    path,
                    invoked,
                    routes,
                    opened,
                    identity: (metadata.dev(), metadata.ino()),
                };
                command.verify()?;
                Ok((label.clone(), Arc::new(command)))
            })
            .collect::<Result<_, BoxError>>()?;
        let commands = Self {
            tools,
            apple_git: None,
        };
        #[cfg(target_os = "macos")]
        let commands =
            commands.with_apple_git(|| developer_git(std::process::Command::new("/usr/bin/xcrun")));
        Ok(commands)
    }

    #[cfg(any(target_os = "macos", test))]
    fn with_apple_git(mut self, discover: impl FnOnce() -> Option<PathBuf>) -> Self {
        if !self.tools.values().any(|command| {
            command.path.file_name() == Some("git".as_ref())
                || command.invoked.file_name() == Some("git".as_ref())
        }) {
            return self;
        }
        let Some(path) = discover().filter(|path| path.is_absolute()) else {
            return self;
        };
        let Ok(path) = path.canonicalize() else {
            return self;
        };
        if path != Path::new("/usr/bin/git")
            && let Some(command) = self.tools.values().find(|command| command.path == path)
            && command.verify().is_ok()
        {
            self.apple_git = Some(path);
        }
        self
    }

    pub(crate) fn apple_git(&self) -> Option<&Path> {
        self.apple_git.as_deref()
    }

    pub(crate) fn get(&self, label: &str) -> Option<&Arc<ConfiguredCommand>> {
        let label = label
            .strip_prefix("[tool.")
            .and_then(|label| label.strip_suffix(']'))
            .unwrap_or(label);
        self.tools.get(label)
    }

    pub(crate) fn refuses_mutation(&self, path: &Path) -> bool {
        self.tools.values().any(|command| command.enclosed_by(path))
    }

    pub(crate) fn validate_reach(&self, table: &str, reach: &DirectReach) -> Result<(), BoxError> {
        for grant in &reach.grants {
            if grant.operation != Operation::Write {
                continue;
            }
            for command in self.tools.values() {
                let overlaps = match grant.scope {
                    Scope::Root | Scope::Dir => command.enclosed_by(&grant.resolved),
                    Scope::File => command.names(&grant.resolved),
                };
                if overlaps {
                    return Err(ConfigError::Filesystem {
                        table: table.to_string(),
                        entry: grant.authored.clone(),
                        reason: format!(
                            "this write grant can change {} command {} or its path. \
                             Keep configured tools outside every process's write grants",
                            command.table,
                            command.path.display()
                        ),
                    }
                    .into());
                }
            }
        }
        Ok(())
    }
}

#[cfg(any(target_os = "macos", test))]
fn developer_git(mut command: std::process::Command) -> Option<PathBuf> {
    use std::io::Read as _;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let mut child = command
        .args(["--find", "git"])
        .env_clear()
        .envs(std::env::var_os("DEVELOPER_DIR").map(|directory| ("DEVELOPER_DIR", directory)))
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut output = Vec::new();
        let result = stdout.take(4097).read_to_end(&mut output).map(|_| output);
        let _ = sender.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let output = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    }?;
    let output = output.ok()?.ok()?;
    if !status.success() || output.len() > 4096 {
        return None;
    }
    let text = String::from_utf8(output).ok()?;
    Some(PathBuf::from(text.strip_suffix('\n').unwrap_or(&text)))
}

impl ConfiguredCommand {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn invoked(&self) -> &Path {
        &self.invoked
    }

    pub(crate) fn opened(&self) -> &File {
        &self.opened
    }

    pub(crate) fn verify(&self) -> Result<(), BoxError> {
        use std::os::unix::fs::MetadataExt as _;
        let one_name = self
            .opened
            .metadata()
            .is_ok_and(|metadata| metadata.nlink() == 1);
        if one_name
            && disk_identity(&self.path) == Some(self.identity)
            && self
                .routes
                .iter()
                .all(|route| disk_identity(route) == Some(self.identity))
        {
            return Ok(());
        }
        Err(refusal(
            &self.table,
            &self.path,
            "changed after this run loaded it. Stop Box before updating a configured tool",
        ))
    }

    fn names(&self, path: &Path) -> bool {
        path == self.path
            || self.routes.iter().any(|route| route == path)
            || disk_identity(path) == Some(self.identity)
    }

    fn enclosed_by(&self, path: &Path) -> bool {
        self.names(path)
            || lies_within(&self.path, path)
            || self.routes.iter().any(|route| lies_within(route, path))
    }
}

fn refusal(table: &str, path: &Path, reason: &str) -> BoxError {
    ConfigError::Process {
        table: table.to_string(),
        reason: format!("configured command {} {reason}", path.display()),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    use crate::record::config::filesystem::{FilesystemContext, direct_grants};
    use crate::record::config::process::{Filesystem, ProcessSpec};

    fn program(path: &Path) {
        std::fs::write(path, "#!/bin/sh\nexit 0\n").expect("program");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("executable");
    }

    fn record(path: &Path) -> Record {
        Record {
            version: crate::record::config::RECORD_VERSION,
            experimental_features: Default::default(),
            box_id: "commands-test".to_string(),
            box_dir: path.parent().expect("directory").join("box-state"),
            name: "commands-test".to_string(),
            policy: None,
            agent: None,
            tool: BTreeMap::from([(
                "reader".to_string(),
                ProcessSpec {
                    native_filesystem_policy: None,
                    command: vec![path.display().to_string()],
                    workspace: None,
                    env: Default::default(),
                    filesystem: Default::default(),
                    network: None,
                    grammar: None,
                },
            )]),
            egress: Default::default(),
            remote_mcp: Default::default(),
            mcp: Default::default(),
            contained_mcp: Default::default(),
            telemetry: Default::default(),
        }
    }

    fn reach(home: &Path, writable: &Path) -> DirectReach {
        direct_grants(
            &Filesystem {
                read: vec![writable.to_path_buf()],
                write: vec![writable.to_path_buf()],
                ..Default::default()
            },
            &FilesystemContext {
                table: "[agent]",
                operator_home: home,
                policy: None,
                authority_directories: Vec::new(),
                program_search_directories: Vec::new(),
            },
        )
        .expect("read-write reach")
    }

    #[test]
    fn developer_git_must_match_a_valid_configured_identity_regardless_of_label() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let command = directory.path().join("git");
        program(&command);
        let real = command.canonicalize().unwrap();
        let relative = command
            .strip_prefix(std::env::current_dir().unwrap())
            .unwrap()
            .to_path_buf();
        assert!(!relative.is_absolute());
        let configured = record(&real);
        let commands = ConfiguredCommands::load(&configured)
            .unwrap()
            .with_apple_git(|| Some(real.clone()));
        assert_eq!(commands.apple_git(), Some(real.as_path()));
        for discovered in [
            None,
            Some("reader".into()),
            Some(relative),
            Some("/usr/bin/git".into()),
            Some(directory.path().join("absent")),
        ] {
            assert!(
                ConfiguredCommands::load(&configured)
                    .unwrap()
                    .with_apple_git(|| discovered)
                    .apple_git()
                    .is_none()
            );
        }
        let other = directory.path().join("other");
        program(&other);
        assert!(
            ConfiguredCommands::load(&configured)
                .unwrap()
                .with_apple_git(|| Some(other.canonicalize().unwrap()))
                .apple_git()
                .is_none()
        );
        let commands = ConfiguredCommands::load(&configured).unwrap();
        std::fs::hard_link(&command, directory.path().join("alias")).unwrap();
        assert!(commands.with_apple_git(|| Some(real)).apple_git().is_none());
    }

    #[test]
    fn developer_git_discovery_requires_a_git_executable_or_invocation() {
        let directory = tempfile::tempdir().unwrap();
        let helper = directory.path().join("helper");
        let git = directory.path().join("git");
        program(&helper);
        ConfiguredCommands::default().with_apple_git(|| panic!("no tools need Git"));
        ConfiguredCommands::load(&record(&helper))
            .unwrap()
            .with_apple_git(|| panic!("an unrelated tool does not need Git"));

        std::os::unix::fs::symlink(&helper, &git).unwrap();
        let commands = ConfiguredCommands::load(&record(&git))
            .unwrap()
            .with_apple_git(|| Some(helper.clone()));
        assert_eq!(
            commands.apple_git(),
            Some(helper.canonicalize().unwrap().as_path())
        );

        std::fs::remove_file(&git).unwrap();
        program(&git);
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(&git, &alias).unwrap();
        let commands = ConfiguredCommands::load(&record(&alias))
            .unwrap()
            .with_apple_git(|| Some(git.clone()));
        assert_eq!(
            commands.apple_git(),
            Some(git.canonicalize().unwrap().as_path())
        );
    }

    #[test]
    fn developer_git_probe_inherits_only_the_selected_developer_directory() {
        use std::process::Command;

        if std::env::var_os("BOX_TEST_GIT_PROBE").is_none() {
            for directory in [None, Some("/Developer Tools/Selected")] {
                let mut child = Command::new(std::env::current_exe().unwrap());
                child
                    .args(["--exact", "run::commands::tests::developer_git_probe_inherits_only_the_selected_developer_directory"])
                    .env("BOX_TEST_GIT_PROBE", "1")
                    .env("BOX_TEST_SECRET", "must-not-reach-the-probe")
                    .env_remove("DEVELOPER_DIR");
                if let Some(directory) = directory {
                    child.env("DEVELOPER_DIR", directory);
                }
                assert!(child.status().unwrap().success());
            }
            return;
        }

        let mut probe = Command::new("/bin/sh");
        probe.args([
            "-c",
            "test -z \"${BOX_TEST_SECRET+x}${BOX_TEST_GIT_PROBE+x}\" || exit 1; \
             printf '%s\\n' \"${DEVELOPER_DIR-/unset}\"",
        ]);
        let expected = std::env::var_os("DEVELOPER_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/unset"));
        assert_eq!(developer_git(probe), Some(expected));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn apple_git_hard_link_refusal_names_the_discovery_command() {
        use std::os::unix::fs::MetadataExt as _;

        let launcher = Path::new("/usr/bin/git");
        if std::fs::metadata(launcher).unwrap().nlink() == 1 {
            eprintln!("skipping: Apple's Git launcher has only one hard link");
            return;
        }
        let error = ConfiguredCommands::load(&record(launcher))
            .unwrap_err()
            .to_string();
        assert!(error.contains("exactly one hard link"), "{error}");
        assert!(error.contains("/usr/bin/xcrun --find git"), "{error}");
    }

    #[test]
    fn configured_commands_refuse_direct_writes_and_allow_unrelated_output() {
        let directory = tempfile::tempdir().expect("directory");
        let home = directory
            .path()
            .canonicalize()
            .expect("canonical directory");
        let project = home.join("project");
        std::fs::create_dir(&project).expect("project");
        let tools = project.join("tools");
        let output = project.join("output");
        std::fs::create_dir(&tools).expect("tools");
        std::fs::create_dir(&output).expect("output");
        let command = tools.join("reader");
        program(&command);
        let commands = ConfiguredCommands::load(&record(&command)).expect("commands");
        for writable in [&project, &tools, &command] {
            for table in ["[agent]", "[tool.builder]", "[mcp.server]"] {
                let error = commands
                    .validate_reach(table, &reach(&home, writable))
                    .expect_err("configured command cannot be writable")
                    .to_string();
                assert!(error.contains(table), "{error}");
                assert!(error.contains("[tool.reader]"), "{error}");
            }
        }
        commands
            .validate_reach("[agent]", &reach(&home, &output))
            .expect("unrelated build output stays writable");
    }

    #[test]
    fn configured_commands_refuse_preexisting_hard_links() {
        let directory = tempfile::tempdir().expect("directory");
        let command = directory.path().join("reader");
        program(&command);
        std::fs::hard_link(&command, directory.path().join("alias")).expect("hard link");
        let error = ConfiguredCommands::load(&record(&command))
            .expect_err("an unseen writable alias cannot be protected")
            .to_string();
        assert!(error.contains("exactly one hard link"), "{error}");
    }

    #[test]
    fn configured_commands_refuse_mutation_through_aliases_and_ancestors() {
        let directory = tempfile::tempdir().expect("directory");
        let home = directory
            .path()
            .canonicalize()
            .expect("canonical directory");
        let tools = home.join("tools");
        let routes = home.join("routes");
        std::fs::create_dir(&tools).expect("tools");
        std::fs::create_dir(&routes).expect("routes");
        let command = tools.join("reader");
        let route = routes.join("reader");
        program(&command);
        std::os::unix::fs::symlink(&command, &route).expect("symbolic link");
        let commands = ConfiguredCommands::load(&record(&route)).expect("commands");
        let alias = home.join("hard-alias");
        std::fs::hard_link(&command, &alias).expect("later hard link");
        for mutation in [&command, &route, &alias, &tools, &routes, &home] {
            assert!(
                commands.refuses_mutation(mutation),
                "{}",
                mutation.display()
            );
        }
        assert!(!commands.refuses_mutation(&tools.join("unrelated-output")));
        commands
            .get("reader")
            .unwrap()
            .verify()
            .expect_err("new hard link refuses launch");
    }

    #[test]
    fn configured_commands_refuse_replacement_and_accept_operator_update_between_runs() {
        let directory = tempfile::tempdir().expect("directory");
        let command = directory.path().join("reader");
        program(&command);
        let configuration = record(&command);
        let commands = ConfiguredCommands::load(&configuration).expect("commands");
        commands
            .get("[tool.reader]")
            .unwrap()
            .verify()
            .expect("unchanged command");
        let replacement = directory.path().join("replacement");
        program(&replacement);
        std::fs::rename(&replacement, &command).expect("replacement");
        commands
            .get("reader")
            .unwrap()
            .verify()
            .expect_err("replacement refuses launch");
        ConfiguredCommands::load(&configuration).expect("a new run accepts the operator update");
    }

    #[test]
    fn configured_commands_refuse_writable_symlink_routes() {
        let directory = tempfile::tempdir().expect("directory");
        let home = directory
            .path()
            .canonicalize()
            .expect("canonical directory");
        let tools = home.join("tools");
        let routes = home.join("routes");
        std::fs::create_dir(&tools).expect("tools");
        std::fs::create_dir(&routes).expect("routes");
        let command = tools.join("reader");
        let route = routes.join("reader");
        program(&command);
        std::os::unix::fs::symlink(&command, &route).expect("symbolic link");
        let commands = ConfiguredCommands::load(&record(&route)).expect("commands");
        commands
            .validate_reach("[agent]", &reach(&home, &routes))
            .expect_err("a writable route can replace the program selection");
        let other = tools.join("other");
        program(&other);
        let new_route = routes.join("replacement");
        std::os::unix::fs::symlink(&other, &new_route).expect("new symbolic link");
        std::fs::rename(&new_route, &route).expect("replace route");
        commands
            .get("reader")
            .unwrap()
            .verify()
            .expect_err("a changed route refuses launch");
    }
}
