//! The configured programs whose identities belong to one run: each tool, and each secret source.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use containment::{Operation, Scope};

use crate::error::{BoxError, ConfigError};
use crate::record::config::Record;
use crate::record::config::filesystem::DirectReach;
use crate::record::config::secret_source::SecretSourceEntry;
use crate::record::layout::{
    disk_identity, lies_within, open_without_following, resolved_through_links,
};

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod aliases;

#[derive(Debug, Default)]
pub(crate) struct ConfiguredCommands {
    tools: BTreeMap<String, Arc<ConfiguredCommand>>,
    /// The program of each `[secret-source.<scheme>]` table, which no workload may change.
    sources: BTreeMap<String, Arc<ConfiguredCommand>>,
}

/// The file each bare name runs in the hosted Shell, from the `[tool]` tables that answer to it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct BareNames {
    /// Each name that one program file answers to: the spelling that runs it, and its tables.
    pub(crate) declared: BTreeMap<String, (PathBuf, Vec<String>)>,
    /// Each name that tables with different program files answer to, and those tables.
    pub(crate) shared: BTreeMap<String, Vec<String>>,
    /// Each declared name that its label settled, and the tables that run other files.
    pub(crate) passed_over: BTreeMap<String, Vec<String>>,
}

impl BareNames {
    /// The declared file of each name, as the Shell reads it.
    pub(crate) fn programs(&self) -> box_shell::HostPrograms {
        Arc::new(
            self.declared
                .iter()
                .map(|(name, (path, _))| (name.clone(), path.clone()))
                .collect(),
        )
    }
}

/// Why command protection refuses a mutation.
#[derive(Debug)]
pub(crate) enum CommandMutationRefusal {
    CommandOrAncestor,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    HardLinkAlias,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    IncompleteScan(std::io::Error),
}

/// A `[tool.<name>]` that a run leaves out because its program is not installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LeftOut {
    /// The table, spelled `[tool.<name>]`.
    pub(crate) table: String,
    /// The program as `command` spells it.
    pub(crate) program: String,
}

/// Remove from `record` each `[tool.<name>]` whose program is not installed, so no later step of the
/// run sees it, and answer with those tables, refusing one whose `command` no run can expand.
pub(crate) fn leave_out_absent(record: &mut Record) -> Result<Vec<LeftOut>, BoxError> {
    use super::contain::boundary::environment;

    let mut left_out = Vec::new();
    for (label, spec) in &record.tool {
        if !super::contain::executable::is_absent(spec.program(), &spec.search_path()) {
            continue;
        }
        let table = format!("[tool.{label}]");
        if let Some(reason) =
            environment::program_refusal(spec).or_else(|| environment::argument_refusal(spec))
        {
            return Err(ConfigError::Process { table, reason }.into());
        }
        left_out.push((label.clone(), table, spec.program().to_string()));
    }
    Ok(left_out
        .into_iter()
        .map(|(label, table, program)| {
            record.tool.remove(&label);
            LeftOut { table, program }
        })
        .collect())
}

#[derive(Debug)]
pub(crate) struct ConfiguredCommand {
    table: String,
    path: PathBuf,
    invoked: PathBuf,
    routes: Vec<PathBuf>,
    /// Each symbolic link that the resolution of a secret source program passes through.
    links: Vec<PathBuf>,
    opened: File,
    identity: (u64, u64),
    loaded: FileState,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    needs_alias_scan: bool,
}

/// The link count, owner, group, and mode of a command file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileState {
    links: u64,
    owner: u32,
    group: u32,
    mode: u32,
}

impl FileState {
    fn of(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            links: metadata.nlink(),
            owner: metadata.uid(),
            group: metadata.gid(),
            mode: metadata.mode(),
        }
    }
}

impl ConfiguredCommands {
    pub(crate) fn load(record: &Record) -> Result<Self, BoxError> {
        let tools = record
            .tool
            .iter()
            .map(|(label, spec)| {
                let command = ConfiguredCommand::load(
                    format!("[tool.{label}]"),
                    spec.program(),
                    &spec.search_path(),
                )?;
                Ok((label.clone(), Arc::new(command)))
            })
            .collect::<Result<_, BoxError>>()?;
        let sources = Self::source_programs(&record.secret_source)?;
        Ok(Self { tools, sources })
    }

    /// The program of each `[secret-source.<scheme>]` table alone, opened and checked.
    pub(crate) fn of_secret_sources(
        entries: &BTreeMap<String, SecretSourceEntry>,
    ) -> Result<Self, BoxError> {
        Ok(Self {
            tools: BTreeMap::new(),
            sources: Self::source_programs(entries)?,
        })
    }

    fn source_programs(
        entries: &BTreeMap<String, SecretSourceEntry>,
    ) -> Result<BTreeMap<String, Arc<ConfiguredCommand>>, BoxError> {
        entries
            .iter()
            .map(|(scheme, entry)| {
                let refuse = |reason: String| ConfigError::SecretSource {
                    scheme: scheme.clone(),
                    reason,
                };
                let program = entry
                    .command
                    .first()
                    .ok_or_else(|| refuse("has an empty command".to_string()))?;
                // The program is an absolute path, so no search path finds it.
                let nowhere = std::ffi::OsStr::new("");
                super::contain::executable::resolve(program, nowhere)
                    .map_err(|error| refuse(format!("its program cannot run: {error}")))?;
                let mut command =
                    ConfiguredCommand::load(format!("[secret-source.{scheme}]"), program, nowhere)?;
                // A workload that can change one link of the chain chooses the file that the
                // next run starts.
                command.links = links_on_the_way(Path::new(program)).map_err(|error| {
                    refuse(format!("its program path cannot be inspected: {error}"))
                })?;
                Ok((scheme.clone(), Arc::new(command)))
            })
            .collect()
    }

    /// The checked program of the `[secret-source.<scheme>]` table for `scheme`.
    pub(crate) fn source(&self, scheme: &str) -> Option<&Arc<ConfiguredCommand>> {
        self.sources.get(scheme)
    }

    /// Whether this value holds the program of a secret source.
    pub(crate) fn has_sources(&self) -> bool {
        !self.sources.is_empty()
    }

    /// Each program that no workload may change: of a tool, and of a secret source.
    fn protected(&self) -> impl Iterator<Item = &Arc<ConfiguredCommand>> {
        self.tools.values().chain(self.sources.values())
    }

    pub(crate) fn get(&self, label: &str) -> Option<&Arc<ConfiguredCommand>> {
        let label = label
            .strip_prefix("[tool.")
            .and_then(|label| label.strip_suffix(']'))
            .unwrap_or(label);
        self.tools.get(label)
    }

    /// The bare names that `record`'s tools answer to: each one's bound name, which a grammar whose
    /// `program` is not its command's file name leaves to `PATH`, and none the Shell implements.
    /// Among tools whose commands resolve to different paths, including hard links to one file,
    /// `search_path` decides when it finds one of them, else the one tool whose label is the name.
    pub(crate) fn bare_names(&self, record: &Record, search_path: &std::ffi::OsStr) -> BareNames {
        use crate::record::config::grammar::{bound_name, called_name};
        let mut found: BTreeMap<&str, Vec<(&str, &ConfiguredCommand, bool)>> = BTreeMap::new();
        for (label, spec) in &record.tool {
            let (Some(name), Some(command)) = (bound_name(spec), self.tools.get(label)) else {
                continue;
            };
            // `python3` and `python` are the Shell's own only while Monty answers them. With
            // `monty = false` a tool declared under either name answers it like any other tool.
            if box_shell::implements_program(name)
                && (record.monty || !matches!(name, "python" | "python3"))
            {
                continue;
            }
            let declares = name == called_name(spec);
            found
                .entry(name)
                .or_default()
                .push((label, command, declares));
        }
        let mut names = BareNames::default();
        for (name, commands) in found {
            let Some((_, declaring, _)) = commands.iter().find(|(_, _, declares)| *declares) else {
                continue;
            };
            let tables = commands
                .iter()
                .map(|(label, _, _)| format!("[tool.{label}]"))
                .collect();
            let chosen = if commands
                .iter()
                .all(|(_, command, _)| command.path == declaring.path)
            {
                Some(*declaring)
            } else {
                Self::label_choice(name, &commands, search_path)
            };
            let Some(command) = chosen else {
                names.shared.insert(name.to_string(), tables);
                continue;
            };
            let (running, other): (Vec<_>, Vec<_>) = commands
                .iter()
                .partition(|(_, candidate, _)| candidate.path == command.path);
            let label =
                |(label, _, _): &(&str, &ConfiguredCommand, bool)| format!("[tool.{label}]");
            if !other.is_empty() {
                names
                    .passed_over
                    .insert(name.to_string(), other.iter().map(label).collect());
            }
            names.declared.insert(
                name.to_string(),
                (command.invoked.clone(), running.iter().map(label).collect()),
            );
        }
        names
    }

    /// The one tool labelled `name` among `commands`, whose commands resolve to different paths,
    /// when `search_path` finds none of those paths for `name`.
    fn label_choice<'a>(
        name: &str,
        commands: &[(&str, &'a ConfiguredCommand, bool)],
        search_path: &std::ffi::OsStr,
    ) -> Option<&'a ConfiguredCommand> {
        let found = super::contain::executable::find_on(name, search_path)
            .and_then(|path| path.canonicalize().ok());
        if commands
            .iter()
            .any(|(_, command, _)| Some(&command.path) == found.as_ref())
        {
            return None;
        }
        let mut labelled = commands
            .iter()
            .filter(|(label, _, declares)| *declares && *label == name);
        match (labelled.next(), labelled.next()) {
            (Some((_, command, _)), None) => Some(command),
            _ => None,
        }
    }

    pub(crate) fn mutation_refusal(&self, path: &Path) -> Option<CommandMutationRefusal> {
        if self.protected().any(|command| command.enclosed_by(path)) {
            return Some(CommandMutationRefusal::CommandOrAncestor);
        }
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let identities = self.mutable_aliases(path);
            if !identities.is_empty() {
                return match aliases::contains(path, &identities) {
                    Ok(true) => Some(CommandMutationRefusal::HardLinkAlias),
                    Ok(false) => None,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => Some(CommandMutationRefusal::IncompleteScan(error)),
                };
            }
        }
        None
    }

    pub(crate) fn validate_reach(&self, table: &str, reach: &DirectReach) -> Result<(), BoxError> {
        for grant in &reach.grants {
            if grant.operation != Operation::Write {
                continue;
            }
            for command in self.protected() {
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
                             Keep {} outside every process's write grants",
                            command.table,
                            command.path.display(),
                            if command.table.starts_with("[secret-source.") {
                                "the program of each secret source"
                            } else {
                                "configured tools"
                            }
                        ),
                    }
                    .into());
                }
            }
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            if grant.scope != Scope::File {
                let identities = self.mutable_aliases(&grant.resolved);
                if identities.is_empty() {
                    continue;
                }
                let reason = match aliases::contains(&grant.resolved, &identities) {
                    Ok(false) => continue,
                    Ok(true) => "contains a hard link to a configured tool command".to_string(),
                    Err(error) => {
                        format!("cannot be inspected for configured command hard links: {error}")
                    }
                };
                return Err(ConfigError::Filesystem {
                    table: table.to_string(),
                    entry: grant.authored.clone(),
                    reason: format!(
                        "this write grant {reason}. Keep configured tools and their hard links \
                         outside every process's write grants"
                    ),
                }
                .into());
            }
        }
        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn mutable_aliases(&self, target: &Path) -> Vec<(u64, u64)> {
        let directory = std::fs::symlink_metadata(target).is_ok_and(|metadata| metadata.is_dir());
        self.protected()
            .filter(|command| {
                command.needs_alias_scan && (!directory || !command.every_name_beside(target))
            })
            .map(|command| command.identity)
            .collect()
    }
}

impl ConfiguredCommand {
    /// Open and check the program file that `table` names as `program`, which `search_path`
    /// finds when it is a bare name.
    pub(crate) fn load(
        table: String,
        program: &str,
        search_path: &std::ffi::OsStr,
    ) -> Result<Self, BoxError> {
        let resolved = super::contain::executable::resolve(program, search_path)?;
        let path = resolved.granted_path().to_path_buf();
        let opened = open_without_following(&path)
            .map_err(|error| refusal(&table, &path, &format!("cannot be opened: {error}")))?;
        let metadata = opened
            .metadata()
            .map_err(|error| refusal(&table, &path, &format!("cannot be inspected: {error}")))?;
        use std::os::unix::fs::MetadataExt as _;
        if !metadata.is_file() {
            return Err(refusal(&table, &path, "must be a regular file"));
        }
        let loaded = FileState::of(&metadata);
        let writable_links = loaded.links > 1 && writable_by_this_user(&opened, &path, loaded);
        if writable_links && !cfg!(any(target_os = "macos", target_os = "linux")) {
            return Err(refusal(
                &table,
                &path,
                &format!(
                    "has {} hard links, and the user that runs Box may be able to write \
                     it. Use a copy with one hard link",
                    loaded.links
                ),
            ));
        }
        let invoked = resolved.invoked().to_path_buf();
        let mut routes = vec![invoked.clone()];
        let authored = Path::new(program);
        if authored.is_absolute() && !routes.iter().any(|route| route == authored) {
            routes.push(authored.to_path_buf());
        }
        let command = Self {
            table,
            path,
            invoked,
            routes,
            links: Vec::new(),
            opened,
            identity: (metadata.dev(), metadata.ino()),
            loaded,
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            needs_alias_scan: writable_links,
        };
        command.verify()?;
        Ok(command)
    }

    /// Whether the current target can omit the hard-link scan for this command.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn every_name_beside(&self, target: &Path) -> bool {
        aliases::every_name_beside(&self.path, &self.opened, self.identity, target)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn invoked(&self) -> &Path {
        &self.invoked
    }

    pub(crate) const fn has_several_names(&self) -> bool {
        self.loaded.links > 1
    }

    pub(crate) fn opened(&self) -> &File {
        &self.opened
    }

    pub(crate) fn verify(&self) -> Result<(), BoxError> {
        let unchanged_names = self.opened.metadata().is_ok_and(|metadata| {
            let now = FileState::of(&metadata);
            if self.loaded.links == 1 {
                now.links == 1
            } else {
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                let protected_by_reach = self.needs_alias_scan;
                #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                let protected_by_reach = false;
                now == self.loaded
                    && (protected_by_reach || !writable_by_this_user(&self.opened, &self.path, now))
            }
        });
        if unchanged_names
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
            || self.links.iter().any(|link| holds(path, link))
    }
}

/// Whether the folder `outer` holds the directory entry `entry`, at any depth.
fn holds(outer: &Path, entry: &Path) -> bool {
    // A change to the entry itself needs a write to its folder, so the folder is what a workload
    // must not write. A grant entry or an interpreter path that names the link itself is refused
    // as a symbolic link, by the filesystem lists and by the path resolver.
    entry
        .parent()
        .is_some_and(|folder| lies_within(folder, outer))
}

/// Each symbolic link that the resolution of the absolute `path` passes through, spelled as the
/// resolved folder that holds it and its own name.
fn links_on_the_way(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    resolved_through_links(path).map(|(_, links)| links)
}

/// Whether the user that runs Box can write `opened`, or can give itself that right, through any name.
fn writable_by_this_user(opened: &File, path: &Path, state: FileState) -> bool {
    // SAFETY: these calls read the process credentials without changing them.
    let users = unsafe { [libc::getuid(), libc::geteuid()] };
    may_change(
        state,
        users,
        || write_access(opened, path),
        || may_carry_access_list(opened),
    )
}

/// Whether a file in `state` may change through some name, for the real and effective `users`, the
/// kernel's answer to a write check, and whether the file may carry an access-control list.
fn may_change(
    state: FileState,
    users: [u32; 2],
    access: impl FnOnce() -> std::io::Result<()>,
    access_list: impl FnOnce() -> bool,
) -> bool {
    users.contains(&0)
        || users.contains(&state.owner)
        || state.mode & 0o022 != 0
        || match access() {
            Ok(()) => true,
            Err(error) => match error.raw_os_error() {
                Some(libc::EACCES) => false,
                Some(libc::EPERM | libc::EROFS) if cfg!(target_os = "macos") => access_list(),
                _ => true,
            },
        }
}

// macOS access-control-list calls, which the `libc` crate does not declare.
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
    fn acl_free(acl: *mut libc::c_void) -> libc::c_int;
}

/// `ACL_TYPE_EXTENDED`, the one list type macOS stores.
#[cfg(target_os = "macos")]
const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;

/// Whether `opened` may carry an access-control list, which can grant a write that its mode does not.
#[cfg(target_os = "macos")]
fn may_carry_access_list(opened: &File) -> bool {
    use std::os::fd::AsRawFd as _;
    // SAFETY: the descriptor is live for the call.
    let list = unsafe { acl_get_fd_np(opened.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if list.is_null() {
        return std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT);
    }
    // SAFETY: `list` came from `acl_get_fd_np`, and this frees it once.
    unsafe { acl_free(list) };
    true
}

#[cfg(not(target_os = "macos"))]
fn may_carry_access_list(_opened: &File) -> bool {
    true
}

#[cfg(target_os = "linux")]
fn write_access(opened: &File, _path: &Path) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    // SAFETY: the descriptor is live, and the empty path is a terminated string.
    let result = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            opened.as_raw_fd(),
            c"".as_ptr(),
            libc::W_OK,
            libc::AT_EACCESS | libc::AT_EMPTY_PATH,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn write_access(_opened: &File, path: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;
    let spelled = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: `spelled` is a NUL-terminated path that outlives the call.
    let result = unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            spelled.as_ptr(),
            libc::W_OK,
            libc::AT_EACCESS,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
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
            file_attributes: false,
            monty: true,
            gateway: Default::default(),
            limits: Default::default(),
            box_id: "commands-test".to_string(),
            box_dir: path.parent().expect("directory").join("box-state"),
            name: "commands-test".to_string(),
            policy: None,
            agent: None,
            tool: BTreeMap::from([(
                "reader".to_string(),
                ProcessSpec {
                    file_watching: false,
                    native_filesystem_policy: None,
                    command: vec![path.display().to_string()],
                    workspace: None,
                    env: Default::default(),
                    filesystem: Default::default(),
                    network: None,
                    grammar: None,
                    ingress: Vec::new(),
                },
            )]),
            egress: Default::default(),
            remote_mcp: Default::default(),
            mcp: Default::default(),
            contained_mcp: Default::default(),
            telemetry: Default::default(),
            secret_source: Default::default(),
            containment: Default::default(),
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
                source_paths: &[],
            },
        )
        .expect("read-write reach")
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

    /// **The program of a secret source is protected as a configured tool command is**: no write
    /// grant covers the program, its link, or a folder of either, and no interpreter changes them.
    #[test]
    fn a_secret_source_program_is_protected_like_a_configured_tool_command() {
        let directory = tempfile::tempdir().expect("directory");
        let home = directory
            .path()
            .canonicalize()
            .expect("canonical directory");
        let project = home.join("project");
        let cellar = project.join("cellar");
        let bin = project.join("bin");
        let output = project.join("output");
        for folder in [&project, &cellar, &bin, &output] {
            std::fs::create_dir(folder).expect("folder");
        }
        let target = cellar.join("op");
        let link = bin.join("op");
        program(&target);
        std::os::unix::fs::symlink(&target, &link).expect("symbolic link");
        let commands = ConfiguredCommands::load(&source_record(&link)).expect("the program loads");

        for writable in [&project, &cellar, &bin, &target] {
            let error = commands
                .validate_reach("[agent]", &reach(&home, writable))
                .expect_err("the program of a secret source cannot be writable")
                .to_string();
            assert_eq!(
                error,
                format!(
                    "`[agent]` filesystem entry {:?} is refused: this write grant can change \
                     [secret-source.op] command {} or its path. Keep the program of each \
                     secret source outside every process's write grants",
                    writable.display().to_string(),
                    target.display()
                )
            );
        }
        for mutation in [&home, &project, &cellar, &bin, &target, &link] {
            assert!(
                matches!(
                    commands.mutation_refusal(mutation),
                    Some(CommandMutationRefusal::CommandOrAncestor)
                ),
                "{}",
                mutation.display()
            );
        }
        commands
            .validate_reach("[agent]", &reach(&home, &output))
            .expect("an unrelated folder stays writable");
        assert!(commands.mutation_refusal(&output.join("file")).is_none());
    }

    /// A record with no tool, whose `[secret-source.op]` table runs `program`.
    fn source_record(program: &Path) -> Record {
        let mut record = record(Path::new("/bin/sh"));
        record.tool.clear();
        record.secret_source.insert(
            "op".to_string(),
            crate::record::config::secret_source::SecretSourceEntry {
                command: vec![program.display().to_string(), "read".to_string()],
                ..Default::default()
            },
        );
        record
    }

    #[test]
    fn a_secret_source_table_with_no_command_does_not_load() {
        let mut record = source_record(Path::new("/bin/sh"));
        record
            .secret_source
            .insert("empty".to_string(), Default::default());
        assert_eq!(
            ConfiguredCommands::load(&record)
                .expect_err("a table with no program")
                .to_string(),
            "invalid `[secret-source.empty]` table: has an empty command"
        );
    }

    /// **Each symbolic link on the way to a secret source program is protected, and a tool command
    /// keeps its own check**: a write grant or an interpreter that can change a link in the middle
    /// of the chain, a folder link, or a folder above one of them is refused.
    #[test]
    fn each_link_on_the_way_to_a_secret_source_program_is_protected() {
        let directory = tempfile::tempdir().expect("directory");
        let home = directory
            .path()
            .canonicalize()
            .expect("canonical directory");
        let folder = |name: &str| {
            let folder = home.join(name);
            std::fs::create_dir_all(&folder).expect("folder");
            folder
        };
        let (bin, middle, links, cellar, output) = (
            folder("bin"),
            folder("outer/middle"),
            folder("links"),
            folder("versions/2"),
            folder("output"),
        );
        // `bin/op` names `outer/middle/op`, which names `links/current/op`, and `links/current`
        // names the folder `versions/2`.
        let target = cellar.join("op");
        program(&target);
        std::os::unix::fs::symlink("../versions/2", links.join("current")).expect("folder link");
        std::os::unix::fs::symlink("../../links/current/op", middle.join("op")).expect("link");
        std::os::unix::fs::symlink(middle.join("op"), bin.join("op")).expect("link");
        assert_eq!(
            links_on_the_way(&bin.join("op")).expect("the path resolves"),
            [bin.join("op"), middle.join("op"), links.join("current")]
        );
        let commands =
            ConfiguredCommands::load(&source_record(&bin.join("op"))).expect("the program loads");

        // A folder above the folder of a link holds that link too.
        let outer = home.join("outer");
        for writable in [&bin, &middle, &outer, &links, &cellar] {
            let error = commands
                .validate_reach("[tool.build]", &reach(&home, writable))
                .expect_err("a link of the chain cannot be writable")
                .to_string();
            assert_eq!(
                error,
                format!(
                    "`[tool.build]` filesystem entry {:?} is refused: this write grant can \
                     change \
                     [secret-source.op] command {} or its path. Keep the program of each \
                     secret source outside every process's write grants",
                    writable.display().to_string(),
                    target.display()
                )
            );
        }
        for mutation in [
            &bin,
            &middle,
            &outer,
            &links,
            &cellar,
            &middle.join("op"),
            &links.join("current"),
            &home.join("versions"),
        ] {
            assert!(
                matches!(
                    commands.mutation_refusal(mutation),
                    Some(CommandMutationRefusal::CommandOrAncestor)
                ),
                "{}",
                mutation.display()
            );
        }
        commands
            .validate_reach("[agent]", &reach(&home, &output))
            .expect("an unrelated folder stays writable");
        assert!(commands.mutation_refusal(&output.join("file")).is_none());

        // A tool command keeps its check: a link in the middle of its path is not held.
        let mut tool = record(&bin.join("op"));
        tool.secret_source.clear();
        ConfiguredCommands::load(&tool)
            .expect("the tool loads")
            .validate_reach("[agent]", &reach(&home, &middle))
            .expect("the tool check does not change");
    }

    #[test]
    fn a_program_path_whose_links_do_not_end_is_an_error() {
        let directory = tempfile::tempdir().expect("directory");
        let (first, second) = (directory.path().join("a"), directory.path().join("b"));
        std::os::unix::fs::symlink(&second, &first).expect("link");
        std::os::unix::fs::symlink(&first, &second).expect("link");
        assert_eq!(
            links_on_the_way(&first)
                .expect_err("the chain does not end")
                .to_string(),
            "the path passes through too many symbolic links"
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn configured_commands_refuse_preexisting_hard_links_this_user_can_write() {
        let directory = tempfile::tempdir().expect("directory");
        let command = directory.path().join("reader");
        program(&command);
        std::fs::hard_link(&command, directory.path().join("alias")).expect("hard link");
        let error = ConfiguredCommands::load(&record(&command))
            .expect_err("an unseen writable alias cannot be protected")
            .to_string();
        assert!(
            error.contains("has 2 hard links, and the user that runs Box may be able to write it"),
            "{error}"
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn linked_commands_are_admitted_only_outside_every_writable_tree() {
        let directory = tempfile::tempdir().expect("directory");
        let home = directory.path().canonicalize().unwrap();
        let tools = home.join("tools");
        let work = home.join("work");
        let nested = work.join("nested");
        std::fs::create_dir(&tools).unwrap();
        std::fs::create_dir_all(&nested).unwrap();
        let command = tools.join("reader");
        let alias = tools.join("alias");
        program(&command);
        std::fs::hard_link(&command, &alias).unwrap();
        let commands = ConfiguredCommands::load(&record(&command)).expect("linked commands load");
        commands
            .validate_reach("[agent]", &reach(&home, &work))
            .unwrap();
        commands.get("reader").unwrap().verify().unwrap();
        std::fs::rename(&alias, nested.join("alias")).unwrap();
        for table in ["[agent]", "[tool.builder]", "[mcp.server]"] {
            let error = commands
                .validate_reach(table, &reach(&home, &work))
                .expect_err("a nested alias makes the grant unsafe")
                .to_string();
            assert!(error.contains(table), "{error}");
            assert!(error.contains("contains a hard link"), "{error}");
        }
    }

    #[cfg(target_os = "linux")]
    fn shortcut_fixture_skip_reason(home: &Path, tools: &Path, work: &Path) -> Option<String> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::MetadataExt as _;

        let inspect = || -> Result<(), String> {
            let file = File::open(home).map_err(|error| error.to_string())?;
            let metadata = file.metadata().map_err(|error| error.to_string())?;
            let device = format!(
                "{}:{}",
                libc::major(metadata.dev()),
                libc::minor(metadata.dev())
            );
            let table = std::fs::read_to_string("/proc/self/mountinfo")
                .map_err(|error| error.to_string())?;
            let mut mounts = Vec::new();
            for line in table.lines().filter(|line| !line.is_empty()) {
                let fields: Vec<_> = line.split_ascii_whitespace().collect();
                let separator = fields
                    .iter()
                    .position(|field| *field == "-")
                    .ok_or("mount table row has no separator")?;
                if separator < 6 || fields.len() != separator + 4 {
                    return Err("mount table row is incomplete".into());
                }
                for field in &fields[..2] {
                    field
                        .parse::<u64>()
                        .map_err(|_| "mount identity is not numeric")?;
                }
                let (major, minor) = fields[2]
                    .split_once(':')
                    .ok_or("mount device is incomplete")?;
                for field in [major, minor] {
                    field
                        .parse::<u32>()
                        .map_err(|_| "mount device is not numeric")?;
                }
                if (!Path::new(fields[3]).is_absolute() && fields[separator + 1] != "nsfs")
                    || !Path::new(fields[4]).is_absolute()
                    || fields[3].contains('\\')
                    || fields[4].contains('\\')
                {
                    return Err("fixture requires absolute mount points and unescaped filesystem paths or nsfs roots".into());
                }
                mounts.push((
                    fields[2],
                    fields[3],
                    Path::new(fields[4]),
                    fields[separator + 1],
                ));
            }
            let matching: Vec<_> = mounts.iter().filter(|mount| mount.0 == device).collect();
            if matching.len() != 1 {
                return Err("fixture device does not have exactly one mount".into());
            }
            let selected = matching[0];
            if selected.1 != "/" || !tools.starts_with(selected.2) || !work.starts_with(selected.2)
            {
                return Err("fixture is not below one complete filesystem mount".into());
            }
            let expected_type = match selected.3 {
                "ext4" => libc::EXT4_SUPER_MAGIC,
                "xfs" => libc::XFS_SUPER_MAGIC,
                "tmpfs" => libc::TMPFS_MAGIC,
                _ => return Err("fixture filesystem is not ext4, XFS, or tmpfs".into()),
            };
            if mounts.iter().filter(|mount| mount.2 == selected.2).count() != 1
                || mounts
                    .iter()
                    .any(|mount| mount.2.starts_with(tools) || mount.2.starts_with(work))
            {
                return Err("fixture paths overlap another mount".into());
            }
            let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
            // SAFETY: the descriptor is live and the output points to writable statfs storage.
            if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            // SAFETY: fstatfs succeeded and initialized the output.
            let filesystem = unsafe { filesystem.assume_init() };
            if filesystem.f_type != expected_type {
                return Err("statfs disagrees with the fixture mount type".into());
            }
            Ok(())
        };
        inspect().err()
    }

    /// Co-located hard links skip inspection on supported Linux layouts and retain the macOS scan.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_linked_command_whose_names_share_its_folder_skips_the_scan_until_a_name_lands_elsewhere() {
        let directory = tempfile::tempdir().expect("directory");
        let home = directory.path().canonicalize().unwrap();
        let tools = home.join("tools");
        let work = home.join("work");
        let locked = work.join("locked");
        std::fs::create_dir(&tools).unwrap();
        std::fs::create_dir_all(&locked).unwrap();
        #[cfg(target_os = "linux")]
        if let Some(reason) = shortcut_fixture_skip_reason(&home, &tools, &work) {
            eprintln!("skipping: linked-command shortcut fixture: {reason}");
            return;
        }
        // SAFETY: these calls only read process credentials.
        if unsafe { [libc::getuid(), libc::geteuid()] }.contains(&0) {
            eprintln!("skipping: linked-command shortcut fixture requires a non-root user");
            return;
        }
        std::fs::write(locked.join("entry"), "").unwrap();
        let command = tools.join("reader");
        program(&command);
        std::fs::hard_link(&command, tools.join("alias")).unwrap();
        let commands = ConfiguredCommands::load(&record(&command)).expect("linked commands load");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = std::fs::read_dir(&locked).is_err();
        let identities = commands.mutable_aliases(&work);
        let skipped = commands.validate_reach("[agent]", &reach(&home, &work));
        let mutation = commands.mutation_refusal(&work);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        if !unreadable {
            eprintln!("skipping: mode-000 directories remain readable for this test user");
            return;
        }
        #[cfg(target_os = "linux")]
        {
            assert!(
                identities.is_empty(),
                "a supported Linux fixture must use the shortcut"
            );
            skipped.expect("the verified layout needs no scan");
            assert!(mutation.is_none(), "the verified layout needs no scan");
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(identities, vec![commands.get("reader").unwrap().identity]);
            assert!(skipped.is_err(), "macOS keeps the existing scan");
            assert!(
                matches!(mutation, Some(CommandMutationRefusal::IncompleteScan(_))),
                "macOS also scans mutation targets"
            );
        }
        commands.get("reader").unwrap().verify().unwrap();

        std::fs::hard_link(&command, work.join("elsewhere")).unwrap();
        assert_eq!(
            commands.mutable_aliases(&work),
            vec![commands.get("reader").unwrap().identity],
            "a name outside the folder brings the scan back"
        );
        let error = commands
            .validate_reach("[agent]", &reach(&home, &work))
            .expect_err("the scan finds the new name")
            .to_string();
        assert!(error.contains("contains a hard link"), "{error}");
        assert!(
            commands.get("reader").unwrap().verify().is_err(),
            "the added name also changes the link count"
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn file_and_missing_targets_retain_direct_command_identity_checks() {
        let directory = tempfile::tempdir().unwrap();
        let tools = directory.path().join("tools");
        let work = directory.path().join("work");
        std::fs::create_dir(&tools).unwrap();
        std::fs::create_dir(&work).unwrap();
        let command = tools.join("reader");
        let alias = tools.join("alias");
        program(&command);
        std::fs::hard_link(&command, &alias).unwrap();
        let commands = ConfiguredCommands::load(&record(&command)).unwrap();
        let ordinary = work.join("ordinary");
        std::fs::write(&ordinary, "unchanged").unwrap();
        for target in [&ordinary, &work.join("missing")] {
            assert_eq!(
                commands.mutable_aliases(target),
                vec![commands.get("reader").unwrap().identity],
                "file and missing targets retain direct identity checks"
            );
            assert!(commands.mutation_refusal(target).is_none());
        }
        assert!(
            commands.mutation_refusal(&alias).is_some(),
            "a direct hard-link file remains protected"
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_name_outside_the_command_folder_requires_a_complete_directory_scan() {
        // SAFETY: these calls only read process credentials.
        if unsafe { [libc::getuid(), libc::geteuid()] }.contains(&0) {
            eprintln!("skipping: unreadable alias-scan fixture requires a non-root user");
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().canonicalize().unwrap();
        let tools = home.join("tools");
        let work = home.join("work");
        let locked = work.join("locked");
        std::fs::create_dir(&tools).unwrap();
        std::fs::create_dir_all(&locked).unwrap();
        let command = tools.join("reader");
        program(&command);
        std::fs::hard_link(&command, home.join("outside")).unwrap();
        let commands = ConfiguredCommands::load(&record(&command)).unwrap();
        let expected = vec![commands.get("reader").unwrap().identity];
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = std::fs::read_dir(&locked).is_err();
        let identities = commands.mutable_aliases(&work);
        let validation = commands.validate_reach("[agent]", &reach(&home, &work));
        let mutation = commands.mutation_refusal(&work);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        if !unreadable {
            eprintln!("skipping: mode-000 directories remain readable for this test user");
            return;
        }
        assert_eq!(
            identities, expected,
            "the name outside the folder requires a scan"
        );
        let error = validation
            .expect_err("an incomplete scan must refuse startup")
            .to_string();
        assert!(error.contains("cannot be inspected"), "{error}");
        assert!(
            matches!(mutation, Some(CommandMutationRefusal::IncompleteScan(_))),
            "a directory mutation also requires a complete scan"
        );
        let alias = work.join("alias");
        std::fs::hard_link(&command, &alias).unwrap();
        assert!(
            commands.mutation_refusal(&alias).is_some(),
            "a direct hard-link file remains protected"
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn linked_commands_refuse_metadata_and_link_count_changes_before_launch() {
        let directory = tempfile::tempdir().expect("directory");
        let command = directory.path().join("reader");
        let alias = directory.path().join("alias");
        program(&command);
        std::fs::hard_link(&command, &alias).unwrap();
        let commands = ConfiguredCommands::load(&record(&command)).unwrap();
        let loaded = commands.get("reader").unwrap();
        loaded.verify().unwrap();
        std::fs::set_permissions(&alias, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert!(loaded.verify().is_err(), "changed mode must refuse");
        std::fs::set_permissions(&alias, std::fs::Permissions::from_mode(0o755)).unwrap();
        loaded.verify().unwrap();
        std::fs::hard_link(&alias, directory.path().join("third")).unwrap();
        assert!(loaded.verify().is_err(), "changed link count must refuse");
    }

    /// A root-owned regular file in a system folder with several names and no group or other write.
    fn system_command_with_several_names() -> Option<PathBuf> {
        use std::os::unix::fs::MetadataExt as _;
        // SAFETY: `geteuid` reads the calling process's effective user id and cannot fail.
        let user = unsafe { libc::geteuid() };
        if user == 0 {
            return None;
        }
        ["/usr/bin", "/bin"]
            .into_iter()
            .filter_map(|folder| std::fs::read_dir(folder).ok())
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                std::fs::symlink_metadata(path).is_ok_and(|metadata| {
                    metadata.is_file()
                        && metadata.nlink() > 1
                        && metadata.uid() == 0
                        && metadata.mode() & 0o022 == 0
                        && metadata.mode() & 0o111 != 0
                })
            })
    }

    /// Report a test that found no [`system_command_with_several_names`]. macOS always has one.
    fn skipping_without_a_system_command() {
        if cfg!(target_os = "macos") {
            panic!(
                "macOS always has a root-owned program with several names, such as /usr/bin/git, \
                 so a skip there hides a regression"
            );
        }
        eprintln!(
            "skipping: no root-owned program with several names in /usr/bin or /bin, or the test \
             runs as root"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn apples_git_loads_as_a_configured_command() {
        use std::os::unix::fs::MetadataExt as _;
        let git = Path::new("/usr/bin/git");
        let metadata = std::fs::symlink_metadata(git).expect("macOS ships /usr/bin/git");
        assert!(
            metadata.is_file()
                && metadata.nlink() > 1
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0,
            "/usr/bin/git is not a root-owned file with several names, so this test checks \
             nothing: {metadata:?}"
        );
        let opened = open_without_following(git).expect("opened");
        assert!(
            !may_carry_access_list(&opened),
            "/usr/bin/git carries an access-control list"
        );
        let commands = ConfiguredCommands::load(&record(git))
            .unwrap_or_else(|error| panic!("/usr/bin/git: {error}"));
        commands
            .get("reader")
            .unwrap()
            .verify()
            .unwrap_or_else(|error| panic!("/usr/bin/git: {error}"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_file_with_an_access_control_list_may_be_written() {
        let directory = tempfile::tempdir().expect("directory");
        let listed = directory.path().join("listed");
        program(&listed);
        let opened = open_without_following(&listed).expect("opened");
        assert!(
            !may_carry_access_list(&opened),
            "a new file carries no list"
        );
        let status = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone deny write"])
            .arg(&listed)
            .status()
            .expect("chmod");
        assert!(status.success(), "chmod +a: {status}");
        assert!(
            may_carry_access_list(&opened),
            "a file with an entry carries a list"
        );
    }

    #[test]
    fn a_root_owned_command_with_several_names_loads_and_launches() {
        let Some(command) = system_command_with_several_names() else {
            skipping_without_a_system_command();
            return;
        };
        let commands = ConfiguredCommands::load(&record(&command))
            .unwrap_or_else(|error| panic!("{}: {error}", command.display()));
        commands
            .get("reader")
            .unwrap()
            .verify()
            .unwrap_or_else(|error| panic!("{}: {error}", command.display()));
    }

    #[test]
    fn this_user_can_write_a_file_it_owns_even_without_a_write_bit() {
        let directory = tempfile::tempdir().expect("directory");
        let owned = directory.path().join("owned");
        program(&owned);
        std::fs::set_permissions(&owned, std::fs::Permissions::from_mode(0o555)).expect("mode");
        let opened = open_without_following(&owned).expect("opened");
        let state = FileState::of(&opened.metadata().expect("metadata"));
        assert!(
            writable_by_this_user(&opened, &owned, state),
            "an owner can change its own mode"
        );
        let Some(system) = system_command_with_several_names() else {
            skipping_without_a_system_command();
            return;
        };
        let opened = open_without_following(&system).expect("opened system command");
        let state = FileState::of(&opened.metadata().expect("system metadata"));
        assert!(
            !writable_by_this_user(&opened, &system, state),
            "{}",
            system.display()
        );
    }

    #[test]
    fn only_a_permission_refusal_shows_that_no_name_can_change_a_file() {
        let foreign = FileState {
            links: 2,
            owner: 4242,
            group: 4242,
            mode: 0o100_755,
        };
        let users = [501, 501];
        let refused = |code: i32| move || Err(std::io::Error::from_raw_os_error(code));
        let no_list = || false;
        assert!(!may_change(foreign, users, refused(libc::EACCES), no_list));
        assert!(
            may_change(foreign, users, || Ok(()), no_list),
            "an allowed write"
        );
        for code in [libc::ENOENT, libc::ENOSYS, libc::EINVAL] {
            assert!(
                may_change(foreign, users, refused(code), no_list),
                "errno {code}"
            );
        }
        assert!(
            may_change(
                foreign,
                users,
                || Err(std::io::ErrorKind::InvalidInput.into()),
                no_list
            ),
            "an answer with no errno"
        );
        assert_eq!(
            may_change(foreign, users, refused(libc::EPERM), no_list),
            !cfg!(target_os = "macos"),
            "EPERM is a refusal only where System Integrity Protection answers it"
        );
        assert_eq!(
            may_change(foreign, users, refused(libc::EROFS), no_list),
            !cfg!(target_os = "macos"),
            "macOS answers EROFS before it checks permissions, so the owner, mode, and list decide"
        );
        for code in [libc::EPERM, libc::EROFS] {
            assert!(
                may_change(foreign, users, refused(code), || true),
                "errno {code}: an access-control list can grant a write that the mode does not"
            );
        }
        for (state, users, why) in [
            (
                FileState {
                    owner: 501,
                    ..foreign
                },
                users,
                "the owner",
            ),
            (foreign, [501, 4242], "the effective user owns it"),
            (foreign, [4242, 501], "the real user owns it"),
            (foreign, [0, 0], "root"),
            (
                FileState {
                    mode: 0o100_775,
                    ..foreign
                },
                users,
                "group write",
            ),
            (
                FileState {
                    mode: 0o100_757,
                    ..foreign
                },
                users,
                "other write",
            ),
        ] {
            assert!(
                may_change(state, users, refused(libc::EACCES), no_list),
                "{why}"
            );
            assert!(
                may_change(state, users, refused(libc::EROFS), no_list),
                "{why} on a read-only mount"
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_path_the_kernel_cannot_take_counts_as_writable() {
        let directory = tempfile::tempdir().expect("directory");
        let command = directory.path().join("reader");
        program(&command);
        let opened = open_without_following(&command).expect("opened");
        let foreign = FileState {
            links: 2,
            owner: 4242,
            group: 4242,
            mode: 0o100_755,
        };
        assert!(writable_by_this_user(
            &opened,
            Path::new("reader\0alias"),
            foreign
        ));
    }

    #[test]
    fn a_command_with_several_names_refuses_launch_when_its_names_owner_or_mode_change() {
        let Some(system) = system_command_with_several_names() else {
            skipping_without_a_system_command();
            return;
        };
        use std::os::unix::fs::MetadataExt as _;
        let loaded_as = |path: &Path, loaded: Option<FileState>| {
            let opened = open_without_following(path).expect("opened");
            let metadata = opened.metadata().expect("metadata");
            ConfiguredCommand {
                table: "[tool.reader]".to_string(),
                path: path.to_path_buf(),
                invoked: path.to_path_buf(),
                routes: vec![path.to_path_buf()],
                links: Vec::new(),
                identity: (metadata.dev(), metadata.ino()),
                loaded: loaded.unwrap_or_else(|| FileState::of(&metadata)),
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                needs_alias_scan: false,
                opened,
            }
        };
        loaded_as(&system, None)
            .verify()
            .expect("an unchanged system command launches");
        let now = FileState::of(&std::fs::metadata(&system).expect("metadata"));
        for (loaded, why) in [
            (
                FileState {
                    links: now.links + 1,
                    ..now
                },
                "a removed name",
            ),
            (
                FileState {
                    links: now.links - 1,
                    ..now
                },
                "an added name",
            ),
            (
                FileState {
                    mode: now.mode ^ 0o004,
                    ..now
                },
                "a changed mode",
            ),
            (
                FileState {
                    owner: now.owner + 1,
                    ..now
                },
                "a changed owner",
            ),
            (
                FileState {
                    group: now.group + 1,
                    ..now
                },
                "a changed group",
            ),
        ] {
            let error = loaded_as(&system, Some(loaded))
                .verify()
                .expect_err(why)
                .to_string();
            assert!(
                error.contains("changed after this run loaded it"),
                "{why}: {error}"
            );
        }

        let directory = tempfile::tempdir().expect("directory");
        let owned = directory.path().join("reader");
        program(&owned);
        std::fs::hard_link(&owned, directory.path().join("alias")).expect("hard link");
        let error = loaded_as(&owned, None)
            .verify()
            .expect_err("a file this user can write")
            .to_string();
        assert!(
            error.contains("changed after this run loaded it"),
            "{error}"
        );
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
                matches!(
                    commands.mutation_refusal(mutation),
                    Some(CommandMutationRefusal::CommandOrAncestor)
                ),
                "{}",
                mutation.display()
            );
        }
        assert!(
            commands
                .mutation_refusal(&tools.join("unrelated-output"))
                .is_none()
        );
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

    fn tool(command: &Path, program: Option<&str>) -> ProcessSpec {
        ProcessSpec {
            file_watching: false,
            native_filesystem_policy: None,
            command: vec![command.display().to_string()],
            workspace: None,
            env: Default::default(),
            filesystem: Default::default(),
            network: None,
            grammar: program.map(|program| {
                toml::Value::Table(toml::Table::from_iter([(
                    "program".to_string(),
                    toml::Value::String(program.to_string()),
                )]))
                .try_into()
                .expect("a grammar table")
            }),
            ingress: Vec::new(),
        }
    }

    fn bare_names(tools: &[(&str, ProcessSpec)], at: &Path) -> BareNames {
        let mut record = record(at);
        record.tool = tools
            .iter()
            .map(|(label, spec)| ((*label).to_string(), spec.clone()))
            .collect();
        ConfiguredCommands::load(&record)
            .expect("the commands load")
            .bare_names(&record, std::ffi::OsStr::new(""))
    }

    /// **With `monty = false` a tool declared as `python3` or `python` answers the bare name**, the
    /// way any tool answers to its command's file name. While Monty is on, the Shell keeps both
    /// names and neither tool answers.
    #[test]
    fn with_monty_off_a_python_tool_answers_its_bare_name() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        std::fs::create_dir_all(root.join("venv/bin")).expect("folder");
        let python3 = root.join("venv/bin/python3");
        let python = root.join("venv/bin/python");
        program(&python3);
        program(&python);
        for monty in [true, false] {
            let mut record = record(&python3);
            record.monty = monty;
            record.tool = BTreeMap::from([
                ("python3".to_string(), tool(&python3, None)),
                ("python".to_string(), tool(&python, None)),
            ]);
            let names = ConfiguredCommands::load(&record)
                .expect("the commands load")
                .bare_names(&record, std::ffi::OsStr::new(""));
            let answered: Vec<&str> = names.declared.keys().map(String::as_str).collect();
            if monty {
                assert!(answered.is_empty(), "Monty keeps both names: {answered:?}");
            } else {
                assert_eq!(answered, ["python", "python3"]);
                assert_eq!(names.declared["python3"].0, python3);
                assert_eq!(names.declared["python"].0, python);
            }
        }
    }

    /// **A tool answers to its command's file name, not its label**, and several tables that run
    /// one file under one name share that name.
    #[test]
    fn a_tool_answers_to_its_commands_file_name() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        std::fs::create_dir_all(root.join("developer/usr/bin")).expect("folder");
        let git = root.join("developer/usr/bin/git");
        program(&git);

        let names = bare_names(
            &[
                ("brew_git", tool(&git, None)),
                ("git_status", tool(&git, None)),
            ],
            &git,
        );

        assert_eq!(
            names.declared,
            BTreeMap::from([(
                "git".to_string(),
                (
                    git.clone(),
                    vec![
                        "[tool.brew_git]".to_string(),
                        "[tool.git_status]".to_string()
                    ]
                )
            )])
        );
        assert!(names.shared.is_empty());
        assert_eq!(
            *names.programs(),
            BTreeMap::from([("git".to_string(), git)])
        );
    }

    /// **A name that two different program files answer to, with no table labelled that name, is
    /// declared by neither**, so the Shell finds it on `PATH` as before.
    #[test]
    fn a_name_two_files_answer_to_is_left_to_path() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        for folder in ["system", "brew"] {
            std::fs::create_dir_all(root.join(folder)).expect("folder");
            program(&root.join(folder).join("git"));
        }

        let names = bare_names(
            &[
                ("system_git", tool(&root.join("system/git"), None)),
                ("brew_git", tool(&root.join("brew/git"), None)),
            ],
            &root.join("system/git"),
        );

        assert!(names.declared.is_empty(), "{:?}", names.declared);
        assert_eq!(
            names.shared,
            BTreeMap::from([(
                "git".to_string(),
                vec![
                    "[tool.brew_git]".to_string(),
                    "[tool.system_git]".to_string()
                ]
            )])
        );
    }

    /// **Hard links at two paths keep the table that `PATH` selects**, because a spawn selects its
    /// tool by the resolved path, not by the file the two paths share. The label settles the name
    /// only when `PATH` finds neither path.
    #[test]
    fn hard_links_at_two_paths_keep_the_table_that_path_selects() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        for folder in ["developer", "project", "stub"] {
            std::fs::create_dir_all(root.join(folder)).expect("folder");
        }
        program(&root.join("developer/git"));
        program(&root.join("stub/git"));
        std::fs::hard_link(root.join("developer/git"), root.join("project/git"))
            .expect("a hard link");
        let mut record = record(&root.join("developer/git"));
        record.tool = BTreeMap::from([
            ("git".to_string(), tool(&root.join("developer/git"), None)),
            (
                "project_git".to_string(),
                tool(&root.join("project/git"), None),
            ),
        ]);
        let commands = ConfiguredCommands::load(&record).expect("the commands load");

        let project_first = commands.bare_names(&record, root.join("project").as_os_str());
        let past_the_stub = commands.bare_names(&record, root.join("stub").as_os_str());

        assert!(
            project_first.declared.is_empty() && project_first.shared.contains_key("git"),
            "{project_first:?}"
        );
        assert_eq!(
            past_the_stub.declared.get("git"),
            Some(&(root.join("developer/git"), vec!["[tool.git]".to_string()])),
            "{past_the_stub:?}"
        );
        assert_eq!(
            past_the_stub.passed_over.get("git"),
            Some(&vec!["[tool.project_git]".to_string()]),
            "{past_the_stub:?}"
        );
    }

    /// **A grammar whose `program` is not its command's file name declares no bare name**, so a
    /// shim that its called name selects keeps the spelling that `PATH` finds.
    #[test]
    fn a_grammar_on_another_program_name_declares_no_bare_name() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        let cli = root.join("npm-cli.js");
        program(&cli);
        let git = root.join("git");
        program(&git);

        let names = bare_names(
            &[
                ("npm", tool(&cli, Some("npm"))),
                ("git", tool(&git, Some("git"))),
            ],
            &cli,
        );

        assert_eq!(
            names.declared.keys().collect::<Vec<_>>(),
            vec!["git"],
            "{:?}",
            names.declared
        );
    }

    /// **Among tools with different command paths under one name, `PATH` decides when it finds one
    /// of them, and otherwise the tool whose label is the name runs.**
    #[test]
    fn the_label_breaks_a_tie_that_path_does_not_settle() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        for folder in ["developer", "brew", "stub"] {
            std::fs::create_dir_all(root.join(folder)).expect("folder");
            program(&root.join(folder).join("git"));
        }
        let mut record = record(&root.join("developer/git"));
        record.tool = BTreeMap::from([
            ("git".to_string(), tool(&root.join("developer/git"), None)),
            ("brew_git".to_string(), tool(&root.join("brew/git"), None)),
        ]);
        let commands = ConfiguredCommands::load(&record).expect("the commands load");

        let past_the_stub = commands.bare_names(&record, root.join("stub").as_os_str());
        let brew_first = commands.bare_names(&record, root.join("brew").as_os_str());

        assert_eq!(
            past_the_stub.declared.get("git"),
            Some(&(root.join("developer/git"), vec!["[tool.git]".to_string()])),
            "{past_the_stub:?}"
        );
        assert_eq!(
            past_the_stub.passed_over.get("git"),
            Some(&vec!["[tool.brew_git]".to_string()]),
            "{past_the_stub:?}"
        );
        assert!(
            brew_first.declared.is_empty() && brew_first.shared.contains_key("git"),
            "{brew_first:?}"
        );
    }

    /// **A grammar's `program` that another tool's different file answers to is left to `PATH`**,
    /// so the startup check that `PATH` reaches the grammar's file still holds for the Shell.
    #[test]
    fn a_grammar_program_another_file_answers_to_is_left_to_path() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        let cli = root.join("npm-cli.js");
        program(&cli);
        std::fs::create_dir_all(root.join("brew")).expect("folder");
        let brew = root.join("brew/npm");
        program(&brew);
        let mut ci = tool(&brew, None);
        ci.command.push("ci".to_string());

        let names = bare_names(&[("npm", tool(&cli, Some("npm"))), ("npm_ci", ci)], &cli);

        assert!(names.declared.is_empty(), "{:?}", names.declared);
        assert_eq!(
            names.shared,
            BTreeMap::from([(
                "npm".to_string(),
                vec!["[tool.npm]".to_string(), "[tool.npm_ci]".to_string()]
            )])
        );
    }

    /// **A name the Shell runs itself is never declared**, because the Shell's own program wins.
    #[test]
    fn a_name_the_shell_implements_is_not_declared() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        let tools: Vec<(&str, ProcessSpec)> = ["python3", "cat", "sh", "echo", "git"]
            .into_iter()
            .map(|name| {
                let path = root.join(name);
                program(&path);
                (name, tool(&path, None))
            })
            .collect();

        let names = bare_names(&tools, &root.join("git"));

        assert_eq!(
            names.declared.keys().collect::<Vec<_>>(),
            vec!["git"],
            "{:?}",
            names.declared
        );
        assert!(names.shared.is_empty(), "{:?}", names.shared);
    }

    /// **A command is declared through the spelling the run starts it by**, so a linked program
    /// keeps its link as `argv[0]`.
    #[test]
    fn a_linked_command_is_declared_through_its_link() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        std::fs::create_dir_all(root.join("cellar")).expect("folder");
        std::fs::create_dir_all(root.join("bin")).expect("folder");
        program(&root.join("cellar/git"));
        std::os::unix::fs::symlink(root.join("cellar/git"), root.join("bin/git")).expect("link");

        let names = bare_names(
            &[("git", tool(&root.join("bin/git"), None))],
            &root.join("bin/git"),
        );

        assert_eq!(
            names.declared.get("git").map(|(path, _)| path.clone()),
            Some(root.join("bin/git"))
        );
    }
}

#[cfg(test)]
mod left_out_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    use crate::record::config::process::ProcessSpec;

    fn spec(command: &[&str], path: Option<&Path>) -> ProcessSpec {
        ProcessSpec {
            file_watching: false,
            native_filesystem_policy: None,
            command: command.iter().map(|part| (*part).to_string()).collect(),
            workspace: None,
            env: path
                .map(|path| BTreeMap::from([("PATH".to_string(), path.display().to_string())]))
                .unwrap_or_default(),
            filesystem: Default::default(),
            network: None,
            grammar: None,
            ingress: Vec::new(),
        }
    }

    fn with_tools(tools: Vec<(&str, ProcessSpec)>) -> Record {
        Record {
            version: crate::record::config::RECORD_VERSION,
            experimental_features: Default::default(),
            file_attributes: false,
            monty: true,
            gateway: Default::default(),
            limits: Default::default(),
            box_id: "left-out-test".to_string(),
            box_dir: PathBuf::from("/var/lib/boxes/left-out"),
            name: "left-out-test".to_string(),
            policy: None,
            agent: None,
            tool: tools
                .into_iter()
                .map(|(label, spec)| (label.to_string(), spec))
                .collect(),
            egress: Default::default(),
            remote_mcp: Default::default(),
            mcp: Default::default(),
            contained_mcp: Default::default(),
            telemetry: Default::default(),
            secret_source: Default::default(),
            containment: Default::default(),
        }
    }

    fn executable(path: &Path, mode: u32) {
        std::fs::write(path, "#!/bin/sh\nexit 0\n").expect("program");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("mode");
    }

    fn tables(left_out: &[LeftOut]) -> Vec<&str> {
        left_out.iter().map(|tool| tool.table.as_str()).collect()
    }

    /// **A tool whose program is not installed is left out of the record**, by a bare name no
    /// search-path entry holds, even when an entry is a file or cannot be searched, by an absolute
    /// path to nothing or beneath a file, and by a link to nothing, and the tools that remain load.
    #[test]
    fn a_tool_whose_program_is_not_installed_is_left_out() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        let bin = root.join("bin");
        std::fs::create_dir(&bin).expect("bin");
        executable(&bin.join("present"), 0o755);
        std::os::unix::fs::symlink(root.join("nowhere"), bin.join("dangling")).expect("link");
        let locked = root.join("locked");
        std::fs::create_dir(&locked).expect("locked");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("mode");
        std::os::unix::fs::symlink("looped", root.join("looped")).expect("a link loop");
        let odd_path = std::env::join_paths([
            bin.clone(),
            bin.join("present"),
            locked.clone(),
            root.join("looped"),
        ])
        .expect("a search path");
        let mut record = with_tools(vec![
            ("present", spec(&["present"], Some(&bin))),
            ("odd_path", spec(&["tsx"], Some(Path::new(&odd_path)))),
            (
                "under_a_file",
                spec(&[&bin.join("present/tsx").display().to_string()], None),
            ),
            ("bare", spec(&["tsx", "--flag"], Some(&bin))),
            (
                "absolute",
                spec(&[&root.join("opt/tsx").display().to_string()], None),
            ),
            (
                "dangling",
                spec(&[&bin.join("dangling").display().to_string()], None),
            ),
            ("dangling_bare", spec(&["dangling"], Some(&bin))),
        ]);

        let left_out = leave_out_absent(&mut record).expect("absent tools are left out");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).expect("mode");

        assert_eq!(
            tables(&left_out),
            [
                "[tool.absolute]",
                "[tool.bare]",
                "[tool.dangling]",
                "[tool.dangling_bare]",
                "[tool.odd_path]",
                "[tool.under_a_file]"
            ]
        );
        assert_eq!(left_out[1].program, "tsx");
        assert_eq!(record.tool.keys().collect::<Vec<_>>(), ["present"]);
        let commands = ConfiguredCommands::load(&record).expect("the remaining tool loads");
        assert!(commands.get("present").is_some());
        assert!(commands.get("bare").is_none());
    }

    /// **Every other check on a tool's file still stops the box**: a file that is not executable,
    /// a directory, and a link loop, by path and by bare name, and a relative path stay in the
    /// record, so the load refuses them.
    #[test]
    fn a_program_that_exists_is_never_left_out() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        let plain = root.join("plain");
        executable(&plain, 0o644);
        let directory = root.join("directory");
        std::fs::create_dir(&directory).expect("directory");
        std::os::unix::fs::symlink("looped", root.join("looped")).expect("a link loop");
        for (label, command, path) in [
            ("plain", plain.display().to_string(), None),
            ("directory", directory.display().to_string(), None),
            ("bare_plain", "plain".to_string(), Some(root.as_path())),
            (
                "bare_directory",
                "directory".to_string(),
                Some(root.as_path()),
            ),
            ("looped", root.join("looped").display().to_string(), None),
            ("bare_looped", "looped".to_string(), Some(root.as_path())),
            ("relative", "bin/tool".to_string(), None),
        ] {
            let mut record = with_tools(vec![(label, spec(&[&command], path))]);

            let left_out = leave_out_absent(&mut record).expect("nothing is refused here");

            assert!(left_out.is_empty(), "{label}: {left_out:?}");
            assert!(record.tool.contains_key(label), "{label}");
            ConfiguredCommands::load(&record).expect_err("the load refuses the file");
        }
    }

    /// **A tool whose program holds a token, or whose argument holds one no run can expand, still
    /// stops the box**, so a typo in a token is reported whether or not the program is installed.
    #[test]
    fn a_left_out_tool_with_an_unexpandable_token_is_refused() {
        let mut record = with_tools(vec![(
            "tsx",
            spec(&["/nonexistent/strands-box/tsx", "${NOT_A_VALUE}"], None),
        )]);

        let refusal = leave_out_absent(&mut record)
            .expect_err("the token is refused")
            .to_string();

        assert!(refusal.contains("[tool.tsx]"), "{refusal}");
        assert!(refusal.contains("NOT_A_VALUE"), "{refusal}");
        for program in ["/nonexistent/${USER}/tsx", "${TSX}"] {
            let mut record = with_tools(vec![("tsx", spec(&[program], None))]);

            let refusal = leave_out_absent(&mut record)
                .expect_err("a program is never expanded")
                .to_string();

            assert!(refusal.contains("[tool.tsx]"), "{refusal}");
            assert!(refusal.contains("a program is never expanded"), "{refusal}");
        }
        let mut record = with_tools(vec![(
            "tsx",
            spec(
                &[
                    "/nonexistent/strands-box/tsx",
                    "${OTEL_EXPORTER_OTLP_ENDPOINT}",
                ],
                None,
            ),
        )]);
        assert_eq!(
            tables(&leave_out_absent(&mut record).expect("a known token passes")),
            ["[tool.tsx]"]
        );
    }
}
