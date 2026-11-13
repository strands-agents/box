//! The configured tool programs whose identities belong to one run.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use containment::{Operation, Scope};

use super::python_install::{self, InstallRoots, PythonInstall};
use crate::error::{BoxError, ConfigError};
use crate::record::config::Record;
use crate::record::config::filesystem::{AddedEntry, DirectReach};
use crate::record::config::process::{Grant, ProcessSpec};
use crate::record::layout::{disk_identity, lies_within, open_without_following};

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod aliases;

#[derive(Debug, Default)]
pub(crate) struct ConfiguredCommands {
    tools: BTreeMap<String, Arc<ConfiguredCommand>>,
    /// The Python tool that answers `python3` and `python`, when `monty = false` declares one.
    python: Option<PythonTool>,
}

/// The `[tool.python3]` or `[tool.python]` table, and the install its command starts.
#[derive(Debug)]
pub(crate) struct PythonTool {
    table: String,
    install: PythonInstall,
    /// The agent's workspace, which the tool reads and writes when its table names no lists.
    workspace: PathBuf,
}

/// The file each bare name runs in the hosted Shell, from the `[tool]` tables that answer to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BareNames {
    /// Each name that one program file answers to: the spelling that runs it, and its tables.
    pub(crate) declared: BTreeMap<String, (PathBuf, Vec<String>)>,
    /// Each name that tables with different program files answer to, and those tables.
    pub(crate) shared: BTreeMap<String, Vec<String>>,
    /// Each declared name that its label settled, and the tables that run other files.
    pub(crate) passed_over: BTreeMap<String, Vec<String>>,
    /// The names the Shell implements itself that run their declared file instead: `python3` and
    /// `python` when Monty is off and `[tool.python3]` or `[tool.python]` is declared.
    pub(crate) replaced: BTreeSet<String>,
    /// Whether a bare `python3` or `python` runs Monty, from the record's `monty` key.
    pub(crate) monty: bool,
    /// The `[tool.python3]` and `[tool.python]` tables a bare `python3` or `python` doesn't use,
    /// because Monty is on.
    pub(crate) unused_python: Vec<String>,
    /// The names the Shell refuses with exit status 126, and why: `python3` and `python` when
    /// Monty is off and no Python table is declared.
    pub(crate) refused: BTreeMap<String, String>,
}

impl Default for BareNames {
    fn default() -> Self {
        Self {
            declared: BTreeMap::new(),
            shared: BTreeMap::new(),
            passed_over: BTreeMap::new(),
            replaced: BTreeSet::new(),
            monty: true,
            unused_python: Vec::new(),
            refused: BTreeMap::new(),
        }
    }
}

/// Why `python3` and `python` exit 126 when Monty is off and no Python table is declared.
pub(crate) const MONTY_OFF_WITHOUT_PYTHON: &str =
    "Monty is off (monty = false) and no [tool.python3] or [tool.python] is declared";

impl BareNames {
    /// The Shell commands that run their declared file instead, as the Shell will read them.
    pub(crate) fn replaced_commands(&self) -> Arc<BTreeSet<String>> {
        Arc::new(self.replaced.clone())
    }

    /// The names the Shell refuses with exit status 126, and the reason it prints.
    pub(crate) fn refused_commands(&self) -> Arc<BTreeMap<String, String>> {
        Arc::new(self.refused.clone())
    }

    /// The tables that a bare `python3` and `python` run in place of Monty, if any.
    pub(crate) fn python_tables(&self) -> Option<&[String]> {
        self.replaced
            .contains("python3")
            .then(|| self.declared.get("python3"))
            .flatten()
            .map(|(_, tables)| tables.as_slice())
    }

    /// The declared file of each name, as the Shell reads it.
    pub(crate) fn programs(&self) -> strands_shell::os::HostPrograms {
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
    /// The path is at, inside or above a folder the Python tool `table` loads code from.
    PythonInstall {
        table: String,
    },
}

#[derive(Debug)]
pub(crate) struct ConfiguredCommand {
    table: String,
    path: PathBuf,
    invoked: PathBuf,
    routes: Vec<PathBuf>,
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
    /// [`Self::load_in`], against the workspace `record` names, else the current directory.
    #[cfg(test)]
    pub(crate) fn load(record: &Record) -> Result<Self, BoxError> {
        Self::load_with(record, &InstallRoots::host())
    }

    /// [`Self::load`], against the agent's effective workspace rather than the one `record` names.
    pub(crate) fn load_in(record: &Record, workspace: &Path) -> Result<Self, BoxError> {
        Self::load_in_with(record, &InstallRoots::host(), workspace)
    }

    /// [`Self::load`], with the folders a Python install is looked up under given.
    #[cfg(test)]
    pub(crate) fn load_with(record: &Record, roots: &InstallRoots) -> Result<Self, BoxError> {
        let workspace = match record
            .agent
            .as_ref()
            .and_then(|agent| agent.workspace.clone())
        {
            Some(workspace) => workspace,
            None => std::env::current_dir().map_err(|source| ConfigError::Contract {
                reason: format!("cannot read the current directory: {source}"),
            })?,
        };
        Self::load_in_with(record, roots, &workspace)
    }

    /// [`Self::load_in`], with the folders a Python install is looked up under given.
    pub(crate) fn load_in_with(
        record: &Record,
        roots: &InstallRoots,
        workspace: &Path,
    ) -> Result<Self, BoxError> {
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
                if !metadata.is_file() {
                    return Err(refusal(&table, &path, "must be a regular file"));
                }
                let loaded = FileState::of(&metadata);
                let writable_links =
                    loaded.links > 1 && writable_by_this_user(&opened, &path, loaded);
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
                    loaded,
                    #[cfg(any(target_os = "macos", target_os = "linux"))]
                    needs_alias_scan: writable_links,
                };
                command.verify()?;
                Ok((label.clone(), Arc::new(command)))
            })
            .collect::<Result<_, BoxError>>()?;
        let mut commands = Self {
            tools,
            python: None,
        };
        commands.python = commands.python_tool(record, roots, workspace)?;
        Ok(commands)
    }

    /// With `monty = false`, the Python table's install. An install Box doesn't recognize, or an
    /// editable install whose source is inside the agent's workspace, refuses startup.
    fn python_tool(
        &self,
        record: &Record,
        roots: &InstallRoots,
        workspace: &Path,
    ) -> Result<Option<PythonTool>, BoxError> {
        use crate::record::config::PYTHON_TABLES;
        if record.monty {
            return Ok(None);
        }
        let Some((label, command)) = PYTHON_TABLES
            .iter()
            .find_map(|label| self.tools.get(*label).map(|command| (*label, command)))
        else {
            return Ok(None);
        };
        let table = format!("[tool.{label}]");
        // The spelling that runs it: a venv's `bin/python3` keeps the `pyvenv.cfg` beside it.
        let install = python_install::detect(command.invoked(), roots).map_err(|error| {
            ConfigError::Process {
                table: table.clone(),
                reason: error.to_string(),
            }
        })?;
        if let Some(source) = install
            .editable_sources
            .iter()
            .find(|source| touches(source, workspace))
        {
            return Err(ConfigError::Process {
                table,
                reason: format!(
                    "an editable install's source or a folder a .pth file names, {}, is inside \
                     the agent's workspace {}, so the agent could change code the Python install \
                     loads. Install that package without -e, or move its source outside the \
                     workspace",
                    source.display(),
                    workspace.display()
                ),
            }
            .into());
        }
        Ok(Some(PythonTool {
            table,
            install,
            workspace: workspace.to_path_buf(),
        }))
    }

    /// The Python tool that answers `python3` and `python`, when `monty = false` declares one.
    pub(crate) fn python(&self) -> Option<&PythonTool> {
        self.python.as_ref()
    }

    /// The folders the Python tool loads code from, its venv root, and its editable sources.
    /// Empty when Monty answers `python3`.
    pub(crate) fn python_protected(&self) -> Vec<PathBuf> {
        self.python
            .iter()
            .flat_map(|python| python.protected())
            .cloned()
            .collect()
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
            if strands_shell::exec::implements_program(name) {
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
        self.python_names(record, &mut names);
        names
    }

    /// What a bare `python3` and `python` mean. With Monty on, both run Monty, and any Python
    /// table is listed as unused. With Monty off, `[tool.python3]` or `[tool.python]` answers to
    /// both names whatever its command's file is called, and with neither table both are refused.
    /// A versioned name such as `python3.14` is left to the loop above, as before.
    fn python_names(&self, record: &Record, names: &mut BareNames) {
        use crate::record::config::PYTHON_TABLES;
        names.monty = record.monty;
        let tables: Vec<(String, &ConfiguredCommand)> = PYTHON_TABLES
            .iter()
            .filter(|label| record.tool.contains_key(**label))
            .filter_map(|label| {
                self.tools
                    .get(*label)
                    .map(|command| (format!("[tool.{label}]"), command.as_ref()))
            })
            .collect();
        if record.monty {
            names.unused_python = tables.into_iter().map(|(table, _)| table).collect();
            return;
        }
        let Some((_, command)) = tables.first() else {
            for name in PYTHON_TABLES {
                names
                    .refused
                    .insert(name.to_string(), MONTY_OFF_WITHOUT_PYTHON.to_string());
            }
            return;
        };
        let labels: Vec<String> = tables.iter().map(|(table, _)| table.clone()).collect();
        for name in PYTHON_TABLES {
            names
                .declared
                .insert(name.to_string(), (command.invoked.clone(), labels.clone()));
            names.replaced.insert(name.to_string());
        }
        // A replaced name with no file would run the Shell's own command, Monty, so it is refused.
        let unfiled: Vec<String> = names
            .replaced
            .iter()
            .filter(|name| !names.declared.contains_key(*name))
            .cloned()
            .collect();
        for name in unfiled {
            names.replaced.remove(&name);
            names.refused.insert(
                name,
                "Monty is off (monty = false) and no Python tool file answers to this name"
                    .to_string(),
            );
        }
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
        if self.tools.values().any(|command| command.enclosed_by(path)) {
            return Some(CommandMutationRefusal::CommandOrAncestor);
        }
        if let Some(python) = &self.python
            && python.protected().any(|folder| touches(path, folder))
        {
            return Some(CommandMutationRefusal::PythonInstall {
                table: python.table.clone(),
            });
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
            if let Some(python) = &self.python {
                python.validate_write(table, grant)?;
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
        self.tools
            .values()
            .filter(|command| {
                command.needs_alias_scan && (!directory || !command.every_name_beside(target))
            })
            .map(|command| command.identity)
            .collect()
    }
}

impl ConfiguredCommand {
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
    }
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

impl PythonTool {
    /// The table this tool came from, as a refusal names it.
    pub(crate) fn table(&self) -> &str {
        &self.table
    }

    /// `spec` with the grants Python needs to start added, and those entries.
    ///
    /// Box adds read on the folders the install loads code from, read on the venv's `pyvenv.cfg`,
    /// and read on the certificate bundle. A link can't be granted, so a linked bundle gets read on
    /// the folder that holds the link. With no lists in the table, Box adds read and write on the
    /// agent's workspace; an operator's own lists replace only that. An entry already covered by
    /// another is left out, and an operator's read entry inside an added folder is dropped, so no
    /// path is granted twice.
    pub(crate) fn augmented(&self, spec: &ProcessSpec) -> (ProcessSpec, Vec<AddedEntry>) {
        let mut spec = spec.clone();
        let mut wanted: Vec<(Grant, PathBuf, &'static str)> = Vec::new();
        if spec.filesystem.is_empty() {
            wanted.push((Grant::Read, self.workspace.clone(), "workspace"));
            wanted.push((Grant::Write, self.workspace.clone(), "workspace"));
        }
        for folder in python_install::outermost(&self.install.code_folders) {
            wanted.push((Grant::Read, folder, "install"));
        }
        if matches!(self.install.kind, python_install::InstallKind::Venv { .. }) {
            let marker = self.install.prefix.join("pyvenv.cfg");
            if marker.is_file() {
                wanted.push((Grant::ReadFile, canonical(&marker), "install"));
            }
        }
        for certificate in self
            .install
            .cert_bundle
            .iter()
            .chain(&self.install.cert_link_chain)
        {
            let linked = std::fs::symlink_metadata(certificate)
                .map(|metadata| metadata.is_symlink())
                .unwrap_or(false);
            match certificate.parent() {
                Some(folder) if linked => {
                    wanted.push((Grant::Read, canonical(folder), "certificates"));
                }
                _ if certificate.is_file() => {
                    wanted.push((Grant::ReadFile, canonical(certificate), "certificates"));
                }
                _ => {}
            }
        }
        let mut added: Vec<AddedEntry> = Vec::new();
        for (kind, path, reason) in wanted {
            let operation_of = |kind: Grant| match kind {
                Grant::Read | Grant::ReadFile => Some(Grant::Read),
                Grant::Write | Grant::WriteFile => Some(Grant::Write),
                _ => None,
            };
            let same = |other: Grant| operation_of(other) == operation_of(kind);
            let tree = |other: Grant| matches!(other, Grant::Read | Grant::Write);
            let operator_covers = spec.filesystem.entries().any(|(other, entry)| {
                same(other) && (entry == path || tree(other) && lies_within(&path, entry))
            });
            let added_covers = added.iter().any(|entry| {
                same(entry.kind)
                    && (entry.path == path || tree(entry.kind) && lies_within(&path, &entry.path))
            });
            if operator_covers || added_covers {
                continue;
            }
            if tree(kind) {
                // A narrower entry inside this folder would grant one path twice.
                added.retain(|entry| !(same(entry.kind) && lies_within(&entry.path, &path)));
                for list in [&mut spec.filesystem.read, &mut spec.filesystem.read_file] {
                    if operation_of(kind) == Some(Grant::Read) {
                        list.retain(|entry| !lies_within(entry, &path));
                    }
                }
            }
            added.push(AddedEntry { kind, path, reason });
        }
        for entry in &added {
            let list = match entry.kind {
                Grant::Read => &mut spec.filesystem.read,
                Grant::Write => &mut spec.filesystem.write,
                Grant::ReadFile => &mut spec.filesystem.read_file,
                _ => continue,
            };
            list.push(entry.path.clone());
        }
        for library in self.libraries(&spec) {
            spec.filesystem.read_file.push(library.clone());
            added.push(AddedEntry {
                kind: Grant::ReadFile,
                path: library,
                reason: "libraries",
            });
        }
        (spec, added)
    }

    /// The libraries the install's extension modules load that no read in `spec` reaches.
    ///
    /// Box walks every `.so` (and `.dylib` on macOS) under the install's code folders, up to
    /// [`MAXIMUM_PYTHON_IMAGES`], the way containment walks an exec file's dependencies. A
    /// dependency reached through a folder `spec` lets the tool write is not derived.
    fn libraries(&self, spec: &ProcessSpec) -> Vec<PathBuf> {
        let images = extension_images(&self.install.code_folders, MAXIMUM_PYTHON_IMAGES);
        if images.is_empty() {
            return Vec::new();
        }
        let mut config = containment::ContainmentConfig::new();
        for (list, scope) in [
            (&spec.filesystem.write, Scope::Root),
            (&spec.filesystem.write_file, Scope::File),
        ] {
            for path in list {
                if let Ok(next) = config.clone().allow(path, Operation::Write, scope) {
                    config = next;
                }
            }
        }
        containment::loaded_libraries(&images, &config)
            .into_iter()
            .filter(|library| {
                !SYSTEM_LIBRARY_FOLDERS
                    .iter()
                    .any(|folder| library.starts_with(folder))
            })
            .filter(|library| {
                let resolved = canonical(library);
                !spec.filesystem.read.iter().any(|folder| {
                    lies_within(library, folder) || lies_within(&resolved, &canonical(folder))
                }) && !spec
                    .filesystem
                    .read_file
                    .iter()
                    .any(|file| file == library || canonical(file) == resolved)
            })
            .collect()
    }

    /// The folders Python loads code from or would if they existed, its venv root, the base's
    /// `lib/`, the folders install links point into, and its editable and `.pth` sources.
    fn protected(&self) -> impl Iterator<Item = &PathBuf> {
        self.install
            .protected
            .iter()
            .chain(&self.install.editable_sources)
    }

    /// Refuse a write grant that reaches the install or an editable source, in either direction.
    fn validate_write(
        &self,
        table: &str,
        grant: &crate::record::config::filesystem::DirectGrant,
    ) -> Result<(), BoxError> {
        let reached = |folder: &Path| match grant.scope {
            Scope::Root | Scope::Dir => touches(&grant.resolved, folder),
            Scope::File => lies_within(&grant.resolved, folder),
        };
        let reason = if let Some(folder) = self.install.protected.iter().find(|f| reached(f)) {
            format!(
                "this write grant reaches {}, which {} loads Python code from. Keep the Python \
                 install outside every write grant",
                folder.display(),
                self.table
            )
        } else if let Some(source) = self.install.editable_sources.iter().find(|s| reached(s)) {
            format!(
                "this write grant reaches {}, the source of an editable install or a folder a \
                 .pth file names, which {} loads Python code from. Keep the Python install \
                 outside every write grant",
                source.display(),
                self.table
            )
        } else {
            return Ok(());
        };
        Err(ConfigError::Filesystem {
            table: table.to_string(),
            entry: grant.authored.clone(),
            reason,
        }
        .into())
    }
}

/// The most extension images Box walks for one Python install.
const MAXIMUM_PYTHON_IMAGES: usize = 5000;

/// Folders whose libraries the system's own grants already reach.
const SYSTEM_LIBRARY_FOLDERS: &[&str] = &[
    "/usr/lib",
    "/lib",
    "/lib64",
    "/usr/lib64",
    "/System",
    "/Library/Apple",
];

/// Every `.so` (and `.dylib` on macOS) file under `folders`, at most `cap`, deduplicated.
fn extension_images(folders: &[PathBuf], cap: usize) -> Vec<PathBuf> {
    let mut images = std::collections::BTreeSet::new();
    let mut pending: Vec<PathBuf> = python_install::outermost(folders);
    let mut visited = std::collections::BTreeSet::new();
    while let Some(folder) = pending.pop() {
        if images.len() >= cap || !visited.insert(folder.clone()) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file()
                && path.extension().is_some_and(|extension| {
                    extension == "so" || cfg!(target_os = "macos") && extension == "dylib"
                })
                && images.len() < cap
            {
                images.insert(path);
            }
        }
    }
    images.into_iter().collect()
}

/// `path` with every link resolved, or as given when it can't be.
fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// Whether `path` is `folder`, inside it, or above it.
fn touches(path: &Path, folder: &Path) -> bool {
    lies_within(path, folder) || lies_within(folder, path)
}

/// Whether a failed call's stderr shows a write the read-only Python install refused: a non-zero
/// `status`, a protected folder (or a path inside one) named in `stderr`, and a permission error.
pub(crate) fn read_only_install_hint(status: i32, stderr: &[u8], protected: &[PathBuf]) -> bool {
    const REFUSALS: [&str; 3] = [
        "Permission denied",
        "Operation not permitted",
        "Read-only file system",
    ];
    if status == 0 {
        return false;
    }
    let text = String::from_utf8_lossy(stderr);
    REFUSALS.iter().any(|refusal| text.contains(refusal))
        && protected.iter().any(|folder| {
            let folder = folder.to_string_lossy();
            let folder = folder.trim_end_matches('/');
            !folder.is_empty()
                && text.match_indices(folder).any(|(start, _)| {
                    // Only the folder itself or a path inside it: `site-packages2` is another folder.
                    text[start + folder.len()..]
                        .chars()
                        .next()
                        .is_none_or(|next| !next.is_alphanumeric() && !"._-@+".contains(next))
                })
        })
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
        bare_names_with(true, tools, at)
    }

    fn bare_names_with(monty: bool, tools: &[(&str, ProcessSpec)], at: &Path) -> BareNames {
        let mut record = record(at);
        record.monty = monty;
        record.tool = tools
            .iter()
            .map(|(label, spec)| ((*label).to_string(), spec.clone()))
            .collect();
        // Names only: these fake programs are no Python install, so load them with Monty on.
        let loaded = Record {
            monty: true,
            ..record.clone()
        };
        ConfiguredCommands::load(&loaded)
            .expect("the commands load")
            .bare_names(&record, std::ffi::OsStr::new(""))
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

    /// The `[tool.python3]` and `[tool.python]` labels, each paired with the file it runs.
    fn python_tools(
        root: &Path,
        tools: &[(&'static str, &str)],
    ) -> Vec<(&'static str, ProcessSpec)> {
        tools
            .iter()
            .map(|(label, file)| {
                let path = root.join(file);
                std::fs::create_dir_all(path.parent().expect("a parent")).expect("folder");
                program(&path);
                (*label, tool(&path, None))
            })
            .collect()
    }

    fn both_python_names() -> BTreeSet<String> {
        ["python".to_string(), "python3".to_string()].into()
    }

    /// **With Monty off, `[tool.python3]` answers to both `python3` and `python`.**
    #[test]
    fn with_monty_off_python3_and_python_answer_to_tool_python3() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        let tools = python_tools(&root, &[("python3", "venv/bin/python3")]);
        let python = root.join("venv/bin/python3");

        let names = bare_names_with(false, &tools, &python);

        let expected = (python, vec!["[tool.python3]".to_string()]);
        assert_eq!(names.declared.get("python3"), Some(&expected));
        assert_eq!(names.declared.get("python"), Some(&expected));
        assert_eq!(names.replaced, both_python_names());
        assert!(!names.monty);
        assert!(names.refused.is_empty(), "{:?}", names.refused);
        assert!(names.unused_python.is_empty(), "{:?}", names.unused_python);
        assert_eq!(*names.replaced_commands(), both_python_names());
        assert!(names.refused_commands().is_empty());
        assert_eq!(
            names.python_tables(),
            Some(&["[tool.python3]".to_string()][..])
        );
    }

    /// **The table's name decides, not its command's file name**: `[tool.python]` whose file is
    /// `native-python` answers to both Python names, and to its own file name as before.
    #[test]
    fn with_monty_off_tool_python_answers_to_both_names_whatever_its_file_is_called() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        let tools = python_tools(&root, &[("python", "venv/bin/native-python")]);
        let python = root.join("venv/bin/native-python");

        let names = bare_names_with(false, &tools, &python);

        let expected = (python, vec!["[tool.python]".to_string()]);
        assert_eq!(names.declared.get("python3"), Some(&expected));
        assert_eq!(names.declared.get("python"), Some(&expected));
        assert_eq!(names.declared.get("native-python"), Some(&expected));
        assert_eq!(names.replaced, both_python_names());
    }

    /// **Two Python tables with one command list both tables** on each name.
    #[test]
    fn with_monty_off_two_python_tables_with_one_command_share_both_names() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        let python = root.join("venv/bin/python3");
        std::fs::create_dir_all(root.join("venv/bin")).expect("folder");
        program(&python);
        let tools = [
            ("python", tool(&python, None)),
            ("python3", tool(&python, None)),
        ];

        let names = bare_names_with(false, &tools, &python);

        let tables = vec!["[tool.python3]".to_string(), "[tool.python]".to_string()];
        assert_eq!(
            names.declared.get("python3"),
            Some(&(python.clone(), tables.clone()))
        );
        assert_eq!(names.declared.get("python"), Some(&(python, tables)));
        assert_eq!(names.replaced, both_python_names());
    }

    /// **With Monty off and no Python table, both names are refused**, and nothing falls back to
    /// Monty.
    #[test]
    fn with_monty_off_and_no_python_table_both_names_are_refused() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        let tools = python_tools(&root, &[("git", "git")]);

        let names = bare_names_with(false, &tools, &root.join("git"));

        assert_eq!(names.declared.keys().collect::<Vec<_>>(), vec!["git"]);
        assert!(names.replaced.is_empty(), "{:?}", names.replaced);
        let reason = MONTY_OFF_WITHOUT_PYTHON.to_string();
        let expected = BTreeMap::from([
            ("python".to_string(), reason.clone()),
            ("python3".to_string(), reason),
        ]);
        assert_eq!(names.refused, expected);
        assert_eq!(*names.refused_commands(), expected);
        assert_eq!(
            MONTY_OFF_WITHOUT_PYTHON,
            "Monty is off (monty = false) and no [tool.python3] or [tool.python] is declared"
        );
        assert_eq!(names.python_tables(), None);
    }

    /// **With Monty on, a Python table is not used for a bare `python3` or `python`**, and is
    /// listed so the startup notice can say so.
    #[test]
    fn with_monty_on_a_python_table_is_unused_and_listed() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        let tools = python_tools(
            &root,
            &[("python3", "a/bin/python3"), ("python", "b/bin/python")],
        );

        let names = bare_names_with(true, &tools, &root.join("a/bin/python3"));

        assert!(names.monty);
        assert!(names.declared.is_empty(), "{:?}", names.declared);
        assert!(names.replaced.is_empty(), "{:?}", names.replaced);
        assert!(names.refused.is_empty(), "{:?}", names.refused);
        assert_eq!(
            names.unused_python,
            vec!["[tool.python3]".to_string(), "[tool.python]".to_string()]
        );
    }

    /// **A versioned name stays as today**: `[tool.python3]` whose file is `python3.14` answers to
    /// `python3.14` by its file name whether Monty is on or off, and that name is never replaced.
    #[test]
    fn versioned_names_stay_separate() {
        let root = tempfile::tempdir().expect("root");
        let root = root.path().canonicalize().expect("canonical root");
        let tools = python_tools(&root, &[("python3", "bin/python3.14")]);
        let python = root.join("bin/python3.14");
        let versioned = (python.clone(), vec!["[tool.python3]".to_string()]);

        let on = bare_names_with(true, &tools, &python);
        assert_eq!(on.declared.keys().collect::<Vec<_>>(), vec!["python3.14"]);
        assert_eq!(on.declared.get("python3.14"), Some(&versioned));
        assert_eq!(on.unused_python, vec!["[tool.python3]".to_string()]);

        let off = bare_names_with(false, &tools, &python);
        assert_eq!(
            off.declared.keys().collect::<Vec<_>>(),
            vec!["python", "python3", "python3.14"]
        );
        assert_eq!(off.declared.get("python3.14"), Some(&versioned));
        assert_eq!(off.replaced, both_python_names());
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

    /// A home folder holding a standard Python base, a venv over it, and a project.
    struct PythonTree {
        _directory: tempfile::TempDir,
        home: PathBuf,
        base: PathBuf,
        venv: PathBuf,
        project: PathBuf,
    }

    impl PythonTree {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("directory");
            let home = directory
                .path()
                .canonicalize()
                .expect("canonical directory");
            // Below `work`, so one grant can sit above the venv without being the home folder.
            let base = home.join("work/base");
            std::fs::create_dir_all(base.join("bin")).expect("base bin");
            program(&base.join("bin/python3.12"));
            std::fs::create_dir_all(base.join("lib/python3.12/site-packages")).expect("stdlib");
            std::fs::write(base.join("lib/python3.12/os.py"), "").expect("os.py");
            let venv = home.join("work/venv");
            std::fs::create_dir_all(venv.join("bin")).expect("venv bin");
            std::fs::create_dir_all(venv.join("lib/python3.12/site-packages")).expect("venv site");
            std::fs::write(
                venv.join("pyvenv.cfg"),
                format!(
                    "home = {}\ninclude-system-site-packages = false\nversion = 3.12.4\n",
                    base.join("bin").display()
                ),
            )
            .expect("pyvenv.cfg");
            std::os::unix::fs::symlink(base.join("bin/python3.12"), venv.join("bin/python3.12"))
                .expect("venv python3.12");
            std::os::unix::fs::symlink("python3.12", venv.join("bin/python3")).expect("python3");
            let project = home.join("project");
            std::fs::create_dir(&project).expect("project");
            Self {
                _directory: directory,
                home,
                base,
                venv,
                project,
            }
        }

        fn site_packages(&self) -> PathBuf {
            self.venv.join("lib/python3.12/site-packages")
        }

        fn roots(&self) -> InstallRoots {
            InstallRoots {
                homebrew: vec![self.home.join("no-brew")],
                macos_library: self.home.join("no-library"),
                system: self.home.join("no-system"),
                home: Some(self.home.join("user")),
                user_site: python_install::UserSiteLayout::MacOs,
            }
        }

        /// `monty = false`, `[tool.python3]` running `command`, and an agent in the project.
        fn record(&self, command: &Path, monty: bool) -> Record {
            let mut record = record(command);
            let spec = record.tool.remove("reader").expect("tool");
            record.monty = monty;
            record.agent = Some(ProcessSpec {
                command: vec!["/bin/sh".to_string()],
                workspace: Some(self.project.clone()),
                ..spec.clone()
            });
            record.tool.insert("python3".to_string(), spec);
            record
        }

        fn commands(&self) -> ConfiguredCommands {
            ConfiguredCommands::load_with(
                &self.record(&self.venv.join("bin/python3"), false),
                &self.roots(),
            )
            .expect("python commands")
        }
    }

    /// The Python tool's judged grants, with `filesystem` as its table's lists and the agent in
    /// `workspace`.
    fn python_grants(
        tree: &PythonTree,
        filesystem: crate::record::config::process::Filesystem,
        workspace: &Path,
    ) -> Result<Vec<crate::record::config::filesystem::DirectGrant>, BoxError> {
        let mut record = tree.record(&tree.venv.join("bin/python3"), false);
        record.tool.get_mut("python3").expect("tool").filesystem = filesystem;
        record.agent.as_mut().expect("agent").workspace = Some(workspace.to_path_buf());
        let commands = ConfiguredCommands::load_in_with(&record, &tree.roots(), workspace)?;
        let approved = crate::run::contain::boundary::ApprovedReach::judge_with(
            &record,
            &[],
            Arc::new(commands),
        )?;
        Ok(approved
            .table("[tool.python3]")
            .expect("the python table")
            .grants
            .clone())
    }

    fn granted(
        grants: &[crate::record::config::filesystem::DirectGrant],
    ) -> Vec<(&'static str, PathBuf, Option<String>)> {
        grants
            .iter()
            .map(|grant| {
                (
                    grant.kind.key(),
                    grant.resolved.clone(),
                    grant.added.clone(),
                )
            })
            .collect()
    }

    fn added(reason: &str) -> Option<String> {
        Some(format!("added for [tool.python3]: {reason}"))
    }

    #[test]
    fn a_python_tool_with_no_lists_gets_the_workspace_and_its_install() {
        let tree = PythonTree::new();
        let grants = python_grants(&tree, Default::default(), &tree.project).expect("judged");
        assert_eq!(
            granted(&grants),
            vec![
                ("read", tree.project.clone(), added("workspace")),
                ("read", tree.site_packages(), added("install")),
                ("read", tree.base.join("lib/python3.12"), added("install")),
                ("write", tree.project.clone(), added("workspace")),
                ("read_file", tree.venv.join("pyvenv.cfg"), added("install")),
            ]
        );
        let lines: Vec<String> = grants.iter().map(|grant| grant.disclosure()).collect();
        assert!(
            lines[0].ends_with("(read-write)  (added for [tool.python3]: workspace)"),
            "{lines:?}"
        );
        assert!(
            lines[1].ends_with(&format!(
                "{}  (read-only)  (added for [tool.python3]: install)",
                tree.site_packages().display()
            )),
            "{lines:?}"
        );
    }

    #[test]
    fn a_python_tools_own_lists_replace_only_the_workspace_grant() {
        let tree = PythonTree::new();
        let notes = tree.home.join("notes");
        std::fs::create_dir(&notes).expect("notes");
        let filesystem = crate::record::config::process::Filesystem {
            read: vec![notes.clone()],
            ..Default::default()
        };
        let grants = python_grants(&tree, filesystem, &tree.project).expect("judged");
        assert_eq!(
            granted(&grants),
            vec![
                ("read", notes, None),
                ("read", tree.site_packages(), added("install")),
                ("read", tree.base.join("lib/python3.12"), added("install")),
                ("read_file", tree.venv.join("pyvenv.cfg"), added("install")),
            ]
        );
        assert!(
            !grants[0].disclosure().contains("added for"),
            "{}",
            grants[0].disclosure()
        );
    }

    #[test]
    fn an_operator_read_over_the_install_is_not_granted_twice() {
        let tree = PythonTree::new();
        let work = tree.home.join("work");
        let filesystem = crate::record::config::process::Filesystem {
            read: vec![work.clone()],
            ..Default::default()
        };
        let grants = python_grants(&tree, filesystem, &tree.project).expect("judged");
        assert_eq!(granted(&grants), vec![("read", work, None)]);

        // An operator's narrower entry inside an added folder gives way to it. The project write
        // keeps its read, because Linux refuses write-only access.
        let inside = tree.site_packages().join("pkg");
        std::fs::create_dir(&inside).expect("pkg");
        let filesystem = crate::record::config::process::Filesystem {
            read: vec![inside, tree.project.clone()],
            write: vec![tree.project.clone()],
            ..Default::default()
        };
        let grants = python_grants(&tree, filesystem, &tree.project).expect("judged");
        assert_eq!(
            granted(&grants),
            vec![
                ("read", tree.project.clone(), None),
                ("read", tree.site_packages(), added("install")),
                ("read", tree.base.join("lib/python3.12"), added("install")),
                ("write", tree.project.clone(), None),
                ("read_file", tree.venv.join("pyvenv.cfg"), added("install")),
            ]
        );
    }

    #[test]
    fn a_venv_inside_the_workspace_refuses_the_default_grants() {
        let tree = PythonTree::new();
        let work = tree.home.join("work");
        let error = python_grants(&tree, Default::default(), &work)
            .expect_err("a writable workspace holding the venv is refused")
            .to_string();
        assert!(
            error.contains("[tool.python3]") && error.contains(&work.display().to_string()),
            "{error}"
        );
    }

    /// Prints the grants Box adds for each `PYTHON_INSTALL_PROBE` command (`:`-separated).
    #[test]
    #[ignore = "reads this machine's Python installs"]
    fn the_grants_for_this_machine() {
        let Some(probes) = std::env::var_os("PYTHON_INSTALL_PROBE") else {
            return;
        };
        for command in std::env::split_paths(&probes) {
            let workspace = tempfile::tempdir().expect("workspace");
            let workspace = workspace.path().canonicalize().expect("canonical");
            let mut record = record(&command);
            let spec = record.tool.remove("reader").expect("tool");
            record.monty = false;
            record.agent = Some(ProcessSpec {
                command: vec!["/bin/sh".to_string()],
                workspace: Some(workspace.clone()),
                ..spec.clone()
            });
            record.tool.insert("python3".to_string(), spec);
            let commands =
                ConfiguredCommands::load_in(&record, &workspace).expect("the install loads");
            let approved = crate::run::contain::boundary::ApprovedReach::judge_with(
                &record,
                &[],
                Arc::new(commands),
            )
            .expect("the grants are judged");
            println!("{}:", command.display());
            for grant in &approved.table("[tool.python3]").expect("table").grants {
                println!("{}", grant.disclosure());
            }
        }
    }

    const INSTALL_REFUSAL: &str = "which [tool.python3] loads Python code from. Keep the Python \
                                   install outside every write grant";

    #[test]
    fn a_write_grant_on_the_python_install_is_refused_in_either_direction() {
        let tree = PythonTree::new();
        let commands = tree.commands();
        assert!(
            commands.python_protected().contains(&tree.site_packages()),
            "{:?}",
            commands.python_protected()
        );

        // The venv itself, which also holds the command's path.
        commands
            .validate_reach("[agent]", &reach(&tree.home, &tree.venv))
            .expect_err("a venv inside a write grant is refused");
        // A grant inside site-packages, and one above the base's standard library.
        for writable in [
            tree.site_packages(),
            tree.site_packages().join("pkg"),
            tree.base.join("lib"),
        ] {
            std::fs::create_dir_all(&writable).expect("writable folder");
            for table in ["[agent]", "[tool.python3]", "[mcp.server]"] {
                let error = commands
                    .validate_reach(table, &reach(&tree.home, &writable))
                    .expect_err("a write grant reaching the install is refused")
                    .to_string();
                assert!(error.contains(INSTALL_REFUSAL), "{error}");
                assert!(error.contains(table), "{error}");
            }
        }
        // A grant on the folder that holds the venv and the base.
        commands
            .validate_reach("[agent]", &reach(&tree.home, &tree.home.join("work")))
            .expect_err("a write grant above the venv is refused");
        commands
            .validate_reach("[agent]", &reach(&tree.home, &tree.project))
            .expect("the project stays writable");
    }

    #[test]
    fn a_write_grant_on_one_file_is_refused_only_inside_the_install() {
        let tree = PythonTree::new();
        let commands = tree.commands();
        let planted = tree.site_packages().join("x.pth");
        std::fs::write(&planted, "").expect("x.pth");
        let file_reach = |path: &Path| {
            // Linux refuses write-only access, so the file write keeps its read.
            direct_grants(
                &Filesystem {
                    read_file: vec![path.to_path_buf()],
                    write_file: vec![path.to_path_buf()],
                    ..Default::default()
                },
                &FilesystemContext {
                    table: "[agent]",
                    operator_home: &tree.home,
                    policy: None,
                    authority_directories: Vec::new(),
                    program_search_directories: Vec::new(),
                },
            )
            .expect("file reach")
        };
        let error = commands
            .validate_reach("[agent]", &file_reach(&planted))
            .expect_err("a file grant inside site-packages is refused")
            .to_string();
        assert!(error.contains(INSTALL_REFUSAL), "{error}");
        let notes = tree.home.join("notes.txt");
        std::fs::write(&notes, "").expect("notes");
        commands
            .validate_reach("[agent]", &file_reach(&notes))
            .expect("a file outside the install stays writable");
    }

    #[test]
    fn a_shell_write_into_the_python_install_is_refused_while_the_box_runs() {
        let tree = PythonTree::new();
        let commands = tree.commands();
        for path in [
            tree.venv.clone(),
            tree.venv.join("bin"),
            tree.site_packages().join("x.pth"),
            tree.site_packages().join("pkg/__init__.py"),
            tree.base.join("lib"),
        ] {
            assert!(
                commands.mutation_refusal(&path).is_some(),
                "{} must be refused",
                path.display()
            );
        }
        let refusal = commands.mutation_refusal(&tree.site_packages().join("x.pth"));
        assert!(
            matches!(
                &refusal,
                Some(CommandMutationRefusal::PythonInstall { table }) if table == "[tool.python3]"
            ),
            "{refusal:?}"
        );
        assert!(
            commands
                .mutation_refusal(&tree.project.join("a.py"))
                .is_none()
        );
    }

    #[test]
    fn an_editable_install_whose_source_is_in_the_project_refuses_startup() {
        let tree = PythonTree::new();
        let source = tree.project.join("src");
        std::fs::create_dir(&source).expect("source");
        let record_folder = tree.site_packages().join("pkg-1.0.dist-info");
        std::fs::create_dir(&record_folder).expect("dist-info");
        std::fs::write(
            record_folder.join("direct_url.json"),
            format!(
                r#"{{"url": "file://{}", "dir_info": {{"editable": true}}}}"#,
                source.display()
            ),
        )
        .expect("direct_url.json");

        let error = ConfiguredCommands::load_with(
            &tree.record(&tree.venv.join("bin/python3"), false),
            &tree.roots(),
        )
        .expect_err("an editable source in the workspace refuses startup")
        .to_string();
        assert!(error.contains("editable install"), "{error}");
        assert!(error.contains(&source.display().to_string()), "{error}");

        // Outside the workspace, only a write grant that reaches it is refused.
        let mut record = tree.record(&tree.venv.join("bin/python3"), false);
        record.agent.as_mut().expect("agent").workspace = Some(tree.home.join("elsewhere"));
        let commands =
            ConfiguredCommands::load_with(&record, &tree.roots()).expect("source outside");
        let error = commands
            .validate_reach("[agent]", &reach(&tree.home, &tree.project))
            .expect_err("a write grant on an editable source is refused")
            .to_string();
        assert!(
            error.contains("the source of an editable install"),
            "{error}"
        );
    }

    #[test]
    fn a_user_site_that_doesnt_exist_yet_is_protected_with_its_parents() {
        let tree = PythonTree::new();
        // The base itself, not the venv, so Python adds the user site.
        let commands = ConfiguredCommands::load_with(
            &tree.record(&tree.base.join("bin/python3.12"), false),
            &tree.roots(),
        )
        .expect("a standard install");
        let user_site = tree.home.join("user/.local/lib/python3.12/site-packages");
        assert!(!user_site.exists());
        for path in [
            user_site.clone(),
            user_site.join("evil.pth"),
            tree.home.join("user/.local/lib"),
            tree.home.join("user/.local"),
        ] {
            assert!(
                matches!(
                    commands.mutation_refusal(&path),
                    Some(CommandMutationRefusal::PythonInstall { .. })
                ),
                "creating {} must be refused",
                path.display()
            );
        }
        assert!(
            commands
                .mutation_refusal(&tree.home.join("user/notes.txt"))
                .is_none()
        );
    }

    #[test]
    fn the_base_lib_folder_is_protected_with_the_zip_that_may_not_exist() {
        let tree = PythonTree::new();
        let commands = tree.commands();
        for path in [
            tree.base.join("lib/python312.zip"),
            tree.base.join("lib/libpython3.12.dylib"),
        ] {
            assert!(
                commands.mutation_refusal(&path).is_some(),
                "{} must be refused",
                path.display()
            );
        }
    }

    #[test]
    fn a_hard_linked_install_file_refuses_startup() {
        let tree = PythonTree::new();
        let installed = tree.site_packages().join("pkg.py");
        std::fs::write(&installed, "").expect("pkg.py");
        std::fs::hard_link(&installed, tree.home.join("other-name.py")).expect("hard link");

        let error = ConfiguredCommands::load_with(
            &tree.record(&tree.venv.join("bin/python3"), false),
            &tree.roots(),
        )
        .expect_err("a hard link refuses startup")
        .to_string();
        assert!(
            error.contains(&format!(
                "[tool.python3]` table: {} has another name outside the install",
                installed.display()
            )),
            "{error}"
        );
        assert!(error.contains("--link-mode=copy"), "{error}");
    }

    #[test]
    fn a_link_out_of_site_packages_protects_its_target() {
        let tree = PythonTree::new();
        let cache = tree.home.join("cache/pkg");
        std::fs::create_dir_all(&cache).expect("cache");
        std::fs::write(cache.join("__init__.py"), "").expect("__init__.py");
        std::os::unix::fs::symlink(&cache, tree.site_packages().join("pkg")).expect("link");

        let commands = tree.commands();
        assert!(
            commands
                .mutation_refusal(&cache.join("__init__.py"))
                .is_some()
        );
        commands
            .validate_reach("[agent]", &reach(&tree.home, &tree.home.join("cache")))
            .expect_err("a write grant on the link's target is refused");
    }

    #[test]
    fn a_pth_folder_in_the_project_refuses_startup() {
        let tree = PythonTree::new();
        let source = tree.project.join("src");
        std::fs::write(
            tree.site_packages().join("develop.pth"),
            format!("import os\n{}\n", source.display()),
        )
        .expect("develop.pth");

        let error = ConfiguredCommands::load_with(
            &tree.record(&tree.venv.join("bin/python3"), false),
            &tree.roots(),
        )
        .expect_err("a .pth folder in the workspace refuses startup")
        .to_string();
        assert!(error.contains("a folder a .pth file names"), "{error}");
        assert!(error.contains(&source.display().to_string()), "{error}");
    }

    #[test]
    fn extension_images_finds_so_files_and_stops_at_the_cap() {
        let tree = PythonTree::new();
        let dynload = tree.base.join("lib/python3.12/lib-dynload");
        std::fs::create_dir_all(&dynload).expect("lib-dynload");
        for name in ["_ssl.so", "_lzma.so", "notes.txt"] {
            std::fs::write(dynload.join(name), "").expect("image");
        }
        let folders = vec![tree.base.join("lib/python3.12")];
        assert_eq!(
            extension_images(&folders, 10),
            vec![dynload.join("_lzma.so"), dynload.join("_ssl.so")]
        );
        assert_eq!(extension_images(&folders, 1).len(), 1);
    }

    #[test]
    fn with_monty_on_no_library_is_seeded() {
        let tree = PythonTree::new();
        let commands = ConfiguredCommands::load_with(
            &tree.record(&tree.venv.join("bin/python3"), true),
            &tree.roots(),
        )
        .expect("Monty on");
        assert!(
            commands.python().is_none(),
            "Monty on has no Python tool to seed"
        );
        let off = tree.commands();
        let spec = tree.record(&tree.venv.join("bin/python3"), false).tool["python3"].clone();
        let (_, added) = off.python().expect("Monty off").augmented(&spec);
        assert!(
            added.iter().all(|entry| entry.reason != "libraries"),
            "an install with no images adds no library: {added:?}"
        );
    }

    /// Time the library walk on real installs on this host:
    /// `cargo test -p strands-box --lib library_walk_timing -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs real Python installs on the host"]
    fn library_walk_timing() {
        let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
        for command in [
            PathBuf::from("/opt/homebrew/bin/python3"),
            home.join("box-native-venv/runtime/.venv/bin/python3"),
        ] {
            let install = python_install::detect(&command, &InstallRoots::host())
                .expect("a recognized install");
            let started = std::time::Instant::now();
            let images = extension_images(&install.code_folders, MAXIMUM_PYTHON_IMAGES);
            let walked = started.elapsed();
            let libraries =
                containment::loaded_libraries(&images, &containment::ContainmentConfig::new());
            let total = started.elapsed();
            println!(
                "{}: {} images found in {walked:?}; {} libraries derived; {total:?} in all",
                command.display(),
                images.len(),
                libraries.len()
            );
            for library in &libraries {
                println!("  {}", library.display());
            }
        }
    }

    #[test]
    fn with_monty_on_box_detects_no_python_install() {
        let tree = PythonTree::new();
        let unknown = tree.home.join("tools/python3");
        std::fs::create_dir_all(unknown.parent().expect("tools")).expect("tools");
        program(&unknown);

        let commands = ConfiguredCommands::load_with(&tree.record(&unknown, true), &tree.roots())
            .expect("Monty on ignores the Python table's install");
        assert!(commands.python_protected().is_empty());
        let venv_commands = ConfiguredCommands::load_with(
            &tree.record(&tree.venv.join("bin/python3"), true),
            &tree.roots(),
        )
        .expect("Monty on");
        assert!(venv_commands.python_protected().is_empty());
        venv_commands
            .validate_reach("[agent]", &reach(&tree.home, &tree.site_packages()))
            .expect("with Monty on, site-packages is not protected");

        let error = ConfiguredCommands::load_with(&tree.record(&unknown, false), &tree.roots())
            .expect_err("Monty off refuses an unknown install")
            .to_string();
        assert!(
            error.contains(&format!(
                "[tool.python3]` table: {} is not a Python install Box recognizes. Use a venv",
                unknown.display()
            )),
            "{error}"
        );
    }

    #[test]
    fn the_read_only_install_hint_needs_a_failure_a_protected_path_and_a_permission_error() {
        let protected = vec![PathBuf::from("/venv/lib/python3.12/site-packages")];
        let pip = b"ERROR: Could not install packages due to an OSError: [Errno 13] \
                    Permission denied: '/venv/lib/python3.12/site-packages/numpy'";
        assert!(read_only_install_hint(1, pip, &protected));
        assert!(read_only_install_hint(
            1,
            b"OSError: [Errno 1] Operation not permitted: '/venv/lib/python3.12/site-packages'",
            &protected
        ));
        assert!(read_only_install_hint(
            2,
            b"Read-only file system: /venv/lib/python3.12/site-packages/x.pth",
            &protected
        ));
        assert!(!read_only_install_hint(0, pip, &protected), "success");
        assert!(
            !read_only_install_hint(1, b"Permission denied: '/project/out.txt'", &protected),
            "another folder"
        );
        assert!(
            !read_only_install_hint(
                1,
                b"Permission denied: '/venv/lib/python3.12/site-packages2/x'",
                &protected
            ),
            "a sibling folder whose name only starts the same"
        );
        assert!(
            !read_only_install_hint(
                1,
                b"No such file: '/venv/lib/python3.12/site-packages/x'",
                &protected
            ),
            "not a permission error"
        );
        assert!(!read_only_install_hint(1, pip, &[]), "nothing protected");
    }
}
