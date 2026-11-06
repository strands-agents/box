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

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod aliases;

#[derive(Debug, Default)]
pub(crate) struct ConfiguredCommands {
    tools: BTreeMap<String, Arc<ConfiguredCommand>>,
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
        Ok(Self { tools })
    }

    pub(crate) fn get(&self, label: &str) -> Option<&Arc<ConfiguredCommand>> {
        let label = label
            .strip_prefix("[tool.")
            .and_then(|label| label.strip_suffix(']'))
            .unwrap_or(label);
        self.tools.get(label)
    }

    pub(crate) fn refuses_mutation(&self, path: &Path) -> bool {
        if self.tools.values().any(|command| command.enclosed_by(path)) {
            return true;
        }
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let identities = self.mutable_aliases();
            if !identities.is_empty() {
                return match aliases::contains(path, &identities) {
                    Ok(found) => found,
                    Err(error) => error.kind() != std::io::ErrorKind::NotFound,
                };
            }
        }
        false
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
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            if grant.scope != Scope::File {
                let identities = self.mutable_aliases();
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
    fn mutable_aliases(&self) -> Vec<(u64, u64)> {
        self.tools
            .values()
            .filter(|command| command.needs_alias_scan)
            .map(|command| command.identity)
            .collect()
    }
}

impl ConfiguredCommand {
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
