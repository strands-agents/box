use std::ffi::OsString;
use std::io::{BufRead, Write};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use serde_json::{Value, json};
use strands_box_cli_telemetry::{
    ActionCatalog, COMPLETION_BUDGET, Consent, ConsentSource, ExitOutcome, Journal, Session,
    save_telemetry_choice,
};

use crate::check::{self, Checked};
use crate::compile::{Compiled, Instance, Run, compile};
#[cfg(any(test, feature = "test-support"))]
use crate::create::Discovery;
use crate::create::{HostSources, process_env};
use crate::error::Error;
use crate::files::{create_real_directory, io_error, remove_if_present};
use crate::host::{Host, box_home_base, canonical, default_box_home, resolved, tilde};
use crate::lang::{self, Inputs, Lookup, PROJECT, Storage};
use crate::locate::closest;
use crate::mcp_config::Import;
use crate::plugin;
use crate::profile::{
    PACKS, POLICY_FILE, PROJECT_CONFIGURATION, Profile, Profiles, Project, ProjectAccess, Resolved,
};
use crate::render::tool_rules;
use crate::resources;
use crate::starter::{Menu, Starter, columns, short_name};
use crate::storage_edit;
use crate::storage_files::State;
use crate::storage_sync::{
    self, Copied, SYNC_LOCK_WAIT, copy_files, copy_state, is_link, is_real_path, remove_link,
};
use crate::telemetry::{InstallationId, Observations, RunContext};

mod banner;
#[cfg(test)]
mod completion_tests;
#[cfg(test)]
mod context_tests;
mod history;
mod policy;
mod startup;
mod terminal;
mod view;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Display {
    Direct,
    Banner,
}

/// The banner when all standard streams are terminals and the first of `flag`, `profile`, and
/// `user` that is set enables it, or none is set.
fn display(
    terminal: bool,
    flag: Option<bool>,
    profile: Option<bool>,
    user: Option<bool>,
) -> Display {
    if terminal && flag.or(profile).or(user).unwrap_or(true) {
        Display::Banner
    } else {
        Display::Direct
    }
}

pub(crate) const RUNS: &str = "r";

/// How many new names a run tries before it stops.
const MINT_ATTEMPTS: u32 = 16;

/// The number of lowercase hexadecimal digits in a box ID.
const ID_DIGITS: usize = 16;
const ID_PREFIX: &str = "b-";

/// The file in a run directory that holds the full name of the profile that minted it.
pub(crate) const PROFILE_RECORD: &str = "profile-name";

pub(crate) fn profiles_root(box_home: &Path) -> PathBuf {
    box_home.join("profiles")
}

fn runs_root(box_home: &Path) -> PathBuf {
    box_home.join(RUNS)
}

/// A preview writes nothing to disk, so every profile can share this fixed ID.
pub(crate) fn preview_instance(box_home: &Path) -> Instance {
    let name = format!("{ID_PREFIX}{}", "0".repeat(ID_DIGITS));
    debug_assert!(is_run_id(&name));
    let directory = runs_root(box_home).join(&name);
    Instance {
        name,
        box_directory: directory.join("box"),
        directory,
    }
}

/// Every directory a later run trusts.
pub(crate) fn protected(host: &Host, install: Option<&Path>, extra: &[PathBuf]) -> Vec<PathBuf> {
    host.box_homes()
        .into_iter()
        .chain(std::iter::once(host.home.join(".local/bin")))
        .chain(install.map(Path::to_path_buf))
        .chain(extra.iter().cloned())
        .collect()
}

/// The installed package directory of this `box`, which a later run trusts.
pub(crate) fn install_root() -> Option<PathBuf> {
    crate::installation::executable()
        .ok()
        .and_then(|exe| crate::installation::root(&exe))
}

/// A profile, its name, and its policy.
#[derive(Clone, Copy)]
pub(crate) struct Loaded<'a> {
    pub(crate) profile: &'a Profile,
    pub(crate) name: &'a str,
    pub(crate) policy: Option<&'a str>,
    /// The profile file and its policy files when they lie outside the workspace's `.box`, which
    /// later runs read again.
    pub(crate) trusted: &'a [PathBuf],
    /// Whether the profile is a profile file that runs by its path.
    pub(crate) by_path: bool,
}

/// Whether a `box run` or `box profile show` argument is a profile file rather than a profile name.
pub fn is_profile_path(argument: &str) -> bool {
    argument.contains('/') || argument.ends_with(".toml")
}

/// The file in a profile's storage that holds the path of the profile file that owns the name.
const PROFILE_SOURCE: &str = ".profile-source";

/// A profile that `box run` found by its name or by its path.
pub(crate) struct Located {
    pub(crate) name: String,
    pub(crate) profile: Profile,
    pub(crate) policy: Option<String>,
    /// The real path of the profile file, when the argument named a path.
    pub(crate) file: Option<PathBuf>,
}

/// The record of which profile file owns `name`: beside the profile's storage namespaces, where
/// no run can write.
fn name_record(box_home: &Path, name: &str) -> PathBuf {
    box_home.join("storage").join(name).join(PROFILE_SOURCE)
}

/// Refuse `name` for a profile that is not a profile file, when a profile file owns it.
pub(crate) fn refuse_owned_name(box_home: &Path, name: &str) -> Result<(), Error> {
    let record = name_record(box_home, name);
    let Ok(owner) = std::fs::read_to_string(&record) else {
        return Ok(());
    };
    let owner = PathBuf::from(owner.trim_end());
    Err(owned(name.to_string(), owner, record))
}

/// Whether the profile file `owner` still declares `name`.
fn still_owns(owner: &Path, name: &str) -> bool {
    std::fs::read_to_string(owner).is_ok_and(|text| {
        Profile::parse(&text, owner)
            .map(|profile| profile.declared_name() == Some(name))
            .unwrap_or(true)
    })
}

/// The refusal for a name that the profile file `owner` holds, by whether that file still
/// declares it.
fn owned(name: String, owner: PathBuf, record: PathBuf) -> Error {
    if still_owns(&owner, &name) {
        Error::ProfileNameOwned { name, owner }
    } else {
        Error::ProfileNameOwnerGone {
            name,
            owner,
            record,
        }
    }
}

/// A profile file and its policy files, which no write grant may reach because later runs trust
/// them. The project's `.box` folder is left out, because every process is denied it.
fn profile_file_protections(
    file: Option<&Path>,
    profile: &Profile,
    workspace: &Path,
) -> Result<Vec<PathBuf>, Error> {
    let Some(file) = file else {
        return Ok(Vec::new());
    };
    let denied = workspace.join(PROJECT_CONFIGURATION);
    let mut protected = vec![file.to_path_buf()];
    protected.extend(profile.policy_files()?);
    protected.retain(|path| !path.starts_with(&denied));
    Ok(protected)
}

/// Refuse `workspace` when it holds a profile file that an earlier run loaded, outside its `.box`,
/// because the agent of a box here could change it before that profile's next run.
fn refuse_workspace_holding_profiles(box_home: &Path, workspace: &Path) -> Result<(), Error> {
    let Ok(entries) = std::fs::read_dir(box_home.join("storage")) else {
        return Ok(());
    };
    let protected = workspace.join(PROJECT_CONFIGURATION);
    for entry in entries.flatten() {
        let Ok(owner) = std::fs::read_to_string(entry.path().join(PROFILE_SOURCE)) else {
            continue;
        };
        let profile = PathBuf::from(owner.trim_end());
        if profile.starts_with(workspace) && !profile.starts_with(&protected) && profile.exists() {
            return Err(Error::WorkspaceHoldsProfile {
                workspace: workspace.to_path_buf(),
                profile,
            });
        }
    }
    Ok(())
}

/// Refuse a profile or policy file that another name or another user can change: a file with a
/// second hard link, a file another user owns, or one that its group or others may write.
fn refuse_shared(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = std::fs::metadata(path).map_err(|source| Error::Io {
        action: "inspect",
        path: path.to_path_buf(),
        source,
    })?;
    let user = nix::unistd::getuid();
    let reason = if metadata.nlink() > 1 {
        Some("it has another hard link, and a change through that name changes it")
    } else if metadata.uid() != user.as_raw() {
        Some("another user owns it")
    } else if metadata.mode() & 0o002 != 0 {
        Some("other users may write it")
    } else if metadata.mode() & 0o020 != 0 && !private_group(metadata.gid(), user) {
        Some("its group, which other users are in, may write it")
    } else {
        None
    };
    match reason {
        Some(reason) => Err(Error::ProfileFileShared {
            path: path.to_path_buf(),
            reason,
        }),
        None => Ok(()),
    }
}

/// Whether the group `gid` holds only the operator: the operator's own primary group, named after
/// the operator, with no other member. A Linux user's private group, with a `002` umask, is this
/// case; a shared primary group such as macOS's `staff` is not, because the system does not list
/// the users whose primary group it is.
fn private_group(gid: u32, user: nix::unistd::Uid) -> bool {
    let Ok(Some(account)) = nix::unistd::User::from_uid(user) else {
        return false;
    };
    if account.gid.as_raw() != gid {
        return false;
    }
    match nix::unistd::Group::from_gid(account.gid) {
        Ok(Some(group)) => {
            group.name == account.name && group.mem.iter().all(|member| *member == account.name)
        }
        _ => false,
    }
}

/// Refuse `path` when it is in `workspace` and outside the project's `.box` folder.
fn refuse_in_workspace(path: &Path, workspace: &Path) -> Result<(), Error> {
    if path.starts_with(workspace) && !path.starts_with(workspace.join(PROJECT_CONFIGURATION)) {
        return Err(Error::ProfileInWorkspace {
            path: path.to_path_buf(),
            workspace: workspace.to_path_buf(),
        });
    }
    Ok(())
}

/// Where `packs` and `extend` find a pack for `host`: `box`'s own packs, the operator's, and each
/// collection that the operator's `config.toml` lists.
pub(crate) fn lookup(host: &Host) -> Result<Lookup, Error> {
    lookup_at(resources::root().ok().map(|root| root.join("packs")), host)
}

/// [`lookup`] with `box`'s own packs in `vendored`.
pub(crate) fn lookup_at(vendored: Option<PathBuf>, host: &Host) -> Result<Lookup, Error> {
    let operator = host.box_home.join(PACKS);
    let mut lookup = Lookup {
        vendored,
        operator,
        collections: Vec::new(),
        version: crate::VERSION,
    };
    lookup.collections = crate::collection::listed(&host.box_home)?;
    Ok(lookup)
}

/// One compiled run: what Box Core reads, the resolved profile, what the host holds, and each pack
/// with its version.
pub(crate) struct CompiledRun {
    pub(crate) compiled: Compiled,
    pub(crate) resolved: Resolved,
    /// What each `[[storage.hooks]]` row imports for this run.
    pub(crate) hooks: Vec<crate::storage_hooks::Imported>,
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) discovery: Discovery,
    pub(crate) packs: Vec<(String, String)>,
    /// Each plugin with its version, in the order of `plugins`.
    pub(crate) plugins: Vec<(String, String)>,
    /// Each declared secret source, as `(scheme, program, the plugin that declares it)`, with no
    /// plugin for a source of the profile.
    pub(crate) sources: Vec<(String, String, Option<String>)>,
}

pub(crate) struct RunSettings<'a> {
    pub(crate) display: Display,
    pub(crate) observations: Option<&'a mut Observations>,
    /// `box`'s resources directory, which a run protects because later runs read it.
    pub(crate) resources: Option<&'a Path>,
    /// The installed package directory of the running `box`, which later runs trust.
    pub(crate) install: Option<&'a Path>,
}

/// Refuse a workspace that is `home` or holds it.
fn refuse_home_workspace(home: &Path, workspace: &Path) -> Result<(), Error> {
    if home.as_os_str().is_empty() {
        return Ok(());
    }
    let real = |path: &Path| canonical(path).unwrap_or_else(|| path.to_path_buf());
    let workspace = real(workspace);
    if crate::host::within(&real(home), &workspace) {
        return Err(Error::ProjectHoldsHome { path: workspace });
    }
    Ok(())
}

/// Resolve a profile against `host` for a run in `workspace`, and compile it for `instance`.
pub(crate) fn compile_run(
    source: Loaded<'_>,
    host: &Host,
    workspace: &Path,
    instance: &Instance,
    extra_protected: &[PathBuf],
    env: &dyn Fn(&str) -> Option<String>,
    mut settings: RunSettings<'_>,
) -> Result<CompiledRun, Error> {
    refuse_home_workspace(&host.home, workspace)?;
    let mut sources = HostSources::new(host, workspace, env);
    let profile_folder = source
        .profile
        .path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let storage = lang::storage_root(&host.box_home, source.name);
    let packs_at = lookup(host)?;
    let inputs = Inputs {
        tool_cache: None,
        home: &host.home,
        box_home: &host.box_home,
        workspace,
        profile: &profile_folder,
        profile_file: &source.profile.path,
        box_dir: &instance.box_directory,
        storage: &storage,
        os: host.os,
        packs: packs_at.vendored.as_deref(),
    };
    let layers = source.profile.layers(source.policy, &packs_at)?;
    if source.by_path {
        strands_box_cli_profile::plugin::refuse_path_profile_programs(
            &layers,
            source.name,
            &host.home,
            &host.box_home,
        )?;
    }
    let packs = lang::pack_versions(&layers);
    let plugins = plugin::versions(&layers);
    if let Some(observations) = settings.observations.as_deref_mut() {
        observations.initial_packs(&layers);
    }
    let (mut resolved, launchers) =
        source
            .profile
            .resolve_layers(&layers, &packs_at, &mut sources, &inputs)?;
    if let Some(observations) = settings.observations {
        observations.resolved_packs(&layers, &launchers, &resolved.servers);
    }
    if matches!(settings.display, Display::Banner) {
        resolved.agent.env.extend([
            ("TERM".into(), "xterm-256color".into()),
            ("COLORTERM".into(), "truecolor".into()),
        ]);
    }
    let hooks = import_hooks(&mut resolved, &host.home);
    let declared = plugin::sources(&layers)
        .into_iter()
        .map(|(scheme, plugin)| {
            let program = resolved
                .secret_source
                .get(&scheme)
                .and_then(|source| source.get("command"))
                .and_then(toml::Value::as_array)
                .and_then(|command| command.first())
                .and_then(toml::Value::as_str)
                .unwrap_or_default()
                .to_string();
            (scheme, program, plugin)
        })
        .collect();
    let rules = tool_rules(&resolved.tools.found, host);
    let resources = settings.resources.map(Path::to_path_buf);
    let mut protected = protected(host, settings.install, extra_protected);
    protected.extend(resources.clone());
    let box_homes = host.box_homes();
    let compiled = compile(&Run {
        profile: &resolved,
        policy: Some(&resolved.policy),
        tool_rules: &rules,
        workspace,
        instance,
        home: &host.home,
        box_homes: &box_homes,
        trusted: source.trusted,
        protected: &protected,
        resources: resources.as_deref(),
        search_path: &host.search_path,
        resolve: &resolved_path,
        root: host.root,
    })?;
    Ok(CompiledRun {
        compiled,
        resolved,
        hooks,
        #[cfg(any(test, feature = "test-support"))]
        discovery: sources.discovery,
        packs,
        plugins,
        sources: declared,
    })
}

/// Import each `[[storage.hooks]]` row's hooks, and record each script they run, which the
/// compile permits the box to read.
fn import_hooks(resolved: &mut Resolved, home: &Path) -> Vec<crate::storage_hooks::Imported> {
    let imports: Vec<crate::storage_hooks::Imported> = resolved
        .storage
        .hooks
        .iter()
        .map(|row| crate::storage_hooks::import(row, &resolved.storage.refusals, home))
        .collect();
    for script in imports.iter().flat_map(|imported| &imported.scripts) {
        if !resolved.storage.hook_scripts.contains(script) {
            resolved.storage.hook_scripts.push(script.clone());
        }
    }
    imports
}

/// Refuse a `<workspace>/.box` that is a link or a file.
pub(crate) fn refuse_linked_project_configuration(workspace: &Path) -> Result<(), Error> {
    let configuration = workspace.join(PROJECT_CONFIGURATION);
    if std::fs::symlink_metadata(&configuration).is_ok_and(|metadata| !metadata.is_dir()) {
        return Err(Error::ProjectConfiguration {
            path: configuration,
        });
    }
    Ok(())
}

fn resolved_path(path: &Path) -> PathBuf {
    resolved(path)
}

/// Runs profiles from the operator's box home.
#[derive(Debug, Clone)]
pub struct Launcher {
    host: Host,
    /// `box`'s resources directory, as `resources::root` finds it.
    resources: Option<PathBuf>,
    /// The installed package directory of the running `box`.
    install: Option<PathBuf>,
    scratch: PathBuf,
    display: Display,
    banner: Option<bool>,
    terminal: bool,
}

/// One compiled run, ready to hand to the engine.
#[derive(Debug, Clone)]
pub struct Launch {
    name: String,
    home: PathBuf,
    reused: bool,
    moved: Option<(PathBuf, PathBuf)>,
    profile_name: String,
    profile: PathBuf,
    config: PathBuf,
    skipped: Vec<(String, String)>,
    journal: PathBuf,
    not_copied: Vec<(String, String)>,
    synced: Vec<String>,
    mcp_unstarted: Vec<(String, String)>,
    mcp_servers: Vec<(String, String, String)>,
    mcp_imports: Vec<String>,
    mcp_dropped: Vec<(String, String, String, String)>,
    mcp_path_dropped: Vec<String>,
    mcp_skipped: Vec<(String, String, String)>,
    mcp_unread: Vec<(String, String)>,
    hooks: Vec<String>,
    project: Option<String>,
    mcp_names: Vec<String>,
    display: Display,
    policy: policy::ProfilePolicy,
    _claim: Arc<RunClaim>,
}

/// A run's lock on its run folder, shared with the telemetry journal.
#[derive(Debug)]
struct RunClaim(std::fs::File);

impl Drop for RunClaim {
    /// Unlock the run folder, even while a forked child shares the file.
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

/// A run preparation result, installation identity, and observed context.
#[derive(Debug)]
pub struct Preparation {
    /// The prepared run, or the preparation error.
    pub result: Result<Launch, Error>,
    /// The immutable telemetry context, including observations made before an error.
    pub context: RunContext,
    /// The persistent installation ID, or `None` when unavailable.
    pub installation_id: Option<InstallationId>,
}

/// Open files that `box` keeps free beside the box locks.
const SPARE_FILES: u64 = 64;

/// Raise the soft limit on open files so that `count` box locks fit at once, or refuse before any
/// lock is taken.
fn room_for_locks(count: usize, command: &'static str) -> Result<(), Error> {
    use nix::sys::resource::{RLIM_INFINITY, Resource, getrlimit, setrlimit};
    let needed = u64::try_from(count)
        .unwrap_or(u64::MAX)
        .saturating_add(SPARE_FILES);
    let Ok((soft, hard)) = getrlimit(Resource::RLIMIT_NOFILE) else {
        return Ok(());
    };
    if soft >= needed
        || (hard >= needed && setrlimit(Resource::RLIMIT_NOFILE, needed, hard).is_ok())
    {
        return Ok(());
    }
    Err(Error::TooManyBoxes {
        command,
        count,
        limit: if hard == RLIM_INFINITY { soft } else { hard },
    })
}

/// Saved boxes that `box profile clean` holds until it removes them.
#[derive(Debug)]
pub struct HeldBoxes {
    held: Vec<(PathBuf, Option<std::fs::File>)>,
}

impl HeldBoxes {
    /// How many boxes are held.
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether no box is held.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Remove each held box. `removed` counts the removed folders, also when a removal fails.
    pub fn remove(self, removed: &mut usize) -> Result<(), Error> {
        for (path, lock) in &self.held {
            if remove_held(path, lock)? {
                *removed += 1;
            }
        }
        Ok(())
    }
}

/// What `box clean --all` removed and kept.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Cleaned {
    /// How many run folders were removed.
    pub removed: usize,
    /// The running boxes that were kept.
    pub running: Vec<String>,
}

impl Launcher {
    /// Run profiles for this process's own operator.
    pub fn from_host() -> Self {
        Self {
            host: Host::current(),
            // A unit test's host has a stand-in home, while Box Core's policy check reads the real
            // `HOME`, which can hold the checkout and so the source tree's resources. The engine
            // tests run the real `box`, which protects them.
            resources: if cfg!(test) {
                None
            } else {
                resources::root().ok()
            },
            install: install_root(),
            scratch: std::env::temp_dir(),
            display: Display::Direct,
            banner: None,
            terminal: false,
        }
    }

    /// Show the banner when all standard streams are terminals, as `flag` says, or else as
    /// `[banner] enabled` in the profile or in `~/.strands/box/config.toml` says. It is on when none
    /// of them sets it.
    pub fn banner(mut self, flag: Option<bool>) -> Self {
        self.banner = flag;
        self.terminal = terminal::attached();
        self
    }

    /// The banner choice of the flags, or `None` when no flag sets it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn banner_flag(&self) -> Option<bool> {
        self.banner
    }

    #[cfg(test)]
    pub(crate) fn at_terminal(mut self) -> Self {
        self.terminal = true;
        self
    }

    /// The display of a run of `profile`, after the whole of `~/.strands/box/config.toml` is checked.
    fn display_for(&self, profile: &Profile) -> Result<Display, Error> {
        let lookup = lookup(&self.host)?;
        Menu::load(&lookup)?;
        crate::policy_starter::PolicyMenu::check_config(&lookup)?;
        let user = crate::starter::banner_enabled(&lookup)?;
        Ok(display(self.terminal, self.banner, profile.banner(), user))
    }

    /// Protect no resources directory, for a host whose home is a stand-in: Box Core's policy
    /// check reads the real `HOME`, which can hold the source tree's resources.
    #[cfg(any(test, feature = "test-support"))]
    pub fn without_resources(mut self) -> Self {
        self.resources = None;
        self
    }

    /// Put the run folders under `directory`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn scratch(mut self, directory: impl Into<PathBuf>) -> Self {
        self.scratch = directory.into();
        self
    }

    /// Read the host home at `home` instead of `HOME`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn home(mut self, home: impl Into<PathBuf>) -> Self {
        // Box Core's policy check reads the real `HOME`, which can hold this test binary.
        self.host.set_home(home.into());
        self.install = None;
        self
    }

    #[cfg(test)]
    pub(crate) fn box_home(mut self, box_home: impl Into<PathBuf>) -> Self {
        self.host.box_home = box_home.into();
        self
    }

    /// Read only `variables` as the environment of `box`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn environment(mut self, variables: &[(&str, &str)]) -> Self {
        self.host.variables = Some(
            variables
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
        );
        self
    }

    /// Answer the command `argv` with `output` instead of running it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn command_output(mut self, argv: &[&str], output: &str) -> Self {
        self.host.answers.push((
            argv.iter().map(|part| part.to_string()).collect(),
            output.to_string(),
        ));
        self
    }

    /// Find programs on `search_path` instead of the `PATH` of `box`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn search_path(mut self, search_path: impl Into<OsString>) -> Self {
        self.host.search_path = search_path.into();
        self
    }

    /// The profile that `argument` names: a profile name, or the path of a profile file.
    /// `workspace` is the real path of the project.
    pub(crate) fn locate(
        &self,
        argument: &str,
        workspace: &Path,
        mut observe: impl FnMut(&[u8]),
    ) -> Result<Located, Error> {
        let profiles = self.profiles();
        if !is_profile_path(argument) {
            crate::profile::validate_name(argument)?;
            refuse_owned_name(&self.host.box_home, argument)?;
            let Some((profile, policy)) = profiles.load_observed(argument, &mut observe)? else {
                return Err(missing(&profiles, argument, &lookup(&self.host)?));
            };
            return Ok(Located {
                name: argument.to_string(),
                profile,
                policy,
                file: None,
            });
        }
        let unreadable = |source| Error::ProfilePath {
            path: PathBuf::from(argument),
            source,
        };
        let file = std::fs::canonicalize(argument).map_err(unreadable)?;
        let text = std::fs::read_to_string(&file).map_err(unreadable)?;
        observe(text.as_bytes());
        let profile = Profile::parse(&text, &file)?;
        let name = profile
            .declared_name()
            .ok_or_else(|| Error::ProfileFileUnnamed { path: file.clone() })?
            .to_string();
        crate::profile::validate_name(&name)?;
        if profiles.contains(&name)? {
            return Err(Error::ProfileNameTaken {
                name: name.clone(),
                path: file,
                owner: profiles.path(&name),
            });
        }
        let record = name_record(&self.host.box_home, &name);
        if let Ok(owner) = std::fs::read_to_string(&record) {
            let owner = PathBuf::from(owner.trim_end());
            if owner != file {
                return Err(if still_owns(&owner, &name) {
                    Error::ProfileNameTaken {
                        name,
                        path: file,
                        owner,
                    }
                } else {
                    owned(name, owner, record)
                });
            }
        }
        refuse_in_workspace(&file, workspace)?;
        refuse_shared(&file)?;
        for policy in profile.policy_files()? {
            refuse_in_workspace(&policy, workspace)?;
            refuse_shared(&policy)?;
        }
        let policy = profile.load_policies()?;
        Ok(Located {
            name,
            profile,
            policy,
            file: Some(file),
        })
    }

    /// Record that the profile file `file` owns the name `name`.
    fn claim_name(&self, name: &str, file: &Path) -> Result<(), Error> {
        let record = name_record(&self.host.box_home, name);
        if let Some(folder) = record.parent() {
            create_real_directory(folder, box_home_base(&self.host.home, &self.host.box_home))?;
        }
        replace(&record, &format!("{}\n", file.display()))
    }

    /// The operator's profiles.
    pub fn profiles(&self) -> Profiles {
        Profiles::at(profiles_root(&self.host.box_home))
    }

    /// The text of `box help agent`, which names the guide that ships with this `box`.
    pub fn agent_help(&self) -> Result<String, Error> {
        let resources = resources::root()?;
        let profiles = self.profiles();
        let names: Vec<String> = profiles
            .list()?
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        crate::profile_guide::help(&resources, &self.host.box_home, profiles.root(), &names)
    }

    /// The directory that holds one folder for each run.
    pub fn runs_root(&self) -> PathBuf {
        runs_root(&self.host.box_home)
    }

    /// Print saved policy decisions without loading a profile or starting a run.
    pub fn records(
        &self,
        id: &str,
        options: &crate::RecordsOptions,
        output: &mut impl std::io::Write,
        warnings: &mut impl std::io::Write,
    ) -> Result<(), Error> {
        crate::records::show(
            &self.host.home,
            &self.host.box_home,
            id,
            options,
            output,
            warnings,
        )
    }

    /// Print saved run IDs and profiles without changing a run or loading its profile. With
    /// `profile`, print only the runs that record that profile.
    pub fn list_runs(
        &self,
        profile: Option<&str>,
        format: crate::OutputFormat,
        output: &mut impl std::io::Write,
    ) -> Result<(), Error> {
        crate::run_list::show(
            &self.host.home,
            &self.host.box_home,
            profile,
            format,
            output,
        )
    }

    /// Whether `box run <profile> --box-id <id>` would reuse that run: every check that
    /// `--box-id` makes, with nothing changed on disk.
    pub fn reusable(&self, profile: &str, id: &str) -> bool {
        let runs = self.runs_root();
        std::fs::symlink_metadata(&runs).is_ok_and(|metadata| metadata.is_dir())
            && reusable_run(&runs, profile, id).is_ok()
    }

    /// Every run folder, by name.
    pub fn runs(&self) -> Result<Vec<String>, Error> {
        let root = self.runs_root();
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => return Err(io_error("list", &root, source)),
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter(|entry| {
                entry
                    .file_type()
                    .is_ok_and(|kind| kind.is_dir() || kind.is_symlink())
            })
            .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
            .collect();
        names.sort();
        Ok(names)
    }

    /// Check that `id` names one of the run folders that `runs` lists, and that its box is not
    /// running. Refuse it otherwise.
    pub fn find_run(&self, id: &str) -> Result<(), Error> {
        self.saved_box(id)?;
        hold(&self.runs_root(), id).map(drop)
    }

    /// Remove the run folder `id`, a link without its target. Refuse a box that is still running,
    /// and hold the lock until the folder is gone, so a box cannot start in it meanwhile.
    pub fn remove_run(&self, id: &str) -> Result<(), Error> {
        self.saved_box(id)?;
        let held = hold(&self.runs_root(), id)?;
        remove_held(&self.runs_root().join(id), &held)?;
        Ok(())
    }

    /// Refuse `id` unless it names one of the run folders that `runs` lists.
    fn saved_box(&self, id: &str) -> Result<(), Error> {
        if self.runs()?.iter().any(|name| name == id) {
            Ok(())
        } else {
            Err(Error::BoxUnknown {
                id: id.to_string(),
                root: self.runs_root(),
            })
        }
    }

    /// Remove every run folder whose box is not running. `cleaned` counts the removed folders and
    /// names the running boxes that were kept, also when a removal fails.
    pub fn remove_runs(&self, cleaned: &mut Cleaned) -> Result<(), Error> {
        let root = self.runs_root();
        for name in self.runs()? {
            let held = match hold(&root, &name) {
                Ok(held) => held,
                Err(Error::BoxRunning { id }) => {
                    cleaned.running.push(id);
                    continue;
                }
                Err(error) => return Err(error),
            };
            if remove_held(&root.join(name), &held)? {
                cleaned.removed += 1;
            }
        }
        Ok(())
    }

    /// The saved boxes of `profiles`, by ID, or every saved box when `profiles` is `None`. A box
    /// belongs to a profile when its ID is valid and its `profile-name` records `profile`,
    /// the same check that `box run --box-id` makes.
    pub fn profile_boxes(&self, profiles: Option<&[String]>) -> Result<Vec<String>, Error> {
        let Some(profiles) = profiles else {
            return self.runs();
        };
        for profile in profiles {
            crate::profile::validate_name(profile)?;
        }
        let root = self.runs_root();
        let mut owned = Vec::new();
        for id in self.runs()? {
            if !std::fs::symlink_metadata(root.join(&id)).is_ok_and(|metadata| metadata.is_dir()) {
                continue;
            }
            for profile in profiles {
                if owned_by(&root, &id, profile)? {
                    owned.push(id);
                    break;
                }
            }
        }
        Ok(owned)
    }

    /// Check that `id` is a saved box that `profile` owns, for `box profile clean --box-id`.
    pub fn profile_box(&self, profile: &str, id: &str) -> Result<(), Error> {
        crate::profile::validate_name(profile)?;
        if !is_run_id(id) {
            return Err(Error::RecordsId { id: id.to_string() });
        }
        let root = self.runs_root();
        if !std::fs::symlink_metadata(root.join(id)).is_ok_and(|metadata| metadata.is_dir()) {
            return Err(Error::BoxIdUnknown {
                id: id.to_string(),
                root,
            });
        }
        if !owned_by(&root, id, profile)? {
            return Err(Error::CleanBoxNotOwned {
                id: id.to_string(),
                profile: profile.to_string(),
            });
        }
        Ok(())
    }

    /// Hold every box in `ids` with the lock that a running box holds, so none can start until
    /// the boxes are removed or released. Refuse, and hold nothing, when one of them is running.
    /// `command` is the `box profile` command that the refusal tells the operator to run again.
    pub fn hold_boxes(&self, ids: &[String], command: &'static str) -> Result<HeldBoxes, Error> {
        room_for_locks(ids.len(), command)?;
        let root = self.runs_root();
        let mut held = Vec::new();
        let mut running = Vec::new();
        for id in ids {
            match hold(&root, id) {
                Ok(lock) => held.push((root.join(id), lock)),
                Err(Error::BoxRunning { id }) => running.push(id),
                Err(error) => return Err(error),
            }
        }
        match running.as_slice() {
            [] => {}
            [id] => {
                return Err(Error::CleanBoxRunning {
                    command,
                    id: id.clone(),
                });
            }
            _ => {
                return Err(Error::BoxesRunning {
                    command,
                    ids: running.join(", "),
                });
            }
        }
        Ok(HeldBoxes { held })
    }

    /// The storage folder of `profile`: its namespaces, and the record of the profile file that owns
    /// its name.
    pub fn storage_folder(&self, profile: &str) -> PathBuf {
        self.host.box_home.join("storage").join(profile)
    }

    /// The names of the storage folders, sorted.
    pub fn stored_profiles(&self) -> Result<Vec<String>, Error> {
        let root = self.host.box_home.join("storage");
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => return Err(io_error("list", &root, source)),
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
            .filter(|name| crate::profile::validate_name(name).is_ok())
            .collect();
        names.sort();
        Ok(names)
    }

    /// Whether `profile` has storage that `box profile reset` would remove: an entry in its storage
    /// folder other than the record of the profile file that owns its name.
    pub fn has_storage(&self, profile: &str) -> Result<bool, Error> {
        Ok(!self.storage_entries(profile)?.is_empty())
    }

    /// Remove the storage of `profile`, and keep the record of the profile file that owns its
    /// name, so the name stays bound to that file.
    pub fn reset_storage(&self, profile: &str) -> Result<(), Error> {
        crate::profile::validate_name(profile)?;
        for entry in self.storage_entries(profile)? {
            remove_if_present(&entry)?;
        }
        Ok(())
    }

    /// Remove the whole storage folder of `profile`, and return whether it existed.
    pub fn remove_storage(&self, profile: &str) -> Result<bool, Error> {
        crate::profile::validate_name(profile)?;
        remove_if_present(&self.storage_folder(profile))
    }

    fn storage_entries(&self, profile: &str) -> Result<Vec<PathBuf>, Error> {
        let folder = self.storage_folder(profile);
        if !std::fs::symlink_metadata(&folder).is_ok_and(|metadata| metadata.is_dir()) {
            return Ok(Vec::new());
        }
        let entries =
            std::fs::read_dir(&folder).map_err(|source| io_error("list", &folder, source))?;
        Ok(entries
            .flatten()
            .filter(|entry| entry.file_name() != PROFILE_SOURCE)
            .map(|entry| entry.path())
            .collect())
    }

    /// Prepare a run and preserve its installation ID and context on success or failure.
    pub fn prepare_with_context(
        &self,
        name: &str,
        workspace: &Path,
        box_id: Option<&str>,
    ) -> Preparation {
        let mut observations = Observations::default();
        let installation_id = self.installation_id();
        let result = self.prepare_observed(name, workspace, box_id, Some(&mut observations));
        Preparation {
            result,
            context: observations.finish(),
            installation_id,
        }
    }

    /// The telemetry context for a failure before profile preparation.
    pub fn failed_preparation(&self, error: Error) -> Preparation {
        Preparation {
            result: Err(error),
            context: Observations::default().finish(),
            installation_id: self.installation_id(),
        }
    }

    fn installation_id(&self) -> Option<InstallationId> {
        let box_dir = self.installation_dir()?;
        self.consent(&box_dir)
            .enabled
            .then(|| InstallationId::load_or_create(&box_dir).ok())
            .flatten()
    }

    /// `~/.strands/box`, which holds the installation metadata whatever `BOX_HOME` says.
    fn installation_dir(&self) -> Option<PathBuf> {
        self.host
            .home
            .is_absolute()
            .then(|| default_box_home(&self.host.home))
    }

    fn consent(&self, box_dir: &Path) -> Consent {
        Consent::resolve(box_dir, |name| self.host.variable_os(name))
    }

    /// Save `choice` when one is given, then print whether telemetry is on and why.
    pub fn telemetry(&self, choice: Option<bool>, output: &mut impl Write) -> Result<(), Error> {
        let box_dir = self.installation_dir().ok_or(Error::NoHome)?;
        if let Some(enabled) = choice {
            save_telemetry_choice(&box_dir, enabled).map_err(|source| Error::Io {
                action: "write",
                path: box_dir.join("installation.toml"),
                source,
            })?;
        }
        let consent = self.consent(&box_dir);
        let state = if consent.enabled { "on" } else { "off" };
        let reason = match consent.source {
            ConsentSource::BoxTelemetry => " (set by BOX_TELEMETRY)",
            ConsentSource::DoNotTrack => " (set by DO_NOT_TRACK)",
            ConsentSource::Saved => " (saved in ~/.strands/box/installation.toml)",
            ConsentSource::Default => "",
            ConsentSource::Unreadable => " (~/.strands/box/installation.toml can't be read)",
        };
        let mut message = format!("Telemetry is {state}{reason}.\n");
        if choice.is_some_and(|enabled| enabled != consent.enabled) {
            message.push_str(
                "Your choice is saved, but the environment overrides it in this shell.\n",
            );
        }
        output
            .write_all(message.as_bytes())
            .map_err(|source| Error::Io {
                action: "print to",
                path: PathBuf::from("standard output"),
                source,
            })
    }

    /// Compile the profile `name` for a run in `workspace`, and write the run's files. The run is
    /// the earlier run `box_id` when one is given, and a new run otherwise.
    pub fn prepare(
        &self,
        argument: &str,
        workspace: &Path,
        box_id: Option<&str>,
    ) -> Result<Launch, Error> {
        self.prepare_observed(argument, workspace, box_id, None)
    }

    fn prepare_observed(
        &self,
        argument: &str,
        workspace: &Path,
        box_id: Option<&str>,
        mut observations: Option<&mut Observations>,
    ) -> Result<Launch, Error> {
        if !cfg!(any(target_os = "macos", target_os = "linux")) {
            return Err(Error::UnsupportedPlatform);
        }
        let home = &self.host.home;
        if home.as_os_str().is_empty() {
            return Err(Error::NoHome);
        }
        let workspace = canonical(workspace)
            .filter(|workspace| workspace.is_dir())
            .ok_or_else(|| Error::Project {
                path: workspace.to_path_buf(),
            })?;
        let Located {
            name,
            profile,
            policy,
            file,
        } = self.locate(argument, &workspace, |bytes| {
            if let Some(observations) = observations.as_deref_mut() {
                observations.profile(bytes);
            }
        })?;
        let name = name.as_str();
        let launcher = Self {
            display: self.display_for(&profile)?,
            ..self.clone()
        };
        let starting = startup::Startup::start("Resolving profile and tools");
        let phase = |label: &str| {
            if let Some(starting) = &starting {
                starting.phase(label);
            }
        };
        refuse_linked_project_configuration(&workspace)?;
        refuse_workspace_holding_profiles(&self.host.box_home, &workspace)?;
        let trusted = profile_file_protections(file.as_deref(), &profile, &workspace)?;
        let extra: Vec<PathBuf> = trusted.clone();
        let runs = runs_root(&self.host.box_home);
        let base = box_home_base(&self.host.home, &self.host.box_home);
        let (instance, reused, mut minted) = match box_id {
            Some(id) => (existing(&runs, base, name, id)?, true, None),
            None => {
                let (instance, claim) = mint_claimed(&runs, name, base)?;
                (instance, false, Some(claim))
            }
        };
        let prepared = (|| {
            let claim = minted.take().map_or_else(|| claim(&instance), Ok)?;
            let run = compile_run(
                Loaded {
                    profile: &profile,
                    name,
                    policy: policy.as_deref(),
                    trusted: &trusted,
                    by_path: file.is_some(),
                },
                &self.host,
                &workspace,
                &instance,
                &extra,
                &process_env,
                RunSettings {
                    display: launcher.display,
                    observations: observations.as_deref_mut(),
                    resources: launcher.resources.as_deref(),
                    install: launcher.install.as_deref(),
                },
            )?;
            let refresh = policy::ProfilePolicy::new(
                launcher.clone(),
                file.as_ref()
                    .map_or_else(|| argument.to_string(), |file| file.display().to_string()),
                file.as_deref(),
                workspace.clone(),
                instance.clone(),
                extra.clone(),
                &run,
            );
            let CompiledRun {
                compiled,
                resolved,
                hooks,
                ..
            } = run;
            let moved = if reused {
                recorded_workspace(&instance.directory.join("box.toml"))?
                    .filter(|last| *last != workspace)
                    .map(|last| (last, workspace.clone()))
            } else {
                None
            };
            phase("Checking policy");
            let config = if reused {
                self.check_in_scratch(&compiled, &resolved)?;
                let config = instance.directory.join("box.toml");
                replace(&config, &compiled.box_toml)?;
                replace(&instance.directory.join(POLICY_FILE), &compiled.policy)?;
                config
            } else {
                write_and_check(&instance.directory, &compiled, &resolved)?.0
            };
            if cfg!(target_os = "linux") {
                create_real_directory(&workspace.join(PROJECT_CONFIGURATION), &workspace)?;
            }
            phase("Preparing files");
            prepare_storage(&compiled.storage, base)?;
            link_storage(&compiled.storage)?;
            if let Some(file) = &file {
                self.claim_name(name, file)?;
            }
            prepare_tool_scratch(&resolved, &instance.directory)?;
            let Copied { not_copied, synced } =
                copy_files(&compiled.storage, &instance.directory, home, base)?;
            let hooks = apply_hooks(&compiled.storage, &hooks, home)?;
            let mut mcp_imports = Vec::new();
            for config in &resolved.servers.configs {
                let path = tilde(home, &config.target.path);
                match config.copy_if_absent(base, &instance.directory)? {
                    Import::Empty | Import::Kept => {}
                    Import::Imported => {
                        mcp_imports.push(format!("Imported MCP settings into {path}."));
                    }
                    Import::Different {
                        missing,
                        changed,
                        extra,
                    } => {
                        let detail = [
                            ("missing", missing),
                            ("changed", changed),
                            ("saved only", extra),
                        ]
                        .into_iter()
                        .filter(|(_, names)| !names.is_empty())
                        .map(|(label, names)| {
                            let names = names
                                .iter()
                                .map(|name| format!("{name:?}"))
                                .collect::<Vec<_>>()
                                .join(", ");
                            format!("{label} {names}")
                        })
                        .collect::<Vec<_>>()
                        .join("; ");
                        mcp_imports.push(format!(
                            "Saved MCP settings in {path} differ from the current import: {detail}. Kept unchanged; see docs/cli/troubleshooting.md for refresh steps."
                        ));
                    }
                    Import::InvalidSection => {
                        mcp_imports.push(format!(
                            "Saved MCP settings in {path} have a non-table {:?} section. Kept unchanged; see docs/cli/troubleshooting.md for refresh steps.",
                            config.target.key.join(".")
                        ));
                    }
                    Import::Skipped => {
                        mcp_imports.push(format!(
                            "Did not import MCP settings into {path}: the target is a link or not a regular file."
                        ));
                    }
                }
            }
            if let Some(observations) = observations {
                observations.mcp(&self.host.box_home, &resolved.servers.targets);
            }
            let project = project_notice(name, resolved.project, &tilde(home, &profile.path));
            Ok(Launch {
                name: instance.name.clone(),
                home: home.clone(),
                reused,
                moved,
                profile_name: name.to_string(),
                profile: profile.path,
                config,
                journal: compiled.journal,
                skipped: resolved.tools.skipped,
                not_copied,
                synced,
                mcp_unstarted: compiled.unstarted,
                mcp_servers: resolved.servers.detected_lines(home),
                mcp_imports,
                mcp_dropped: resolved.servers.dropped_lines(home),
                mcp_path_dropped: compiled.path_dropped,
                mcp_skipped: resolved.servers.skipped_lines(home),
                mcp_unread: resolved.servers.unread_lines(home),
                hooks,
                project,
                mcp_names: resolved.mcp.keys().cloned().collect(),
                display: launcher.display,
                policy: refresh,
                _claim: Arc::new(RunClaim(claim)),
            })
        })();
        if prepared.is_err() && !reused {
            let _ = std::fs::remove_dir_all(&instance.directory);
        }
        prepared
    }
}

/// The line `box run` prints when the profile `name`, in the file `path`, gives less than read
/// and write on the project.
fn project_notice(name: &str, project: Option<Project>, path: &str) -> Option<String> {
    let Some(project) = project else {
        return Some(format!(
            "profile {name} gives the agent no access to this project; to allow it, add \
             `[{PROJECT}] access = \"write\"` to {path}"
        ));
    };
    let reach = match project.access {
        ProjectAccess::Write => return None,
        ProjectAccess::Read => "can read but not change",
        ProjectAccess::None => "can't read or change",
    };
    Some(format!(
        "the agent {reach} this project (`[{PROJECT}] access = {:?}` in {path})",
        project.access.name()
    ))
}

/// Create each storage directory, never through a link.
pub(crate) fn prepare_storage(storage: &Storage, home: &Path) -> Result<(), Error> {
    for directory in storage
        .directories
        .iter()
        .chain(&storage.tool_states)
        .chain(&storage.launcher_caches)
    {
        create_real_directory(directory, home)?;
    }
    Ok(())
}

/// Bring each link row of a tool's `[[storage.files]]` up to date with its source: make a missing
/// link, point a link at a new source, and remove a link whose source is gone. In a
/// `link-children` folder, a link to anything but an entry of the source is removed. What the tool
/// put there that is not a link stays, and no folder on the way is a link, so a box that changed
/// the tool's storage cannot point a new link elsewhere.
pub(crate) fn link_storage(storage: &Storage) -> Result<(), Error> {
    for link in &storage.links {
        let parent = link.target.parent().unwrap_or(&link.root);
        if !link.children {
            if std::fs::symlink_metadata(&link.source).is_err() {
                if is_link(&link.target) && is_real_path(parent, &link.root) {
                    remove_link(&link.target)?;
                }
                continue;
            }
            create_real_directory(parent, &link.root)?;
            set_link(&link.source, &link.target)?;
            continue;
        }
        let mut names = std::collections::BTreeSet::new();
        if std::fs::metadata(&link.source).is_ok_and(|metadata| !metadata.is_dir()) {
            return Err(Error::Copy {
                path: link.source.clone(),
                reason: format!(
                    "`{} mode = \"link-children\"` needs a folder, and this is a file; use \
                     `mode = \"link\"`",
                    link.at
                ),
            });
        }
        match std::fs::read_dir(&link.source) {
            Ok(entries) => {
                create_real_directory(&link.target, &link.root)?;
                for entry in entries {
                    let entry = entry.map_err(|source| io_error("list", &link.source, source))?;
                    set_link(&entry.path(), &link.target.join(entry.file_name()))?;
                    names.insert(entry.file_name());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !is_real_path(&link.target, &link.root) {
                    continue;
                }
            }
            Err(source) => return Err(io_error("list", &link.source, source)),
        }
        let made = std::fs::read_dir(&link.target)
            .map_err(|source| io_error("list", &link.target, source))?;
        for entry in made {
            let entry = entry.map_err(|source| io_error("list", &link.target, source))?;
            if !names.contains(&entry.file_name()) && is_link(&entry.path()) {
                remove_link(&entry.path())?;
            }
        }
    }
    Ok(())
}

/// Make `target` a link to `source`. A link elsewhere is replaced, and anything else at `target`
/// stays.
fn set_link(source: &Path, target: &Path) -> Result<(), Error> {
    match std::fs::symlink_metadata(target) {
        Ok(metadata) if !metadata.file_type().is_symlink() => return Ok(()),
        Ok(_) if std::fs::read_link(target).is_ok_and(|to| to == source) => return Ok(()),
        Ok(_) => remove_link(target)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error("inspect", target, error)),
    }
    match std::os::unix::fs::symlink(source, target) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(io_error("link", target, error)),
    }
}

/// Create each tool's own temporary folder in the run's directory `run`, never through a link,
/// and start it empty. A link inside it is removed, never followed.
pub(crate) fn prepare_tool_scratch(resolved: &Resolved, run: &Path) -> Result<(), Error> {
    for (name, process) in &resolved.tool {
        let folder = crate::tool::scratch(run, name);
        if process.env.get("TMPDIR").map(Path::new) != Some(folder.as_path()) {
            continue;
        }
        create_real_directory(&folder, run)?;
        let entries =
            std::fs::read_dir(&folder).map_err(|source| io_error("list", &folder, source))?;
        for entry in entries {
            let entry = entry.map_err(|source| io_error("list", &folder, source))?;
            remove_if_present(&entry.path())?;
        }
    }
    Ok(())
}

/// Write each row's imported hooks into its copy, under the storage lock, and return the report
/// lines.
pub(crate) fn apply_hooks(
    storage: &Storage,
    imports: &[crate::storage_hooks::Imported],
    home: &Path,
) -> Result<Vec<String>, Error> {
    if storage.hooks.is_empty() {
        return Ok(Vec::new());
    }
    let _lock = storage_sync::lock(&storage.root, SYNC_LOCK_WAIT)?;
    let mut lines = Vec::new();
    for (row, imported) in storage.hooks.iter().zip(imports) {
        lines.extend(imported.notes.iter().cloned());
        for (hook, why) in &imported.refused {
            lines.push(format!("did not import the hook {hook}: {why}"));
        }
        for script in &imported.scripts {
            lines.push(format!(
                "imported hooks run {}, and the policy permits its read",
                tilde(home, script)
            ));
        }
        if let Some(line) = crate::storage_hooks::apply(row, imported, home)? {
            lines.push(line);
        }
    }
    Ok(lines)
}

/// What `box profile show` prints for the copies.
struct CopyLines {
    /// Each copy as `(source, target, what the run does)`.
    copies: Vec<(String, String, String)>,
    /// Each link a copy follows or leaves out, as `(link, what happens)`.
    links: Vec<(String, String)>,
    /// Each part of a file that a copy keeps, drops, lacks, or sets, as `(what, target, names)`.
    parts: Vec<(String, String, Vec<storage_edit::KeyPath>)>,
}

fn describe_copies(storage: &Storage, home: &Path) -> Result<CopyLines, Error> {
    let mut copies = Vec::new();
    let mut links: Vec<_> = storage
        .skipped
        .iter()
        .map(|(path, reason)| (tilde(home, path), format!("not copied: {reason}")))
        .collect();
    let mut parts = Vec::new();
    let record = if storage.files.iter().any(|file| file.sync) {
        storage_sync::load(&storage.root)?
    } else {
        storage_sync::Record::default()
    };
    for file in &storage.files {
        if file.sync && std::fs::symlink_metadata(&file.target).is_ok() {
            let update = storage_sync::update(
                file,
                record.row(&file.relative),
                &storage.refusals,
                &storage.root,
                false,
            )?;
            links.extend(
                update
                    .skipped
                    .iter()
                    .map(|(path, why)| (tilde(home, path), format!("not copied: {why}"))),
            );
            copies.push((
                tilde(home, &file.source),
                file.relative.clone(),
                update.summary(),
            ));
            continue;
        }
        let state = copy_state(file, storage)?;
        let what = match &state {
            State::InStorage => "already in storage".to_string(),
            State::NothingKept => "holds none of the settings it keeps".to_string(),
            State::Fill { kept, .. } => {
                if !kept.kept.is_empty() {
                    parts.push((
                        "fills".to_string(),
                        file.relative.clone(),
                        kept.kept.clone(),
                    ));
                }
                "already in storage".to_string()
            }
            State::Absent if file.edit.as_ref().is_some_and(|edit| !edit.set.is_empty()) => {
                "absent on this host, so it will hold only what it sets".to_string()
            }
            State::Absent => "absent on this host".to_string(),
            State::WillCopy(plan) => {
                if let Some(kept) = &plan.kept {
                    for (what, paths) in [
                        ("keeps", &kept.kept),
                        ("drops", &kept.dropped),
                        ("missing", &kept.missing),
                    ] {
                        let fills = file.edit.as_ref().is_some_and(|edit| edit.fill);
                        if !paths.is_empty() && !(fills && what == "drops") {
                            parts.push((what.to_string(), file.relative.clone(), paths.clone()));
                        }
                    }
                }
                links.extend(plan.followed.iter().map(|(path, target)| {
                    (
                        tilde(home, &file.source.join(path)),
                        format!("follows the link to {}", tilde(home, target)),
                    )
                }));
                links.extend(plan.skipped.iter().map(|(path, why)| {
                    (
                        tilde(home, &file.source.join(path)),
                        format!("not copied: {why}"),
                    )
                }));
                "will copy".to_string()
            }
        };
        if let Some(edit) = &file.edit
            && !edit.set.is_empty()
        {
            let keys: Vec<_> = edit.set.iter().map(|setting| setting.key.clone()).collect();
            parts.push(("sets".to_string(), file.relative.clone(), keys));
        }
        copies.push((tilde(home, &file.source), file.relative.clone(), what));
    }
    Ok(CopyLines {
        copies,
        links,
        parts,
    })
}

/// What a run of one profile in one workspace would get, without starting it.
#[derive(Debug, Clone)]
pub struct Preview {
    /// The `box.toml` the run would write.
    pub box_toml: String,
    /// The `policy.dw` the run would write.
    pub policy: String,
    /// Every option and variable the run reads, as `(name, value, source)`.
    pub inputs: Vec<(String, String, String)>,
    /// Each pack the profile uses, as `(name, version)`, in the order `packs` and `extend` name
    /// them.
    pub packs: Vec<(String, String)>,
    /// Each plugin the profile lists, as `(name, version)`, in the order of `plugins`.
    pub plugins: Vec<(String, String)>,
    /// Each declared secret source, as `(scheme, program, the plugin that declares it)`, with no
    /// plugin for a source of the profile.
    pub sources: Vec<(String, String, Option<String>)>,
    /// The policy files the profile names in `policies`.
    pub policies: Vec<String>,
    /// The storage directory of this profile.
    pub storage: PathBuf,
    /// The profile's `[project]`, or `None` when it has none.
    pub project: Option<Project>,
    /// Each tool the run leaves out, as `(tool, reason)`, where `tool` names its pack too.
    pub skipped: Vec<(String, String)>,
    /// Each path or helper of a kept tool that the host lacks, as `(tool, path)`.
    pub dropped: Vec<(String, String)>,
    /// Each `[[storage.files]]` copy, as `(source, target, action)`, where `action` is what the
    /// run does.
    pub copies: Vec<(String, String, String)>,
    /// Each link a copy follows or leaves out, as `(link, action)`.
    pub links: Vec<(String, String)>,
    /// Each part of a file that a copy keeps, drops, lacks, sets, or fills, as
    /// `(what, target, names)`, with each name as its key path. It names keys, never their values.
    pub parts: Vec<(String, String, Vec<storage_edit::KeyPath>)>,
    /// Each stdio MCP server that gets no permit to start, as `(server, reason)`.
    pub mcp_unstarted: Vec<(String, String)>,
    /// Each MCP server the run declares, as `(server, file, detail)`, where `file` is its source
    /// file and `detail` ends its report line with the variable its key comes from or the
    /// variables it gets.
    pub mcp_servers: Vec<(String, String, String)>,
    /// Each variable a declared MCP server goes without, as `(variable, server, file, reason)`.
    pub mcp_dropped: Vec<(String, String, String, String)>,
    /// Each entry of the operator's `PATH` that is not a full path, which `box` drops from each MCP
    /// server that inherits that `PATH`, as the end of its `dropped` line.
    pub mcp_path_dropped: Vec<String>,
    /// Each MCP server the run does not declare, as `(server, file, reason)`.
    pub mcp_skipped: Vec<(String, String, String)>,
    /// Each MCP source file the run does not read, as `(file, reason)`.
    pub mcp_unread: Vec<(String, String)>,
    /// Each warning that Box Core reports about the policy, in its own words.
    pub warnings: Vec<String>,
    /// Each route with no secret, which only opens its hosts, as `(route, destinations)`.
    pub open_routes: Vec<(String, Vec<String>)>,
}

impl Preview {
    /// The project access, as the `project` row of `box profile show` prints it.
    pub fn project_row(&self) -> &'static str {
        match self.project.map(|project| project.access) {
            Some(ProjectAccess::Write) => "read and write",
            Some(ProjectAccess::Read) => "read only",
            Some(ProjectAccess::None) => "none",
            None => "none (no [project] in this profile)",
        }
    }

    /// Each pack and its version, as `box profile show` prints them.
    pub fn pack_list(&self) -> String {
        versions(&self.packs)
    }

    /// Each part, as `(what, target, names)`, with the names as `box profile show` prints them.
    pub fn part_lines(&self) -> Vec<(&str, &str, String)> {
        self.parts
            .iter()
            .map(|(what, target, names)| {
                let names = names
                    .iter()
                    .map(|path| storage_edit::shown(path))
                    .collect::<Vec<_>>()
                    .join(", ");
                (what.as_str(), target.as_str(), names)
            })
            .collect()
    }

    /// The preview of the profile `name`, as `box profile show --format json` prints it, with the
    /// `box.toml` and `policy.dw` only when `full` is set.
    pub fn json(&self, name: &str, full: bool) -> Result<Value, Error> {
        let mut document = json!({
            "profile": name,
            "packs": rows(&self.packs, |(name, version)| {
                json!({"name": name, "version": version})
            }),
            "plugins": rows(&self.plugins, |(name, version)| {
                json!({"name": name, "version": version})
            }),
            "sources": rows(&self.sources, |(scheme, program, plugin)| {
                json!({"scheme": scheme, "program": program, "plugin": plugin})
            }),
            "policies": self.policies,
            "storage": self.storage.display().to_string(),
            "project": self.project,
            "inputs": rows(&self.inputs, |(name, value, source)| {
                json!({"name": name, "value": value, "source": source})
            }),
            "skipped": rows(&self.skipped, |(tool, reason)| {
                json!({"tool": tool, "reason": reason})
            }),
            "dropped": rows(&self.dropped, |(tool, path)| json!({"tool": tool, "path": path})),
            "open_routes": rows(&self.open_routes, |(route, destinations)| {
                json!({"route": route, "destinations": destinations})
            }),
            "copies": rows(&self.copies, |(source, target, action)| {
                json!({"source": source, "target": target, "action": action})
            }),
            "links": rows(&self.links, |(link, action)| json!({"link": link, "action": action})),
            "parts": rows(&self.parts, |(what, target, names)| {
                json!({"what": what, "target": target, "names": names})
            }),
            "mcp": {
                "unstarted": rows(&self.mcp_unstarted, |(server, reason)| {
                    json!({"server": server, "reason": reason})
                }),
                "servers": rows(&self.mcp_servers, |(server, file, detail)| {
                    json!({"server": server, "file": file, "detail": detail})
                }),
                "dropped": rows(&self.mcp_dropped, |(variable, server, file, reason)| {
                    json!({"variable": variable, "server": server, "file": file, "reason": reason})
                }),
                "path_dropped": self.mcp_path_dropped,
                "skipped": rows(&self.mcp_skipped, |(server, file, reason)| {
                    json!({"server": server, "file": file, "reason": reason})
                }),
                "unread": rows(&self.mcp_unread, |(file, reason)| {
                    json!({"file": file, "reason": reason})
                }),
            },
            "warnings": self.warnings,
        });
        if full {
            let box_toml =
                toml_edit::Document::parse(self.box_toml.as_str()).map_err(Error::Reread)?;
            document["box_toml"] = table_json(box_toml.as_table());
            document["policy"] = Value::from(self.policy.as_str());
        }
        Ok(document)
    }

    /// The lines that `box profile show` prints first, as `(label, text)`: the packs, the
    /// plugins, each declared secret source and the program it runs, the policies, storage, and
    /// project access.
    pub fn overview(&self) -> Vec<(&'static str, String)> {
        let mut lines = vec![("packs", self.pack_list())];
        if !self.plugins.is_empty() {
            lines.push(("plugins", versions(&self.plugins)));
        }
        for (scheme, program, plugin) in &self.sources {
            let owner = plugin.as_deref().unwrap_or("your profile");
            lines.push(("source", format!("{scheme}:// runs {program} ({owner})")));
        }
        if !self.policies.is_empty() {
            lines.push(("policies", self.policies.join(", ")));
        }
        lines.push(("storage", self.storage.display().to_string()));
        lines.push(("project", self.project_row().to_string()));
        lines
    }
}

/// A JSON array with one `row` for each item.
fn rows<T>(items: &[T], row: impl Fn(&T) -> Value) -> Value {
    items.iter().map(row).collect()
}

/// `table` as a JSON object in document order, with each TOML datetime as its text.
fn table_json(table: &toml_edit::Table) -> Value {
    Value::Object(
        table
            .iter()
            .map(|(key, item)| (key.to_string(), item_json(item)))
            .collect(),
    )
}

fn item_json(item: &toml_edit::Item) -> Value {
    match item {
        toml_edit::Item::None => Value::Null,
        toml_edit::Item::Value(value) => value_json(value),
        toml_edit::Item::Table(table) => table_json(table),
        toml_edit::Item::ArrayOfTables(tables) => tables.iter().map(table_json).collect(),
    }
}

fn value_json(value: &toml_edit::Value) -> Value {
    match value {
        toml_edit::Value::String(text) => Value::from(text.value().as_str()),
        toml_edit::Value::Integer(number) => Value::from(*number.value()),
        toml_edit::Value::Float(number) => Value::from(*number.value()),
        toml_edit::Value::Boolean(flag) => Value::from(*flag.value()),
        toml_edit::Value::Datetime(datetime) => Value::from(datetime.value().to_string()),
        toml_edit::Value::Array(values) => values.iter().map(value_json).collect(),
        toml_edit::Value::InlineTable(table) => Value::Object(
            table
                .iter()
                .map(|(key, value)| (key.to_string(), value_json(value)))
                .collect(),
        ),
    }
}

/// Each `(name, version)` of `files`, as `box profile show` lists them.
fn versions(files: &[(String, String)]) -> String {
    files
        .iter()
        .map(|(name, version)| format!("{name} {version}"))
        .collect::<Vec<_>>()
        .join(", ")
}

impl Launcher {
    /// Resolve and compile the profile `name` for `workspace`, and write nothing.
    pub fn preview(&self, argument: &str, workspace: &Path) -> Result<Preview, Error> {
        let workspace = canonical(workspace)
            .filter(|workspace| workspace.is_dir())
            .ok_or_else(|| Error::Project {
                path: workspace.to_path_buf(),
            })?;
        let Located {
            name,
            profile,
            policy,
            file,
        } = self.locate(argument, &workspace, |_| {})?;
        let name = name.as_str();
        let instance = preview_instance(&self.host.box_home);
        refuse_workspace_holding_profiles(&self.host.box_home, &workspace)?;
        let trusted = profile_file_protections(file.as_deref(), &profile, &workspace)?;
        let extra: Vec<PathBuf> = trusted.clone();
        let CompiledRun {
            compiled,
            resolved,
            packs,
            plugins,
            sources,
            ..
        } = compile_run(
            Loaded {
                profile: &profile,
                name,
                policy: policy.as_deref(),
                trusted: &trusted,
                by_path: file.is_some(),
            },
            &self.host,
            &workspace,
            &instance,
            &extra,
            &process_env,
            RunSettings {
                display: Display::Direct,
                observations: None,
                resources: self.resources.as_deref(),
                install: self.install.as_deref(),
            },
        )?;
        let CopyLines {
            copies,
            links,
            parts,
        } = describe_copies(&compiled.storage, &self.host.home)?;
        let home = &self.host.home;
        let warnings = self.check_in_scratch(&compiled, &resolved)?;
        Ok(Preview {
            warnings,
            open_routes: crate::compile::open_routes(&resolved.egress),
            mcp_unstarted: compiled.unstarted.clone(),
            packs,
            plugins,
            sources,
            policies: profile.policies(),
            copies,
            links,
            parts,
            mcp_servers: resolved.servers.detected_lines(home),
            mcp_dropped: resolved.servers.dropped_lines(home),
            mcp_path_dropped: compiled.path_dropped.clone(),
            mcp_skipped: resolved.servers.skipped_lines(home),
            mcp_unread: resolved.servers.unread_lines(home),
            box_toml: compiled.box_toml,
            policy: compiled.policy,
            inputs: resolved
                .inputs
                .into_iter()
                .map(|input| (input.name, input.value, input.source))
                .collect(),
            storage: compiled.storage.root,
            project: resolved.project,
            skipped: resolved.tools.skipped,
            dropped: resolved.tools.dropped,
        })
    }
}

impl Launcher {
    /// Check the policy of `compiled` from a private directory that the check then removes.
    fn check_in_scratch(
        &self,
        compiled: &Compiled,
        resolved: &Resolved,
    ) -> Result<Vec<String>, Error> {
        let scratch = tempfile::Builder::new()
            .prefix("box-show-")
            .tempdir_in(&self.scratch)
            .map_err(|source| io_error("create a directory in", &self.scratch, source))?;
        let checked = write_and_check(scratch.path(), compiled, resolved);
        let removed = scratch.path().to_path_buf();
        let closed = scratch
            .close()
            .map_err(|source| io_error("remove", &removed, source));
        let (_, warnings) = checked?;
        closed.map(|()| warnings)
    }
}

/// Write the `box.toml` and `policy.dw` of `compiled` into `directory`, each as a new file, check
/// the policy, and return the path of `box.toml` and the text of each warning.
fn write_and_check(
    directory: &Path,
    compiled: &Compiled,
    resolved: &Resolved,
) -> Result<(PathBuf, Vec<String>), Error> {
    let config = directory.join("box.toml");
    for (path, text) in [
        (&config, &compiled.box_toml),
        (&directory.join(POLICY_FILE), &compiled.policy),
    ] {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut file| file.write_all(text.as_bytes()))
            .map_err(|source| io_error("write", path, source))?;
    }
    let warnings = check::policy(&Checked {
        config: &config,
        profile: &resolved.policy,
        generated_ids: &compiled.generated_ids,
    })?;
    Ok((config, warnings))
}

fn missing(profiles: &Profiles, name: &str, lookup: &Lookup) -> Error {
    let menu = match Menu::load(lookup) {
        Ok(menu) => menu,
        Err(error) => return error,
    };
    let mut known: Vec<String> = profiles
        .list()
        .unwrap_or_default()
        .into_iter()
        .map(|entry| entry.name)
        .chain(
            menu.starters
                .iter()
                .map(|starter| short_name(starter).to_string()),
        )
        .filter(|known| known != name)
        .collect();
    known.sort();
    known.dedup();
    let close = closest(name, known.iter().map(String::as_str))
        .map(|close| format!("Did you mean {close}? "))
        .unwrap_or_default();
    let hint = if menu.named(lookup, name).is_some() {
        format!("Create it with `box profile create {name}`.")
    } else if menu.starters.is_empty() {
        format!("Create it with `box profile create {name} --with <agent>,<provider>`.")
    } else {
        let rows: Vec<(String, String)> = menu
            .starters
            .iter()
            .map(|starter| {
                let label = Starter::load(starter, lookup)
                    .map(|starter| starter.label)
                    .unwrap_or_else(|reason| format!("invalid: {reason}"));
                (
                    format!(
                        "box profile create {name} --with {}",
                        Menu::spelling(lookup, starter)
                    ),
                    label,
                )
            })
            .collect();
        format!(
            "{name} isn't a starter, so box can't tell which agent it runs. Create the profile \
             from one of these starters:\n{}",
            columns(&rows)
        )
    };
    Error::ProfileMissing {
        name: name.to_string(),
        path: profiles.path(name),
        hint: format!("{close}{hint}"),
    }
}

impl Launcher {
    /// Whether `name` is the name of a starter.
    pub fn is_starter(&self, name: &str) -> Result<bool, Error> {
        let lookup = lookup(&self.host)?;
        Ok(Menu::load(&lookup)?.named(&lookup, name).is_some())
    }

    /// Refuse a workspace that is the home or holds it.
    pub fn refuse_home_workspace(&self, workspace: &Path) -> Result<(), Error> {
        refuse_home_workspace(&self.host.home, workspace)
    }

    /// Each starter in menu order, with its label or why it does not load.
    pub fn starters(&self) -> Result<Vec<ListedStarter>, Error> {
        let lookup = lookup(&self.host)?;
        Ok(Menu::load(&lookup)?
            .starters
            .iter()
            .map(|starter| ListedStarter {
                name: Menu::spelling(&lookup, starter),
                label: Starter::load(starter, &lookup).map(|starter| starter.label),
            })
            .collect())
    }
}

/// One starter that `box profile list` shows.
#[derive(Debug, Clone)]
pub struct ListedStarter {
    /// The name that `box run` and `--with` take.
    pub name: String,
    /// Its label, or why its `starter.toml` does not load.
    pub label: Result<String, String>,
}

fn is_run_id(id: &str) -> bool {
    id.strip_prefix(ID_PREFIX).is_some_and(|digits| {
        digits.len() == ID_DIGITS
            && digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// Whether `id` has the form of Box Core's box identity: `box-` and 16 hexadecimal digits.
fn is_core_box_id(id: &str) -> bool {
    id.strip_prefix("box-").is_some_and(|digits| {
        digits.len() == 16
            && digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// The earlier run `id` under `runs`, when it is a run of `profile`.
pub(crate) fn existing(
    runs: &Path,
    base: &Path,
    profile: &str,
    id: &str,
) -> Result<Instance, Error> {
    create_real_directory(runs, base)?;
    reusable_run(runs, profile, id)
}

/// The earlier run `id` under `runs`, when it is a run of `profile`. It changes nothing on disk.
fn reusable_run(runs: &Path, profile: &str, id: &str) -> Result<Instance, Error> {
    let mut components = Path::new(id).components();
    let one_name = matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(_)), None)
    );
    let directory = runs.join(id);
    let config = directory.join("box.toml");
    let box_directory = directory.join("box");
    let real = |path: &Path| std::fs::symlink_metadata(path).ok();
    if !one_name
        || !real(&directory).is_some_and(|metadata| metadata.is_dir())
        || !real(&box_directory).is_some_and(|metadata| metadata.is_dir())
        || !real(&config).is_some_and(|metadata| metadata.is_file())
    {
        if is_core_box_id(id) {
            return Err(Error::BoxIdCore { id: id.to_string() });
        }
        return Err(Error::BoxIdUnknown {
            id: id.to_string(),
            root: runs.to_path_buf(),
        });
    }
    if !minted_by(&directory, id, profile)? {
        return Err(Error::BoxIdProfile {
            id: id.to_string(),
            profile: profile.to_string(),
        });
    }
    if recorded_workspace(&config)?.is_none() {
        return Err(Error::BoxIdUnknown {
            id: id.to_string(),
            root: runs.to_path_buf(),
        });
    }
    Ok(Instance {
        name: id.to_string(),
        directory,
        box_directory,
    })
}

/// The workspace that the run's `box.toml` at `config` names, or `None` when it names none.
fn recorded_workspace(config: &Path) -> Result<Option<PathBuf>, Error> {
    let text =
        std::fs::read_to_string(config).map_err(|source| io_error("read", config, source))?;
    Ok(toml::from_str::<toml::Value>(&text).ok().and_then(|value| {
        value
            .get("agent")?
            .get("workspace")?
            .as_str()
            .map(PathBuf::from)
    }))
}

/// Whether the saved box `id` in `runs` belongs to `profile`: `id` is a run ID, and the box's
/// `profile-name` record holds exactly `profile`. `box profile clean <name>`,
/// `box profile clean <name> --box-id <id>`, and `box runs list <name>` decide ownership with it.
pub(crate) fn owned_by(runs: &Path, id: &str, profile: &str) -> Result<bool, Error> {
    minted_by(&runs.join(id), id, profile)
}

/// The profile name in a `profile-name` `record`: a nonempty name followed by one newline, as
/// `box` writes it. `box runs list` shows this name.
pub(crate) fn profile_of(record: &str) -> Option<&str> {
    record
        .strip_suffix('\n')
        .filter(|profile| !profile.is_empty())
}

/// Whether a saved box `id` whose record holds `recorded` belongs to `profile`: `id` is a run ID
/// and [`profile_of`] the record is exactly `profile`. Every ownership check uses this rule.
pub(crate) fn owns(id: &str, recorded: Option<&str>, profile: &str) -> bool {
    is_run_id(id) && recorded == Some(profile)
}

/// Whether the run `id` in `directory` was minted for `profile`, by [`owns`].
fn minted_by(directory: &Path, id: &str, profile: &str) -> Result<bool, Error> {
    if !is_run_id(id) {
        return Ok(false);
    }
    let record = directory.join(PROFILE_RECORD);
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(&record)
    {
        Ok(file) => file,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(nix::libc::ELOOP) =>
        {
            return Ok(false);
        }
        Err(_) if std::fs::symlink_metadata(&record).is_ok_and(|metadata| !metadata.is_file()) => {
            return Ok(false);
        }
        Err(source) => return Err(io_error("read", &record, source)),
    };
    let metadata = file
        .metadata()
        .map_err(|source| io_error("read", &record, source))?;
    if !metadata.is_file() {
        return Ok(false);
    }
    let mut text = String::new();
    std::io::Read::read_to_string(&mut file, &mut text)
        .map_err(|source| io_error("read", &record, source))?;
    Ok(owns(id, profile_of(&text), profile))
}

/// Hold the run folder `name` in `runs` with the lock that `claim` takes, so a box that is still
/// running is refused. A link holds no box that `claim` accepts, so it needs no lock.
fn hold(runs: &Path, name: &str) -> Result<Option<std::fs::File>, Error> {
    let directory = runs.join(name);
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(&directory)
    {
        Ok(file) => file,
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(nix::libc::ELOOP | nix::libc::ENOTDIR)
            ) || error.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(source) => return Err(io_error("open", &directory, source)),
    };
    lock_run(file, &directory, || Error::BoxRunning {
        id: name.to_string(),
    })
    .map(Some)
}

/// Remove the run folder `path` while `_held` holds its lock, so no box starts in it meanwhile.
fn remove_held(path: &Path, _held: &Option<std::fs::File>) -> Result<bool, Error> {
    remove_if_present(path)
}

/// Take the lock that a box holds on its run folder for as long as it runs, or return `running`
/// when a box holds it.
fn lock_run(
    file: std::fs::File,
    directory: &Path,
    running: impl FnOnce() -> Error,
) -> Result<std::fs::File, Error> {
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(running()),
        Err(std::fs::TryLockError::Error(source)) => Err(io_error("lock", directory, source)),
    }
}

/// Hold `instance` for one run, so a second run of the same box ID is refused.
fn claim(instance: &Instance) -> Result<std::fs::File, Error> {
    let directory = &instance.directory;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(directory)
        .map_err(|source| io_error("open", directory, source))?;
    lock_run(file, directory, || Error::BoxIdRunning {
        id: instance.name.clone(),
    })
}

/// Replace `path` with `text`: write a new file beside it, then rename it over `path`.
fn replace(path: &Path, text: &str) -> Result<(), Error> {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let staging = path.with_file_name(format!(".{name}.new"));
    remove_if_present(&staging)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staging)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .map_err(|source| io_error("write", &staging, source))?;
    std::fs::rename(&staging, path).map_err(|source| io_error("replace", path, source))
}

/// A suffix of `ID_DIGITS` lowercase hexadecimal digits from `/dev/urandom`.
fn random_digits() -> Result<String, Error> {
    let source = Path::new("/dev/urandom");
    let mut bytes = [0_u8; ID_DIGITS / 2];
    std::fs::File::open(source)
        .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut bytes))
        .map_err(|error| io_error("read", source, error))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// A new instance under `runs`, without its lock.
#[cfg(test)]
pub(crate) fn mint(runs: &Path, profile: &str, base: &Path) -> Result<Instance, Error> {
    mint_claimed(runs, profile, base).map(|(instance, _)| instance)
}

/// A new instance under `runs`: a name no other run holds, its directory, and its `box_dir`, and
/// the lock on its directory, taken before the directory holds anything, so `box clean` keeps it.
pub(crate) fn mint_claimed(
    runs: &Path,
    profile: &str,
    base: &Path,
) -> Result<(Instance, std::fs::File), Error> {
    create_real_directory(runs, base)?;
    let mut last = None;
    for _ in 0..MINT_ATTEMPTS {
        let name = format!("{ID_PREFIX}{}", random_digits()?);
        debug_assert!(is_run_id(&name));
        let directory = runs.join(&name);
        match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {
                let Some(claim) = lock_new(&directory)? else {
                    last = Some((
                        directory,
                        std::io::Error::from(std::io::ErrorKind::AlreadyExists),
                    ));
                    continue;
                };
                let box_directory = directory.join("box");
                let record = directory.join(PROFILE_RECORD);
                let filled = std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&box_directory)
                    .map_err(|source| io_error("create", &box_directory, source))
                    .and_then(|()| {
                        std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(&record)
                            .and_then(|mut file| file.write_all(format!("{profile}\n").as_bytes()))
                            .map_err(|source| io_error("write", &record, source))
                    });
                if let Err(error) = filled {
                    let _ = std::fs::remove_dir_all(&directory);
                    return Err(error);
                }
                return Ok((
                    Instance {
                        name,
                        directory,
                        box_directory,
                    },
                    claim,
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last = Some((directory, error));
            }
            Err(source) => return Err(io_error("create", &directory, source)),
        }
    }
    let (directory, source) = last.expect("at least one attempt");
    Err(io_error("create", &directory, source))
}

/// Lock the run folder that `mint_claimed` just created. `None` when `box clean` took it first:
/// it holds the lock, or it removed the folder before the lock.
fn lock_new(directory: &Path) -> Result<Option<std::fs::File>, Error> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(directory)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error("open", directory, source)),
    };
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
        Err(std::fs::TryLockError::Error(source)) => {
            return Err(io_error("lock", directory, source));
        }
    }
    let held = file
        .metadata()
        .map_err(|source| io_error("inspect", directory, source))?;
    let same = std::fs::symlink_metadata(directory).is_ok_and(|now| {
        std::os::unix::fs::MetadataExt::ino(&now) == std::os::unix::fs::MetadataExt::ino(&held)
            && std::os::unix::fs::MetadataExt::dev(&now)
                == std::os::unix::fs::MetadataExt::dev(&held)
    });
    Ok(same.then_some(file))
}

impl Launch {
    /// The run's box ID, which is also its box name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the run reuses the box of an earlier run.
    pub fn reused(&self) -> bool {
        self.reused
    }

    /// The workspace this reused box was last set up for, and the one it runs in now, when
    /// they differ.
    pub fn moved(&self) -> Option<(&Path, &Path)> {
        self.moved
            .as_ref()
            .map(|(last, now)| (last.as_path(), now.as_path()))
    }

    /// The compiled `box.toml`.
    pub fn config(&self) -> &Path {
        &self.config
    }

    /// Each tool the run leaves out, as `(tool and pack, reason)`.
    pub fn skipped(&self) -> &[(String, String)] {
        &self.skipped
    }

    /// Each link or entry that a copy into storage left out, with the reason.
    pub fn not_copied(&self) -> &[(String, String)] {
        &self.not_copied
    }

    /// Each line about a copy that this run brought up to date with the host.
    pub fn synced(&self) -> &[String] {
        &self.synced
    }

    /// Each stdio MCP server that gets no permit to start, as `(name, reason)`.
    pub fn mcp_unstarted(&self) -> &[(String, String)] {
        &self.mcp_unstarted
    }

    /// Each MCP server the run declares, as `(name, source file, detail)`.
    pub fn mcp_servers(&self) -> &[(String, String, String)] {
        &self.mcp_servers
    }

    /// The MCP configuration import notices for this run.
    pub fn mcp_imports(&self) -> &[String] {
        &self.mcp_imports
    }

    /// Each variable a declared MCP server goes without, as `(variable, name, source file, reason)`.
    pub fn mcp_dropped(&self) -> &[(String, String, String, String)] {
        &self.mcp_dropped
    }

    /// Each entry of the operator's `PATH` that is not a full path, which `box` drops from each MCP
    /// server that inherits that `PATH`, as the end of its `dropped` line.
    pub fn mcp_path_dropped(&self) -> &[String] {
        &self.mcp_path_dropped
    }

    /// Each MCP server the run does not declare, as `(name, source file, reason)`.
    pub fn mcp_skipped(&self) -> &[(String, String, String)] {
        &self.mcp_skipped
    }

    /// Each MCP source file the run does not read, as `(file, reason)`.
    pub fn mcp_unread(&self) -> &[(String, String)] {
        &self.mcp_unread
    }

    /// Each line about the hooks that the run imports, refuses, grants, or removes.
    pub fn hooks(&self) -> &[String] {
        &self.hooks
    }

    /// The line that says the agent gets less than read and write on the project, if it does.
    pub fn project_notice(&self) -> Option<&str> {
        self.project.as_deref()
    }

    /// Where the run's records go.
    pub fn journal(&self) -> &Path {
        &self.journal
    }

    fn report(&self) {
        let name = &self.profile_name;
        for (link, why) in self.not_copied() {
            eprintln!("box: did not copy {link}: {why}");
        }
        for notice in self.synced() {
            eprintln!("box: {notice}");
        }
        for (tool, why) in self.skipped() {
            eprintln!("box: skipped tool {tool}: {why}");
        }
        for (server, why) in self.mcp_unstarted() {
            eprintln!("box: no permit to start MCP server {server}: {why}");
        }
        for (file, why) in self.mcp_unread() {
            eprintln!("box: did not read {file}: {why}");
        }
        for (server, file, detail) in self.mcp_servers() {
            eprintln!("box: MCP server {server} declared from {file}{detail}");
        }
        for notice in self.mcp_imports() {
            eprintln!("box: {notice}");
        }
        for (variable, server, file, why) in self.mcp_dropped() {
            eprintln!("box: dropped {variable} from MCP server {server} (from {file}): {why}");
        }
        for line in self.mcp_path_dropped() {
            eprintln!("box: dropped {line}");
        }
        for (server, file, why) in self.mcp_skipped() {
            eprintln!("box: no automatic MCP declaration for {server} (from {file}): {why}");
        }
        for line in self.hooks() {
            eprintln!("box: {line}");
        }
        if let Some(line) = self.project_notice() {
            eprintln!("box: {line}");
        }
        let id = self.name();
        if self.reused() {
            eprintln!(
                "box: running profile {name} with box ID {id} again (records: {})",
                self.journal().display()
            );
            if let Some((last, now)) = self.moved() {
                eprintln!(
                    "box: box ID {id} was last set up for {}; it now runs in {}",
                    last.display(),
                    now.display()
                );
            }
        } else {
            eprintln!(
                "box: running profile {name} with box ID {id} (records: {})",
                self.journal().display()
            );
            eprintln!("box: to reuse this box run: box run {name} --box-id {id}");
        }
        eprintln!("box: policy history: box runs history {id}");
    }

    /// The options every Box Core run of this launch starts from: its box ID, and defaults otherwise.
    pub(crate) fn run_options<'a>(&self) -> strands_box::RunOptions<'a> {
        strands_box::RunOptions {
            box_id: Some(self.name.clone()),
            ..Default::default()
        }
    }

    /// Run the engine, which appends `args` to the agent's command.
    pub fn run(self, args: &[OsString]) -> Result<ExitCode, Error> {
        self.run_inner(args)
    }

    /// Run the engine and finish telemetry with the box's instance lock retained.
    pub fn run_with_telemetry(
        self,
        args: &[OsString],
        telemetry: Option<Session>,
    ) -> Result<ExitCode, Error> {
        self.run_observed(telemetry, |launch| launch.run_inner(args))
    }

    fn run_observed(
        self,
        mut telemetry: Option<Session>,
        execute: impl FnOnce(&Self) -> Result<ExitCode, Error>,
    ) -> Result<ExitCode, Error> {
        if let Some(session) = telemetry.as_mut()
            && let Ok(journal) = Journal::start_locked(&self.journal, self._claim.clone())
        {
            session.observe(journal, ActionCatalog::new(self.mcp_names.iter().cloned()));
        }
        let result = execute(&self);
        let completed = Instant::now();
        if let Some(session) = telemetry {
            let outcome = if result.as_ref().is_ok_and(|code| *code == ExitCode::SUCCESS) {
                ExitOutcome::Zero
            } else {
                ExitOutcome::Nonzero
            };
            session.finish_with_timeout(completed, outcome, COMPLETION_BUDGET);
        }
        result
    }

    fn run_inner(&self, args: &[OsString]) -> Result<ExitCode, Error> {
        let result = if terminal::attached() {
            terminal::run(self, |options| {
                strands_box::run(self.config.clone(), args.to_vec(), options)
            })
        } else {
            self.report();
            Ok(strands_box::run(
                self.config.clone(),
                args.to_vec(),
                self.run_options(),
            ))
        };
        if !self.reused
            && !result.as_ref().is_ok_and(|code| *code == ExitCode::SUCCESS)
            && let Some(directory) = self.config.parent()
            && std::fs::remove_dir(directory.join("box")).is_ok()
            && let Err(error) = remove_if_present(directory)
        {
            eprintln!("box: could not remove unused run: {error}");
        }
        result
    }
}

/// Ask `question` before a removal, and refuse to go on without a yes or when `interactive` is
/// false.
pub fn confirm(
    question: &str,
    interactive: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<(), Error> {
    if !interactive {
        return Err(Error::Unconfirmed);
    }
    if answer_yes(question, input, output)? {
        Ok(())
    } else {
        Err(Error::Kept)
    }
}

/// Ask `question` with a `[y/N]` and read whether the answer is yes.
fn answer_yes(
    question: &str,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<bool, Error> {
    let _ = write!(output, "{question} [y/N] ");
    let _ = output.flush();
    let mut answer = String::new();
    input
        .read_line(&mut answer)
        .map_err(|source| io_error("read", Path::new("stdin"), source))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_packs_come_from_the_box_home() {
        let mut host = Host::current();
        host.box_home = PathBuf::from("/t/home");
        assert_eq!(
            crate::run::lookup(&host).expect("lookup").operator,
            Path::new("/t/home/packs")
        );
    }

    #[test]
    fn a_profile_cannot_replace_the_installed_launcher() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap();
        let workspace = home.join("project");
        let bin = home.join(".local/bin");
        let alias = home.join("linked-bin");
        let profile = home.join(".strands/box/profiles/test/profile.toml");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(profile.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&bin, &alias).unwrap();
        let launcher = Launcher::from_host()
            .home(&home)
            .search_path("/usr/bin:/bin")
            .environment(&[]);
        for grant in [home.join(".local"), bin, alias] {
            std::fs::write(
                &profile,
                format!(
                    "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.write = [{:?}]\n",
                    grant.to_str().unwrap()
                ),
            )
            .unwrap();
            let error = launcher.preview("test", &workspace).unwrap_err();
            assert!(matches!(error, Error::WriteOverProtected { .. }), "{error}");
        }
    }

    #[test]
    fn a_run_names_project_access_below_write_and_what_to_add_without_it() {
        let path = "~/.strands/box/profiles/claude/profile.toml";
        let project = |access| Some(Project { access });
        assert_eq!(
            project_notice("claude", None, path).as_deref(),
            Some(
                "profile claude gives the agent no access to this project; to allow it, add \
                 `[project] access = \"write\"` to ~/.strands/box/profiles/claude/profile.toml"
            )
        );
        assert_eq!(
            project_notice("claude", project(ProjectAccess::Read), path).as_deref(),
            Some(
                "the agent can read but not change this project (`[project] access = \"read\"` \
                 in ~/.strands/box/profiles/claude/profile.toml)"
            )
        );
        assert_eq!(
            project_notice("claude", project(ProjectAccess::None), path).as_deref(),
            Some(
                "the agent can't read or change this project (`[project] access = \"none\"` in \
                 ~/.strands/box/profiles/claude/profile.toml)"
            )
        );
        assert_eq!(
            project_notice("claude", project(ProjectAccess::Write), path),
            None
        );
    }

    #[test]
    fn the_run_lock_refuses_a_run_directory_that_is_a_link() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = root.path().join("probe-00000000");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let instance = Instance {
            name: "probe-00000000".into(),
            box_directory: link.join("box"),
            directory: link,
        };
        assert!(matches!(
            claim(&instance),
            Err(Error::Io { action: "open", .. })
        ));
        let instance = Instance {
            name: "probe-00000000".into(),
            box_directory: real.join("box"),
            directory: real,
        };
        claim(&instance).expect("a real run directory");
    }

    #[test]
    fn the_flag_then_the_profile_then_the_operator_decide_the_banner() {
        use Display::{Banner, Direct};
        for (flag, profile, user, expected) in [
            (None, None, None, Banner),
            (None, None, Some(false), Direct),
            (None, Some(true), Some(false), Banner),
            (None, Some(false), Some(true), Direct),
            (Some(true), Some(false), Some(false), Banner),
            (Some(false), Some(true), Some(true), Direct),
        ] {
            assert_eq!(
                display(true, flag, profile, user),
                expected,
                "{flag:?} {profile:?} {user:?}"
            );
            assert_eq!(display(false, flag, profile, user), Direct);
        }
    }

    #[test]
    fn banner_configuration_advertises_its_terminal_without_changing_policy() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap().join("home");
        let workspace = home.join("project");
        std::fs::create_dir_all(&workspace).unwrap();
        let host = Host {
            home: home.clone(),
            box_home: home.join(".strands/box"),
            search_path: "/usr/bin:/bin".into(),
            os: std::env::consts::OS,
            variables: Some(Vec::new()),
            answers: Vec::new(),
            root: false,
            apple_stubs: crate::host::APPLE_STUBS.into(),
        };
        let instance = Instance {
            name: "test-00000000".into(),
            directory: home.join(".strands/box/r/test-00000000"),
            box_directory: home.join(".strands/box/r/test-00000000/box"),
        };
        let profile = Profile::parse(
            r#"
            [agent]
            command = ["/usr/bin/true"]
            [agent.env]
            TERM = "xterm-ghostty"
            COLORTERM = "host-color"
            KEEP = "profile-value"
        "#,
            &home.join(".strands/box/profiles/test/profile.toml"),
        )
        .unwrap();
        let make = |display| {
            compile_run(
                Loaded {
                    profile: &profile,
                    name: "test",
                    policy: None,
                    trusted: &[],
                    by_path: false,
                },
                &host,
                &workspace,
                &instance,
                &[],
                &|_| None,
                RunSettings {
                    display,
                    observations: None,
                    resources: None,
                    install: None,
                },
            )
            .unwrap()
            .compiled
        };
        let direct = make(Display::Direct);
        let banner = make(Display::Banner);
        let mut direct_config: toml::Value = toml::from_str(&direct.box_toml).unwrap();
        let banner_config: toml::Value = toml::from_str(&banner.box_toml).unwrap();
        for (key, direct, banner) in [
            ("TERM", "xterm-ghostty", "xterm-256color"),
            ("COLORTERM", "host-color", "truecolor"),
        ] {
            assert_eq!(direct_config["agent"]["env"][key].as_str(), Some(direct));
            direct_config["agent"]["env"][key] = banner.into();
        }
        assert_eq!(direct_config, banner_config);
        assert_eq!(direct.policy, banner.policy);
    }

    /// A preview with one distinct row in each list, and `box_toml` as its `box.toml`.
    fn preview(box_toml: &str) -> Preview {
        let text = |text: &str| text.to_string();
        Preview {
            box_toml: text(box_toml),
            policy: text("@id(\"own\") permit (principal, action, resource);\n"),
            inputs: vec![(text("terminal.term"), text("vt100"), text("your profile"))],
            packs: vec![(text("@box/base"), text("1"))],
            plugins: vec![(text("@box/1password"), text("1"))],
            sources: vec![
                (
                    text("op"),
                    text("/usr/local/bin/op"),
                    Some(text("@box/1password")),
                ),
                (text("vault"), text("/opt/vault/bin/read"), None),
            ],
            policies: vec![text("policy.dw")],
            storage: PathBuf::from("/home/.strands/box/storage/probe/default"),
            project: Some(Project {
                access: ProjectAccess::Read,
            }),
            skipped: vec![(text("cargo (@box/cargo)"), text("no cargo on this host"))],
            dropped: vec![(text("git"), text("/opt/git/libexec"))],
            copies: vec![(
                text("~/.claude/rules"),
                text("config/rules"),
                text("will copy"),
            )],
            links: vec![(text("~/.claude/skills/review"), text("not copied: a loop"))],
            parts: vec![(
                text("keeps"),
                text("config/settings.json"),
                vec![vec![text("env"), text("TERM")], vec![text("Smith, John")]],
            )],
            mcp_unstarted: vec![(text("fetch"), text("no mcp-fetch on your PATH"))],
            mcp_servers: vec![(
                text("github"),
                text("~/.claude.json"),
                text(", with the key in GITHUB_TOKEN"),
            )],
            mcp_dropped: vec![(
                text("HOME"),
                text("issues"),
                text("~/.codex/config.toml"),
                text("the box sets it"),
            )],
            mcp_path_dropped: vec![text("\"bin\" from the PATH of each MCP server")],
            mcp_skipped: vec![(
                text("linear"),
                text("~/.cursor/mcp.json"),
                text("needs a key"),
            )],
            mcp_unread: vec![(text("~/.gemini/settings.json"), text("not JSON"))],
            warnings: vec![text("rule 1 never applies")],
            open_routes: vec![(
                text("login"),
                vec![text("login.example.com"), text("auth.example.com:8443")],
            )],
        }
    }

    #[test]
    fn the_json_preview_names_each_field_in_order() {
        let summary = preview("name = \"probe-preview\"\n")
            .json("probe", false)
            .unwrap();
        let mut expected = json!({
            "profile": "probe",
            "packs": [{"name": "@box/base", "version": "1"}],
            "plugins": [{"name": "@box/1password", "version": "1"}],
            "sources": [
                {"scheme": "op", "program": "/usr/local/bin/op", "plugin": "@box/1password"},
                {"scheme": "vault", "program": "/opt/vault/bin/read", "plugin": null},
            ],
            "policies": ["policy.dw"],
            "storage": "/home/.strands/box/storage/probe/default",
            "project": {"access": "read"},
            "inputs": [{"name": "terminal.term", "value": "vt100", "source": "your profile"}],
            "skipped": [{"tool": "cargo (@box/cargo)", "reason": "no cargo on this host"}],
            "dropped": [{"tool": "git", "path": "/opt/git/libexec"}],
            "open_routes": [{
                "route": "login",
                "destinations": ["login.example.com", "auth.example.com:8443"],
            }],
            "copies": [{
                "source": "~/.claude/rules",
                "target": "config/rules",
                "action": "will copy",
            }],
            "links": [{"link": "~/.claude/skills/review", "action": "not copied: a loop"}],
            "parts": [{
                "what": "keeps",
                "target": "config/settings.json",
                "names": [["env", "TERM"], ["Smith, John"]],
            }],
            "mcp": {
                "unstarted": [{"server": "fetch", "reason": "no mcp-fetch on your PATH"}],
                "servers": [{
                    "server": "github",
                    "file": "~/.claude.json",
                    "detail": ", with the key in GITHUB_TOKEN",
                }],
                "dropped": [{
                    "variable": "HOME",
                    "server": "issues",
                    "file": "~/.codex/config.toml",
                    "reason": "the box sets it",
                }],
                "path_dropped": ["\"bin\" from the PATH of each MCP server"],
                "skipped": [{
                    "server": "linear",
                    "file": "~/.cursor/mcp.json",
                    "reason": "needs a key",
                }],
                "unread": [{"file": "~/.gemini/settings.json", "reason": "not JSON"}],
            },
            "warnings": ["rule 1 never applies"],
        });
        assert_eq!(summary.to_string(), expected.to_string());
        let full = preview("name = \"probe-preview\"\n")
            .json("probe", true)
            .unwrap();
        expected["box_toml"] = json!({"name": "probe-preview"});
        expected["policy"] = json!("@id(\"own\") permit (principal, action, resource);\n");
        assert_eq!(full.to_string(), expected.to_string());
        let unset = Preview {
            project: None,
            ..preview("name = \"probe-preview\"\n")
        };
        assert_eq!(unset.json("probe", false).unwrap()["project"], Value::Null);
    }

    #[test]
    fn the_json_preview_holds_an_mcp_server_key_only_with_full() {
        let secret = "ghp_SCRATCHSECRET";
        let preview = preview(&format!(
            "name = \"probe-preview\"\n\n[mcp.github]\ncommand = [\"npx\"]\n\
             env.GITHUB_PERSONAL_ACCESS_TOKEN = \"{secret}\"\n"
        ));
        let summary = preview.json("probe", false).unwrap();
        assert!(!summary.to_string().contains(secret), "{summary}");
        for key in ["box_toml", "policy"] {
            assert!(summary.get(key).is_none(), "{key}: {summary}");
        }
        let full = preview.json("probe", true).unwrap();
        assert_eq!(
            full["box_toml"]["mcp"]["github"]["env"]["GITHUB_PERSONAL_ACCESS_TOKEN"],
            secret
        );
    }

    #[test]
    fn a_part_line_shows_each_key_path_as_the_text_report_prints_it() {
        assert_eq!(
            preview("name = \"probe-preview\"\n").part_lines(),
            [(
                "keeps",
                "config/settings.json",
                "env.TERM, \"Smith, John\"".to_string()
            )]
        );
    }

    #[test]
    fn the_json_box_toml_keeps_the_document_order_and_writes_a_datetime_as_text() {
        let box_toml = "name = \"probe-preview\"\nbox_dir = \"/b\"\nat = 1979-05-27T07:32:00Z\n\
                        ratio = 0.5\nnever = inf\non = true\n\
                        limits = { soft = 1, hard = [2, \"3\"] }\n\n\
                        [agent]\nenv.TERM = \"vt100\"\nenv.COLORTERM = \"truecolor\"\n\n\
                        [[agent.ingress]]\nport = 8080\n\n[[agent.ingress]]\nport = 8081\n";
        let document = preview(box_toml).json("probe", true).unwrap();
        assert_eq!(
            document["box_toml"].to_string(),
            "{\"name\":\"probe-preview\",\"box_dir\":\"/b\",\"at\":\"1979-05-27T07:32:00Z\",\
             \"ratio\":0.5,\"never\":null,\"on\":true,\"limits\":{\"soft\":1,\"hard\":[2,\"3\"]},\
             \"agent\":{\"env\":{\"TERM\":\"vt100\",\"COLORTERM\":\"truecolor\"},\
             \"ingress\":[{\"port\":8080},{\"port\":8081}]}}"
        );
    }

    #[test]
    fn a_box_toml_that_does_not_read_back_is_an_error_and_not_a_document() {
        let error = preview("name = = 1\n").json("probe", true).unwrap_err();
        assert!(matches!(error, Error::Reread(_)), "{error}");
    }
}

#[cfg(test)]
mod hook_import_tests {
    use super::*;

    /// `apply_hooks` removes the hooks of a copy when its row imports none, and lists the change.
    #[test]
    fn apply_hooks_removes_the_hooks_of_a_row_that_imports_none() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let home = directory.path().canonicalize().expect("canonical");
        let root = home.join(".strands/box/storage/agent/default");
        std::fs::create_dir_all(root.join("config")).expect("a folder");
        let target = root.join("config/settings.json");
        std::fs::write(&target, r#"{"theme":"dark","hooks":{"Stop":[]}}"#).expect("a copy");
        let storage = Storage {
            root: root.clone(),
            hooks: vec![crate::storage_hooks::HookImport {
                source: home.join(".agent/settings.json"),
                target: target.clone(),
                relative: "config/settings.json".into(),
                at: "storage.hooks[0]".into(),
                import: false,
                key: vec!["hooks".into(), "*".into()],
                ..Default::default()
            }],
            ..Storage::default()
        };

        let lines = apply_hooks(
            &storage,
            &[crate::storage_hooks::Imported::default()],
            &home,
        )
        .expect("apply");

        assert!(lines[0].starts_with("removed the hooks"), "{lines:?}");
        let copy: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&target).unwrap()).unwrap();
        assert_eq!(copy, serde_json::json!({"theme": "dark"}));
    }

    /// Each distinct imported script is recorded once for its permit, and gets no grant, with or
    /// without a `read` entry that covers it.
    #[test]
    fn each_imported_script_is_recorded_once_and_gets_no_grant() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let home = directory.path().canonicalize().expect("canonical");
        let hooks = home.join(".agent/hooks");
        std::fs::create_dir_all(&hooks).expect("a folder");
        let covered = home.join("shared");
        std::fs::create_dir_all(&covered).expect("a folder");
        for path in [hooks.join("a.sh"), covered.join("b.sh")] {
            std::fs::write(path, "exit 0\n").expect("a script");
        }
        std::fs::write(
            home.join(".agent/hooks.json"),
            format!(
                r#"{{"hooks":[{{"run":"~/.agent/hooks/a.sh"}},{{"run":"bash ~/.agent/hooks/a.sh"}},{{"run":"{}"}}]}}"#,
                covered.join("b.sh").display()
            ),
        )
        .expect("host hooks");
        let row = crate::storage_hooks::HookImport {
            source: home.join(".agent/hooks.json"),
            target: home.join(".strands/box/storage/agent/default/config/hooks.json"),
            relative: "config/hooks.json".into(),
            at: "storage.hooks[0]".into(),
            import: true,
            key: vec!["hooks".into(), "*".into()],
            command: vec!["run".into()],
            set: vec![crate::lang::HookSetting {
                key: vec!["run".into()],
                value: crate::lang::HookValue::Text(vec![". ".into(), String::new()]),
            }],
            ..Default::default()
        };
        let mut resolved = Resolved::default();
        resolved.agent.filesystem.read = vec![covered.to_str().unwrap().to_string()];
        resolved.storage.hooks = vec![
            row.clone(),
            crate::storage_hooks::HookImport {
                target: home.join(".strands/box/storage/agent/default/config/other.json"),
                relative: "config/other.json".into(),
                at: "storage.hooks[1]".into(),
                ..row
            },
        ];

        let imported = import_hooks(&mut resolved, &home);

        assert_eq!(imported[0].scripts.len(), 2);
        assert_eq!(imported[1].scripts.len(), 2);
        assert_eq!(
            resolved.storage.hook_scripts,
            vec![hooks.join("a.sh"), covered.join("b.sh")]
        );
        assert_eq!(resolved.agent.filesystem.read_file, Vec::<String>::new());
    }
}
