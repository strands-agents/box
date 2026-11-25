use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::files::{create_real_directory, holds, io_error};
use crate::host::Host;
use crate::lang::{self, Lookup};
use crate::policy_starter::{self, PolicyMenu, PolicyStarter};
use crate::profile::{PROFILE_FILE, Profile, Profiles, validate_name};
use crate::reference::Sources;
use crate::starter;
use crate::tool::{Found, Tools};

/// What `box profile create` writes into a new profile.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub(crate) with: Vec<String>,
    /// `with` holds full pack names, which a starter chose.
    pub(crate) full_names: bool,
    pub(crate) options: Vec<(String, String)>,
    /// The policy starter `--policy` names, or the one the operator picked.
    pub(crate) policy: Option<String>,
    pub(crate) tools: Option<Vec<String>>,
    pub(crate) host: Host,
    pub(crate) resources: Option<PathBuf>,
}

impl Settings {
    pub(crate) fn current() -> Self {
        Self {
            with: Vec::new(),
            full_names: false,
            options: Vec::new(),
            policy: None,
            tools: None,
            host: Host::current(),
            resources: None,
        }
    }
}

/// The builder methods `NewProfile` and the test `Trial` share.
macro_rules! settings_builder {
    () => {
        /// Use the pack `pack`: for a short name, the operator's pack of that name, else `@box/<pack>`.
        pub fn with(mut self, pack: impl Into<String>) -> Self {
            self.settings.with.push(pack.into());
            self
        }

        /// Set the input `name` to `value` in the profile's `[options]`.
        pub fn option(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
            self.settings.options.push((name.into(), value.into()));
            self
        }

        /// Start the profile from the policy starter `name`, such as `open` or `@box/open`.
        pub fn policy(mut self, name: impl Into<String>) -> Self {
            self.settings.policy = Some(name.into());
            self
        }

        /// Use the tool pack `@box/<name>` for each of `tools`, and no other tool pack.
        pub fn tools<I, S>(mut self, tools: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            self.settings.tools = Some(tools.into_iter().map(Into::into).collect());
            self
        }

        /// Read the packs from `directory`.
        pub fn resources(mut self, directory: impl Into<std::path::PathBuf>) -> Self {
            self.settings.resources = Some(directory.into());
            self
        }

        /// Find programs on `search_path` instead of the `PATH` of `box`.
        #[cfg(any(test, feature = "test-support"))]
        pub fn search_path(mut self, search_path: impl Into<std::ffi::OsString>) -> Self {
            self.settings.host.search_path = search_path.into();
            self
        }

        /// Read the host home at `home` instead of `HOME`.
        #[cfg(any(test, feature = "test-support"))]
        pub fn home(mut self, home: impl Into<std::path::PathBuf>) -> Self {
            self.settings.set_home(home.into());
            self
        }

        #[cfg(test)]
        pub(crate) fn box_home(mut self, box_home: impl Into<std::path::PathBuf>) -> Self {
            self.settings.host.box_home = box_home.into();
            self
        }

        /// Read only `variables` as the environment of `box`.
        #[cfg(any(test, feature = "test-support"))]
        pub fn environment(mut self, variables: &[(&str, &str)]) -> Self {
            self.settings.host.variables = Some(
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
            self.settings.host.answers.push((
                argv.iter().map(|part| part.to_string()).collect(),
                output.to_string(),
            ));
            self
        }
    };
}
#[cfg(all(
    any(test, feature = "test-support"),
    any(target_os = "macos", target_os = "linux")
))]
pub(crate) use settings_builder;

/// What the host resolved for one run: the agent's program and the tools.
#[derive(Debug, Clone, Default)]
pub(crate) struct Discovery {
    pub(crate) agent: Option<PathBuf>,
    pub(crate) missing_agent: Option<String>,
    /// The program of a declared secret source that the host lacks, as `(its name, why)`.
    pub(crate) missing_source: Option<(String, String)>,
    pub(crate) tools: Tools,
}

/// The host, as `box run` resolves a profile's references against it in `workspace`.
pub(crate) struct HostSources<'a> {
    host: &'a Host,
    workspace: &'a Path,
    env: &'a dyn Fn(&str) -> Option<String>,
    developer_dir: Option<Result<String, String>>,
    pub(crate) discovery: Discovery,
}

impl<'a> HostSources<'a> {
    /// Sources for a run in `workspace`: a program inside it is never taken.
    pub(crate) fn new(
        host: &'a Host,
        workspace: &'a Path,
        env: &'a dyn Fn(&str) -> Option<String>,
    ) -> Self {
        Self {
            host,
            workspace,
            env,
            developer_dir: None,
            discovery: Discovery::default(),
        }
    }
}

impl Sources for HostSources<'_> {
    fn env(&self, name: &str) -> Option<String> {
        if name == "PATH" {
            return self.host.search_path.to_str().map(str::to_string);
        }
        match &self.host.variables {
            Some(variables) => variables
                .iter()
                .find(|(set, _)| set == name)
                .map(|(_, value)| value.clone()),
            None => (self.env)(name),
        }
    }

    fn env_with_prefix(&self, prefix: &str) -> Vec<(String, String)> {
        let names: Vec<String> = match &self.host.variables {
            Some(variables) => variables.iter().map(|(name, _)| name.clone()).collect(),
            None => std::env::vars_os()
                .filter_map(|(name, _)| name.into_string().ok())
                .collect(),
        };
        names
            .into_iter()
            .filter(|name| name.starts_with(prefix))
            .filter_map(|name| Some((name.clone(), self.env(&name)?)))
            .collect()
    }

    fn program(&mut self, name: &str) -> Option<PathBuf> {
        self.host
            .find(name)
            .filter(|found| !crate::host::within(found, self.workspace))
    }

    fn search_path(&self) -> Vec<PathBuf> {
        std::env::split_paths(&self.host.search_path).collect()
    }

    fn search(&self, name: &str) -> Option<PathBuf> {
        self.host.find(name)
    }

    fn developer_dir(&mut self) -> Result<String, String> {
        let host = self.host;
        self.developer_dir
            .get_or_insert_with(|| {
                host.command(&["/usr/bin/xcode-select".to_string(), "-p".to_string()])
            })
            .clone()
    }

    fn apple_stubs(&self) -> PathBuf {
        self.host.apple_stubs.clone()
    }
}

/// The environment of this process, as a reference reads it.
pub(crate) fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

impl Settings {
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn set_home(&mut self, home: PathBuf) {
        self.host.set_home(home);
    }

    /// Where `packs` finds a pack for this host.
    pub(crate) fn lookup(&self) -> Result<Lookup, Error> {
        match &self.resources {
            Some(root) => crate::run::lookup_at(Some(root.join("packs")), &self.host),
            None => crate::run::lookup(&self.host),
        }
    }

    /// The new profile's packs and text: the agent, its provider, the operator's values, and
    /// nothing a pack already says.
    pub(crate) fn draft(
        &self,
        name: &str,
        path: &Path,
        saved: Option<&Profile>,
    ) -> Result<Draft, Error> {
        if !cfg!(any(target_os = "macos", target_os = "linux")) {
            return Err(Error::UnsupportedPlatform);
        }
        if self.host.home.as_os_str().is_empty() {
            return Err(Error::NoHome);
        }
        let refuse = |reason: String| Error::Profile {
            path: path.to_path_buf(),
            line: None,
            reason,
        };
        let lookup = self.lookup()?;
        let table = |pack: &str| lookup.table(pack).map_err(refuse);
        let shipped = lookup.tool_packs();
        let tools: Vec<String> = match &self.tools {
            None => crate::starter::default_tools(&lookup)?,
            Some(names) => names
                .iter()
                .map(|name| {
                    let pack = format!("{}{name}", lang::VENDORED);
                    if shipped.contains(&pack) {
                        Ok(pack)
                    } else {
                        Err(Error::UnknownTool {
                            name: name.clone(),
                            known: shipped
                                .iter()
                                .map(|pack| pack.trim_start_matches(lang::VENDORED))
                                .collect::<Vec<_>>()
                                .join(", "),
                        })
                    }
                })
                .collect::<Result<_, _>>()?,
        };
        let mut packs: Vec<String> = Vec::new();
        for pack in &self.with {
            let pack = if self.full_names {
                pack.clone()
            } else {
                lookup.full_name(pack).map_err(refuse)?
            };
            if !packs.contains(&pack) {
                table(&pack)?;
                packs.push(pack);
            }
        }
        let mut agent = None;
        for pack in &packs {
            if lang::runs_agent(&lookup, pack).map_err(refuse)? {
                agent = Some(pack.clone());
                break;
            }
        }
        if agent.is_none()
            && let Ok(candidate) = lookup.full_name(name)
            && lang::runs_agent(&lookup, &candidate).unwrap_or(false)
        {
            packs.insert(0, candidate.clone());
            agent = Some(candidate);
        }
        let imported = lang::imported(&lookup, &packs).map_err(refuse)?;
        for pack in tools {
            let short = starter::short_name(&pack);
            let yours = imported
                .iter()
                .any(|named| named == short && lookup.shadows(short));
            if !yours && !packs.contains(&pack) {
                packs.push(pack);
            }
        }
        let agent = agent.ok_or_else(|| {
            refuse(
                "no pack runs an agent; name an agent pack with `--with`, or name the profile \
                 after a starter (`box profile list` lists them)"
                    .to_string(),
            )
        })?;
        let mut text = format!(
            "# Written by `box profile create`. Your values go here, and the packs hold the rest.\n\
             # `box profile show {name}` prints what a run gets.\n\
             # For help from a coding agent, tell it: Run box help agent and follow it.\n"
        );
        let mut list = toml_edit::Array::new();
        for pack in &packs {
            list.push(pack.as_str());
        }
        text.push_str(&format!("packs = {list}\n"));
        let policy = match &self.policy {
            Some(policy) => {
                let starter = PolicyStarter::find(policy, &lookup).map_err(refuse)?;
                let copy = starter.copy().map_err(refuse)?;
                let mut files = toml_edit::Array::new();
                let file = if saved.is_some() {
                    (1..)
                        .map(|index| format!("policy-{index}.dw"))
                        .find(|file| path.with_file_name(file).symlink_metadata().is_err())
                        .unwrap()
                } else {
                    policy_starter::PROFILE_FILE.to_string()
                };
                files.push(file);
                text.push_str(&format!("policies = {files}\n"));
                Some((starter, copy))
            }
            None => None,
        };
        if let Some(access) = policy.as_ref().and_then(|(starter, _)| starter.project) {
            text.push_str(&format!(
                "\n# How much of your project the agent reaches: {}.\n[{}]\naccess = {:?}\n",
                crate::profile::ProjectAccess::VALUES
                    .map(|value| format!("{value:?}"))
                    .join(", "),
                lang::PROJECT,
                access.name(),
            ));
        }
        if !self.options.is_empty() {
            text.push_str("\n[options]\n");
            for (index, (option, value)) in self.options.iter().enumerate() {
                if self.options[..index]
                    .iter()
                    .any(|(earlier, _)| earlier == option)
                {
                    return Err(Error::OptionFlag {
                        option: option.clone(),
                        reason: "is given twice",
                    });
                }
                if option.is_empty()
                    || !option.split('.').all(|part| {
                        !part.is_empty()
                            && part
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
                    })
                {
                    return Err(Error::OptionFlag {
                        option: option.clone(),
                        reason: "is not an input name",
                    });
                }
                text.push_str(&format!(
                    "{option} = {}\n",
                    toml_edit::value(value.as_str())
                ));
            }
        }
        if let Some(saved) = saved {
            let parse = |text: &str| {
                text.parse::<toml_edit::DocumentMut>()
                    .map_err(|error| refuse(error.to_string()))
            };
            let mut document = parse(&saved.text)?;
            let changes = parse(&text)?;
            if saved.packs() != packs {
                document["packs"] = changes["packs"].clone();
            }
            if policy.is_some() {
                document["policies"] = changes["policies"].clone();
                if !document.contains_key(lang::PROJECT)
                    && let Some(project) = changes.get(lang::PROJECT)
                {
                    document[lang::PROJECT] = project.clone();
                }
            }
            if let (Some(old), Some(new)) = (
                document
                    .get_mut("options")
                    .and_then(toml_edit::Item::as_table_like_mut),
                changes
                    .get("options")
                    .and_then(toml_edit::Item::as_table_like),
            ) {
                update_options(old, new);
            } else if let Some(options) = changes.get("options") {
                document["options"] = options.clone();
            } else {
                document.remove("options");
            }
            text = document.to_string();
        }
        let mut profile = Profile::parse(&text, path, crate::VERSION)?;
        if let Some(saved) = saved.filter(|saved| saved.table == profile.table) {
            text = saved.text.clone();
            profile = saved.clone();
        }
        let layers = profile.layers(None, &lookup)?;
        let mut merged = lang::merge(&layers)?;
        let mut egress = merged
            .table
            .remove("egress")
            .and_then(|egress| match egress {
                toml::Value::Table(egress) => Some(egress),
                _ => None,
            })
            .unwrap_or_default();
        egress
            .retain(|_, route| !input_condition_fails(route, &profile.table, &merged.declarations));
        Ok(Draft {
            profile,
            text,
            policy,
            agent,
            egress,
        })
    }
}

fn editing_starter(profile: &Profile, lookup: &Lookup) -> Result<String, Error> {
    let refuse = |reason| Error::Profile {
        path: profile.path.clone(),
        line: None,
        reason,
    };
    let imported = lang::imported(lookup, &profile.packs()).map_err(refuse)?;
    for name in starter::Menu::load(lookup)?.starters {
        for pack in imported.iter().filter(|pack| starter::owns(&name, pack)) {
            if lang::runs_agent(lookup, pack).map_err(refuse)? {
                return Ok(name);
            }
        }
    }
    Err(refuse(
        "guided setup is not available for this profile. Edit this profile.toml in your editor."
            .to_string(),
    ))
}

/// Whether `route` has a `when` on an input that the profile's `[options]`, or else the literal
/// `default` of an input that reads nothing from the host, does not meet:
/// `{ variable = "inputs.<name>", equals = ... }`, or `"${{ inputs.<name> }}"` for a `bool`. Any
/// other `when` is kept.
pub(crate) fn input_condition_fails(
    route: &toml::Value,
    profile: &toml::Table,
    declarations: &std::collections::BTreeMap<String, lang::Declaration>,
) -> bool {
    let (variable, equals) = match route.get("when") {
        Some(toml::Value::Table(condition)) => match (
            condition.get("variable").and_then(toml::Value::as_str),
            condition.get("equals").and_then(toml::Value::as_str),
        ) {
            (Some(variable), Some(equals)) => (variable, equals),
            _ => return false,
        },
        Some(toml::Value::String(text)) => match text
            .trim()
            .strip_prefix("${{")
            .and_then(|rest| rest.strip_suffix("}}"))
        {
            Some(variable) => (variable.trim(), "true"),
            None => return false,
        },
        _ => return false,
    };
    let Some(name) = variable.strip_prefix("inputs.") else {
        return false;
    };
    let mut options = std::collections::BTreeMap::new();
    if let Some(section) = profile.get("options")
        && lang::collect_values(section, &mut Vec::new(), &mut options).is_err()
    {
        return false;
    }
    if let Some(value) = options.get(name) {
        return value != equals;
    }
    let Some(declaration) = declarations.get(name) else {
        return false;
    };
    !declaration.reads_host()
        && declaration
            .default_value()
            .is_some_and(|value| !value.contains("${{") && value != equals)
}

fn update_options(old: &mut dyn toml_edit::TableLike, new: &dyn toml_edit::TableLike) {
    let removed: Vec<String> = old
        .iter()
        .filter(|(key, _)| !new.contains_key(key))
        .map(|(key, _)| key.to_string())
        .collect();
    for key in removed {
        old.remove(&key);
    }
    for (key, value) in new.iter() {
        if let Some(current) = old.get_mut(key) {
            if let (Some(old), Some(new)) = (current.as_table_like_mut(), value.as_table_like()) {
                update_options(old, new);
                continue;
            }
            let original = current
                .as_str()
                .map(str::to_string)
                .or_else(|| current.as_integer().map(|value| value.to_string()))
                .or_else(|| current.as_bool().map(|value| value.to_string()));
            if original.as_deref() == value.as_str() {
                continue;
            }
            let decor = current.as_value().map(|value| value.decor().clone());
            *current = value.clone();
            if let (Some(value), Some(decor)) = (current.as_value_mut(), decor) {
                *value.decor_mut() = decor;
            }
        } else {
            old.insert(key, value.clone());
        }
    }
}

/// A new profile before it is written.
pub(crate) struct Draft {
    pub(crate) profile: Profile,
    pub(crate) text: String,
    /// The policy starter the profile starts from, and the `policy.dw` copied from it.
    pub(crate) policy: Option<(PolicyStarter, String)>,
    pub(crate) agent: String,
    /// The merged `[egress]` table, with its placeholders as written.
    pub(crate) egress: toml::Table,
}

/// A profile to create from the host.
#[derive(Debug, Clone)]
pub struct NewProfile {
    name: Option<String>,
    settings: Settings,
    profiles: Option<PathBuf>,
    force: bool,
    detected: Vec<crate::detect::Line>,
    /// The starter whose `[starter] policy` answered the policy question.
    policy_from: Option<String>,
    /// The workspace that the profile runs in once it is saved.
    run: Option<PathBuf>,
    editing: Option<Profile>,
}

impl NewProfile {
    /// Create a profile from this process's own host.
    pub fn from_host() -> Self {
        Self {
            name: None,
            settings: Settings::current(),
            profiles: None,
            force: false,
            detected: Vec::new(),
            policy_from: None,
            run: None,
            editing: None,
        }
    }

    /// Review the profile as one that runs in `workspace` once it is saved.
    pub fn run_in(mut self, workspace: impl Into<PathBuf>) -> Self {
        self.run = Some(workspace.into());
        self
    }

    /// Pick a starter on `terminal` when neither `--with` nor the name selects one. Without a
    /// name, the profile takes the starter's name, or a name the operator gives when a profile
    /// has it.
    pub(crate) fn pick_starter(
        mut self,
        terminal: &mut starter::Terminal<'_>,
    ) -> Result<Self, Error> {
        if !self.picks_starter()? {
            return Ok(self);
        }
        let lookup = self.settings.lookup()?;
        let menu = starter::Menu::load(&lookup)?;
        if let Some(name) = &self.name {
            let path = self.profiles_at().path(name);
            if !self.force && path.symlink_metadata().is_ok() {
                return Err(Error::Exists { path });
            }
        }
        let starters: Vec<Option<starter::Starter>> = menu
            .starters
            .iter()
            .map(|name| starter::Starter::load(name, &lookup).ok())
            .collect();
        let labels: Vec<String> = menu
            .starters
            .iter()
            .zip(&starters)
            .map(|(name, loaded)| {
                loaded.as_ref().map_or_else(
                    || starter::short_name(name).to_string(),
                    |loaded| loaded.label.clone(),
                )
            })
            .collect();
        let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
        let shown = self.name.as_deref().unwrap_or_default();
        terminal.stage(shown, crate::prompt::AGENT);
        let picked = terminal.pick("Which agent do you want to use?", &labels)?;
        let picked_name = menu.starters[picked].clone();
        if self.name.is_none() {
            let profiles = self.profiles_at();
            let existing: Vec<(String, Profile)> = profiles
                .list()?
                .into_iter()
                .filter_map(|entry| {
                    let profile = entry.profile.ok()?;
                    let imported = lang::imported(&lookup, &profile.packs()).ok()?;
                    imported
                        .iter()
                        .any(|pack| starter::owns(&picked_name, pack))
                        .then_some((entry.name, profile))
                })
                .collect();
            let mut name = starter::short_name(&picked_name).to_string();
            let mut ask = !self.force && !existing.is_empty();
            let mut prompted = false;
            let names: Vec<&str> = existing.iter().map(|(name, _)| name.as_str()).collect();
            let descriptions: Vec<String> = existing
                .iter()
                .map(|(_, profile)| format!("packs {}", profile.packs().join(", ")))
                .collect();
            let descriptions: Vec<&str> = descriptions.iter().map(String::as_str).collect();
            let saved = if existing.is_empty() {
                String::new()
            } else {
                format!(
                    "\n\nEXISTING {} PROFILES{}",
                    labels[picked].to_uppercase(),
                    if terminal.choice_controls {
                        String::new()
                    } else {
                        names
                            .iter()
                            .zip(&descriptions)
                            .map(|(name, packs)| format!("\n\n  ✓ {name}\n    {packs}"))
                            .collect::<String>()
                    }
                )
            };
            loop {
                let taken = !self.force && profiles.path(&name).symlink_metadata().is_ok();
                let why = match validate_name(&name) {
                    Ok(()) if !taken && !ask => break,
                    Ok(()) if !taken => String::new(),
                    Ok(()) if prompted => format!("A profile named {name} exists."),
                    Ok(()) => String::new(),
                    Err(error) => format!("{error}."),
                };
                let default = if why.is_empty() && !taken {
                    format!(" [{name}]")
                } else if why.is_empty() {
                    String::new()
                } else {
                    format!("\n{why}")
                };
                let answer = terminal.profile_name(
                    &format!("Choose a name for the profile{default}{saved}"),
                    &names,
                    &descriptions,
                )?;
                if let Some((name, profile)) = answer
                    .strip_prefix('\0')
                    .and_then(|name| existing.iter().find(|(entry, _)| entry == name))
                {
                    let profile = terminal
                        .session
                        .as_ref()
                        .and_then(|session| session.editing.as_ref())
                        .filter(|saved| saved.path == profile.path)
                        .unwrap_or(profile)
                        .clone();
                    if let Some(session) = terminal.session.as_mut() {
                        session.edit(profile.clone());
                    }
                    return self.edit_profile(name, profile);
                }
                if !answer.is_empty() || taken || !why.is_empty() {
                    name = answer;
                }
                ask = false;
                prompted = true;
            }
            self.name = Some(name);
        }
        if let Some(session) = terminal.session.as_mut()
            && session.editing.take().is_some()
        {
            session.clear_setup();
        }
        self.settings.with.push(picked_name);
        Ok(self)
    }

    /// Replace a profile that exists [default: refuse it before the first question].
    pub fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    /// Name the profile `name` [default: the agent's command name].
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Write the profile under `root` [default: `~/.strands/box/profiles`].
    pub fn profiles(mut self, root: impl Into<PathBuf>) -> Self {
        self.profiles = Some(root.into());
        self
    }

    /// Reopen a saved profile with its current settings and policy files.
    pub fn edit(self, name: &str) -> Result<Self, Error> {
        let profiles = self.profiles_at();
        let (profile, _) = profiles.load(name)?.ok_or_else(|| Error::ProfileMissing {
            name: name.to_string(),
            path: profiles.path(name),
            hint: "Use `box profile create` to create one.".to_string(),
        })?;
        self.edit_profile(name, profile)
    }

    fn edit_profile(mut self, name: &str, profile: Profile) -> Result<Self, Error> {
        editing_starter(&profile, &self.settings.lookup()?)?;
        self.settings.with = profile.packs();
        self.settings.full_names = true;
        self.settings.tools.get_or_insert_with(Vec::new);
        self.name = Some(name.to_string());
        self.editing = Some(profile);
        Ok(self)
    }

    settings_builder!();

    /// The profile name: the name given, else the short name of the first pack.
    fn profile_name(&self) -> Result<String, Error> {
        let name = match &self.name {
            Some(name) => name.clone(),
            None => self
                .settings
                .with
                .first()
                .map(|pack| starter::short_name(pack).to_string())
                .ok_or(Error::ProfileUnnamed)?,
        };
        validate_name(&name)?;
        crate::run::refuse_owned_name(&self.settings.host.box_home, &name)?;
        Ok(name)
    }

    fn profiles_at(&self) -> Profiles {
        Profiles::at(
            self.profiles
                .clone()
                .unwrap_or_else(|| crate::run::profiles_root(&self.settings.host.box_home)),
            crate::VERSION,
        )
    }

    /// Answer the questions of the starter that the packs or the name select, then the policy
    /// question: first from the packs, options, and policy given, then on `terminal` when there is
    /// one. Without an agent starter, only each input with a `warning` and the policy question
    /// are asked. An existing profile is refused before the first prompt unless
    /// [`NewProfile::force`] or [`NewProfile::edit`] selects it.
    pub fn answer(self, mut terminal: Option<starter::Terminal<'_>>) -> Result<Self, Error> {
        self.answer_on(terminal.as_mut())
    }

    /// Answer and review in one inline view, without writing a profile.
    pub fn guided(self, terminal: &mut starter::Terminal<'_>) -> Result<CreatedProfile, Error> {
        if !terminal.choice_controls {
            return self
                .pick_starter(terminal)?
                .answer_on(Some(terminal))?
                .create();
        }
        let mut session = crate::prompt::Session::default();
        session.run = self.run.clone();
        session.agent = self.picks_starter()?;
        session.editing = self.editing.clone();
        terminal.session = Some(session);
        let result = loop {
            terminal.session.as_mut().unwrap().restart();
            let result = self
                .clone()
                .pick_starter(terminal)
                .and_then(|profile| profile.answer_on(Some(terminal)))
                .and_then(Self::create)
                .and_then(|created| created.review(terminal).map(|save| (created, save)));
            match result {
                Ok((created, true)) => break Ok(created),
                Ok((_, false)) => {}
                Err(Error::StarterAborted { .. })
                    if terminal.session.as_ref().unwrap().navigating => {}
                Err(error) => break Err(error),
            }
        };
        let finished = crate::prompt::finish(terminal);
        terminal.session = None;
        finished?;
        result
    }

    /// Whether neither `--with` nor the name picks a starter, so the operator picks one.
    fn picks_starter(&self) -> Result<bool, Error> {
        let lookup = self.settings.lookup()?;
        let menu = starter::Menu::load(&lookup)?;
        Ok(self.settings.with.is_empty()
            && !menu.starters.is_empty()
            && self
                .name
                .as_deref()
                .is_none_or(|name| menu.named(&lookup, name).is_none()))
    }

    fn answer_on(
        mut self,
        mut terminal: Option<&mut starter::Terminal<'_>>,
    ) -> Result<Self, Error> {
        let name = self.profile_name()?;
        let lookup = self.settings.lookup()?;
        let menu = starter::Menu::load(&lookup)?;
        let policies = PolicyMenu::load(&lookup)?;
        let path = self.profiles_at().path(&name);
        let workspace = std::env::current_dir().unwrap_or_default();
        let exists =
            self.editing.is_none() && !self.force && std::fs::symlink_metadata(&path).is_ok();
        let request = starter::Request {
            name: &name,
            with: &self.settings.with,
            options: &self.settings.options,
            lookup: &lookup,
            path: &path,
            exists,
            host: &self.settings.host,
            workspace: &workspace,
        };
        if !exists && let Some(terminal) = terminal.as_mut() {
            terminal.stage(&name, crate::prompt::SETUP);
        }
        let mut warned = Vec::new();
        let selected = if let Some(saved) = &self.editing {
            Some(editing_starter(saved, &lookup)?)
        } else {
            starter::select(&menu, &request)?
        };
        let answered = match selected {
            Some(starter_name) => {
                let starter = starter::Starter::load(&starter_name, &lookup).map_err(|reason| {
                    Error::Profile {
                        path: path.clone(),
                        line: None,
                        reason,
                    }
                })?;
                if self.editing.is_none()
                    && self.settings.policy.is_none()
                    && let Some(policy) = &starter.policy
                    && policies.named(policy).is_none()
                {
                    return Err(Error::Profile {
                        path: path.clone(),
                        line: None,
                        reason: format!(
                            "the starter {starter_name} sets `[starter] policy` to {policy}, which is not \
                             in your `[policy-starters]` list; the policy starters are {}. Name \
                             one with `--policy`, such as `--policy {}`",
                            policies
                                .starters
                                .iter()
                                .map(|starter| starter.name.as_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                            policies.starters[policies.default].flag_name()
                        ),
                    });
                }
                Some((
                    starter_name,
                    starter::answer(
                        &starter,
                        &request,
                        terminal.as_deref_mut(),
                        self.editing.as_ref(),
                    )?,
                ))
            }
            None => {
                warned = starter::answer_warnings(
                    &self.settings.with,
                    &request,
                    terminal.as_deref_mut(),
                )?;
                None
            }
        };
        self.settings.options.extend(std::mem::take(&mut warned));
        let mut from_starter = None;
        if let Some((pack, answered)) = answered {
            self.settings.with = answered.packs;
            self.settings.full_names = true;
            self.settings.options = answered.options;
            self.detected = answered.detected;
            from_starter = answered.policy.map(|policy| (pack, policy));
        }
        let unanswered = Settings {
            policy: None,
            ..self.settings.clone()
        };
        unanswered.draft(&name, &path, self.editing.as_ref())?;
        let command = format!("box profile create {name}");
        if !exists && let Some(terminal) = terminal.as_mut() {
            terminal.stage(&name, crate::prompt::POLICY);
        }
        if self.settings.policy.is_none()
            && let Some(profile) = &self.editing
        {
            let Some(terminal) = terminal.as_deref_mut() else {
                return Ok(self);
            };
            let current = if profile.policies().is_empty() {
                "Pack rules".to_string()
            } else {
                profile.policies().join(", ")
            };
            let keep = format!("Keep current policy ({current})");
            let labels: Vec<&str> = std::iter::once(keep.as_str())
                .chain(policies.starters.iter().map(|policy| policy.label.as_str()))
                .collect();
            let picked = terminal.pick("Which policy should this profile use?", &labels)?;
            self.settings.policy = picked
                .checked_sub(1)
                .map(|index| policies.starters[index].name.clone());
            return Ok(self);
        }
        let policy = match (&self.settings.policy, from_starter) {
            (None, Some((pack, policy))) => {
                self.policy_from = Some(pack);
                policy
            }
            _ => policy_starter::choose(
                &policies,
                &policy_starter::Request {
                    command: &command,
                    given: self.settings.policy.as_deref(),
                    path: &path,
                    exists,
                },
                terminal,
            )?,
        };
        self.settings.policy = Some(policy);
        self.name = Some(name);
        Ok(self)
    }

    /// Build the profile, and check what the host resolves for it now, without writing it.
    pub fn create(mut self) -> Result<CreatedProfile, Error> {
        let detected = std::mem::take(&mut self.detected);
        let policy_from = self.policy_from.take();
        let name = self.profile_name()?;
        let profiles = self.profiles_at();
        let draft = self
            .settings
            .draft(&name, &profiles.path(&name), self.editing.as_ref())?;
        let profile = draft.profile;
        let workspace = std::env::current_dir()
            .ok()
            .and_then(|directory| canonical_directory(&directory))
            .filter(|directory| !crate::host::within(&self.settings.host.home, directory))
            .unwrap_or_else(|| profiles.folder(&name));
        let mut sources = HostSources::new(&self.settings.host, &workspace, &process_env);
        let home = self.settings.host.home.clone();
        let box_home = self.settings.host.box_home.clone();
        let storage = crate::lang::storage_root(&box_home, &name);
        let box_dir = crate::run::preview_instance(&box_home).box_directory;
        let lookup = self.settings.lookup()?;
        let inputs = crate::lang::Inputs {
            tool_cache: None,
            home: &home,
            box_home: &box_home,
            workspace: &workspace,
            profile: &profiles.folder(&name),
            profile_file: &profiles.folder(&name).join("profile.toml"),
            box_dir: &box_dir,
            storage: &storage,
            os: self.settings.host.os,
            arch: self.settings.host.arch,
            packs: lookup.vendored.as_deref(),
        };
        let layers = profile.layers(None, &lookup)?;
        let declared = crate::plugin::sources(&layers).into_iter().collect();
        let egress = match profile.resolve(None, &lookup, &mut sources, &inputs) {
            Ok(resolved) => {
                sources.discovery.agent = resolved.agent.command.first().map(PathBuf::from);
                sources.discovery.tools = resolved.tools;
                resolved.egress
            }
            Err(Error::NotOnHost { reason, .. }) => {
                match missing_source(&layers, &declared, &reason) {
                    Some(program) => sources.discovery.missing_source = Some((program, reason)),
                    None => sources.discovery.missing_agent = Some(reason),
                }
                draft.egress
            }
            Err(error) => return Err(error),
        };
        let agent_label = starter::agent_name(&lookup, &draft.agent)
            .map_err(|reason| Error::Profile {
                path: profiles.path(&name),
                line: None,
                reason,
            })?
            .unwrap_or_else(|| starter::short_name(&draft.agent).to_string());
        let shadowing = layers
            .into_iter()
            .filter(|layer| layer.shared && lookup.shadows(&layer.name))
            .map(|layer| (layer.name, layer.path))
            .collect();
        let (mut policy, policy_text) = draft.policy.unzip();
        if self.editing.is_some()
            && policy.is_none()
            && let [file] = profile.policies().as_slice()
        {
            let current = crate::files::read_regular(&profiles.folder(&name).join(file))
                .map_err(|source| io_error("read", &profiles.folder(&name).join(file), source))?;
            policy = PolicyMenu::load(&lookup)?
                .starters
                .into_iter()
                .find(|starter| starter.copy().is_ok_and(|copy| copy == current));
        }
        Ok(CreatedProfile {
            home: self.settings.host.home.clone(),
            base: crate::host::box_home_base(
                &self.settings.host.home,
                &self.settings.host.box_home,
            )
            .to_path_buf(),
            folder: profiles.folder(&name),
            text: draft.text,
            name,
            agent_label,
            agent_pack: draft.agent,
            shadowing,
            routes: routes(&egress),
            sources: declared,
            policy,
            policy_text,
            policy_from,
            profile,
            discovery: sources.discovery,
            detected,
            editing: self.editing,
        })
    }
}

/// The program of the declared secret source whose `command` the absence `reason` names, as the
/// report names it, such as `op (@box/1password)`, or `None` when `reason` names no source.
fn missing_source(
    layers: &[crate::lang::Layer],
    declared: &BTreeMap<String, Option<String>>,
    reason: &str,
) -> Option<String> {
    let (scheme, plugin) = declared
        .iter()
        .find(|(scheme, plugin)| crate::plugin::names_command(reason, scheme, plugin.as_deref()))?;
    Some(match plugin {
        Some(plugin) => {
            let program = layers
                .iter()
                .find(|layer| layer.plugin && layer.name == *plugin)
                .and_then(|layer| crate::plugin::program(layer, scheme));
            match program {
                Some(program) => format!("{program} ({plugin})"),
                None => format!("The program of {plugin}"),
            }
        }
        None => format!("The program of your `[secret-source.{scheme}]`"),
    })
}

/// One `[egress.<name>]` route of a profile, as the create report states it.
#[derive(Debug, Clone)]
pub(crate) struct Route {
    pub(crate) name: String,
    pub(crate) destinations: Vec<String>,
    pub(crate) secret: Option<String>,
}

/// Each route of an `[egress]` table, in name order.
fn routes(egress: &toml::Table) -> Vec<Route> {
    egress
        .iter()
        .filter_map(|(name, route)| {
            let route = route.as_table()?;
            Some(Route {
                name: name.clone(),
                destinations: route
                    .get("destinations")
                    .and_then(toml::Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|item| item.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                secret: route
                    .get("secret")
                    .and_then(|secret| secret.get("ref"))
                    .and_then(toml::Value::as_str)
                    .map(str::to_string),
            })
        })
        .collect()
}

fn canonical_directory(path: &Path) -> Option<PathBuf> {
    crate::host::canonical(path).filter(|path| path.is_dir())
}

/// A profile built from a starter, ready to write.
#[derive(Debug, Clone)]
pub struct CreatedProfile {
    pub(crate) home: PathBuf,
    /// The folder below which writing the profile refuses links.
    pub(crate) base: PathBuf,
    pub(crate) name: String,
    pub(crate) folder: PathBuf,
    pub(crate) text: String,
    /// The agent's name as a person reads it.
    pub(crate) agent_label: String,
    /// The pack that runs the agent.
    pub(crate) agent_pack: String,
    /// Each of the operator's packs that has the name of a shipped pack, with its file.
    pub(crate) shadowing: Vec<(String, PathBuf)>,
    pub(crate) routes: Vec<Route>,
    /// The plugin that declares each `[secret-source.<scheme>]`, by scheme, with no plugin for a
    /// source of the profile.
    pub(crate) sources: BTreeMap<String, Option<String>>,
    /// The policy starter the profile starts from.
    pub(crate) policy: Option<PolicyStarter>,
    /// The `policy.dw` that `write` copies into the profile folder.
    pub(crate) policy_text: Option<String>,
    /// The starter whose `[starter] policy` picked the policy.
    pub(crate) policy_from: Option<String>,
    pub(crate) profile: Profile,
    pub(crate) discovery: Discovery,
    pub(crate) detected: Vec<crate::detect::Line>,
    pub(crate) editing: Option<Profile>,
}

impl CreatedProfile {
    /// The profile name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The profile folder.
    pub fn folder(&self) -> &Path {
        &self.folder
    }

    /// Where `profile.toml` is written.
    pub fn path(&self) -> PathBuf {
        self.folder.join(PROFILE_FILE)
    }

    /// The profile as TOML.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The profile.
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Every tool the host resolves now.
    pub fn resolutions(&self) -> Vec<Resolution> {
        self.discovery
            .tools
            .found
            .iter()
            .cloned()
            .map(Resolution::from)
            .collect()
    }

    /// Where the copy of the policy starter is written, when the profile starts from one.
    pub fn policy_path(&self) -> Option<PathBuf> {
        self.policy_text.as_ref().and_then(|_| {
            self.profile
                .policies()
                .first()
                .map(|file| self.folder.join(file))
        })
    }

    /// Write the policy copy and the profile; replace differing files only with `force`.
    pub fn write(&self, force: bool) -> Result<(), Error> {
        if let Some(saved) = &self.editing
            && !holds(&saved.path, &saved.text)
        {
            return Err(Error::Profile {
                path: saved.path.clone(),
                line: None,
                reason: "this profile changed during setup; reopen it before saving".to_string(),
            });
        }
        let mut files: Vec<(PathBuf, &String)> = self
            .policy_path()
            .into_iter()
            .zip(self.policy_text.as_ref())
            .collect();
        files.push((self.path(), &self.text));
        if !force {
            files.retain(|(path, text)| !holds(path, text));
            if let Some((existing, _)) = files.iter().find(|(path, _)| {
                std::fs::symlink_metadata(path).is_ok()
                    && !self
                        .editing
                        .as_ref()
                        .is_some_and(|saved| saved.path == *path)
            }) {
                return Err(Error::Exists {
                    path: existing.clone(),
                });
            }
        }
        let root = &self.folder;
        create_real_directory(root, &self.base)?;
        for (target, text) in files {
            let mut file = tempfile::NamedTempFile::new_in(root)
                .map_err(|source| io_error("stage", &target, source))?;
            file.write_all(text.as_bytes())
                .map_err(|source| io_error("write", &target, source))?;
            let persisted = if force
                || self
                    .editing
                    .as_ref()
                    .is_some_and(|saved| saved.path == target)
            {
                file.persist(&target)
            } else {
                file.persist_noclobber(&target)
            };
            persisted.map_err(|failure| io_error("replace", &target, failure.error))?;
        }
        Ok(())
    }
}

/// What one tool resolved to.
#[derive(Debug, Clone)]
pub struct Resolution {
    /// The name of its table.
    pub name: String,
    /// The pack that declares it.
    pub pack: String,
    /// Where the lookup on the search path found it.
    pub spelling: PathBuf,
    /// The real file its table runs and its permit names.
    pub identity: PathBuf,
    /// Every path its table reads.
    pub read: Vec<PathBuf>,
    /// Every host its permits add.
    pub hosts: Vec<String>,
}

impl From<Found> for Resolution {
    fn from(tool: Found) -> Self {
        Self {
            name: tool.name,
            pack: tool.pack,
            spelling: tool.spelling,
            identity: tool.identity,
            read: tool.read,
            hosts: tool.hosts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(variables: Option<Vec<(String, String)>>) -> Host {
        Host {
            home: PathBuf::from("/home/you"),
            box_home: PathBuf::from("/home/you/.strands/box"),
            search_path: "/usr/bin:/bin".into(),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            variables,
            answers: Vec::new(),
            root: false,
            apple_stubs: crate::host::APPLE_STUBS.into(),
        }
    }

    #[test]
    fn the_host_lists_each_variable_whose_name_starts_with_a_prefix() {
        let workspace = PathBuf::from("/home/you/project");
        let set = host(Some(
            [
                ("OP_SESSION_my", "a"),
                ("OP_ACCOUNT", "b"),
                ("OP_SESSION_work", "c"),
            ]
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .to_vec(),
        ));
        let none = |_: &str| None;
        assert_eq!(
            HostSources::new(&set, &workspace, &none).env_with_prefix("OP_SESSION_"),
            vec![
                ("OP_SESSION_my".to_string(), "a".to_string()),
                ("OP_SESSION_work".to_string(), "c".to_string())
            ]
        );
        let process = host(None);
        let home = |name: &str| (name == "HOME").then(|| "from the shell".to_string());
        assert_eq!(
            HostSources::new(&process, &workspace, &home).env_with_prefix("HOM"),
            vec![("HOME".to_string(), "from the shell".to_string())],
            "without stand-in variables, the names come from the environment of box and each \
             value from its reader"
        );
    }
}
