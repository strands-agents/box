use std::collections::BTreeMap;
use std::io::{self, Read as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::files::remove_if_present;
use crate::lang::{self, Input, Inputs, Layer, Lookup, Refusal, Storage};
use crate::reference::{self, Sources};

/// The directory, under the workspace, that the workload can never reach.
pub const PROJECT_CONFIGURATION: &str = ".box";

/// The telemetry target `box run` writes for each run.
pub(crate) const RECORDS: &str = "records";

/// The profile file in a profile folder.
pub const PROFILE_FILE: &str = "profile.toml";

/// The policy file written for a run.
pub const POLICY_FILE: &str = "policy.dw";

/// A name no profile takes.
pub(crate) const BASE: &str = "base";

/// The name of the folder of the operator's packs, beside `profiles`.
pub const PACKS: &str = "packs";

/// The longest profile name `box` accepts.
const MAXIMUM_PROFILE_NAME: usize = 64;

/// A profile as its author wrote it, with its placeholders unresolved.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    pub table: toml::Table,
    pub text: String,
    pub path: PathBuf,
}

/// A profile with every reference resolved, in the shape of the engine's tables.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resolved {
    pub agent: Process,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tool: BTreeMap<String, Process>,
    #[serde(default, skip_serializing_if = "toml::Table::is_empty")]
    pub egress: toml::Table,
    #[serde(default, skip_serializing_if = "toml::Table::is_empty")]
    pub mcp: toml::Table,
    #[serde(default, skip_serializing_if = "toml::Table::is_empty")]
    pub(crate) telemetry: toml::Table,
    #[serde(
        default,
        rename = "experimental-features",
        skip_serializing_if = "ExperimentalFeatures::is_empty"
    )]
    pub(crate) experimental_features: ExperimentalFeatures,
    /// Each `[secret-source.<scheme>]` that a plugin or the profile declares, by scheme.
    #[serde(
        default,
        rename = "secret-source",
        skip_serializing_if = "toml::Table::is_empty"
    )]
    pub secret_source: toml::Table,
    /// The profile's `file-attributes`, or `None` when the profile leaves it to the user ID.
    #[serde(
        default,
        rename = "file-attributes",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) file_attributes: Option<bool>,
    #[serde(default, skip_serializing_if = "toml::Table::is_empty")]
    pub(crate) limits: toml::Table,
    /// The profile's `[project]`, or `None` when the profile has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<Project>,
    /// The profile's `[filesystem]`, which reaches every process.
    #[serde(default, skip_serializing_if = "ProfileFilesystem::is_empty")]
    pub filesystem: ProfileFilesystem,
    #[serde(skip)]
    pub storage: Storage,
    #[serde(skip)]
    pub inputs: Vec<Input>,
    #[serde(skip)]
    pub policy: String,
    /// The plugin, or `the profile`, that declares each secret source, by scheme.
    #[serde(skip)]
    pub(crate) source_owners: BTreeMap<String, String>,
    /// The layers that declare each table, such as `egress.github`, in the order they apply.
    #[serde(skip)]
    pub table_owners: BTreeMap<String, Vec<String>>,
    #[serde(skip)]
    pub servers: crate::mcp::Servers,
    #[serde(skip)]
    pub tools: crate::tool::Tools,
}

/// The experimental features a profile can select.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExperimentalFeatures {
    #[serde(
        default,
        rename = "native-filesystem-policy",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) native_filesystem_policy: Option<bool>,
}

impl ExperimentalFeatures {
    fn is_empty(&self) -> bool {
        self.native_filesystem_policy.is_none()
    }
}

/// A profile's `[filesystem]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileFilesystem {
    /// The paths that no process reaches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// The folders that each process whose write grants reach them keeps read-only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_write: Vec<String>,
}

impl ProfileFilesystem {
    fn is_empty(&self) -> bool {
        self.deny.is_empty() && self.deny_write.is_empty()
    }
}

/// A profile's `[project]` table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub access: ProjectAccess,
}

/// How much of the project the agent, its tools, and its detected MCP servers reach.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectAccess {
    #[default]
    None,
    Read,
    Write,
}

impl ProjectAccess {
    /// The values of `[project] access`, from least to most.
    pub const VALUES: [&'static str; 3] = ["none", "read", "write"];

    /// The level that `value` names.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            _ => None,
        }
    }

    /// The value of `[project] access` for this level.
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    pub fn reads(self) -> bool {
        self != Self::None
    }

    pub fn writes(self) -> bool {
        self == Self::Write
    }
}

impl Resolved {
    /// The project access a run gets: `none` when the profile has no `[project]`.
    pub fn project_access(&self) -> ProjectAccess {
        self.project
            .map(|project| project.access)
            .unwrap_or_default()
    }
}

/// An `[agent]` or `[tool.<name>]` table.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Process {
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) workspace: Option<String>,
    #[serde(default, skip_serializing)]
    pub dependency: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Filesystem::is_empty")]
    pub filesystem: Filesystem,
    #[serde(
        default,
        rename = "file-watching",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) file_watching: Option<bool>,
    #[serde(default, skip_serializing_if = "Network::is_empty")]
    pub(crate) network: Network,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) grammar: Option<toml::Table>,
    #[serde(
        default,
        rename = "native-filesystem-policy",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) native_filesystem_policy: Option<bool>,
    /// The agent's `[[agent.ingress]]` entries, which Box Core validates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) ingress: Vec<toml::Table>,
}

/// The `[tool.<name>.network]` table of one tool.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contain_egress: Option<bool>,
}

impl Network {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// The filesystem lists of one process.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filesystem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive_mounts: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_file: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write_file: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub list: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metadata: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exec: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_write: Vec<String>,
}

impl Filesystem {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

impl Profile {
    /// Read a profile from its text, refusing every key that belongs to one run. Its
    /// `[requires]` is checked against `box` `version` first and taken out, so a profile for a
    /// later `box` gets the version it needs before any key that the later `box` added.
    pub fn parse(text: &str, path: &Path, version: &str) -> Result<Self, Error> {
        let invalid = |refusal: Refusal| refusal.in_file(path, text);
        let mut table: toml::Table =
            toml::from_str(text).map_err(|error| invalid(error.to_string().into()))?;
        lang::take_requires(&mut table, "profile", version).map_err(invalid)?;
        if let Some(refusal) = run_key(&table, "profile") {
            return Err(invalid(refusal));
        }
        if table.contains_key("policy") {
            return Err(invalid(Refusal::at(
                "a profile holds no `policy`; list authored files in `policies`".to_string(),
                &["policy"],
            )));
        }
        policy_references(&table).map_err(|reason| invalid(Refusal::at(reason, &["policies"])))?;
        lang::read_banner(&table).map_err(invalid)?;
        declared_name(&table).map_err(|reason| invalid(Refusal::at(reason, &["profile"])))?;
        lang::check_syntax(&table).map_err(|reason| invalid(reason.into()))?;
        Ok(Self {
            table,
            text: text.to_string(),
            path: path.to_path_buf(),
        })
    }

    /// The saved profile text, before packs and placeholders are resolved.
    pub fn source(&self) -> &str {
        &self.text
    }

    /// The name in `[profile] name`, when the profile declares one.
    pub fn declared_name(&self) -> Option<&str> {
        declared_name(&self.table).ok().flatten()
    }

    /// The packs this profile names in `packs`.
    pub fn packs(&self) -> Vec<String> {
        self.table
            .get("packs")
            .and_then(toml::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The policy files this profile names in `policies`.
    pub fn policies(&self) -> Vec<String> {
        policy_references(&self.table)
            .unwrap_or_default()
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    /// The profile's `[banner] enabled`, or `None` when it sets none.
    pub fn banner(&self) -> Option<bool> {
        lang::read_banner(&self.table).ok().flatten()
    }

    /// The real path of each file in `policies`.
    pub fn policy_files(&self) -> Result<Vec<PathBuf>, Error> {
        let invalid = |reason| Refusal::at(reason, &["policies"]).in_file(&self.path, &self.text);
        let references = policy_references(&self.table).map_err(invalid)?;
        let folder = self.path.parent().unwrap_or_else(|| Path::new(""));
        let real_folder = std::fs::canonicalize(folder).map_err(|error| {
            invalid(format!(
                "`policies`: cannot resolve profile folder {}: {error}",
                folder.display()
            ))
        })?;
        references
            .iter()
            .map(|reference| {
                policy_path(folder, &real_folder, reference)
                    .map_err(|error| invalid(format!("`policies` = {reference:?}: {error}")))
            })
            .collect()
    }

    /// The text of the files in `policies`, or `None` when it names none.
    pub fn load_policies(&self) -> Result<Option<String>, Error> {
        let invalid = |reason| Refusal::at(reason, &["policies"]).in_file(&self.path, &self.text);
        let references = policy_references(&self.table).map_err(invalid)?;
        if references.is_empty() {
            return Ok(None);
        }
        let folder = self.path.parent().unwrap_or_else(|| Path::new(""));
        let unresolved = |error| {
            invalid(format!(
                "`policies`: cannot resolve profile folder {}: {error}",
                folder.display()
            ))
        };
        for directory in folder
            .ancestors()
            .take(2)
            .filter(|path| path.file_name().is_some())
        {
            let metadata = std::fs::symlink_metadata(directory).map_err(unresolved)?;
            if metadata.file_type().is_symlink() {
                return Err(invalid(format!(
                    "`policies`: {} is a symbolic link; policy files need a real profile folder",
                    directory.display()
                )));
            }
        }
        let real_folder = std::fs::canonicalize(folder).map_err(unresolved)?;
        let mut seen = BTreeMap::new();
        let mut policies = Vec::new();
        for (index, reference) in references.iter().enumerate() {
            let candidate = folder.join(reference);
            let unreadable = |error| {
                invalid(format!(
                    "`policies[{index}]` = {reference:?}: cannot read {}: {error}",
                    candidate.display()
                ))
            };
            let path = policy_path(folder, &real_folder, reference).map_err(unreadable)?;
            if let Some(first) = seen.insert(path.clone(), index) {
                return Err(invalid(format!(
                    "`policies[{index}]` = {reference:?} names the same file as `policies[{first}]`"
                )));
            }
            let mut file = crate::files::open_regular(&path).map_err(unreadable)?;
            let metadata = file.metadata().map_err(unreadable)?;
            if metadata.nlink() != 1 {
                return Err(unreadable(io::Error::other(
                    "policy files must have exactly one hard link; use a separate copy",
                )));
            }
            let mut text = String::new();
            file.read_to_string(&mut text).map_err(unreadable)?;
            policies.push(text);
        }
        Ok(Some(join_policy_files(&policies)))
    }

    /// Load every profile this one extends, merge them, and fill in each placeholder.
    pub fn resolve(
        &self,
        policy: Option<&str>,
        lookup: &Lookup,
        sources: &mut impl Sources,
        inputs: &Inputs<'_>,
    ) -> Result<Resolved, Error> {
        let layers = self.layers(policy, lookup)?;
        self.resolve_layers(&layers, lookup, sources, inputs)
            .map(|(resolved, _)| resolved)
    }

    /// The profile and every pack it imports, bases first.
    pub fn layers(&self, policy: Option<&str>, lookup: &Lookup) -> Result<Vec<Layer>, Error> {
        lang::chain(
            &self.table,
            &self.text,
            &self.path,
            policy.map(str::to_string),
            lookup,
        )
    }

    /// Merge `layers`, fill in each placeholder, and retain the loaded launcher packs.
    pub fn resolve_layers(
        &self,
        layers: &[Layer],
        lookup: &Lookup,
        sources: &mut impl Sources,
        inputs: &Inputs<'_>,
    ) -> Result<(Resolved, BTreeMap<String, lang::LauncherPack>), Error> {
        let merged = lang::merge(layers)?;
        let launchers = lookup.launchers().map_err(|reason| Error::Profile {
            path: self.path.clone(),
            line: None,
            reason,
        })?;
        let resolved = reference::resolve(merged, &launchers, sources, inputs, &self.path)?;
        resolved.validate().map_err(|reason| Error::Profile {
            path: self.path.clone(),
            line: None,
            reason,
        })?;
        Ok((resolved, launchers))
    }
}

fn policy_path(folder: &Path, real_folder: &Path, reference: &str) -> io::Result<PathBuf> {
    let outside = || {
        io::Error::other(format!(
            "policy path leaves the profile folder {}",
            folder.display()
        ))
    };
    let path = std::fs::canonicalize(folder.join(reference))?;
    if !path.starts_with(real_folder) {
        return Err(outside());
    }
    let folder = std::path::absolute(folder)?;
    let relative = |path: &Path| {
        if path.is_absolute() {
            path.strip_prefix(&folder)
                .or_else(|_| path.strip_prefix(real_folder))
                .map(Path::to_path_buf)
                .map_err(|_| outside())
        } else {
            Ok(path.to_path_buf())
        }
    };
    let mut remaining = relative(Path::new(reference))?;
    let mut current = real_folder.to_path_buf();
    let mut links = 0;
    loop {
        let mut components = remaining.components();
        let Some(component) = components.next() else {
            break;
        };
        let rest = components.as_path().to_path_buf();
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if current == real_folder {
                    return Err(outside());
                }
                current.pop();
            }
            Component::Normal(name) => {
                let next = current.join(name);
                if std::fs::symlink_metadata(&next)?.file_type().is_symlink() {
                    links += 1;
                    if links > 40 {
                        return Err(io::Error::other("too many symbolic links in policy path"));
                    }
                    let target = std::fs::read_link(&next)?;
                    if target.is_absolute() {
                        current = real_folder.to_path_buf();
                    }
                    remaining = relative(&target)?.join(rest);
                    continue;
                }
                current = next;
            }
            _ => return Err(outside()),
        }
        remaining = rest;
    }
    Ok(path)
}

fn join_policy_files(files: &[String]) -> String {
    files
        .iter()
        .filter_map(|text| {
            let first = text.find(|c: char| !c.is_whitespace())?;
            let last = text.rfind(|c: char| !c.is_whitespace())?;
            let start = text[..first].rfind(['\r', '\n']).map_or(0, |i| i + 1);
            let end = text[last..]
                .find(['\r', '\n'])
                .map_or(text.len(), |i| last + i);
            Some(&text[start..end])
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// The `[profile] name` of `table`, or `None` when it has no `[profile]` table.
fn declared_name(table: &toml::Table) -> Result<Option<&str>, String> {
    let Some(header) = table.get(lang::PROFILE_HEADER) else {
        return Ok(None);
    };
    let header = header
        .as_table()
        .ok_or("`profile` is a table that holds `name`")?;
    header
        .get("name")
        .ok_or("`[profile]` needs a `name`")?
        .as_str()
        .map(Some)
        .ok_or_else(|| "`[profile] name` is not a string".to_string())
}

fn policy_references(table: &toml::Table) -> Result<Vec<&str>, String> {
    let Some(value) = table.get("policies") else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or("`policies` is not a list of file paths")?;
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            item.as_str()
                .filter(|path| !path.is_empty() && !path.contains(lang::OPEN))
                .ok_or_else(|| {
                    format!("`policies[{index}]` must be a nonempty file path with no placeholder")
                })
        })
        .collect()
}

impl Resolved {
    /// Every `[agent]` and `[tool.<name>]` table, with its label.
    pub(crate) fn processes(&self) -> impl Iterator<Item = (String, &Process)> {
        std::iter::once(("agent".to_string(), &self.agent)).chain(
            self.tool
                .iter()
                .map(|(name, tool)| (format!("tool.{name}"), tool)),
        )
    }

    pub(crate) fn processes_mut(&mut self) -> impl Iterator<Item = &mut Process> {
        std::iter::once(&mut self.agent).chain(self.tool.values_mut())
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.agent.command.first().is_none_or(String::is_empty) {
            return Err("`[agent] command` names no program".to_string());
        }
        if self.telemetry.contains_key(RECORDS) {
            return Err(format!(
                "`[telemetry.{RECORDS}]` is the target `box run` writes for each run"
            ));
        }
        Ok(())
    }
}

/// The refusal of the first key of `table` that belongs to one run, in a file of `kind`.
pub(crate) fn run_key(table: &toml::Table, kind: &str) -> Option<Refusal> {
    let refuse = |key: &str, at: &[&str]| {
        Refusal::at(
            format!("a {kind} holds no `{key}`, because `box run` sets it for each run"),
            at,
        )
    };
    if let Some(key) = ["name", "box_dir", "workspace"]
        .into_iter()
        .find(|key| table.contains_key(*key))
    {
        return Some(refuse(key, &[key]));
    }
    if table
        .get("agent")
        .and_then(toml::Value::as_table)
        .is_some_and(|agent| agent.contains_key("workspace"))
    {
        return Some(refuse("[agent] workspace", &["agent", "workspace"]));
    }
    table
        .get("tool")
        .and_then(toml::Value::as_table)?
        .iter()
        .find(|(_, tool)| {
            tool.as_table()
                .is_some_and(|tool| tool.contains_key("workspace"))
        })
        .map(|(name, _)| {
            refuse(
                &format!("[tool.{name}] workspace"),
                &["tool", name, "workspace"],
            )
        })
}

/// Refuse a profile name `box` does not accept.
pub fn validate_name(name: &str) -> Result<(), Error> {
    let refuse = |reason| {
        Err(Error::ProfileName {
            name: name.to_string(),
            reason,
        })
    };
    if name == BASE {
        return refuse("`base` is reserved and names no profile");
    }
    if name == "box" {
        return refuse("`box` is reserved and names no profile");
    }
    if name.is_empty() || name.len() > MAXIMUM_PROFILE_NAME {
        return refuse("use 1 to 64 characters");
    }
    if name.starts_with(['.', '-']) {
        return refuse("a name cannot start with `.` or `-`");
    }
    if !name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
    {
        return refuse("use only letters, digits, `.`, `_`, and `-`");
    }
    if name.ends_with(".toml") {
        return refuse(
            "a name cannot end in `.toml`, because `box run` reads that as a profile file",
        );
    }
    Ok(())
}

/// The directory that holds one folder for each profile.
#[derive(Debug, Clone)]
pub struct Profiles {
    root: PathBuf,
    /// The version of `box` that each profile's `[requires]` is checked against.
    version: &'static str,
}

/// One profile folder as `box profile list` reports it.
#[derive(Debug)]
pub struct Listed {
    /// The profile name.
    pub name: String,
    /// The profile, or why it cannot be read.
    pub profile: Result<Profile, Error>,
}

impl Profiles {
    /// The profiles under `root`, read by `box` `version`.
    pub fn at(root: impl Into<PathBuf>, version: &'static str) -> Self {
        Self {
            root: root.into(),
            version,
        }
    }

    /// The directory that holds the profiles.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The folder of the profile `name`.
    pub fn folder(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// The `profile.toml` of the profile `name`.
    pub fn path(&self, name: &str) -> PathBuf {
        self.folder(name).join(PROFILE_FILE)
    }

    /// The profile `name` and its policy text, or `None` when it does not exist.
    pub fn load(&self, name: &str) -> Result<Option<(Profile, Option<String>)>, Error> {
        self.load_observed(name, |_| {})
    }

    pub fn load_observed(
        &self,
        name: &str,
        observe: impl FnOnce(&[u8]),
    ) -> Result<Option<(Profile, Option<String>)>, Error> {
        validate_name(name)?;
        let path = self.path(name);
        let Some(bytes) = read_if_present(&path)? else {
            return Ok(None);
        };
        observe(&bytes);
        let text = String::from_utf8(bytes).map_err(|source| Error::Io {
            action: "read",
            path: path.clone(),
            source: io::Error::new(io::ErrorKind::InvalidData, source),
        })?;
        let profile = Profile::parse(&text, &path, self.version)?;
        if let Some(declared) = profile.declared_name()
            && declared != name
        {
            return Err(Refusal::at(
                format!(
                    "`[profile] name` is {declared:?}, but this profile's folder names it {name:?}; \
                     remove `[profile]` or make the two match"
                ),
                &[lang::PROFILE_HEADER, "name"],
            )
            .in_file(&path, &text));
        }
        let policy = profile.load_policies()?;
        Ok(Some((profile, policy)))
    }

    /// Every profile folder in the root, by name.
    pub fn list(&self) -> Result<Vec<Listed>, Error> {
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(Error::Io {
                    action: "list",
                    path: self.root.clone(),
                    source,
                });
            }
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter(|entry| entry.path().join(PROFILE_FILE).is_file())
            .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
            .filter(|name| validate_name(name).is_ok())
            .collect();
        names.sort();
        Ok(names
            .into_iter()
            .map(|name| {
                let path = self.path(&name);
                let profile = self.load(&name).and_then(|found| {
                    found.map(|(profile, _)| profile).ok_or(Error::Profile {
                        path,
                        line: None,
                        reason: "the file was removed while it was listed".to_string(),
                    })
                });
                Listed { name, profile }
            })
            .collect())
    }

    /// Whether the folder of the profile `name` holds anything.
    pub fn contains(&self, name: &str) -> Result<bool, Error> {
        validate_name(name)?;
        Ok(std::fs::symlink_metadata(self.folder(name)).is_ok())
    }

    /// Remove the folder of the profile `name`, and return whether it existed.
    pub fn remove(&self, name: &str) -> Result<bool, Error> {
        validate_name(name)?;
        remove_if_present(&self.folder(name))
    }

    /// Remove the profiles folder and everything in it, and return whether it existed.
    pub fn reset(&self) -> Result<bool, Error> {
        remove_if_present(&self.root)
    }
}

/// The bytes of `path`, or `None` when it does not exist.
fn read_if_present(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    match crate::files::open_regular(path).and_then(|mut file| {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(Error::Io {
            action: "read",
            path: path.to_path_buf(),
            source,
        }),
    }
}
