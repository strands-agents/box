//! The MCP servers that the packs' `[[mcp-servers]]` rows name in host files.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde_json::{Map, Value};
use strands_box::ReservedEnv;

use crate::compile::authority;
use crate::host::{canonical, is_executable_file, tilde, unique, utf8};
use crate::install_layout::{self, Layout};
use crate::lang;
use crate::mcp_config::{Config, Target};
use crate::reference::{Credentials, Sources};
use crate::storage_files::Refusals;

/// The server fields `box` reads, besides the fields a row's `env-var-locations` names. Every other
/// field passes through: it stays in the agent's own configuration, and it keeps no server out.
pub(crate) const KNOWN_FIELDS: &[&str] = &["type", "command", "args", "env", "url", "enabled"];

/// The known stdio fields that accept the `references` role.
pub(crate) const EXPANDED_FIELDS: &[&str] = &["command", "args", "env"];

/// The programs that fetch a server's code when it starts.
pub(crate) const LAUNCHERS: &[&str] = &["npx", "uvx", "bunx", "pnpx", "docker"];

/// The interpreters and package runners that run code their arguments name.
const RUNTIMES: &[&str] = &[
    "node", "deno", "bun", "ruby", "perl", "php", "java", "uv", "pipx", "npm", "pnpm", "yarn",
];

/// Whether Box Core sets `name` itself in each process it starts.
fn box_owned(name: &str) -> bool {
    matches!(
        strands_box::reserved_env(name),
        Some(ReservedEnv::GatewayProxy | ReservedEnv::GatewayCaFile | ReservedEnv::SetByBox)
    )
}

/// Whether Box Core sets `name` only in a process whose egress goes through the gateway.
fn gateway_routing(name: &str) -> bool {
    matches!(
        strands_box::reserved_env(name),
        Some(ReservedEnv::GatewayProxy | ReservedEnv::GatewayCaFile)
    )
}

/// Whether `name` is a gateway-routing variable that names a CA file.
fn names_ca_file(name: &str) -> bool {
    strands_box::reserved_env(name) == Some(ReservedEnv::GatewayCaFile)
}

/// A gateway-routing variable that a server with direct network access keeps.
#[derive(Debug, Clone, PartialEq)]
enum Held {
    /// A proxy setting, with its value.
    Value(String),
    /// A CA file the server reads, with its full path.
    File(String),
    /// A CA path the box cannot grant, with the reason.
    Refused(String),
    /// A reference with no value, with the reason.
    Unset(String),
}

/// Whether a stdio server with `table`, and the profile's `addition` to it, has direct network
/// access.
fn native_egress(table: &toml::Table, addition: Option<&toml::Value>) -> bool {
    let contain = |value: Option<&toml::Value>| {
        value
            .and_then(|entry| entry.get("network"))
            .and_then(|network| network.get("contain_egress"))
            .and_then(toml::Value::as_bool)
    };
    table.get("type").and_then(toml::Value::as_str) == Some("stdio")
        && contain(addition).or(contain(Some(&toml::Value::Table(table.clone())))) == Some(false)
}

/// Whether `name` makes a program load code.
fn loads_code(name: &str) -> bool {
    strands_box::reserved_env(name) == Some(ReservedEnv::LoadsCode)
}

/// Whether a remote server's key cannot come from `name`, because Box Core sets it or writes over it.
fn reserved_for_key(name: &str) -> bool {
    matches!(name, "HOME" | "PATH") || box_owned(name) || loads_code(name)
}

/// What a remote server's field holds, as a row's `env-var-locations` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// The variable whose value is the bearer token.
    BearerVariable,
    /// A table from a header to the variable whose value is that header.
    HeaderVariables,
    /// A table from a header to a value that ends in one variable.
    HeaderReferences,
    /// A stdio server's `command`, `args`, or `env` with variable references.
    References,
    /// A list of variables a stdio server gets from the operator's environment.
    VariableNames,
}

impl Role {
    /// Each role, by the name a row writes.
    pub(crate) const NAMES: &[(&str, Role)] = &[
        ("bearer-variable", Role::BearerVariable),
        ("header-variables", Role::HeaderVariables),
        ("header-references", Role::HeaderReferences),
        ("references", Role::References),
        ("variable-names", Role::VariableNames),
    ];

    /// The role `name` names.
    pub(crate) fn named(name: &str) -> Option<Self> {
        Self::NAMES
            .iter()
            .find(|(known, _)| *known == name)
            .map(|(_, role)| *role)
    }

    /// The name a row writes for the role.
    pub(crate) fn name(self) -> &'static str {
        Self::NAMES
            .iter()
            .find(|(_, role)| *role == self)
            .map_or("", |(name, _)| *name)
    }

    /// Whether the role is for a stdio server's field, not a remote server's.
    pub(crate) fn is_local(self) -> bool {
        matches!(self, Self::References | Self::VariableNames)
    }

    /// Whether the role reads variables written in the row's `env-var-syntax`.
    pub(crate) fn needs_syntax(self) -> bool {
        matches!(self, Self::HeaderReferences | Self::References)
    }

    /// Whether the role fills in each variable in the field's own values.
    pub(crate) fn expands(self) -> bool {
        self == Self::References
    }
}

/// One variable a remote server takes its key from, and where the key goes on a request.
struct Key {
    variable: String,
    placement: Placement,
    has_default: bool,
}

/// Where Box Core puts a remote server's key on a request.
enum Placement {
    /// `Authorization: Bearer <key>`, Box Core's default.
    Bearer,
    /// A header, with the text before the key.
    Header { name: String, prefix: String },
    /// A query parameter of the URL.
    Query(String),
}

impl Placement {
    /// The place, as a skip reason names it.
    fn described(&self) -> String {
        match self {
            Self::Bearer => "the header Authorization".to_string(),
            Self::Header { name, .. } => format!("the header {name}"),
            Self::Query(param) => format!("the url's {param}"),
        }
    }
}

/// The reason for a variable in a URL that `box` cannot read as a key.
const VARIABLE_IN_URL: &str = "passes a variable in its url, which box does not fill in";

/// How a harness writes a variable inside a string: one or more forms, each with `NAME` once after
/// the text that opens it, such as `${NAME}`, and the text that starts a value the harness runs as
/// a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Syntax {
    /// Each form as `(open, close)`, the longest `open` first, so `${NAME}` is tried before `$NAME`.
    forms: Vec<(String, String)>,
    /// The text that starts a value the harness runs as a command, such as pi's `!`.
    command_prefix: Option<String>,
}

impl Syntax {
    /// The syntax of `forms`, or the first form that does not hold `NAME` once after its opening.
    pub(crate) fn new(forms: &[String], command_prefix: Option<String>) -> Result<Self, String> {
        let mut parsed = Vec::new();
        for form in forms {
            match form.split_once("NAME") {
                Some((open, close)) if !open.is_empty() && !close.contains("NAME") => {
                    parsed.push((open.to_string(), close.to_string()));
                }
                _ => return Err(form.clone()),
            }
        }
        parsed.sort_by_key(|(open, _)| std::cmp::Reverse(open.len()));
        Ok(Self {
            forms: parsed,
            command_prefix,
        })
    }

    /// The syntax of one form, with no command prefix.
    #[cfg(test)]
    pub(crate) fn one(form: &str) -> Self {
        Self::new(&[form.to_string()], None).expect("a form")
    }

    /// The forms that have closing text, such as `${NAME}`, or `None` when no form has it. A URL is
    /// read with these only, because a `$` in a URL, such as OData's `$filter`, is plain text.
    fn closed(&self) -> Option<Self> {
        let forms: Vec<(String, String)> = self
            .forms
            .iter()
            .filter(|(_, close)| !close.is_empty())
            .cloned()
            .collect();
        (!forms.is_empty()).then_some(Self {
            forms,
            command_prefix: None,
        })
    }

    /// The syntax that marks a variable in `field`: every form when the field has the `references`
    /// role, else only the forms that have closing text. A harness that fills in no variable in
    /// `args`, such as pi, passes `$HOME/x` as written, so the argument stays literal.
    fn for_field(
        syntax: Option<&Self>,
        roles: &BTreeMap<String, Role>,
        field: &str,
    ) -> Option<Self> {
        if roles.get(field) == Some(&Role::References) {
            syntax.cloned()
        } else {
            syntax.and_then(Self::closed)
        }
    }

    /// Each variable name that `text` writes in one of the forms, with or without a default.
    fn variables(&self, text: &str) -> Vec<String> {
        let mut found = Vec::new();
        for (open, close) in &self.forms {
            for (at, _) in text.match_indices(open.as_str()) {
                let after = &text[at + open.len()..];
                let length = after
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(after.len());
                let (name, tail) = after.split_at(length);
                let closed =
                    close.is_empty() || tail.starts_with(close.as_str()) || tail.starts_with(":-");
                if closed && is_variable(name) && !found.iter().any(|known| known == name) {
                    found.push(name.to_string());
                }
            }
        }
        found
    }

    /// Whether `text` opens a variable in one of the forms. A form with no closing text, such as
    /// `$NAME`, opens one only before a letter or `_`.
    fn opens(&self, text: &str) -> bool {
        self.forms.iter().any(|(open, close)| {
            if close.is_empty() {
                text.match_indices(open.as_str()).any(|(at, _)| {
                    text[at + open.len()..]
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                })
            } else {
                text.contains(open.as_str())
            }
        })
    }

    /// Why `box` cannot read `text` as the harness does: a command the harness runs, or an escape
    /// that a form with no closing text writes, such as pi's `$$` and `$!`.
    fn unread(&self, text: &str) -> Option<String> {
        if let Some(prefix) = &self.command_prefix
            && text.starts_with(prefix.as_str())
        {
            return Some(format!(
                "starts with `{prefix}`, so the agent runs it as a command, which box does not do"
            ));
        }
        for (open, close) in &self.forms {
            if !close.is_empty() {
                continue;
            }
            for next in std::iter::once(open).chain(self.command_prefix.as_ref()) {
                let escape = format!("{open}{next}");
                if text.contains(&escape) {
                    return Some(format!(
                        "writes `{escape}`, an escape that box does not read"
                    ));
                }
            }
        }
        None
    }
}

impl std::fmt::Display for Syntax {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let forms: Vec<String> = self
            .forms
            .iter()
            .map(|(open, close)| format!("`{open}NAME{close}`"))
            .collect();
        f.write_str(&forms.join(" or "))
    }
}

/// One `[[mcp-servers]]` row, resolved: a host file, its format, and the keys to its servers.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Source {
    pub(crate) target: Option<Target>,
    pub(crate) active: bool,
    pub(crate) file: PathBuf,
    pub(crate) kind: Format,
    pub(crate) key: Vec<String>,
    /// What each harness field holds, by field.
    pub(crate) env_var_locations: BTreeMap<String, Role>,
    /// How the harness writes a variable in a string, such as `${NAME}`.
    pub(crate) env_var_syntax: Option<Syntax>,
    /// Why `box` does not read the file, when it lies where a box can write.
    pub(crate) refused: Option<String>,
}

/// What a run did with one source file.
#[derive(Debug, Clone, PartialEq)]
pub enum Reading {
    Read,
    Absent,
    NotRead(String),
}

/// How the box reaches a detected server.
#[derive(Debug, Clone, PartialEq)]
pub enum Transport {
    Stdio {
        program: String,
        program_path: PathBuf,
        /// The launcher that starts the server, when its program is one.
        launcher: Option<Box<Launcher>>,
    },
    Http,
}

/// The resolved tool requirements used by an MCP launcher.
#[derive(Debug, Clone, PartialEq)]
pub struct Launcher {
    pub pack: String,
    pub hosts: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub read: Vec<PathBuf>,
    /// The folders the launcher's table lists, such as Homebrew's `opt` for its Python.
    pub list: Vec<PathBuf>,
    pub deny: Vec<String>,
    /// The folder in storage that the launcher's cache settings name.
    pub cache: PathBuf,
}

/// One server that becomes an `[mcp.<name>]` table.
#[derive(Debug, Clone, PartialEq)]
pub struct Detected {
    pub installations: Vec<String>,
    pub name: String,
    pub source: PathBuf,
    pub transport: Transport,
    /// Whether a profile table with no `type` adds to the server.
    pub extended: bool,
    /// The variables the server takes its keys from.
    pub variables: Vec<String>,
    /// The names in a stdio server's `env`, and each variable filled in in its `command`.
    pub env: Vec<String>,
    /// Each variable the server's configuration sets that the box sets itself, with the reason.
    pub dropped: Vec<(String, String)>,
}

impl Detected {
    /// The end of the server's report line: its key, or the variables it gets.
    fn detail(&self) -> String {
        if !self.variables.is_empty() {
            format!(", with the key in {}", self.variables.join(", "))
        } else if !self.env.is_empty() {
            format!(", with {}", self.env.join(", "))
        } else {
            String::new()
        }
    }
}

/// One server that the box does not declare, with the reason.
#[derive(Debug, Clone, PartialEq)]
pub struct Skipped {
    pub name: String,
    pub source: PathBuf,
    pub reason: String,
}

/// What the run read, detected, and skipped.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Servers {
    /// Each resolved storage target, including rows with import disabled.
    pub targets: Vec<Target>,
    pub configs: Vec<Config>,
    pub sources: Vec<(PathBuf, Reading)>,
    pub detected: Vec<Detected>,
    pub skipped: Vec<Skipped>,
}

impl Servers {
    /// The program path of the detected stdio server `name`.
    pub(crate) fn program_path(&self, name: &str) -> Option<&Path> {
        self.detected
            .iter()
            .find(|server| server.name == name)
            .and_then(|server| match &server.transport {
                Transport::Stdio { program_path, .. } => Some(program_path.as_path()),
                Transport::Http => None,
            })
    }

    /// The program path of the detected stdio server `name`, when it still starts `program`.
    pub(crate) fn spawns(&self, name: &str, program: &str) -> Option<&Path> {
        self.detected
            .iter()
            .find(|server| server.name == name)
            .and_then(|server| match &server.transport {
                Transport::Stdio {
                    program: detected,
                    program_path,
                    ..
                } if detected == program => Some(program_path.as_path()),
                _ => None,
            })
    }

    /// The launcher of the detected stdio server `name`, when a launcher starts it.
    pub(crate) fn launcher(&self, name: &str) -> Option<&Launcher> {
        self.detected
            .iter()
            .find(|server| server.name == name)
            .and_then(|server| match &server.transport {
                Transport::Stdio { launcher, .. } => launcher.as_deref(),
                Transport::Http => None,
            })
    }

    /// Each cache folder a detected server's launcher writes, once each.
    pub(crate) fn caches(&self) -> Vec<PathBuf> {
        let mut caches: Vec<PathBuf> = self
            .detected
            .iter()
            .filter_map(|server| match &server.transport {
                Transport::Stdio {
                    launcher: Some(launcher),
                    ..
                } => Some(launcher.cache.clone()),
                _ => None,
            })
            .collect();
        caches.sort();
        caches.dedup();
        caches
    }

    /// Whether `name` is a detected stdio server.
    pub(crate) fn is_detected_stdio(&self, name: &str) -> bool {
        self.program_path(name).is_some()
    }

    /// Each detected server as `(name, source, detail)`, where `detail` ends its report line.
    pub fn detected_lines(&self, home: &Path) -> Vec<(String, String, String)> {
        self.detected
            .iter()
            .map(|server| {
                (
                    server.name.clone(),
                    tilde(home, &server.source),
                    server.detail(),
                )
            })
            .collect()
    }

    /// Each variable a detected server goes without, as `(variable, name, source, reason)`.
    pub fn dropped_lines(&self, home: &Path) -> Vec<(String, String, String, String)> {
        self.detected
            .iter()
            .flat_map(|server| {
                server.dropped.iter().map(|(variable, reason)| {
                    (
                        variable.clone(),
                        server.name.clone(),
                        tilde(home, &server.source),
                        reason.clone(),
                    )
                })
            })
            .collect()
    }

    /// Each skipped server as `(name, source, reason)`.
    pub fn skipped_lines(&self, home: &Path) -> Vec<(String, String, String)> {
        self.skipped
            .iter()
            .map(|server| {
                (
                    server.name.clone(),
                    tilde(home, &server.source),
                    server.reason.clone(),
                )
            })
            .collect()
    }

    /// Each source file that was not read, as `(file, reason)`.
    pub fn unread_lines(&self, home: &Path) -> Vec<(String, String)> {
        self.sources
            .iter()
            .filter_map(|(file, reading)| match reading {
                Reading::NotRead(reason) => Some((tilde(home, file), reason.clone())),
                _ => None,
            })
            .collect()
    }
}

/// How a source file is read. A pack names no reader yet, so each source takes the generic one.
#[derive(Debug, Clone, Copy)]
enum Reader {
    Generic,
}

impl Reader {
    fn for_source(_source: &Source) -> Self {
        Self::Generic
    }

    /// Each server under the keys `path` in `document`, by name, or why the keys do not name a
    /// server table.
    fn servers(self, document: &Value, path: &[String]) -> Result<Vec<(String, Value)>, String> {
        match self {
            Self::Generic => {
                let mut value = document;
                for key in path {
                    match value.get(key) {
                        Some(next) => value = next,
                        None => return Ok(Vec::new()),
                    }
                }
                let table = value.as_object().ok_or_else(|| {
                    format!(
                        "the value at {} is not a table of servers",
                        path.iter()
                            .map(|key| format!("{key:?}"))
                            .collect::<Vec<_>>()
                            .join(" > ")
                    )
                })?;
                Ok(table
                    .iter()
                    .map(|(name, server)| (name.clone(), server.clone()))
                    .collect())
            }
        }
    }
}

/// The text format of a source file, as its row's `kind` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Format {
    Json,
    Toml,
}

impl Format {
    /// The format that a row's `kind` names, or `None` when it names neither.
    pub fn named(kind: &str) -> Option<Self> {
        match kind {
            "json" => Some(Self::Json),
            "toml" => Some(Self::Toml),
            _ => None,
        }
    }

    pub fn parse(self, text: &str) -> Result<Value, String> {
        match self {
            Self::Json => serde_json::from_str(text).map_err(|error| format!("not JSON: {error}")),
            Self::Toml => toml::from_str::<toml::Value>(text)
                .map_err(|error| format!("not TOML: {error}"))
                .and_then(|value| serde_json::to_value(value).map_err(|error| error.to_string())),
        }
    }
}

/// What the run knows besides the sources.
pub(crate) struct Context<'a> {
    pub(crate) os: &'a str,
    pub(crate) home: &'a Path,
    pub(crate) workspace: &'a Path,
    /// How much of the workspace a detected stdio server reaches.
    pub(crate) project: crate::profile::ProjectAccess,
    /// The profile file, which a skipped addition names as its source.
    pub(crate) profile: &'a Path,
    /// The pack file of each addition that a pack holds, which a skipped addition names instead.
    pub(crate) additions: &'a BTreeMap<String, PathBuf>,
    pub(crate) refusals: &'a Refusals,
    /// The profile's routes, whose hosts a remote server cannot share.
    pub(crate) egress: &'a toml::Table,
    /// The agent's and each tool's program, as `(label, command[0])`.
    pub(crate) programs: &'a [(String, String)],
    /// The variables the profile sets in `[agent.env]`.
    pub(crate) agent_env: &'a BTreeMap<String, String>,
    /// The host variables that hold a credential, which no server gets.
    pub(crate) credentials: &'a Credentials,
    /// Each variable that holds the stand-in of a key from a secret source, with what names it.
    pub(crate) stand_ins: &'a BTreeMap<String, String>,
}

/// Each variable that a route of `egress` or a remote server of `mcp` names in `secret.env` for a
/// key that is not that variable's own `env://` reference, with what names it, such as
/// "the route github names in `secret.env` for its op:// key".
pub(crate) fn stand_ins(egress: &toml::Table, mcp: &toml::Table) -> BTreeMap<String, String> {
    let entries = egress
        .iter()
        .map(|(name, entry)| (format!("the route {name}"), entry))
        .chain(
            mcp.iter()
                .filter(|(_, entry)| {
                    entry.get("type").and_then(toml::Value::as_str) == Some("http")
                })
                .map(|(name, entry)| (format!("the server {name}"), entry)),
        );
    let mut found = BTreeMap::new();
    for (owner, entry) in entries {
        let Some(secret) = entry.get("secret") else {
            continue;
        };
        let (Some(variable), Some(reference)) = (
            secret.get("env").and_then(toml::Value::as_str),
            secret.get("ref").and_then(toml::Value::as_str),
        ) else {
            continue;
        };
        if reference.strip_prefix("env://") == Some(variable) {
            continue;
        }
        let scheme = reference
            .split_once("://")
            .map_or(reference, |(scheme, _)| scheme);
        found
            .entry(variable.to_string())
            .or_insert_with(|| format!("{owner} names in `secret.env` for its {scheme}:// key"));
    }
    found
}

/// Whether two destination ports overlap as Box Core reads them: no port means 443 or 80.
fn ports_overlap(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left == right,
        (Some(port), None) | (None, Some(port)) => port == "443" || port == "80",
        (None, None) => true,
    }
}

/// The `destinations` strings of a profile's `[mcp.<name>]` addition.
fn added_destinations(addition: Option<&toml::Value>) -> impl Iterator<Item = &str> {
    addition
        .and_then(|addition| addition.get("destinations"))
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
}
/// A launcher pack resolved for the executable a server names.
pub(crate) type Launchers<'a> =
    dyn FnMut(&str, &str, &mut dyn Sources) -> Result<Option<Launcher>, String> + 'a;

/// Whether the destination host `held`, which can be a `*.` wildcard, covers `host`.
fn same_host(held: &str, host: &str) -> bool {
    held.eq_ignore_ascii_case(host)
        || held.strip_prefix("*.").is_some_and(|domain| {
            host.to_ascii_lowercase()
                .ends_with(&format!(".{}", domain.to_ascii_lowercase()))
        })
}

/// A server that passed every check of its own, before names and programs are compared.
struct Candidate {
    installations: Vec<String>,
    name: String,
    source: PathBuf,
    table: toml::Table,
    transport: Transport,
    variables: Vec<String>,
    env: Vec<String>,
    dropped: Vec<(String, String)>,
    held: BTreeMap<String, Held>,
}

/// One selected host entry and the source fields that supply its environment.
struct Import {
    target: Target,
    value: Value,
    env_fields: Vec<String>,
    /// The syntax that marks a variable in `command` and in `args`.
    command_syntax: Option<Syntax>,
    args_syntax: Option<Syntax>,
}

/// Read each source for import, and add each supported server to `mcp`.
pub(crate) fn detect(
    rows: &[Source],
    mcp: &mut toml::Table,
    sources: &mut impl Sources,
    context: &Context<'_>,
    launchers: &mut Launchers<'_>,
) -> Servers {
    let mut servers = Servers::default();
    let mut found: BTreeMap<String, Found> = BTreeMap::new();
    let mut documents: BTreeMap<(PathBuf, Format), Result<Value, Reading>> = BTreeMap::new();
    for row in rows {
        if let Some(target) = &row.target
            && !servers.targets.contains(target)
        {
            servers.targets.push(target.clone());
        }
        if !row.active {
            continue;
        }
        if let Some(target) = &row.target
            && !servers
                .configs
                .iter()
                .any(|config| config.target == *target)
        {
            servers.configs.push(Config {
                target: target.clone(),
                servers: Map::new(),
            });
        }
        let entry = (row.file.clone(), read(row, &mut documents, &mut found));
        if !servers.sources.contains(&entry) {
            servers.sources.push(entry);
        }
    }
    let path_reach = sources
        .search_path()
        .into_iter()
        .filter(|directory| directory.is_absolute())
        .find_map(|directory| {
            context
                .refusals
                .reach(&directory)
                .map(|reason| format!("your PATH directory {reason}; a server inherits your PATH"))
        });
    let mut imports = BTreeMap::new();
    let mut candidates = Vec::new();
    for (name, Found(source, value, roles, syntax, target)) in found {
        let converted = convert(
            &value,
            &roles,
            syntax.as_ref(),
            sources,
            context,
            path_reach.as_deref(),
            launchers,
        );
        if let Some(target) = target {
            imports.insert(
                name.clone(),
                Import {
                    target,
                    value,
                    env_fields: roles
                        .iter()
                        .filter_map(|(field, role)| {
                            (*role == Role::VariableNames).then_some(field.clone())
                        })
                        .collect(),
                    command_syntax: Syntax::for_field(syntax.as_ref(), &roles, "command"),
                    args_syntax: Syntax::for_field(syntax.as_ref(), &roles, "args"),
                },
            );
        }
        match converted {
            Ok(Converted {
                installations,
                table,
                transport,
                variables,
                env,
                dropped,
                held,
            }) => candidates.push(Candidate {
                installations,
                name,
                source,
                table,
                transport,
                variables,
                env,
                dropped,
                held,
            }),
            Err(reason) => servers.skipped.push(Skipped {
                name,
                source,
                reason,
            }),
        }
    }
    let declared: BTreeSet<String> = mcp
        .iter()
        .filter(|(_, entry)| entry.get("type").is_some())
        .map(|(name, _)| name.clone())
        .collect();
    let programs: BTreeMap<String, String> = context
        .programs
        .iter()
        .map(|(label, program)| (program_name(program).to_string(), label.clone()))
        .collect();
    let mut commands: BTreeMap<(Vec<String>, bool), String> = BTreeMap::new();
    let mut wildcard_commands: BTreeMap<Vec<String>, String> = BTreeMap::new();
    for (name, entry) in mcp.iter().filter(|(name, _)| declared.contains(*name)) {
        if let Some(command) = matching_command_of(entry) {
            commands.insert(
                (command, wildcard_command_of(entry).is_some()),
                name.clone(),
            );
        }
        if let Some(command) = wildcard_command_of(entry) {
            wildcard_commands.insert(command, name.clone());
        }
    }
    let destinations = |table: &toml::Value| -> Vec<String> {
        table
            .get("destinations")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .map(|destination| authority(destination).0.to_string())
            .collect()
    };
    let mut keyed: BTreeMap<String, String> = mcp
        .iter()
        .filter(|(_, entry)| entry.get("type").and_then(toml::Value::as_str) == Some("http"))
        .filter_map(|(name, entry)| Some((key_variable(entry)?.to_string(), name.clone())))
        .collect();
    let mut hosts: Vec<(String, String)> = Vec::new();
    for (name, route) in context.egress {
        if crate::compile::is_open_route(route) {
            continue;
        }
        for host in destinations(route) {
            hosts.push((format!("the route {name}"), host));
        }
    }
    for (name, entry) in mcp.iter() {
        if entry.get("type").and_then(toml::Value::as_str) == Some("http") {
            for host in destinations(entry) {
                hosts.push((format!("the server {name}"), host));
            }
        }
    }
    for candidate in candidates {
        let name = candidate.name.clone();
        let skip = |reason: String| Skipped {
            name: candidate.name.clone(),
            source: candidate.source.clone(),
            reason,
        };
        if !allowed_name(&name) {
            servers.skipped.push(skip(
                "its name holds a character Box Core does not take in a server name (only \
                 letters, digits, `.`, `_`, and `-`); rename the server in your agent's \
                 configuration"
                    .to_string(),
            ));
            continue;
        }
        if declared.contains(&name) {
            servers.skipped.push(skip(format!(
                "the profile declares `[mcp.{name}]`, which takes its place"
            )));
            continue;
        }
        let direct = native_egress(&candidate.table, mcp.get(&name));
        if direct
            && let Some(reason) = candidate.held.values().find_map(|kept| match kept {
                Held::Unset(reason) => Some(reason.clone()),
                _ => None,
            })
        {
            servers.skipped.push(skip(reason));
            continue;
        }
        if let Transport::Stdio {
            program, launcher, ..
        } = &candidate.transport
            && let Some(other) = programs.get(program_name(program))
            && !(launcher.is_some() && other.starts_with("the tool "))
        {
            servers.skipped.push(skip(format!(
                "runs {program}, which {other} runs too; the box puts one program of each name \
                 on PATH"
            )));
            continue;
        }
        let entry = toml::Value::Table(candidate.table.clone());
        if let Some(command) = matching_command_of(&entry)
            && let Some(other) = commands.get(&(command, wildcard_command_of(&entry).is_some()))
        {
            servers.skipped.push(skip(format!(
                "has the same detected command as the server {other}; calls routed to {other} \
                 use its policy and environment"
            )));
            continue;
        }
        if let Some(command) = wildcard_command_of(&entry)
            && let Some((_, other)) = wildcard_commands.iter().find(|(held, _)| {
                held.len() == command.len()
                    && held
                        .iter()
                        .zip(&command)
                        .all(|(left, right)| left == right || left == "*" || right == "*")
            })
        {
            servers.skipped.push(skip(format!(
                "its argument wildcards overlap with the server {other}; calls routed to \
                 {other} use its policy and environment"
            )));
            continue;
        }
        let host = candidate
            .table
            .get("destinations")
            .and_then(|items| items.get(0))
            .and_then(toml::Value::as_str)
            .map(|destination| authority(destination).0);
        if let Some(host) = host
            && let Some((other, _)) = hosts.iter().find(|(_, held)| same_host(held, host))
        {
            servers.skipped.push(skip(format!(
                "reaches {host}, which {other} reaches too; the box routes a remote server by \
                 its host alone"
            )));
            continue;
        }
        let port = candidate
            .table
            .get("destinations")
            .and_then(|items| items.get(0))
            .and_then(toml::Value::as_str)
            .and_then(|destination| authority(destination).1);
        if let Some(host) = host
            && let Some(wildcard) = added_destinations(mcp.get(&name)).find(|added| {
                let (added, added_port) = authority(added);
                (added == "*" || added.starts_with("*.") && same_host(added, host))
                    && ports_overlap(port, added_port)
            })
        {
            servers.skipped.push(skip(format!(
                "`[mcp.{name}]` adds {wildcard}, which covers its own host {host}; Box Core \
                 refuses two destinations of one server that overlap"
            )));
            continue;
        }
        let supplies_secret = mcp
            .get(&name)
            .and_then(|addition| addition.get("secret"))
            .is_some_and(|added| {
                let held = candidate.table.get("secret");
                held.is_none()
                    || added.as_table().is_none_or(|added| {
                        added
                            .iter()
                            .any(|(key, value)| held.and_then(|held| held.get(key)) != Some(value))
                    })
            });
        if supplies_secret {
            servers.skipped.push(skip(format!(
                "the profile's `[mcp.{name}]` sets `secret` without a `type`, and the box gives a \
                 key only to a server the profile declares; to give this server a key, declare \
                 it with a `type` and its own `destinations`"
            )));
            continue;
        }
        if let (Transport::Http, Some(variable)) =
            (&candidate.transport, candidate.variables.first())
        {
            if let Some(other) = keyed.get(variable) {
                servers.skipped.push(skip(format!(
                    "takes its key from {variable}, which the server {other} takes too; the box \
                     gives each key to one remote server"
                )));
                continue;
            }
            keyed.insert(variable.clone(), name.clone());
        }
        if let Some(host) = host {
            hosts.push((format!("the server {name}"), host.to_string()));
        }
        if let Some(command) = matching_command_of(&entry) {
            commands.insert(
                (command, wildcard_command_of(&entry).is_some()),
                name.clone(),
            );
        }
        if let Some(command) = wildcard_command_of(&entry) {
            wildcard_commands.insert(command, name.clone());
        }
        let mut table = candidate.table;
        let addition = mcp.remove(&name);
        let extended = addition.is_some();
        if let Some(toml::Value::Table(mut additions)) = addition {
            if let (Some(toml::Value::Array(held)), Some(toml::Value::Array(added))) = (
                table.get("destinations").cloned(),
                additions.get("destinations").cloned(),
            ) {
                let mut joined = held;
                for item in added {
                    let covered = item.as_str().is_some_and(|added| {
                        let (host, port) = authority(added);
                        joined.iter().filter_map(toml::Value::as_str).any(|held| {
                            let (held_host, held_port) = authority(held);
                            held_host.eq_ignore_ascii_case(host) && ports_overlap(held_port, port)
                        })
                    });
                    if !covered {
                        joined.push(item);
                    }
                }
                additions.insert("destinations".into(), toml::Value::Array(joined));
            }
            lang::merge_table(
                &mut table,
                additions,
                &mut vec!["mcp".to_string(), name.clone()],
            );
        }
        if let Some(import) = imports.get_mut(&name)
            && matches!(candidate.transport, Transport::Stdio { .. })
            && let Some(fields) = import.value.as_object_mut()
        {
            fields.remove("env");
            for field in &import.env_fields {
                fields.remove(field);
            }
            if let Some(command) = command_of(&toml::Value::Table(table.clone()))
                && let Some((program, arguments)) = command.split_first()
            {
                fields.insert(
                    "command".into(),
                    Value::String(program_name(program).into()),
                );
                if !arguments.is_empty() || fields.contains_key("args") {
                    let wildcards = table
                        .get("argument_wildcards")
                        .and_then(toml::Value::as_bool)
                        == Some(true);
                    let arguments = arguments
                        .iter()
                        .enumerate()
                        .map(|(index, argument)| {
                            if wildcards
                                && argument == "*"
                                && let Some(original) = fields
                                    .get("args")
                                    .and_then(|args| args.get(index))
                                    .and_then(Value::as_str)
                            {
                                return Value::String(original.to_string());
                            }
                            Value::String(argument.clone())
                        })
                        .collect();
                    fields.insert("args".into(), Value::Array(arguments));
                }
            }
        }
        let mut env = candidate.env;
        let mut dropped = candidate.dropped;
        if direct && !candidate.held.is_empty() {
            let mut files = Vec::new();
            if let toml::Value::Table(own) = table
                .entry("env")
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            {
                for (variable, kept) in candidate.held {
                    let value = match kept {
                        Held::Value(value) => value,
                        Held::File(value) => {
                            files.push(value.clone());
                            value
                        }
                        Held::Refused(reason) | Held::Unset(reason) => {
                            for (name, why) in &mut dropped {
                                if *name == variable {
                                    *why = reason.clone();
                                }
                            }
                            continue;
                        }
                    };
                    if !own.contains_key(&variable) {
                        own.insert(variable.clone(), toml::Value::from(value));
                    }
                    if !env.contains(&variable) {
                        env.push(variable.clone());
                    }
                    dropped.retain(|(name, _)| *name != variable);
                }
                if own.is_empty() {
                    table.remove("env");
                }
            }
            if !files.is_empty()
                && let toml::Value::Table(filesystem) = table
                    .entry("filesystem")
                    .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                && let toml::Value::Array(read_file) = filesystem
                    .entry("read_file")
                    .or_insert_with(|| toml::Value::Array(Vec::new()))
            {
                for file in files {
                    if !read_file.iter().any(|held| held.as_str() == Some(&file)) {
                        read_file.push(toml::Value::from(file));
                    }
                }
            }
            env.sort();
        }
        mcp.insert(name.clone(), toml::Value::Table(table));
        servers.detected.push(Detected {
            installations: candidate.installations,
            name,
            source: candidate.source,
            transport: candidate.transport,
            extended,
            variables: candidate.variables,
            env,
            dropped,
        });
    }
    let additions: Vec<String> = mcp
        .iter()
        .filter(|(_, entry)| entry.get("type").is_none())
        .map(|(name, _)| name.clone())
        .collect();
    for name in additions {
        mcp.remove(&name);
        if servers.skipped.iter().any(|skip| skip.name == name) {
            continue;
        }
        servers.skipped.push(Skipped {
            reason: format!(
                "`[mcp.{name}]` has no `type`, so it adds to a server this run finds, and this \
                 run finds no server named {name}"
            ),
            source: context
                .additions
                .get(&name)
                .cloned()
                .unwrap_or_else(|| context.profile.to_path_buf()),
            name,
        });
    }
    for (name, mut import) in imports {
        let holds = import
            .value
            .as_object()
            .is_some_and(|fields| imports_credential(fields, &*sources, context.credentials));
        let argument = import
            .value
            .as_object()
            .is_some_and(|fields| imports_argument(fields, &*sources, context.credentials));
        let program = declared_stdio(&import, mcp);
        if argument && let Some(fields) = import.value.as_object_mut() {
            fields.remove("args");
        }
        if (holds || program.is_some())
            && let Some(fields) = import.value.as_object_mut()
        {
            fields.remove("env");
            for field in &import.env_fields {
                fields.remove(field);
            }
            if let Some(program) = program {
                fields.insert("command".into(), Value::String(program));
            }
        } else if declared.contains(&name)
            && carries_env(&import)
            && let Some(skip) = servers.skipped.iter_mut().find(|skip| skip.name == name)
        {
            skip.reason.push_str(&format!(
                "; the profile's `[mcp.{name}]` does not match its command and arguments, so its \
                 environment stays in the agent's settings, where the agent can read it"
            ));
        }
        if let Some(config) = servers
            .configs
            .iter_mut()
            .find(|config| config.target == import.target)
        {
            config.servers.insert(name, import.value);
        }
    }
    servers
        .detected
        .sort_by(|left, right| left.name.cmp(&right.name));
    servers
        .skipped
        .sort_by(|left, right| left.name.cmp(&right.name));
    servers
}

/// The filename that an imported stdio entry runs on `PATH` when a final stdio declaration covers
/// each of its invocations by filename and arguments, as Box Core selects a server.
fn declared_stdio(import: &Import, mcp: &toml::Table) -> Option<String> {
    let fields = import.value.as_object()?;
    if transport_of(fields) != Ok("stdio") {
        return None;
    }
    let program = program_name(fields.get("command")?.as_str()?);
    if program.is_empty() || has_variable(program, import.command_syntax.as_ref()) {
        return None;
    }
    let args = match fields.get("args") {
        None => Vec::new(),
        Some(Value::Array(args)) => args.iter().map(Value::as_str).collect::<Option<Vec<_>>>()?,
        Some(_) => return None,
    };
    mcp.values()
        .any(|entry| {
            if entry.get("type").and_then(toml::Value::as_str) != Some("stdio") {
                return false;
            }
            let Some(command) = matching_command_of(entry) else {
                return false;
            };
            let Some((held_program, held_args)) = command.split_first() else {
                return false;
            };
            let wildcards = entry
                .get("argument_wildcards")
                .and_then(toml::Value::as_bool)
                == Some(true);
            program == held_program
                && args.len() == held_args.len()
                && args.iter().zip(held_args).all(|(arg, held)| {
                    wildcards && held == "*"
                        || !has_variable(arg, import.args_syntax.as_ref()) && *arg == held
                })
        })
        .then(|| program.to_string())
}

/// Whether an imported entry holds an environment field with something in it.
fn carries_env(import: &Import) -> bool {
    let Some(fields) = import.value.as_object() else {
        return false;
    };
    std::iter::once("env")
        .chain(import.env_fields.iter().map(String::as_str))
        .filter_map(|field| fields.get(field))
        .any(|value| match value {
            Value::Object(map) => !map.is_empty(),
            Value::Array(items) => !items.is_empty(),
            Value::Null => false,
            _ => true,
        })
}

/// A server command with at least one active argument wildcard.
fn wildcard_command_of(entry: &toml::Value) -> Option<Vec<String>> {
    if entry.get("argument_wildcards")?.as_bool()? {
        matching_command_of(entry).filter(|command| command.iter().skip(1).any(|arg| arg == "*"))
    } else {
        None
    }
}

/// The filename and arguments by which Box Core selects a stdio server.
fn matching_command_of(entry: &toml::Value) -> Option<Vec<String>> {
    let mut command = command_of(entry)?;
    let program = command.first_mut()?;
    *program = program_name(program).to_string();
    Some(command)
}

/// The full `command` of a stdio `[mcp.<name>]` table, which Box Core starts the server by.
fn command_of(entry: &toml::Value) -> Option<Vec<String>> {
    entry
        .get("command")?
        .as_array()?
        .iter()
        .map(|word| word.as_str().map(str::to_string))
        .collect()
}

/// The name a program goes by on `PATH`: the last component of `program`.
fn program_name(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

/// One server as a source holds it: the file, the server's fields, and the row's roles.
struct Found(
    PathBuf,
    Value,
    BTreeMap<String, Role>,
    Option<Syntax>,
    Option<Target>,
);

/// Read one source into `found`, where a later server replaces an earlier one of its name. Each
/// file is read and parsed once, in `documents`.
fn read(
    row: &Source,
    documents: &mut BTreeMap<(PathBuf, Format), Result<Value, Reading>>,
    found: &mut BTreeMap<String, Found>,
) -> Reading {
    if let Some(reason) = &row.refused {
        return Reading::NotRead(reason.clone());
    }
    let document = documents
        .entry((row.file.clone(), row.kind))
        .or_insert_with(|| parse(&row.file, row.kind));
    let document = match document {
        Ok(document) => &*document,
        Err(reading) => return reading.clone(),
    };
    match Reader::for_source(row).servers(document, &row.key) {
        Ok(listed) => {
            for (name, server) in listed {
                found.insert(
                    name,
                    Found(
                        row.file.clone(),
                        server,
                        row.env_var_locations.clone(),
                        row.env_var_syntax.clone(),
                        row.target.clone(),
                    ),
                );
            }
            Reading::Read
        }
        Err(reason) => Reading::NotRead(reason),
    }
}

/// The parsed text of `file` in the format `kind`, or what a run does instead of reading it.
fn parse(file: &Path, kind: Format) -> Result<Value, Reading> {
    let text = match crate::files::read_regular(file) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(Reading::Absent),
        Err(error) => return Err(Reading::NotRead(format!("box cannot read it: {error}"))),
    };
    kind.parse(&text)
        .map_err(|reason| Reading::NotRead(format!("it is {reason}")))
}

/// Whether Box Core takes `name` as a server name: letters, digits, `.`, `_`, and `-`.
fn allowed_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// The transport a server's fields state, from an explicit `type`, else `command` or `url`.
fn transport_of(fields: &Map<String, Value>) -> Result<&'static str, String> {
    match fields.get("type") {
        Some(Value::String(kind)) if kind == "stdio" => Ok("stdio"),
        Some(Value::String(kind)) if kind == "http" => Ok("http"),
        Some(Value::String(kind)) => Err(format!("uses type {kind}")),
        Some(_) => Err("`type` is not a string".into()),
        None => match (fields.contains_key("command"), fields.contains_key("url")) {
            (true, false) => Ok("stdio"),
            (false, true) => Ok("http"),
            (true, true) => Err("names both a command and a url".into()),
            (false, false) => Err("names no command or url".into()),
        },
    }
}

/// One server as an `[mcp.<name>]` table, with what its report line names.
struct Converted {
    installations: Vec<String>,
    table: toml::Table,
    transport: Transport,
    /// The variables a remote server takes its keys from.
    variables: Vec<String>,
    /// The names in a stdio server's `env`, and each variable filled in in its `command`.
    env: Vec<String>,
    /// Each variable left out of a stdio server's `env`, with the reason.
    dropped: Vec<(String, String)>,
    /// Each left-out variable that a server with direct network access keeps, with its value.
    held: BTreeMap<String, Held>,
}

/// Why `box` cannot read a value of a field that `roles` reads as the harness does, if one holds
/// a command or an escape that `syntax` names.
fn unread(
    fields: &Map<String, Value>,
    roles: &BTreeMap<String, Role>,
    syntax: &Syntax,
) -> Option<String> {
    roles
        .iter()
        .filter(|(_, role)| role.needs_syntax())
        .filter_map(|(field, _)| Some((field, fields.get(field)?)))
        .find_map(|(field, value)| {
            let texts: Vec<&str> = match value {
                Value::String(text) => vec![text.as_str()],
                Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
                Value::Object(entries) => entries.values().filter_map(Value::as_str).collect(),
                _ => Vec::new(),
            };
            texts
                .into_iter()
                .find_map(|text| syntax.unread(text))
                .map(|reason| format!("has a value in its {field} that {reason}"))
        })
}

/// The `[mcp.<name>]` table for one server, or why the box cannot run it.
fn convert(
    value: &Value,
    roles: &BTreeMap<String, Role>,
    syntax: Option<&Syntax>,
    sources: &mut impl Sources,
    context: &Context<'_>,
    path_reach: Option<&str>,
    launchers: &mut Launchers<'_>,
) -> Result<Converted, String> {
    let fields = value.as_object().ok_or("is not a table")?;
    match fields.get("enabled") {
        None | Some(Value::Bool(true)) => {}
        Some(Value::Bool(false)) => return Err("is turned off (enabled = false)".into()),
        Some(_) => return Err("`enabled` is not true or false".into()),
    }
    let transport = transport_of(fields)?;
    if let Some(syntax) = syntax
        && let Some(reason) = unread(fields, roles, syntax)
    {
        return Err(reason);
    }
    let foreign: &[&str] = if transport == "stdio" {
        &["url"]
    } else {
        &["command", "args", "env"]
    };
    if let Some(field) = foreign.iter().find(|field| fields.contains_key(**field)) {
        return Err(format!("uses {field}"));
    }
    if let Some((field, _)) = roles.iter().find(|(field, role)| {
        if !fields.contains_key(*field) || role.is_local() == (transport == "stdio") {
            return false;
        }
        if transport != "stdio" {
            return true;
        }
        let role = BTreeMap::from([((*field).clone(), **role)]);
        keys(fields, &role, syntax).map_or(true, |keys| !keys.is_empty())
    }) {
        return Err(format!("uses {field}"));
    }
    if transport == "stdio" {
        return stdio(
            fields, roles, syntax, sources, context, path_reach, launchers,
        );
    }
    let url = match fields.get("url") {
        Some(Value::String(url)) => url,
        Some(_) => return Err("`url` is not a string".into()),
        None => return Err("names no url".into()),
    };
    let url_syntax = syntax.and_then(Syntax::closed);
    let (address, from_url) = query_keys(url, url_syntax.as_ref())?;
    let mut keys = keys(fields, roles, syntax)?;
    keys.extend(from_url);
    for key in &keys {
        if reserved_for_key(&key.variable) {
            return Err(format!(
                "takes a key from {}, which the box sets itself",
                key.variable
            ));
        }
        if context.agent_env.contains_key(&key.variable) {
            return Err(format!(
                "takes its key from {}, which your profile sets in `[agent.env]`, so the agent \
                 holds that value and not a stand-in",
                key.variable
            ));
        }
        if let Some(source) = context.credentials.passing(&key.variable) {
            return Err(format!(
                "takes its key from {}, which {source}, so the box sends its value to no host",
                key.variable
            ));
        }
    }
    keys.retain(|key| {
        !key.has_default
            || context.stand_ins.contains_key(&key.variable)
            || sources.env(&key.variable).is_some()
    });
    let mut variables: Vec<String> = Vec::new();
    for key in &keys {
        if !variables.contains(&key.variable) {
            variables.push(key.variable.clone());
        }
    }
    if let [first, second, ..] = variables.as_slice() {
        return Err(format!(
            "takes keys from {first} and {second}, and the box attaches one key to a remote server"
        ));
    }
    if let ([first, _, ..], [variable]) = (keys.as_slice(), variables.as_slice()) {
        return Err(format!(
            "sends {variable} in more than one place, such as {}, and the box attaches one key \
             to a remote server",
            first.placement.described()
        ));
    }
    for key in &keys {
        if !context.stand_ins.contains_key(&key.variable)
            && sources
                .env(&key.variable)
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(format!(
                "needs {}, which is not set in your environment",
                key.variable
            ));
        }
    }
    let destination = destination(&address)?;
    if !keys.is_empty() && address.starts_with("http://") {
        return Err(
            "takes a key over http://; Box Core sends keys only over https://; change the server URL to https://"
                .into(),
        );
    }
    let mut table = toml::Table::from_iter([
        ("type".to_string(), toml::Value::from("http")),
        (
            "destinations".to_string(),
            toml::Value::Array(vec![toml::Value::from(destination)]),
        ),
    ]);
    if let Some(key) = keys.first() {
        let reference = format!("env://{}", key.variable);
        if let Some((name, _)) = context
            .egress
            .iter()
            .find(|(_, route)| key_variable(route) == Some(key.variable.as_str()))
        {
            return Err(format!(
                "takes its key from {}, which the route {name} sends to its own hosts",
                key.variable
            ));
        }
        let mut secret =
            toml::Table::from_iter([("ref".to_string(), toml::Value::from(reference))]);
        match &key.placement {
            Placement::Bearer => {}
            Placement::Header { name, prefix } => {
                secret.insert("header".into(), toml::Value::from(name.clone()));
                secret.insert("prefix".into(), toml::Value::from(prefix.clone()));
            }
            Placement::Query(param) => {
                secret.insert("placement".into(), toml::Value::from("query_param"));
                secret.insert("param".into(), toml::Value::from(param.clone()));
            }
        }
        table.insert("secret".into(), toml::Value::Table(secret));
    }
    Ok(Converted {
        installations: Vec::new(),
        table,
        transport: Transport::Http,
        variables,
        env: Vec::new(),
        dropped: Vec::new(),
        held: BTreeMap::new(),
    })
}

/// Each key that the fields `roles` names hold, or why one is not a key box can pass.
fn keys(
    fields: &Map<String, Value>,
    roles: &BTreeMap<String, Role>,
    syntax: Option<&Syntax>,
) -> Result<Vec<Key>, String> {
    let mut keys = Vec::new();
    for (field, role) in roles {
        let Some(value) = fields.get(field) else {
            continue;
        };
        let named = |variable: &str| -> Result<String, String> {
            if is_variable(variable) {
                Ok(variable.to_string())
            } else {
                Err(format!("its {field} {variable:?} is not a variable name"))
            }
        };
        match role {
            Role::References | Role::VariableNames => {}
            Role::BearerVariable => {
                let variable = value
                    .as_str()
                    .ok_or_else(|| format!("`{field}` is not a variable name"))?;
                keys.push(Key {
                    variable: named(variable)?,
                    placement: Placement::Bearer,
                    has_default: false,
                });
            }
            Role::HeaderVariables | Role::HeaderReferences => {
                let entries = value
                    .as_object()
                    .ok_or_else(|| format!("`{field}` is not a table of headers"))?;
                for (header, value) in entries {
                    let value = value
                        .as_str()
                        .ok_or_else(|| format!("`{field}` is not a table of headers"))?;
                    if *role == Role::HeaderReferences
                        && !has_variable(
                            value,
                            Some(syntax.ok_or("its row names no `env-var-syntax`")?),
                        )
                    {
                        continue;
                    }
                    if header.is_empty()
                        || !header
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-')
                    {
                        return Err(format!(
                            "its {field} header {header:?} is not a header name"
                        ));
                    }
                    let (prefix, variable, has_default) = if *role == Role::HeaderVariables {
                        (String::new(), named(value)?, false)
                    } else {
                        let syntax = syntax.ok_or("its row names no `env-var-syntax`")?;
                        let (prefix, variable, has_default) =
                            reference(value, syntax).ok_or_else(|| {
                                format!(
                                    "sets its {field} header {header} to a value that does not end \
                                 in one variable written {syntax}; box takes a key only from \
                                 your variable"
                                )
                            })?;
                        if !is_plain_prefix(&prefix) {
                            return Err(format!(
                                "sets its {field} header {header} to text before its variable \
                                 that holds a character other than a letter, a digit, a space, \
                                 `-`, `_`, `.`, or `:`"
                            ));
                        }
                        (prefix, variable, has_default)
                    };
                    keys.push(Key {
                        variable,
                        placement: Placement::Header {
                            name: header.clone(),
                            prefix,
                        },
                        has_default,
                    });
                }
            }
        }
    }
    Ok(keys)
}

/// The text before the variable and the variable of a value that ends in one variable written in
/// `syntax`, with a variable name in place of `NAME`.
fn reference(value: &str, syntax: &Syntax) -> Option<(String, String, bool)> {
    syntax.forms.iter().find_map(|(open, close)| {
        let (prefix, rest) = value
            .strip_suffix(close.as_str())?
            .split_once(open.as_str())?;
        let (name, default) = match rest.split_once(":-") {
            Some((name, default)) if !close.is_empty() => (name, Some(default)),
            _ => (rest, None),
        };
        if !is_variable(name)
            || default.is_some_and(|default| {
                has_variable(default, Some(syntax))
                    || (!close.is_empty() && default.contains(close.as_str()))
            })
        {
            return None;
        }
        Some((prefix.to_string(), name.to_string(), default.is_some()))
    })
}

/// Whether Box Core can send `prefix` before a key: letters, digits, spaces, `-`, `_`, `.`, `:`.
fn is_plain_prefix(prefix: &str) -> bool {
    prefix
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | ':'))
}

/// Whether `text` holds a variable in a syntax a known harness expands, or in `syntax`.
fn has_variable(text: &str, syntax: Option<&Syntax>) -> bool {
    text.contains("${") || text.contains("{env:") || syntax.is_some_and(|syntax| syntax.opens(text))
}

/// `url` without its query when its query holds a key, and each key: a query parameter whose
/// value is one variable written in `syntax`.
fn query_keys(url: &str, syntax: Option<&Syntax>) -> Result<(String, Vec<Key>), String> {
    let (url, fragment) = url.split_once('#').unwrap_or((url, ""));
    if has_variable(fragment, syntax) {
        return Err(VARIABLE_IN_URL.into());
    }
    let (address, query) = url.split_once('?').unwrap_or((url, ""));
    if has_variable(address, syntax) {
        return Err(VARIABLE_IN_URL.into());
    }
    if !has_variable(query, syntax) {
        return Ok((url.to_string(), Vec::new()));
    }
    let syntax = syntax.ok_or(VARIABLE_IN_URL)?;
    let mut keys = Vec::new();
    for pair in query
        .split('&')
        .filter(|pair| has_variable(pair, Some(syntax)))
    {
        let (param, value) = pair.split_once('=').ok_or(VARIABLE_IN_URL)?;
        match reference(value, syntax) {
            Some((prefix, variable, has_default))
                if prefix.is_empty()
                    && !param.is_empty()
                    && param
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')) =>
            {
                keys.push(Key {
                    variable,
                    placement: Placement::Query(param.to_string()),
                    has_default,
                });
            }
            _ => return Err(VARIABLE_IN_URL.into()),
        }
    }
    Ok((address.to_string(), keys))
}

/// Whether `name` is a variable name: a letter or `_`, then letters, digits, and `_`.
fn is_variable(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `text` with each variable written in `syntax` filled in from the operator's environment, and
/// `NAME:-default` filled in with `default` when `NAME` is not set; or the variable that has no
/// value. Text that opens a variable but names none is kept as written. Each variable whose value
/// comes from the operator's environment joins `read`.
fn expand(
    text: &str,
    syntax: &Syntax,
    sources: &impl Sources,
    read: &mut BTreeSet<String>,
) -> Result<String, String> {
    let mut expanded = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = syntax
        .forms
        .iter()
        .filter_map(|(open, _)| rest.find(open.as_str()))
        .min()
    {
        expanded.push_str(&rest[..at]);
        let here = &rest[at..];
        let mut found = None;
        let mut skipped = None;
        for (open, close) in &syntax.forms {
            let Some(after) = here.strip_prefix(open.as_str()) else {
                continue;
            };
            skipped.get_or_insert(open.len());
            let length = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(after.len());
            let name = &after[..length];
            let tail = &after[length..];
            if !is_variable(name) {
                continue;
            }
            let value = sources.env(name);
            let matched = if close.is_empty() {
                Some((value.clone().ok_or_else(|| name.to_string())?, tail))
            } else if let Some(tail) = tail.strip_prefix(close.as_str()) {
                Some((value.clone().ok_or_else(|| name.to_string())?, tail))
            } else if let Some((default, tail)) = tail
                .strip_prefix(":-")
                .and_then(|tail| tail.split_once(close.as_str()))
            {
                Some((value.clone().unwrap_or_else(|| default.to_string()), tail))
            } else {
                None
            };
            if let Some(matched) = matched {
                if value.is_some() {
                    read.insert(name.to_string());
                }
                found = Some(matched);
                break;
            }
        }
        match found {
            Some((value, tail)) => {
                expanded.push_str(&value);
                rest = tail;
            }
            None => {
                let length = skipped.unwrap_or(1);
                expanded.push_str(&here[..length]);
                rest = &here[length..];
            }
        }
    }
    expanded.push_str(rest);
    Ok(expanded)
}

/// The reason for a variable that has no value where `box` runs.
fn unset(name: String) -> String {
    format!("it needs {name}, which isn't set where you ran box")
}

/// Where one variable of a stdio server's `env` comes from.
enum Origin<'a> {
    /// The operator's environment, by name.
    Passed(String),
    /// The value the configuration writes.
    Written(&'a str),
}

/// One environment variable a local server inherits.
#[derive(serde::Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum PassedVariable {
    Name(String),
    Config {
        name: String,
        source: Option<String>,
    },
}

/// The `env` a stdio server gets, by name, and each variable it goes without, with the reason.
struct LocalEnv {
    env: BTreeMap<String, String>,
    dropped: Vec<(String, String)>,
    held: BTreeMap<String, Held>,
}

/// The `env` a stdio server gets, or why its declaration is refused.
fn local_env(
    fields: &Map<String, Value>,
    roles: &BTreeMap<String, Role>,
    expanded: impl Fn(&str, &str) -> Result<Option<String>, String>,
    sources: &impl Sources,
    context: &Context<'_>,
) -> Result<LocalEnv, String> {
    let mut named: BTreeMap<String, Origin<'_>> = BTreeMap::new();
    for (field, role) in roles {
        if *role != Role::VariableNames {
            continue;
        }
        let Some(value) = fields.get(field) else {
            continue;
        };
        let names: Vec<PassedVariable> = serde_json::from_value(value.clone()).map_err(|_| {
            format!("`{field}` is not a list of variable names or local variable entries")
        })?;
        for variable in names {
            let name = match variable {
                PassedVariable::Name(name) => name,
                PassedVariable::Config { name, source }
                    if source.as_deref().is_none_or(|source| source == "local") =>
                {
                    name
                }
                PassedVariable::Config { .. } => {
                    return Err(format!(
                        "`{field}` selects a non-local variable source; use source = \"local\" for a stdio server"
                    ));
                }
            };
            if !is_variable(&name) {
                return Err(format!("its {field} {name:?} is not a variable name"));
            }
            if let Some(value) = sources.env(&name) {
                named.insert(name, Origin::Passed(value));
            }
        }
    }
    match fields.get("env") {
        None => {}
        Some(Value::Object(table)) => {
            for (name, value) in table {
                let value = value.as_str().ok_or("`env` is not a table of strings")?;
                named.insert(name.clone(), Origin::Written(value));
            }
        }
        Some(_) => return Err("`env` is not a table".into()),
    }
    let mut dropped = Vec::new();
    let mut held = BTreeMap::new();
    let mut env = BTreeMap::new();
    let value_of = |origin: Origin<'_>| -> Result<String, String> {
        Ok(match origin {
            Origin::Passed(value) => value,
            Origin::Written(value) => match expanded("env", value)? {
                Some(value) => match value.strip_prefix('~') {
                    Some("") => context.home.display().to_string(),
                    Some(rest) if rest.starts_with('/') => {
                        context.home.join(&rest[1..]).display().to_string()
                    }
                    _ => value,
                },
                None => value.to_string(),
            },
        })
    };
    for (name, origin) in named {
        if !is_variable(&name) {
            return Err(format!(
                "its env name {name:?} is not a variable name, which Box Core refuses"
            ));
        }
        if loads_code(&name) {
            return Err(format!(
                "sets {name}, a variable that makes a program load code, so box does not declare \
                 this server automatically"
            ));
        }
        if name == "PATH" {
            return Err(
                "sets PATH, which can change the programs a server starts; box uses your PATH"
                    .into(),
            );
        }
        if box_owned(&name) {
            if gateway_routing(&name) {
                let kept = match value_of(origin) {
                    Err(reason) => Held::Unset(reason),
                    Ok(value) if !names_ca_file(&name) => Held::Value(value),
                    Ok(value) => ca_file(&name, value, sources, context),
                };
                held.insert(name.clone(), kept);
            }
            dropped.push((name, "the box sets it itself".to_string()));
            continue;
        }
        let value = value_of(origin)?;
        if matches!(name.as_str(), "HOME" | "TMPDIR") {
            let path = Path::new(&value);
            if !path.is_absolute() {
                return Err(format!(
                    "its {name} {value:?} is not a full path, which the box refuses"
                ));
            }
        }
        env.insert(name, value);
    }
    Ok(LocalEnv { env, dropped, held })
}

/// The CA file that `name` names, or why the box cannot grant a server a read of it.
fn ca_file(name: &str, value: String, sources: &impl Sources, context: &Context<'_>) -> Held {
    let path = Path::new(&value);
    let shown = tilde(context.home, path);
    if !path.is_absolute() {
        return Held::Refused(format!(
            "its {name} {value:?} is not a full path, so the server cannot read it"
        ));
    }
    if !path.is_file() {
        return Held::Refused(format!(
            "its {name} names {shown}, which is not a file here"
        ));
    }
    if let Some(reason) = context
        .refusals
        .reach(path)
        .or_else(|| context.refusals.protects(path))
    {
        return Held::Refused(format!(
            "its {name} names a file the box grants no server: {reason}"
        ));
    }
    let Ok(real) = std::fs::canonicalize(path) else {
        return Held::Refused(format!(
            "its {name} names {shown}, which is not a file here"
        ));
    };
    let value = real.display().to_string();
    match sources.read_grant(&real) {
        Ok(false) => Held::File(value),
        Ok(true) => Held::Refused(format!(
            "its {name} names {shown}, which lies in a credential store"
        )),
        Err((_, reason)) => Held::Refused(format!(
            "its {name} names {shown}, which the box refuses to grant: {reason}"
        )),
    }
}

/// The variable that holds the key of a route or a remote server in `entry`: the one that its
/// `secret.ref = "env://NAME"` reads, or else the one that its `secret.env` names.
fn key_variable(entry: &toml::Value) -> Option<&str> {
    let secret = entry.get("secret")?;
    secret
        .get("ref")
        .and_then(toml::Value::as_str)
        .and_then(|reference| reference.strip_prefix("env://"))
        .or_else(|| secret.get("env").and_then(toml::Value::as_str))
}

/// Why a stdio server cannot come in, when one of its fields reads a variable that a secret source
/// passes to its program, or a field that `box` fills in reads a variable that holds the stand-in
/// of a key from a secret source: a name in a `variable-names` field, or a variable that a
/// `references` field writes in `syntax`. `args` is never filled in, so the harness passes the
/// stand-in there.
fn reads_credential(
    fields: &Map<String, Value>,
    roles: &BTreeMap<String, Role>,
    syntax: Option<&Syntax>,
    context: &Context<'_>,
) -> Option<String> {
    let strings = |value: &Value| -> Vec<String> {
        match value {
            Value::String(text) => vec![text.clone()],
            Value::Array(items) => items
                .iter()
                .filter_map(|item| match item {
                    Value::String(text) => Some(text.clone()),
                    Value::Object(entry) => entry.get("name")?.as_str().map(str::to_string),
                    _ => None,
                })
                .collect(),
            Value::Object(entries) => entries
                .values()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        }
    };
    for (field, role) in roles {
        let Some(value) = fields.get(field) else {
            continue;
        };
        let names: Vec<String> = match (role, syntax) {
            (Role::VariableNames, _) => strings(value),
            (Role::References, Some(syntax)) => strings(value)
                .iter()
                .flat_map(|text| syntax.variables(text))
                .collect(),
            _ => continue,
        };
        if let Some((name, source)) = names
            .iter()
            .find_map(|name| Some((name, context.credentials.passing(name)?)))
        {
            return Some(format!(
                "reads {name}, which {source}, so no server in the box gets its value"
            ));
        }
        if let Some((name, owner)) = names
            .iter()
            .filter(|_| field != "args")
            .find_map(|name| Some((name, context.stand_ins.get(name)?)))
        {
            return Some(format!(
                "reads {name}, which {owner}, and the host's value of {name} is not that key"
            ));
        }
    }
    None
}

/// Why a stdio server cannot come in, when a value of its `env` holds the operator's value of a
/// variable that a secret source passes to its program, a prefix entry included, pasted or through
/// another variable.
fn holds_credential(
    env: &BTreeMap<String, String>,
    sources: &impl Sources,
    credentials: &Credentials,
) -> Option<String> {
    let env = env
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()));
    let (name, variable, source) = held_credential(env, sources, credentials)?;
    Some(format!(
        "its env {name} holds the value of {variable}, which {source}, so no server in the box \
         gets its value"
    ))
}

/// Why a stdio server cannot come in, when its `env` sets a variable that a secret source passes
/// to its program, a prefix entry included, whatever value it writes there.
fn sets_credential(fields: &Map<String, Value>, credentials: &Credentials) -> Option<String> {
    let Some(Value::Object(env)) = fields.get("env") else {
        return None;
    };
    env.keys().find_map(|name| {
        let source = credentials.passing(name)?;
        Some(format!(
            "its env sets {name}, which {source}, so no server in the box gets its value"
        ))
    })
}

/// The first `(name, value)` of `env` whose value holds the operator's non-blank value of a
/// variable that a `pass-secret-env` entry covers, a prefix entry included, as `(name, the
/// variable, its source)`.
fn held_credential<'a>(
    env: impl Iterator<Item = (&'a str, &'a str)> + Clone,
    sources: &impl Sources,
    credentials: &Credentials,
) -> Option<(&'a str, String, String)> {
    let named = credentials.passed_names().filter_map(|(variable, source)| {
        Some((variable.to_string(), sources.env(variable)?, source))
    });
    let prefixed = credentials.passed_prefixes().flat_map(|(prefix, source)| {
        sources
            .env_with_prefix(prefix)
            .into_iter()
            .map(move |(variable, value)| (variable, value, source.clone()))
    });
    named.chain(prefixed).find_map(|(variable, value, source)| {
        if value.trim().is_empty() {
            return None;
        }
        let (name, _) = env
            .clone()
            .find(|(_, held)| held.contains(value.as_str()))?;
        Some((name, variable, source))
    })
}

/// Why a stdio server cannot come in, when one of its arguments, as written, holds the operator's
/// value of a variable that a secret source passes to its program, a prefix entry included. The
/// reason names the place of the argument, and never the argument, which holds the value.
fn holds_argument(
    args: &[String],
    sources: &impl Sources,
    credentials: &Credentials,
) -> Option<String> {
    let places: Vec<String> = (1..=args.len()).map(|place| place.to_string()).collect();
    let numbered = places
        .iter()
        .zip(args)
        .map(|(place, argument)| (place.as_str(), argument.as_str()));
    let (place, variable, source) = held_credential(numbered, sources, credentials)?;
    Some(format!(
        "its argument {place} holds the value of {variable}, which {source}, so no server in the \
         box gets its value"
    ))
}

/// Whether the imported stdio entry `fields` writes, in its `args`, the operator's value of a
/// variable that a `pass-secret-env` entry covers, which the agent would read in its own
/// configuration.
fn imports_argument(
    fields: &Map<String, Value>,
    sources: &impl Sources,
    credentials: &Credentials,
) -> bool {
    let Some(Value::Array(args)) = fields.get("args") else {
        return false;
    };
    let args: Vec<String> = args
        .iter()
        .filter_map(|argument| argument.as_str().map(str::to_string))
        .collect();
    transport_of(fields) == Ok("stdio") && holds_argument(&args, sources, credentials).is_some()
}

/// Whether the imported stdio entry `fields` writes, in its `env`, the operator's value of a
/// variable that a `pass-secret-env` entry covers, or sets such a variable, which the agent would
/// read in its own configuration.
fn imports_credential(
    fields: &Map<String, Value>,
    sources: &impl Sources,
    credentials: &Credentials,
) -> bool {
    let Some(Value::Object(env)) = fields.get("env") else {
        return false;
    };
    let values = env
        .iter()
        .filter_map(|(name, value)| Some((name.as_str(), value.as_str()?)));
    transport_of(fields) == Ok("stdio")
        && (held_credential(values, sources, credentials).is_some()
            || sets_credential(fields, credentials).is_some())
}

fn stdio(
    fields: &Map<String, Value>,
    roles: &BTreeMap<String, Role>,
    syntax: Option<&Syntax>,
    sources: &mut impl Sources,
    context: &Context<'_>,
    path_reach: Option<&str>,
    launchers: &mut Launchers<'_>,
) -> Result<Converted, String> {
    if let Some(reason) = reads_credential(fields, roles, syntax, context) {
        return Err(reason);
    }
    let expands = |field: &str| roles.get(field).is_some_and(|role| role.expands());
    let read = std::cell::RefCell::new(BTreeSet::new());
    let expanded = |field: &str, text: &str| -> Result<Option<String>, String> {
        match syntax {
            Some(syntax) if expands(field) => {
                expand(text, syntax, &*sources, &mut read.borrow_mut())
                    .map(Some)
                    .map_err(unset)
            }
            _ => Ok(None),
        }
    };
    let program = match fields.get("command") {
        Some(Value::String(program)) => {
            expanded("command", program)?.unwrap_or_else(|| program.clone())
        }
        Some(_) => return Err("`command` is not a string".into()),
        None => return Err("names no command".into()),
    };
    let args: Vec<String> = match fields.get("args") {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .ok_or("`args` is not a list of strings")?,
        Some(_) => return Err("`args` is not a list of strings".into()),
    };
    if let Some(reason) = holds_argument(&args, &*sources, context.credentials) {
        return Err(reason);
    }
    let args_syntax = Syntax::for_field(syntax, roles, "args");
    let argument_wildcards = args
        .iter()
        .any(|arg| has_variable(arg, args_syntax.as_ref()));
    if argument_wildcards && args.iter().any(|arg| arg == "*") {
        return Err(
            "mixes a literal `*` argument with a variable argument; Box Core would treat both as wildcards"
                .into(),
        );
    }
    let args = args.into_iter().map(|arg| {
        if has_variable(&arg, args_syntax.as_ref()) {
            "*".to_string()
        } else {
            arg
        }
    });
    let mut names = read.borrow().clone();
    let LocalEnv { env, dropped, held } = local_env(fields, roles, expanded, &*sources, context)?;
    if let Some(reason) = holds_credential(&env, &*sources, context.credentials) {
        return Err(reason);
    }
    if let Some(reason) = sets_credential(fields, context.credentials) {
        return Err(reason);
    }
    let absolute = Path::new(&program).is_absolute();
    if program.contains('/') && !absolute {
        return Err(format!(
            "runs {program}, a relative path; use an absolute path or a program name on your PATH"
        ));
    }
    let name = program_name(&program);
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(format!("runs {program:?}, which is not a program name"));
    }
    if strands_box::INTERPRETER_ALIASES.contains(&name) {
        return Err(format!(
            "runs {program}, which the box does not start as a server"
        ));
    }
    if RUNTIMES.contains(&name) {
        return Err(format!(
            "runs {program}, which runs a script or a package rather than an installed server \
             program"
        ));
    }
    if absolute && !is_executable_file(Path::new(&program)) {
        return Err(format!("runs {program}, which is not an executable file"));
    }
    let launcher = launchers(name, &program, sources)?;
    if launcher.is_none() && LAUNCHERS.contains(&name) {
        return Err(format!(
            "runs {program}, a launcher that fetches the server when it starts, and box ships no \
             pack that runs it in the box"
        ));
    }
    if let Some(reason) = path_reach {
        return Err(reason.to_string());
    }
    let found = if absolute {
        PathBuf::from(&program)
    } else {
        sources.program(&program).ok_or_else(|| {
            format!("runs {program}, which is not on your PATH outside the project")
        })?
    };
    let real = canonical(&found)
        .ok_or_else(|| format!("runs {program}, whose executable path cannot be resolved"))?;
    let refuse = |what: &str, path: &Path| {
        context
            .refusals
            .reach(path)
            .or_else(|| context.refusals.protects(path))
            .map(|reason| format!("{what} {reason}; box runs no program from there"))
    };
    for path in [&found, &real] {
        if let Some(reason) = refuse("its program", path) {
            return Err(reason);
        }
    }
    if absolute {
        stays(&found, &real, "its program", context)?;
    }
    let mut read = Vec::new();
    let mut files = vec![("its program", real.clone())];
    let mut helper_files = Vec::new();
    if let Some(launcher) = &launcher {
        for directory in &launcher.read {
            let Some(real) = canonical(directory) else {
                continue;
            };
            if let Some(reason) = refuse("its runtime directory", directory) {
                return Err(reason);
            }
            if let Some(reason) = refuse("its runtime directory", &real) {
                return Err(reason);
            }
            if real.is_dir() {
                read.push(real);
            } else {
                // The helper's own name, which Box Core follows to its target.
                files.push(("its runtime helper", real));
                helper_files.push(directory.clone());
            }
        }
    }
    let chain = interpreters(&real, sources)?;
    for env in chain.envs {
        if let Some(reason) = refuse("its interpreter", &env) {
            return Err(reason);
        }
        files.push(("its interpreter", env.clone()));
        helper_files.push(env);
    }
    let interpreters = chain.spellings;
    for interpreter in chain.interpreters {
        if let Some(reason) = refuse("its interpreter", &interpreter) {
            return Err(reason);
        }
        files.push(("its interpreter", interpreter.clone()));
        helper_files.push(interpreter);
    }
    for (what, file) in &files {
        match sources.read_grant(file) {
            Ok(false) => {}
            Ok(true) => {
                return Err(format!(
                    "{what} {} lies in a credential store, which box grants no server",
                    file.display()
                ));
            }
            Err((_, reason)) => {
                return Err(format!(
                    "{what} {} is one the box refuses to grant: {reason}",
                    file.display()
                ));
            }
        }
    }
    let check = |path: &Path| match context
        .refusals
        .reach(path)
        .or_else(|| context.refusals.protects(path))
    {
        Some(reason) => Err(format!(
            "its installation {reason}; box reads no installation from there"
        )),
        None => Ok(()),
    };
    let mut requirements = install_layout::resolve(&found, Layout::ALL, context.os, &check)?;
    for interpreter in &interpreters {
        requirements.extend(install_layout::resolve(
            interpreter,
            Layout::ALL,
            context.os,
            &check,
        )?);
    }
    read.extend(requirements.read.iter().cloned());
    helper_files.extend(requirements.read_file.iter().cloned());
    if let Some(launcher) = &launcher {
        requirements.extend(install_layout::Requirements {
            list: launcher.list.clone(),
            ..Default::default()
        });
    }
    let read = unique(read);
    if let Some(directory) = read
        .iter()
        .find(|directory| context.home.starts_with(directory))
    {
        return Err(format!(
            "its install directory {} holds your home folder",
            directory.display()
        ));
    }
    if let Some(directory) = read
        .iter()
        .find(|directory| context.workspace.starts_with(directory))
    {
        return Err(format!(
            "its install directory {} holds the project",
            tilde(context.home, directory)
        ));
    }
    let mut granted = Vec::new();
    for directory in read {
        match sources.read_grant(&directory) {
            Ok(false) => granted.push(directory),
            Ok(true) => {
                return Err(format!(
                    "its install directory {} lies in a credential store, which box grants no \
                     server",
                    tilde(context.home, &directory)
                ));
            }
            Err((kind, reason)) => {
                let system = matches!(
                    kind,
                    strands_box::GrantRefusal::Forbidden(strands_box::ForbiddenClass::SystemTree)
                );
                if !system {
                    return Err(format!(
                        "its install directory {} is one the box refuses to grant: {reason}",
                        tilde(context.home, &directory)
                    ));
                }
            }
        }
    }
    let read = granted;
    if context.os == "macos"
        && let Some(parent) = found.parent()
        && let Some(directory) = canonical(parent)
        && !directory.starts_with(context.home)
        && Some(directory.as_path()) != real.parent()
        && !read
            .iter()
            .chain(&requirements.list)
            .any(|root| directory.starts_with(root))
    {
        for path in [parent, directory.as_path()] {
            install_layout::check_path(
                path,
                context.home,
                context.workspace,
                context.refusals,
                &|path| sources.read_grant(path),
            )?;
        }
        if matches!(sources.read_grant(&directory), Ok(false)) {
            requirements
                .list
                .retain(|path| !path.starts_with(&directory));
            requirements.list.push(directory);
        }
    }
    let workspace = utf8(context.workspace).map_err(|error| error.to_string())?;
    let mut entries: Vec<toml::Value> = context
        .project
        .reads()
        .then(|| toml::Value::from(workspace.clone()))
        .into_iter()
        .collect();
    let read: Vec<PathBuf> = match &launcher {
        Some(launcher) => unique(read.into_iter().chain([launcher.cache.clone()]).collect()),
        None => read,
    };
    for directory in &read {
        entries.push(toml::Value::from(
            utf8(directory).map_err(|error| error.to_string())?,
        ));
    }
    let mut writes: Vec<toml::Value> = context
        .project
        .writes()
        .then(|| toml::Value::from(workspace))
        .into_iter()
        .collect();
    names.extend(env.keys().cloned());
    let mut env = env;
    if let Some(launcher) = &launcher {
        writes.push(toml::Value::from(
            utf8(&launcher.cache).map_err(|error| error.to_string())?,
        ));
        env.extend(launcher.env.clone());
    }
    let mut filesystem = toml::Table::from_iter(
        [("read", entries), ("write", writes)]
            .into_iter()
            .filter(|(_, list)| !list.is_empty())
            .map(|(key, list)| (key.to_string(), toml::Value::Array(list))),
    );
    let helper_files = unique(helper_files)
        .into_iter()
        .filter(|path| !read.iter().any(|directory| path.starts_with(directory)))
        .map(|path| {
            utf8(&path)
                .map(toml::Value::from)
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !helper_files.is_empty() {
        filesystem.insert("read_file".to_string(), toml::Value::Array(helper_files));
    }
    if let Some(launcher) = &launcher
        && !launcher.deny.is_empty()
    {
        filesystem.insert(
            "deny".into(),
            toml::Value::try_from(&launcher.deny).expect("strings"),
        );
    }
    if !requirements.list.is_empty() {
        filesystem.insert(
            "list".into(),
            toml::Value::Array(
                requirements
                    .list
                    .iter()
                    .map(|path| toml::Value::String(path.display().to_string()))
                    .collect(),
            ),
        );
    }
    let mut table = toml::Table::from_iter([
        ("type".to_string(), toml::Value::from("stdio")),
        (
            "command".to_string(),
            toml::Value::Array(
                std::iter::once(program.clone())
                    .chain(args)
                    .map(toml::Value::from)
                    .collect(),
            ),
        ),
        ("filesystem".to_string(), toml::Value::Table(filesystem)),
    ]);
    if argument_wildcards {
        table.insert("argument_wildcards".to_string(), toml::Value::Boolean(true));
    }
    let names: Vec<String> = names.into_iter().collect();
    if !env.is_empty() {
        table.insert(
            "env".to_string(),
            toml::Value::Table(
                env.into_iter()
                    .map(|(name, value)| (name, toml::Value::from(value)))
                    .collect(),
            ),
        );
    }
    Ok(Converted {
        installations: requirements.sources,
        table,
        transport: Transport::Stdio {
            program,
            program_path: real,
            launcher: launcher.map(Box::new),
        },
        variables: Vec::new(),
        env: names,
        dropped,
        held,
    })
}

/// The links that select an external MCP executable, script, or project.
fn stays(path: &Path, real: &Path, what: &str, context: &Context<'_>) -> Result<(), String> {
    if real.starts_with(context.workspace) {
        return Ok(());
    }
    let roots: Vec<PathBuf> = context
        .refusals
        .roots
        .iter()
        .map(|(root, _)| root.clone())
        .collect();
    check_links(path, real, what, context.home, &roots)
}

/// Check each link that selects an MCP executable, script, or project.
pub(crate) fn check_links(
    path: &Path,
    real: &Path,
    what: &str,
    home: &Path,
    roots: &[PathBuf],
) -> Result<(), String> {
    let cannot_check =
        |error: std::io::Error| format!("{what} {} cannot be checked: {error}", tilde(home, path));
    let changed = || {
        format!(
            "{what} {} changed while box checked its links",
            tilde(home, path)
        )
    };
    let mut remaining = path.to_path_buf();
    let mut current = PathBuf::new();
    let mut links = 0;
    loop {
        let mut components = remaining.components();
        let Some(component) = components.next() else {
            break;
        };
        let rest = components.as_path().to_path_buf();
        match component {
            Component::Prefix(_) | Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                current.pop();
            }
            Component::Normal(name) => {
                let next = current.join(name);
                let metadata = std::fs::symlink_metadata(&next).map_err(&cannot_check)?;
                let same_file = |other: &std::fs::Metadata| {
                    metadata.dev() == other.dev() && metadata.ino() == other.ino()
                };
                if metadata.file_type().is_symlink() {
                    if roots.iter().any(|root| {
                        next.starts_with(root)
                            || next.starts_with(crate::host::resolved(root))
                            || std::fs::symlink_metadata(root).is_ok_and(|root| same_file(&root))
                    }) {
                        return Err(format!(
                            "{what} {} is a link out of a folder the box can write",
                            tilde(home, path)
                        ));
                    }
                    links += 1;
                    if links > 40 {
                        return Err(cannot_check(std::io::Error::other(
                            "too many symbolic links",
                        )));
                    }
                    remaining = std::fs::read_link(&next).map_err(&cannot_check)?.join(rest);
                    continue;
                }
                let canonical = std::fs::canonicalize(&next).map_err(&cannot_check)?;
                let after = std::fs::symlink_metadata(&next).map_err(&cannot_check)?;
                let real_metadata = std::fs::symlink_metadata(&canonical).map_err(&cannot_check)?;
                if canonical.parent() != Some(current.as_path())
                    || after.file_type().is_symlink()
                    || real_metadata.file_type().is_symlink()
                    || !same_file(&after)
                    || !same_file(&real_metadata)
                {
                    return Err(changed());
                }
                current = canonical;
            }
        }
        remaining = rest;
    }
    if current != real {
        return Err(changed());
    }
    Ok(())
}

/// The `host[:port]` destination of an `http://` or `https://` URL, or why it has none.
fn destination(url: &str) -> Result<String, String> {
    if has_variable(url, None) {
        return Err(VARIABLE_IN_URL.into());
    }
    let (rest, plain) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
        (Some(rest), _) => (rest, false),
        (None, Some(rest)) => (rest, true),
        (None, None) => return Err(format!("its url {url:?} is not an http:// or https:// URL")),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err("its url holds a user name".into());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            (host, Some(port))
        }
        Some(_) => return Err(format!("its url {url:?} has no valid port")),
        None => (authority, None),
    };
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return Err(format!("its url {url:?} names no host name"));
    }
    let host = host.to_ascii_lowercase();
    Ok(match (port, plain) {
        (Some(port), true) => format!("{host}:{port}"),
        (None, true) => format!("{host}:80"),
        (Some(port), false) if port != "443" => format!("{host}:{port}"),
        (_, false) => host,
    })
}

/// The `#!` chain of `program`: the real `env` file of each line that runs through it, and the real
/// file of the interpreter, of its interpreter, and so on, with each interpreter as its line names it.
#[derive(Debug, Default, PartialEq)]
struct Chain {
    envs: Vec<PathBuf>,
    interpreters: Vec<PathBuf>,
    spellings: Vec<PathBuf>,
}

fn interpreters(program: &Path, sources: &mut impl Sources) -> Result<Chain, String> {
    let mut chain = Chain::default();
    let mut script = program.to_path_buf();
    while let Some((env, spelling, interpreter)) = interpreter(&script, sources)? {
        if let Some(env) = env
            && !chain.envs.contains(&env)
        {
            chain.envs.push(env);
        }
        if interpreter == program || chain.interpreters.contains(&interpreter) {
            break;
        }
        chain.interpreters.push(interpreter.clone());
        chain.spellings.push(spelling);
        script = interpreter;
    }
    Ok(chain)
}

/// The real `env` file, when the `#!` line of `program` runs through it, and the interpreter that
/// the line names, as named and as its real file, if it has one.
fn interpreter(
    program: &Path,
    sources: &mut impl Sources,
) -> Result<Option<(Option<PathBuf>, PathBuf, PathBuf)>, String> {
    let real = |path: PathBuf| canonical(&path).unwrap_or(path);
    let file = |path: PathBuf| Some(path).filter(|path| path.is_file());
    let (env, named, found) = match crate::program::interpreter(program) {
        Ok(None) => return Ok(None),
        Err(_) => return Err("starts with `env` and names no interpreter".into()),
        Ok(Some(crate::program::Interpreter::Path(path))) => {
            (None, path.display().to_string(), file(path))
        }
        Ok(Some(crate::program::Interpreter::Named(env, name))) => {
            let env = file(env.clone())
                .map(real)
                .ok_or_else(|| format!("starts with {}, which box cannot find", env.display()))?;
            let found = if name.contains('/') {
                file(PathBuf::from(&name))
            } else {
                sources.program(&name)
            };
            (Some(env), name, found)
        }
    };
    found
        .map(|spelling| Some((env, spelling.clone(), real(spelling))))
        .ok_or_else(|| format!("starts with the interpreter {named}, which box cannot find"))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::*;

    /// A home, a workspace below it, and programs on a search path outside both.
    struct Host {
        _root: tempfile::TempDir,
        root: PathBuf,
        path: Vec<PathBuf>,
        egress: toml::Table,
        others: Vec<(String, String)>,
        set: Vec<(&'static str, &'static str)>,
        agent_env: BTreeMap<String, String>,
        credentials: Credentials,
        read_grants: BTreeMap<PathBuf, (strands_box::GrantRefusal, String)>,
        launchers: BTreeMap<String, Result<Launcher, String>>,
    }

    impl Host {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("a root");
            let root = directory.path().canonicalize().expect("a canonical root");
            std::fs::create_dir_all(root.join("home/project")).expect("a workspace");
            Self {
                _root: directory,
                path: vec![root.join("bin")],
                egress: toml::Table::new(),
                others: Vec::new(),
                set: Vec::new(),
                agent_env: BTreeMap::new(),
                credentials: Credentials::default(),
                read_grants: BTreeMap::new(),
                launchers: BTreeMap::new(),
                root,
            }
        }

        fn home(&self) -> PathBuf {
            self.root.join("home")
        }

        fn workspace(&self) -> PathBuf {
            self.home().join("project")
        }

        /// An executable at `relative` under the root, with `#!line` as its first line.
        fn program(&self, relative: &str, line: &str) -> PathBuf {
            let path = self.root.join(relative);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a folder");
            std::fs::write(&path, format!("#!{line}\n")).expect("a program");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("mode");
            path
        }

        /// A link at `bin/<name>` to `target`.
        fn link(&self, name: &str, target: &Path) {
            std::fs::create_dir_all(self.root.join("bin")).expect("bin");
            symlink(target, self.root.join("bin").join(name)).expect("a link");
        }

        fn refusals(&self) -> Refusals {
            Refusals {
                home: self.home(),
                roots: vec![
                    (self.workspace(), "the workspace".into()),
                    (self.home().join(".strands/box"), "the box home".into()),
                    (self.home().join("shared"), "a write grant".into()),
                ],
                shipped: None,
                protected: Vec::new(),
            }
        }

        fn file(&self, relative: &str, text: &str) -> PathBuf {
            let path = self.home().join(relative);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a folder");
            std::fs::write(&path, text).expect("a file");
            path
        }

        fn detect(&self, rows: &[Source], mcp: &mut toml::Table) -> Servers {
            let refusals = self.refusals();
            let home = self.home();
            let workspace = self.workspace();
            let stand_ins = stand_ins(&self.egress, mcp);
            detect(
                rows,
                mcp,
                &mut SearchPath(
                    self.path.clone(),
                    self.set.clone(),
                    self.read_grants.clone(),
                ),
                &Context {
                    os: std::env::consts::OS,
                    home: &home,
                    workspace: &workspace,
                    project: crate::profile::ProjectAccess::Write,
                    profile: Path::new("profile.toml"),
                    additions: &BTreeMap::new(),
                    refusals: &refusals,
                    egress: &self.egress,
                    programs: &self.others,
                    agent_env: &self.agent_env,
                    credentials: &self.credentials,
                    stand_ins: &stand_ins,
                },
                &mut |pack, _, _| self.launchers.get(pack).cloned().transpose(),
            )
        }
    }

    /// Sources that find a program in the directories of a search path, where each `(name, value)`
    /// variable is set.
    struct SearchPath(
        Vec<PathBuf>,
        Vec<(&'static str, &'static str)>,
        BTreeMap<PathBuf, (strands_box::GrantRefusal, String)>,
    );

    impl Sources for SearchPath {
        fn env(&self, name: &str) -> Option<String> {
            self.1
                .iter()
                .find(|(set, _)| *set == name)
                .map(|(_, value)| value.to_string())
        }

        fn env_with_prefix(&self, prefix: &str) -> Vec<(String, String)> {
            self.1
                .iter()
                .filter(|(set, _)| set.starts_with(prefix))
                .map(|(set, value)| (set.to_string(), value.to_string()))
                .collect()
        }

        fn search(&self, _: &str) -> Option<PathBuf> {
            None
        }

        fn developer_dir(&mut self) -> Result<String, String> {
            Err("ran xcode-select, which this host never runs".to_string())
        }

        fn program(&mut self, name: &str) -> Option<PathBuf> {
            self.0
                .iter()
                .map(|directory| directory.join(name))
                .find(|candidate| candidate.is_file())
        }

        fn search_path(&self) -> Vec<PathBuf> {
            self.0.clone()
        }

        fn read_grant(&self, path: &Path) -> Result<bool, (strands_box::GrantRefusal, String)> {
            if let Some(refusal) = self.2.get(path) {
                return Err(refusal.clone());
            }
            let named = |name: &str| path.components().any(|part| part.as_os_str() == name);
            if named("Keychains") {
                return Err((
                    strands_box::GrantRefusal::Forbidden(
                        strands_box::ForbiddenClass::MachineCredential,
                    ),
                    format!("{} is refused beneath every grant", path.display()),
                ));
            }
            if named(".docker") || named(".ssh") {
                return Ok(true);
            }
            if path.join("gcloud").is_dir() {
                return Err((
                    strands_box::GrantRefusal::Other,
                    format!("{} holds a credential store", path.display()),
                ));
            }
            strands_box::check_read_grant(path).map_err(|error| (error.kind(), error.to_string()))
        }
    }

    fn row(file: &Path, key: &[&str]) -> Source {
        Source {
            target: None,
            active: true,
            file: file.to_path_buf(),
            kind: if file
                .extension()
                .is_some_and(|extension| extension == "toml")
            {
                Format::Toml
            } else {
                Format::Json
            },
            key: key.iter().map(|key| key.to_string()).collect(),
            env_var_locations: BTreeMap::new(),
            env_var_syntax: None,
            refused: None,
        }
    }

    /// `source`, where each `(field, role)` names what a harness field holds, and a variable is
    /// `${NAME}`.
    fn with_roles(mut source: Source, roles: &[(&str, &str)]) -> Source {
        source.env_var_syntax = Some(Syntax::one("${NAME}"));
        for (field, role) in roles {
            source
                .env_var_locations
                .insert(field.to_string(), Role::named(role).expect("a role"));
        }
        source
    }

    fn grants(mcp: &toml::Table, name: &str, key: &str) -> Vec<String> {
        mcp[name]["filesystem"]
            .get(key)
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .map(|item| item.as_str().expect("a path").to_string())
            .collect()
    }

    fn shown(path: &Path) -> String {
        path.display().to_string()
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_server_alias_in_the_home_needs_no_directory_listing() {
        for linked_parent in [false, true] {
            let host = Host::new();
            let real = host.program("package/server", "/bin/sh");
            let directory = host.home().join("aliases");
            std::fs::create_dir_all(&directory).unwrap();
            symlink(&real, directory.join("server")).unwrap();
            let parent = if linked_parent {
                let link = host.root.join("linked-home-aliases");
                symlink(&directory, &link).unwrap();
                link
            } else {
                directory
            };
            let command = parent.join("server");
            let file = host.file(
                ".agent.json",
                &serde_json::json!({"s": {"server": {"command": command}}}).to_string(),
            );
            let mut mcp = toml::Table::new();
            let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
            assert!(servers.skipped.is_empty(), "{:?}", servers.skipped);
            assert_eq!(mcp["server"]["command"][0].as_str(), command.to_str());
            assert!(grants(&mcp, "server", "list").is_empty(), "{mcp:?}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_server_alias_refuses_a_directory_that_holds_credentials() {
        for linked_parent in [false, true] {
            let host = Host::new();
            let real = host.program("package/server", "/bin/sh");
            let directory = host.root.join("aliases");
            std::fs::create_dir_all(directory.join("gcloud")).unwrap();
            symlink(&real, directory.join("server")).unwrap();
            let parent = if linked_parent {
                let link = host.root.join("linked-aliases");
                symlink(&directory, &link).unwrap();
                link
            } else {
                directory
            };
            let file = host.file(
                ".agent.json",
                &serde_json::json!({"s": {"server": {"command": parent.join("server")}}})
                    .to_string(),
            );
            let mut mcp = toml::Table::new();
            let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
            assert!(mcp.is_empty(), "{mcp:?}");
            assert!(
                reasons(&servers)
                    .iter()
                    .any(|(name, reason)| *name == "server"
                        && reason.contains("holds a credential store")),
                "{:?}",
                reasons(&servers)
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_server_alias_omits_directory_grants_that_core_refuses() {
        use strands_box::{ForbiddenClass, GrantRefusal};

        for class in [
            ForbiddenClass::SystemTree,
            ForbiddenClass::LoaderDirectory,
            ForbiddenClass::WholeFilesystem,
            ForbiddenClass::HomeNamespace,
        ] {
            for linked_parent in [false, true] {
                let mut host = Host::new();
                let real = host.program("package/server", "/bin/sh");
                let directory = host.root.join("aliases");
                std::fs::create_dir_all(&directory).unwrap();
                symlink(&real, directory.join("server")).unwrap();
                host.read_grants.insert(
                    directory.clone(),
                    (GrantRefusal::Forbidden(class), "Core refused root".into()),
                );
                let parent = if linked_parent {
                    let link = host.root.join("linked-aliases");
                    symlink(&directory, &link).unwrap();
                    link
                } else {
                    directory
                };
                let command = parent.join("server");
                let file = host.file(
                    ".agent.json",
                    &serde_json::json!({"s": {"server": {"command": command}}}).to_string(),
                );
                let mut mcp = toml::Table::new();
                let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
                assert!(
                    servers.skipped.is_empty(),
                    "{class:?}: {:?}",
                    servers.skipped
                );
                assert_eq!(mcp["server"]["command"][0].as_str(), command.to_str());
                assert!(
                    grants(&mcp, "server", "list").is_empty(),
                    "{class:?}: {mcp:?}"
                );
            }
        }
    }

    #[test]
    fn absolute_mcp_commands_keep_the_selected_file_and_copy_its_filename() {
        for (on_path, format) in [(false, Format::Json), (true, Format::Toml)] {
            let mut host = Host::new();
            let real = host.program("selected tools/package/weather-server", "/bin/sh");
            let selected = host.root.join("selected tools/weather");
            symlink(&real, &selected).unwrap();
            let decoy = host.program("bin/weather", "/bin/sh");
            if !on_path {
                host.path.clear();
            }
            host.set = vec![("COMMAND_ROOT", "/")];
            let command = match format {
                Format::Json => shown(&selected),
                Format::Toml => format!(
                    "${{COMMAND_ROOT}}{}",
                    selected.strip_prefix("/").unwrap().display()
                ),
            };
            let document = serde_json::json!({"s": {
                "weather": {
                    "command": command,
                    "args": ["--stdio", "${TOKEN}"],
                    "env": {"TOKEN": "private-key"},
                    "startup_timeout_sec": 7
                }
            }});
            let file = match format {
                Format::Json => host.file(".agent.json", &document.to_string()),
                Format::Toml => host.file(".agent.toml", &toml::to_string(&document).unwrap()),
            };
            let mut source = expanding(row(&file, &["s"]));
            source.target = Some(Target {
                path: host.home().join(".strands/box/storage/agent-config"),
                kind: format,
                key: vec!["s".into()],
            });
            let mut mcp = toml::Table::new();
            let servers = host.detect(&[source], &mut mcp);
            assert!(servers.skipped.is_empty(), "{:?}", servers.skipped);
            assert_eq!(servers.program_path("weather"), Some(real.as_path()));
            assert_eq!(
                mcp["weather"]["command"],
                toml::Value::from(vec![shown(&selected), "--stdio".into(), "*".into()])
            );
            assert_eq!(mcp["weather"]["env"]["TOKEN"].as_str(), Some("private-key"));
            assert_eq!(
                servers.configs[0].servers["weather"],
                serde_json::json!({
                    "command": "weather",
                    "args": ["--stdio", "${TOKEN}"],
                    "startup_timeout_sec": 7
                })
            );
            let reads = grants(&mcp, "weather", "read");
            assert!(reads.contains(&shown(real.parent().unwrap())), "{reads:?}");
            assert!(
                !reads.contains(&shown(decoy.parent().unwrap())),
                "{reads:?}"
            );
        }
    }

    #[test]
    fn absolute_mcp_commands_compare_the_filename_and_arguments_for_collisions() {
        let host = Host::new();
        let first = host.program("first/tool", "/bin/sh");
        let second = host.program("second/tool", "/bin/sh");
        let file = host.file(
            ".agent.json",
            &serde_json::json!({"s": {
                "a-first": {"command": first, "args": ["fixed"]},
                "b-duplicate": {"command": second, "args": ["fixed"]},
                "c-separate": {"command": second, "args": ["different"]},
                "d-pattern": {"command": first, "args": ["--token", "${TOKEN}"]},
                "e-overlap": {"command": second, "args": ["${FLAG}", "value"]},
                "f-exact": {"command": second, "args": ["--token", "value"]}
            }})
            .to_string(),
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert_eq!(
            mcp.keys().map(String::as_str).collect::<Vec<_>>(),
            ["a-first", "c-separate", "d-pattern", "f-exact"]
        );
        assert_eq!(
            servers
                .skipped
                .iter()
                .map(|skip| skip.name.as_str())
                .collect::<Vec<_>>(),
            ["b-duplicate", "e-overlap"]
        );
        assert!(servers.skipped[0].reason.contains("same detected command"));
        assert!(servers.skipped[1].reason.contains("overlap"));
        assert_eq!(mcp["c-separate"]["command"][0].as_str(), second.to_str());
    }

    #[test]
    fn absolute_mcp_commands_refuse_unusable_targets_without_searching_path() {
        let host = Host::new();
        host.program("bin/tool", "/bin/sh");
        let nonexecutable = host.file("installed/tool", "not executable");
        let missing = host.root.join("missing/tool");
        let writable = host.program("home/project/tool", "/bin/sh");
        let linked = host.root.join("linked");
        symlink(host.workspace(), &linked).unwrap();
        for (program, expected) in [
            (shown(&missing), "not an executable file"),
            (shown(&nonexecutable), "not an executable file"),
            (shown(&writable), "workspace"),
            (shown(&linked.join("tool")), "workspace"),
            ("./tool".into(), "relative"),
            ("~/tool".into(), "relative"),
            (
                shown(&host.root.join("python3")),
                "does not start as a server",
            ),
            (shown(&host.root.join("bad name")), "not a program name"),
        ] {
            let file = host.file(
                ".agent.json",
                &serde_json::json!({"s": {"test": {"command": program}}}).to_string(),
            );
            let mut mcp = toml::Table::new();
            let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
            assert!(mcp.is_empty(), "{program}");
            assert_eq!(servers.skipped.len(), 1, "{program}");
            assert!(
                servers.skipped[0].reason.contains(expected),
                "{program}: {:?}",
                servers.skipped
            );
        }
    }

    #[test]
    fn absolute_mcp_commands_refuse_writable_intermediate_links() {
        let host = Host::new();
        let program = host.program("home/private/server/tool", "/bin/sh");
        let installed = program.parent().unwrap();
        std::fs::create_dir_all(installed.join("inner")).unwrap();
        std::fs::create_dir_all(host.home().join("aliases")).unwrap();
        symlink("private/server/inner", host.home().join("trusted")).unwrap();
        let trusted = host.home().join("trusted/../tool");
        let mut entries = serde_json::Map::from_iter([(
            "trusted".into(),
            serde_json::json!({"command": trusted}),
        )]);
        for (name, root, target) in [
            ("project", "project", "../private/server/inner"),
            ("shared", "shared", "../private/server/inner"),
            ("box", ".strands/box", "../../private/server/inner"),
        ] {
            std::fs::create_dir_all(host.home().join(root)).unwrap();
            symlink(target, host.home().join(root).join("switch")).unwrap();
            symlink(
                format!("../{root}/switch"),
                host.home().join("aliases").join(name),
            )
            .unwrap();
            let path = host.home().join("aliases").join(name).join("../tool");
            assert_eq!(canonical(&path), Some(program.clone()));
            entries.insert(name.into(), serde_json::json!({"command": path}));
        }
        let file = host.file(
            ".agent.json",
            &serde_json::json!({"s": entries}).to_string(),
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert_eq!(
            mcp.keys().map(String::as_str).collect::<Vec<_>>(),
            ["trusted"]
        );
        assert_eq!(servers.program_path("trusted"), Some(program.as_path()));
        assert_eq!(mcp["trusted"]["command"][0].as_str(), trusted.to_str());
        assert_eq!(servers.skipped.len(), 3);
        for (_, reason) in reasons(&servers) {
            assert!(
                reason.ends_with("is a link out of a folder the box can write"),
                "{reason}"
            );
        }
    }

    #[test]
    fn absolute_mcp_commands_refuse_the_agents_and_tools_filenames() {
        for label in ["the agent", "the tool existing"] {
            let mut host = Host::new();
            let program = host.program("selected/tool", "/bin/sh");
            host.others.push((label.into(), "/another/tool".into()));
            let file = host.file(
                ".agent.json",
                &serde_json::json!({"s": {"server": {"command": program}}}).to_string(),
            );
            let mut mcp = toml::Table::new();
            let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
            assert!(mcp.is_empty());
            assert_eq!(servers.skipped.len(), 1);
            assert!(
                servers.skipped[0]
                    .reason
                    .contains(&format!("{label} runs too")),
                "{:?}",
                servers.skipped
            );
        }
    }

    #[test]
    fn an_unknown_field_passes_through_and_the_server_comes_in() {
        let host = Host::new();
        host.program("bin/tool", "/bin/sh");
        let file = host.file(
            ".codex.json",
            r#"{"s": {
                "timed": {"command": "tool", "startup_timeout_sec": 5, "http_headers": {"X-Client": "codex"}},
                "signed": {"url": "https://signed.example.com", "oauth": {}}
            }}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert_eq!(reasons(&servers), Vec::<(&str, &str)>::new());
        assert_eq!(
            servers.detected_lines(&host.home()),
            vec![
                (
                    "signed".to_string(),
                    "~/.codex.json".to_string(),
                    String::new()
                ),
                (
                    "timed".to_string(),
                    "~/.codex.json".to_string(),
                    String::new()
                ),
            ],
            "a field box does not read keeps no server out"
        );
        let workspace = host.workspace().display().to_string();
        let expected: toml::Table = toml::from_str(&format!(
            r#"
            [signed]
            type = "http"
            destinations = ["signed.example.com"]

            [timed]
            type = "stdio"
            command = ["tool"]
            filesystem.read = [{workspace:?}, {bin:?}]
            filesystem.read_file = [{shell:?}]
            filesystem.write = [{workspace:?}]
            "#,
            shell = crate::fixtures::shell(),
            bin = host.root.join("bin").display().to_string(),
        ))
        .expect("TOML");
        assert_eq!(
            mcp, expected,
            "box writes only the fields Box Core takes, so each other field stays in the agent's \
             own configuration"
        );
    }

    fn reasons(servers: &Servers) -> Vec<(&str, &str)> {
        servers
            .skipped
            .iter()
            .map(|skip| (skip.name.as_str(), skip.reason.as_str()))
            .collect()
    }

    #[test]
    fn mcp_import_keeps_runtime_servers_without_generated_policy() {
        let mut host = Host::new();
        host.program("bin/tool", "/bin/sh");
        host.set = vec![("PROGRAM", "tool"), ("PASSED", "host-value")];
        let document = serde_json::json!({"s": {
            "node": {"command": "node", "args": ["server.js"], "env": {"KEY": "node-key"}},
            "uv": {"command": "uv", "args": ["run", "server.py"], "cwd": "/project"},
            "python": {"command": "python", "args": ["server.py"], "env_vars": ["PASSED"]},
            "python3": {"command": "python3", "args": ["-m", "server"]},
            "absolute": {
                "command": host.root.join("missing/server"), "env": {"KEY": "absolute-key"},
                "env_vars": ["PASSED"], "startup_timeout_sec": 60
            },
            "accepted": {
                "command": "${PROGRAM}", "args": ["--token", "${TOKEN}"],
                "env": {"KEY": "server-key"}, "env_vars": ["PASSED"],
                "startup_timeout_sec": 5
            }
        }});
        let file = host.file(".agent.json", &document.to_string());
        let mut source = with_roles(
            row(&file, &["s"]),
            &[
                ("command", "references"),
                ("env", "references"),
                ("env_vars", "variable-names"),
            ],
        );
        source.target = Some(Target {
            path: host.home().join(".strands/box/storage/agent.json"),
            kind: Format::Json,
            key: vec!["s".into()],
        });
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[source], &mut mcp);
        assert_eq!(
            mcp.keys().map(String::as_str).collect::<Vec<_>>(),
            ["accepted"]
        );
        assert_eq!(
            servers
                .skipped
                .iter()
                .map(|server| server.name.as_str())
                .collect::<Vec<_>>(),
            ["absolute", "node", "python", "python3", "uv"]
        );
        let imported = &servers.configs[0].servers;
        for name in ["absolute", "node", "python", "python3", "uv"] {
            assert_eq!(imported.get(name), Some(&document["s"][name]), "{name}");
        }
        assert_eq!(
            imported["accepted"],
            serde_json::json!({
                "command": "tool", "args": ["--token", "${TOKEN}"], "startup_timeout_sec": 5
            })
        );
        assert_eq!(mcp["accepted"]["env"]["KEY"].as_str(), Some("server-key"));
        assert_eq!(
            mcp["accepted"]["env"]["PASSED"].as_str(),
            Some("host-value")
        );
        assert_eq!(mcp["accepted"]["command"][2].as_str(), Some("*"));
    }

    #[test]
    fn mcp_import_keeps_servers_rejected_after_conversion() {
        let mut host = Host::new();
        host.program("bin/tool", "/bin/sh");
        host.egress = toml::from_str(
            "[api]\ndestinations = [\"api.example.com\"]\nsecret.ref = \"env://ROUTE_KEY\"",
        )
        .expect("a route");
        let document = serde_json::json!({"s": {
            "accepted": {"command": "tool", "env": {"KEY": "accepted-key"}},
            "duplicate": {"command": "tool", "env": {"KEY": "duplicate-key"}, "pass": ["PASSED"]},
            "routed": {"url": "https://api.example.com/mcp", "headers": {"X-Client": "agent"}},
            "with space": {"url": "https://other.example.com/mcp"}
        }});
        let file = host.file(".agent.json", &document.to_string());
        let mut source = with_roles(row(&file, &["s"]), &[("pass", "variable-names")]);
        source.target = Some(Target {
            path: host.home().join(".strands/box/storage/agent.json"),
            kind: Format::Json,
            key: vec!["s".into()],
        });
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[source], &mut mcp);
        assert_eq!(
            mcp.keys().map(String::as_str).collect::<Vec<_>>(),
            ["accepted"]
        );
        assert_eq!(
            servers
                .skipped
                .iter()
                .map(|server| server.name.as_str())
                .collect::<Vec<_>>(),
            ["duplicate", "routed", "with space"]
        );
        let imported = &servers.configs[0].servers;
        for name in ["routed", "with space"] {
            assert_eq!(imported.get(name), Some(&document["s"][name]), "{name}");
        }
        assert_eq!(imported["accepted"], serde_json::json!({"command": "tool"}));
        assert_eq!(
            imported["duplicate"],
            serde_json::json!({"command": "tool"})
        );
        assert_eq!(mcp["accepted"]["env"]["KEY"].as_str(), Some("accepted-key"));
        assert_eq!(
            servers.skipped[0].reason,
            "has the same detected command as the server accepted; calls routed to accepted \
             use its policy and environment"
        );
    }

    #[test]
    fn mcp_import_uses_private_env_only_for_a_matching_profile_command() {
        let mut host = Host::new();
        host.program("bin/tool", "/bin/sh");
        host.set = vec![("PASSED", "host-value"), ("PROGRAM", "tool")];
        let fixed = || vec!["--fixed"];
        for (command, args, declared, private) in [
            ("tool", fixed(), vec!["tool", "--fixed"], true),
            ("tool", fixed(), vec!["/opt/bin/tool", "--fixed"], true),
            ("tool", fixed(), vec!["/opt/bin/tool", "--other"], false),
            ("tool", fixed(), vec!["other", "--fixed"], false),
            ("tool", fixed(), vec!["tool", "--other"], false),
            ("tool", fixed(), vec!["tool"], false),
            ("/usr/bin/tool", fixed(), vec!["tool", "--fixed"], true),
            (
                "/usr/bin/tool",
                fixed(),
                vec!["/opt/bin/tool", "--fixed"],
                true,
            ),
            (
                "/usr/bin/tool",
                vec!["--other"],
                vec!["tool", "--fixed"],
                false,
            ),
            ("/usr/bin/other", fixed(), vec!["tool", "--fixed"], false),
            ("/usr/bin/", fixed(), vec!["tool", "--fixed"], false),
            ("/usr/bin/", fixed(), vec!["", "--fixed"], false),
            ("./tool", fixed(), vec!["tool", "--fixed"], true),
            ("bin/tool", fixed(), vec!["tool", "--fixed"], true),
            ("${PROGRAM}/tool", fixed(), vec!["tool", "--fixed"], true),
            ("${PROGRAM}", fixed(), vec!["tool", "--fixed"], false),
            ("${PROGRAM}", fixed(), vec!["${PROGRAM}", "--fixed"], false),
            (
                "/usr/bin/${PROGRAM}",
                fixed(),
                vec!["tool", "--fixed"],
                false,
            ),
            ("missing", vec![], vec!["missing"], true),
        ] {
            let original = serde_json::json!({
                "command": command, "args": args, "env": {"KEY": "host-key"},
                "pass": ["PASSED"], "startup_timeout_sec": 5
            });
            let file = host.file(
                ".agent.json",
                &serde_json::json!({"s": {"server": original}}).to_string(),
            );
            let mut source = with_roles(
                row(&file, &["s"]),
                &[("command", "references"), ("pass", "variable-names")],
            );
            source.target = Some(Target {
                path: host.home().join(".strands/box/storage/agent.json"),
                kind: Format::Json,
                key: vec!["s".into()],
            });
            let mut mcp = toml::Table::from_iter([(
                "server".into(),
                toml::Value::Table(toml::Table::from_iter([
                    ("type".into(), toml::Value::from("stdio")),
                    ("command".into(), toml::Value::from(declared)),
                    (
                        "env".into(),
                        toml::Value::Table(
                            toml::from_str("KEY = \"profile-key\"").expect("profile env"),
                        ),
                    ),
                ])),
            )]);
            let expected = mcp.clone();
            let servers = host.detect(&[source], &mut mcp);
            assert_eq!(mcp, expected, "the profile declaration does not change");
            let mut copied = original;
            if private {
                let fields = copied.as_object_mut().expect("entry");
                fields.remove("env");
                fields.remove("pass");
                fields.insert(
                    "command".into(),
                    Value::String(program_name(command).into()),
                );
            }
            assert_eq!(
                servers.configs[0].servers["server"], copied,
                "command {command:?}, profile {expected:?}"
            );
            assert!(servers.detected.is_empty());
            let [skip] = &servers.skipped[..] else {
                panic!("one skip: {:?}", servers.skipped);
            };
            assert_eq!(
                skip.reason.ends_with(&env_stays("server")),
                !private,
                "command {command:?}, profile {expected:?}: {}",
                skip.reason
            );
        }
    }

    fn env_stays(name: &str) -> String {
        format!(
            "; the profile's `[mcp.{name}]` does not match its command and arguments, so its \
             environment stays in the agent's settings, where the agent can read it"
        )
    }

    #[test]
    fn a_typed_table_says_when_an_entry_it_replaces_keeps_its_environment() {
        let host = Host::new();
        host.program("bin/tool", "/bin/sh");
        for (original, declaration, note) in [
            (
                serde_json::json!({"command": "tool", "env": {"KEY": "host-key"}}),
                "type = \"http\"\ndestinations = [\"tool.example.com\"]",
                true,
            ),
            (
                serde_json::json!({"command": "/opt/other", "pass": ["KEY"]}),
                "type = \"stdio\"\ncommand = [\"tool\"]",
                true,
            ),
            (
                serde_json::json!({"command": "missing-tool", "env": {"KEY": "host-key"}}),
                "type = \"stdio\"\ncommand = [\"other\"]",
                true,
            ),
            (
                serde_json::json!({"command": "tool", "env": {"LD_PRELOAD": "/x.so", "KEY": "k"}}),
                "type = \"stdio\"\ncommand = [\"other\"]",
                true,
            ),
            (
                serde_json::json!({"command": "/opt/other", "env": "KEY=host-key"}),
                "type = \"stdio\"\ncommand = [\"tool\"]",
                true,
            ),
            (
                serde_json::json!({"command": "/opt/other", "env": {}, "pass": []}),
                "type = \"stdio\"\ncommand = [\"tool\"]",
                false,
            ),
            (
                serde_json::json!({"command": "/opt/other"}),
                "type = \"stdio\"\ncommand = [\"tool\"]",
                false,
            ),
            (
                serde_json::json!({"url": "https://tool.example.com", "headers": {"X": "y"}}),
                "type = \"http\"\ndestinations = [\"tool.example.com\"]",
                false,
            ),
        ] {
            let file = host.file(
                ".agent.json",
                &serde_json::json!({"s": {"server": original}}).to_string(),
            );
            let mut source = with_roles(row(&file, &["s"]), &[("pass", "variable-names")]);
            source.target = Some(Target {
                path: host.home().join(".strands/box/storage/agent.json"),
                kind: Format::Json,
                key: vec!["s".into()],
            });
            let mut mcp: toml::Table =
                toml::from_str(&format!("[server]\n{declaration}")).expect("profile");
            let servers = host.detect(&[source], &mut mcp);
            assert_eq!(servers.configs[0].servers["server"], original);
            let [skip] = &servers.skipped[..] else {
                panic!("one skip: {:?}", servers.skipped);
            };
            assert_eq!(
                skip.reason.ends_with(&env_stays("server")),
                note,
                "{original}: {}",
                skip.reason
            );
        }
    }

    #[test]
    fn mcp_import_requires_full_argument_coverage_before_removing_env() {
        let host = Host::new();
        host.program("bin/tool", "/bin/sh");
        for (args, declared, wildcards, private) in [
            (vec!["a", "${ARG}"], vec!["tool", "a", "*"], true, true),
            (vec!["${ARG}", "b"], vec!["tool", "a", "*"], true, false),
            (vec!["a", "b"], vec!["tool", "a", "*"], true, true),
            (vec!["*"], vec!["tool", "*"], false, true),
            (vec!["${ARG}"], vec!["tool", "*"], false, false),
            (vec!["${ARG}"], vec!["tool", "${ARG}"], false, false),
            (vec!["%ARG%"], vec!["tool", "%ARG%"], false, false),
            (vec!["%ARG%"], vec!["tool", "*"], true, true),
        ] {
            let original = serde_json::json!({
                "command": "tool", "args": args, "env": {"KEY": "host-key"}
            });
            let file = host.file(
                ".agent.json",
                &serde_json::json!({"s": {"server": original}}).to_string(),
            );
            let mut source = row(&file, &["s"]);
            source.env_var_syntax = Some(Syntax::one("%NAME%"));
            source.target = Some(Target {
                path: host.home().join(".strands/box/storage/agent.json"),
                kind: Format::Json,
                key: vec!["s".into()],
            });
            let mut mcp = toml::Table::from_iter([(
                "server".into(),
                toml::Value::Table(toml::Table::from_iter([
                    ("type".into(), toml::Value::from("stdio")),
                    ("command".into(), toml::Value::from(declared)),
                    ("argument_wildcards".into(), toml::Value::Boolean(wildcards)),
                ])),
            )]);
            let expected = mcp.clone();
            let servers = host.detect(&[source], &mut mcp);
            assert_eq!(mcp, expected);
            let mut copied = original;
            if private {
                copied.as_object_mut().expect("entry").remove("env");
            }
            assert_eq!(
                servers.configs[0].servers["server"], copied,
                "profile {expected:?}"
            );
            assert!(servers.detected.is_empty());
        }
    }

    #[test]
    fn mcp_import_omits_a_path_override_and_any_env_shape_that_a_declaration_covers() {
        let host = Host::new();
        host.program("bin/tool", "/bin/sh");
        for environment in [
            serde_json::json!({"env": {"PATH": "/other", "KEY": "host-key"}}),
            serde_json::json!({"env": {"KEY": "host-key"}, "pass": ["PATH"]}),
            serde_json::json!({"env": {"KEY": "host-key"}, "pass": [{"name": "PATH"}]}),
            serde_json::json!({"env": "KEY=host-key", "pass": "KEY"}),
            serde_json::json!({"pass": [7]}),
        ] {
            let mut original = environment;
            original
                .as_object_mut()
                .expect("entry")
                .insert("command".into(), Value::String("tool".into()));
            let file = host.file(
                ".agent.json",
                &serde_json::json!({"s": {"server": original}}).to_string(),
            );
            let mut source = with_roles(row(&file, &["s"]), &[("pass", "variable-names")]);
            source.target = Some(Target {
                path: host.home().join(".strands/box/storage/agent.json"),
                kind: Format::Json,
                key: vec!["s".into()],
            });
            let mut mcp: toml::Table = toml::from_str(
                "[server]\ntype = \"stdio\"\ncommand = [\"tool\"]\nenv.KEY = \"profile-key\"",
            )
            .expect("profile");
            let servers = host.detect(&[source], &mut mcp);
            assert_eq!(
                servers.configs[0].servers["server"],
                serde_json::json!({"command": "tool"}),
                "{original}"
            );
        }
    }

    #[test]
    fn stored_mcp_targets_survive_disabled_import_and_are_deduplicated() {
        let host = Host::new();
        let file = host.home().join("missing.json");
        let mut own = row(&file, &["own"]);
        own.target = Some(Target {
            path: host.home().join(".strands/box/storage/agent.json"),
            kind: Format::Json,
            key: vec!["s".into()],
        });
        own.active = false;
        let mut project = own.clone();
        project.target.as_mut().unwrap().key =
            vec!["projects".into(), "/current".into(), "s".into()];
        let expected = vec![own.target.clone().unwrap(), project.target.clone().unwrap()];
        let servers = host.detect(
            &[own.clone(), project, own, row(&file, &["policy-only"])],
            &mut toml::Table::new(),
        );
        assert_eq!(servers.targets, expected);
        assert!(servers.configs.is_empty());
        assert!(servers.detected.is_empty());
    }

    #[test]
    fn mcp_import_keeps_source_precedence_for_servers_without_policy() {
        let host = Host::new();
        let document = serde_json::json!({
            "own": {"server": {"command": "node", "args": ["own.js"]}},
            "project": {"server": {"command": "uv", "args": ["run", "project.py"]}}
        });
        let file = host.file(".agent.json", &document.to_string());
        let mut own = row(&file, &["own"]);
        own.target = Some(Target {
            path: host.home().join(".strands/box/storage/agent.json"),
            kind: Format::Json,
            key: vec!["s".into()],
        });
        let mut project = row(&file, &["project"]);
        project.target = Some(Target {
            path: host.home().join(".strands/box/storage/agent.json"),
            kind: Format::Json,
            key: vec!["projects".into(), "current".into(), "s".into()],
        });
        for (last, targeted) in [(project.clone(), true), (row(&file, &["project"]), false)] {
            let servers = host.detect(&[own.clone(), last], &mut toml::Table::new());
            assert_eq!(servers.configs.len(), if targeted { 2 } else { 1 });
            assert!(servers.configs[0].servers.is_empty());
            if targeted {
                assert_eq!(
                    servers.configs[1].servers["server"],
                    document["project"]["server"]
                );
            }
            assert!(servers.detected.is_empty());
            assert_eq!(servers.skipped.len(), 1);
        }
        for suppressed in ["inactive", "refused"] {
            let mut later = project.clone();
            if suppressed == "inactive" {
                later.active = false;
            } else {
                later.refused = Some("the workspace".into());
            }
            let servers = host.detect(&[own.clone(), later], &mut toml::Table::new());
            assert_eq!(
                servers.configs[0].servers["server"],
                document["own"]["server"]
            );
            assert!(
                servers
                    .configs
                    .iter()
                    .skip(1)
                    .all(|config| config.servers.is_empty())
            );
        }
    }

    #[test]
    fn a_json_and_a_toml_source_each_give_their_servers() {
        let host = Host::new();
        let keg = host.program("brew/Cellar/fetcher/1.2.0/bin/fetcher", "/bin/sh");
        std::fs::create_dir_all(host.root.join("brew/opt")).expect("opt");
        std::fs::write(
            host.root
                .join("brew/Cellar/fetcher/1.2.0/INSTALL_RECEIPT.json"),
            r#"{"runtime_dependencies":[]}"#,
        )
        .unwrap();
        host.link("fetcher", &keg);
        let package = host.program("brew/lib/node_modules/@acme/notes/dist/index.js", "/bin/sh");
        host.link("notes", &package);
        let claude = host.file(
            ".claude.json",
            r#"{"mcpServers": {"fetch": {"type": "stdio", "command": "fetcher", "args": ["--quiet"], "env": {}},
                "docs": {"type": "http", "url": "https://docs.example.com/mcp"}}}"#,
        );
        let codex = host.file(
            ".codex/config.toml",
            "[mcp_servers.notes]\ncommand = \"notes\"\n[mcp_servers.remote]\nurl = \"https://Remote.example.com:8443/x\"\n",
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(
            &[row(&claude, &["mcpServers"]), row(&codex, &["mcp_servers"])],
            &mut mcp,
        );
        assert_eq!(reasons(&servers), Vec::<(&str, &str)>::new());
        assert_eq!(
            servers.sources,
            vec![(claude.clone(), Reading::Read), (codex, Reading::Read)]
        );
        let workspace = host.workspace().display().to_string();
        let mut expected: toml::Table = toml::from_str(&format!(
            r#"
            [docs]
            type = "http"
            destinations = ["docs.example.com"]

            [fetch]
            type = "stdio"
            command = ["fetcher", "--quiet"]
            filesystem.read = [{workspace:?}, {keg:?}]
            filesystem.read_file = [{shell:?}]
            filesystem.write = [{workspace:?}]

            [notes]
            type = "stdio"
            command = ["notes"]
            filesystem.read = [{workspace:?}, {package:?}]
            filesystem.read_file = [{shell:?}]
            filesystem.write = [{workspace:?}]

            [remote]
            type = "http"
            destinations = ["remote.example.com:8443"]
            "#,
            shell = crate::fixtures::shell(),
            keg = host
                .root
                .join("brew/Cellar/fetcher/1.2.0")
                .display()
                .to_string(),
            package = host
                .root
                .join("brew/lib/node_modules")
                .display()
                .to_string(),
        ))
        .expect("TOML");
        if cfg!(target_os = "macos") {
            expected["fetch"]["filesystem"]
                .as_table_mut()
                .unwrap()
                .insert(
                    "list".into(),
                    toml::Value::from(vec![
                        shown(&host.root.join("brew/opt")),
                        shown(&host.root.join("bin")),
                    ]),
                );
            expected["notes"]["filesystem"]
                .as_table_mut()
                .unwrap()
                .insert(
                    "list".into(),
                    toml::Value::from(vec![shown(&host.root.join("bin"))]),
                );
        }
        assert_eq!(mcp, expected);
        assert_eq!(
            servers.program_path("fetch"),
            Some(keg.as_path()),
            "the real file, with each link resolved"
        );
    }

    #[test]
    fn a_later_row_wins_by_name_and_a_missing_file_or_key_reads_nothing() {
        let host = Host::new();
        host.program("bin/first", "/bin/sh");
        host.program("bin/second", "/bin/sh");
        let user = host.file(
            ".claude.json",
            r#"{"mcpServers": {"tool": {"command": "first"}},
                "projects": {"/elsewhere": {"mcpServers": {}}}}"#,
        );
        let workspace = host.workspace().display().to_string();
        let local = host.file(
            "local.json",
            &format!(r#"{{"projects": {{"{workspace}": {{"mcpServers": {{"tool": {{"command": "second"}}}}}}}}}}"#),
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(
            &[
                row(&user, &["mcpServers"]),
                row(&user, &["projects", "/absent", "mcpServers"]),
                row(&local, &["projects", &workspace, "mcpServers"]),
                row(&host.home().join("none.json"), &["mcpServers"]),
            ],
            &mut mcp,
        );
        assert_eq!(mcp["tool"]["command"][0].as_str(), Some("second"));
        assert_eq!(servers.detected.len(), 1);
        assert_eq!(servers.detected[0].source, local);
        assert_eq!(
            servers.sources.last(),
            Some(&(host.home().join("none.json"), Reading::Absent))
        );
    }

    #[test]
    fn each_server_the_box_cannot_run_is_skipped_with_its_reason() {
        let host = Host::new();
        for name in ["npx", "bash", "tool"] {
            host.program(&format!("bin/{name}"), "/bin/sh");
        }
        let planted = host.program("home/project/planted", "/bin/sh");
        host.link("planted", &planted);
        let file = host.file(
            ".claude.json",
            r#"{"mcpServers": {
            "off": {"command": "tool", "enabled": false},
            "sse": {"type": "sse", "url": "https://x.example.com"},
            "launched": {"command": "npx", "args": ["-y", "server"]},
            "shell": {"command": "bash"},
            "absolute": {"command": "/usr/local/bin/tool"},
            "missing": {"command": "absent"},
            "planted": {"command": "planted"},
            "both": {"command": "tool", "url": "https://x.example.com"},
            "neither": {},
            "remote-env": {"type": "http", "url": "https://x.example.com", "env": {}}
        }}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["mcpServers"])], &mut mcp);
        assert!(mcp.is_empty(), "{mcp:?}");
        let mut expected =
            vec![
            ("absolute", "runs /usr/local/bin/tool, which is not an executable file".to_string()),
            ("both", "names both a command and a url".to_string()),
            (
                "launched",
                "runs npx, a launcher that fetches the server when it starts, and box ships no \
                 pack that runs it in the box"
                    .to_string(),
            ),
            ("missing", "runs absent, which is not on your PATH outside the project".to_string()),
            ("neither", "names no command or url".to_string()),
            ("off", "is turned off (enabled = false)".to_string()),
            (
                "planted",
                format!(
                    "its program {} (a link to ~/project/planted) lies in the workspace, \
                     ~/project; box runs no program from there",
                    host.root.join("bin/planted").display()
                ),
            ),
            ("remote-env", "uses env".to_string()),
            ("shell", "runs bash, which the box does not start as a server".to_string()),
            ("sse", "uses type sse".to_string()),
        ];
        expected.sort();
        let found: Vec<(&str, String)> = servers
            .skipped
            .iter()
            .map(|skip| (skip.name.as_str(), skip.reason.clone()))
            .collect();
        assert_eq!(found, expected);
    }

    #[test]
    fn a_server_whose_argument_names_a_file_in_the_workspace_is_declared() {
        let host = Host::new();
        for name in ["sqlite", "playwright", "tuiwright"] {
            host.program(&format!("bin/{name}"), "/bin/sh");
        }
        let database = host.workspace().join("data.sqlite");
        std::fs::write(&database, "").expect("a file");
        let config = host.workspace().join("playwright-mcp.json");
        std::fs::write(&config, "{}").expect("a file");
        std::fs::write(host.workspace().join("tuiwright.toml"), "").expect("a file");
        let file = host.file(
            ".claude.json",
            &format!(
                r#"{{"mcpServers": {{
                "written": {{"command": "sqlite", "args": ["--db-path", "{database}"]}},
                "flag-value": {{"command": "playwright", "args": ["--config={config}"]}},
                "relative": {{"command": "tuiwright", "args": ["--config", "tuiwright.toml"]}}
            }}}}"#,
                database = database.display(),
                config = config.display()
            ),
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["mcpServers"])], &mut mcp);
        assert_eq!(reasons(&servers), Vec::<(&str, &str)>::new());
        let command = |name: &str| mcp[name]["command"].clone();
        let database = database.display().to_string();
        assert_eq!(
            command("written"),
            toml::Value::from(vec!["sqlite", "--db-path", &database])
        );
        assert_eq!(
            command("flag-value"),
            toml::Value::from(vec![
                "playwright".to_string(),
                format!("--config={}", config.display())
            ])
        );
        assert_eq!(
            command("relative"),
            toml::Value::from(vec!["tuiwright", "--config", "tuiwright.toml"])
        );
    }

    #[test]
    fn a_name_outside_the_allowed_characters_is_skipped_and_never_renamed() {
        let host = Host::new();
        for name in ["a", "b", "c", "d"] {
            host.program(&format!("bin/{name}"), "/bin/sh");
        }
        let file = host.file(
            ".claude.json",
            r#"{"mcpServers": {
                "my server": {"command": "a"},
                "my-server": {"command": "b"},
                "team/notes": {"command": "c"},
                "team-notes": {"command": "c"},
                "kept": {"command": "d"},
                "twin": {"command": "d"}
            }}"#,
        );
        let mut mcp: toml::Table =
            toml::from_str("[team-notes]\ntype = \"http\"\ndestinations = [\"notes.example.com\"]")
                .expect("TOML");
        let servers = host.detect(&[row(&file, &["mcpServers"])], &mut mcp);
        assert_eq!(
            reasons(&servers),
            vec![
                (
                    "my server",
                    "its name holds a character Box Core does not take in a server name (only letters, digits, `.`, `_`, and `-`); rename the server in your agent's configuration"
                ),
                (
                    "team-notes",
                    "the profile declares `[mcp.team-notes]`, which takes its place"
                ),
                (
                    "team/notes",
                    "its name holds a character Box Core does not take in a server name (only letters, digits, `.`, `_`, and `-`); rename the server in your agent's configuration"
                ),
                (
                    "twin",
                    "has the same detected command as the server kept; calls routed to kept use its policy and environment"
                ),
            ]
        );
        assert_eq!(
            mcp["team-notes"]["type"].as_str(),
            Some("http"),
            "the profile's own table"
        );
        assert_eq!(
            servers.detected_lines(&host.home()),
            vec![
                (
                    "kept".to_string(),
                    "~/.claude.json".to_string(),
                    String::new()
                ),
                (
                    "my-server".to_string(),
                    "~/.claude.json".to_string(),
                    String::new()
                ),
            ],
            "each declared server keeps the name the agent's configuration gives it"
        );
    }

    #[test]
    fn a_source_where_a_box_can_write_or_that_does_not_parse_is_not_read() {
        let host = Host::new();
        let broken = host.file("broken.json", "{");
        let scalar = host.file("scalar.toml", "mcp_servers = 1\n");
        let mut refused = row(&host.workspace().join(".mcp.json"), &["mcpServers"]);
        refused.refused = Some("the workspace".into());
        let servers = host.detect(
            &[
                row(&broken, &["mcpServers"]),
                row(&scalar, &["mcp_servers"]),
                refused,
            ],
            &mut toml::Table::new(),
        );
        let readings: Vec<String> = servers
            .unread_lines(&host.home())
            .into_iter()
            .map(|(file, reason)| format!("{file}: {reason}"))
            .collect();
        assert_eq!(readings.len(), 3, "{readings:?}");
        assert!(
            readings[0].starts_with("~/broken.json: it is not JSON"),
            "{readings:?}"
        );
        assert_eq!(
            readings[1],
            "~/scalar.toml: the value at \"mcp_servers\" is not a table of servers"
        );
        assert_eq!(readings[2], "~/project/.mcp.json: the workspace");
    }

    #[test]
    fn a_path_directory_where_a_box_can_write_skips_every_stdio_server() {
        for before in [None, Some(".")] {
            let mut host = Host::new();
            host.program("bin/tool", "/bin/sh");
            host.path.extend(before.map(PathBuf::from));
            host.path.push(host.workspace().join("node_modules/.bin"));
            let file = host.file(
                ".claude.json",
                r#"{"s": {"tool": {"command": "tool"}, "docs": {"url": "https://docs.example.com"}}}"#,
            );
            let mut mcp = toml::Table::new();
            let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
            assert_eq!(
                reasons(&servers),
                vec![(
                    "tool",
                    "your PATH directory ~/project/node_modules/.bin lies in the workspace, ~/project; a server inherits your PATH"
                )],
                "{before:?}"
            );
            assert!(mcp.contains_key("docs"), "an http server needs no PATH");
        }
    }

    #[test]
    fn a_program_in_a_python_venv_reads_the_whole_venv() {
        let host = Host::new();
        let program = host.program("pipx/venvs/notes/bin/mcp-notes", "/bin/sh");
        std::fs::write(host.root.join("pipx/venvs/notes/pyvenv.cfg"), "home = /x\n")
            .expect("a venv");
        assert_eq!(
            install_layout::resolve(&program, Layout::ALL, "macos", &|_| Ok(()))
                .unwrap()
                .read,
            vec![host.root.join("pipx/venvs/notes")]
        );
    }

    #[test]
    fn servers_keep_their_own_python_environment_without_interpreter_tools() {
        let host = Host::new();
        let python = host.program("runtime/bin/python3.12", "/bin/sh");
        std::fs::create_dir_all(host.root.join("runtime/lib")).unwrap();
        for name in ["first", "second"] {
            let environment = host.root.join(name);
            std::fs::create_dir_all(environment.join("bin")).unwrap();
            std::fs::write(environment.join("pyvenv.cfg"), "home = /unused").unwrap();
            symlink(&python, environment.join("bin/python")).unwrap();
            let script = host.program(
                &format!("launchers/{name}"),
                &environment.join("bin/python").display().to_string(),
            );
            host.link(name, &script);
        }
        let file = host.file(".claude.json",
            r#"{"s":{"first":{"command":"first","env":{"SETTING":"kept"}},"second":{"command":"second"}}}"#);
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert!(servers.skipped.is_empty(), "{:?}", servers.skipped);
        assert_eq!(mcp.len(), 2);
        for (name, other) in [("first", "second"), ("second", "first")] {
            let read = mcp[name]["filesystem"]["read"].as_array().unwrap();
            assert!(read.contains(&toml::Value::String(
                host.root.join(name).display().to_string()
            )));
            assert!(!read.contains(&toml::Value::String(
                host.root.join(other).display().to_string()
            )));
        }
        assert_eq!(mcp["first"]["env"]["SETTING"].as_str(), Some("kept"));
    }

    #[test]
    fn a_uv_tool_reads_its_directory_and_uvs_python_and_an_env_line_finds_its_interpreter() {
        let host = Host::new();
        let python = host.program("uv/python/cpython-3.12/bin/python3.12", "/bin/sh");
        let tool = host.program(
            "uv/tools/fetch/bin/mcp-server-fetch",
            &python.display().to_string(),
        );
        host.link("mcp-server-fetch", &tool);
        let node = host.program("nvm/v22/bin/node", "/bin/sh");
        host.link("node", &node);
        let script = host.program(
            "nvm/v22/lib/node_modules/notes/cli.js",
            "/usr/bin/env -S node --flag",
        );
        host.link("notes", &script);
        let file = host.file(
            ".claude.json",
            r#"{"s": {"fetch": {"command": "mcp-server-fetch"}, "notes": {"command": "notes"}}}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert_eq!(reasons(&servers), Vec::<(&str, &str)>::new());
        let read = |name: &str| -> Vec<String> {
            mcp[name]["filesystem"]["read"]
                .as_array()
                .expect("a list")
                .iter()
                .skip(1)
                .map(|item| item.as_str().expect("a path").to_string())
                .collect()
        };
        let shown = |relative: &str| host.root.join(relative).display().to_string();
        assert_eq!(
            read("fetch"),
            vec![shown("uv/tools/fetch"), shown("uv/python/cpython-3.12")]
        );
        assert_eq!(
            read("notes"),
            vec![shown("nvm/v22/lib/node_modules"), shown("nvm/v22/bin")]
        );
        let real = |path: &str| {
            toml::Value::from(
                std::fs::canonicalize(path)
                    .expect("a system file")
                    .display()
                    .to_string(),
            )
        };
        assert_eq!(
            mcp["notes"]["filesystem"]["read_file"],
            toml::Value::Array(vec![real("/usr/bin/env"), real("/bin/sh")]),
            "env, and the #! line of the node it runs, each come in as a file"
        );
    }

    #[test]
    fn an_env_line_whose_interpreter_has_its_own_env_line_grants_the_last_interpreter() {
        let host = Host::new();
        host.program("bin/real", "/bin/sh");
        host.program("bin/shim", "/usr/bin/env real");
        host.program("bin/server", "/usr/bin/env shim");
        let file = host.file(
            ".claude.json",
            r#"{"s": {"server": {"command": "server"}}}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert_eq!(reasons(&servers), Vec::<(&str, &str)>::new());
        let real = |path: &str| {
            toml::Value::from(
                std::fs::canonicalize(path)
                    .expect("a system file")
                    .display()
                    .to_string(),
            )
        };
        assert_eq!(
            mcp["server"]["filesystem"]["read_file"],
            toml::Value::Array(vec![real("/usr/bin/env"), real("/bin/sh")]),
            "env comes in once, and the chain goes on past the second env line"
        );
    }

    #[test]
    fn a_chain_that_returns_to_a_program_it_ran_ends() {
        let host = Host::new();
        let a = host.root.join("bin/a");
        let b = host.program("bin/b", &a.display().to_string());
        host.program("bin/a", &b.display().to_string());
        let own = host.root.join("bin/own");
        host.program("bin/own", &own.display().to_string());
        let path = host.path.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut sources = SearchPath(path, Vec::new(), BTreeMap::new());
            let _ = sender.send((
                interpreters(&a, &mut sources),
                interpreters(&own, &mut sources),
            ));
        });
        let (cycle, own) = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the walk ends");
        assert_eq!(
            cycle,
            Ok(Chain {
                envs: Vec::new(),
                interpreters: vec![b.clone()],
                spellings: vec![b]
            })
        );
        assert_eq!(own, Ok(Chain::default()));
    }

    #[test]
    fn an_env_outside_the_system_folders_comes_in_as_its_file_and_not_its_folder() {
        let host = Host::new();
        let env = host.program("coreutils/env", "/bin/sh");
        host.program("bin/node", "/bin/sh");
        host.program("bin/server", &format!("{} node", env.display()));
        let file = host.file(
            ".claude.json",
            r#"{"s": {"server": {"command": "server"}}}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert_eq!(reasons(&servers), Vec::<(&str, &str)>::new());
        let filesystem = &mcp["server"]["filesystem"];
        let folder = host.root.join("coreutils").display().to_string();
        assert!(
            !filesystem["read"]
                .as_array()
                .expect("a list")
                .iter()
                .any(|entry| entry.as_str() == Some(folder.as_str())),
            "{filesystem}"
        );
        assert_eq!(
            filesystem["read_file"][0].as_str(),
            Some(env.display().to_string().as_str()),
            "{filesystem}"
        );
    }

    #[test]
    fn a_program_deeper_in_the_chain_that_a_box_can_write_skips_the_server() {
        let host = Host::new();
        let planted = host.root.join("home/shared/interp");
        std::fs::create_dir_all(planted.parent().expect("a parent")).expect("a folder");
        std::fs::write(&planted, "#!/bin/sh\n").expect("a program");
        let mid = host.program("bin/mid", &planted.display().to_string());
        host.program("bin/server", &mid.display().to_string());
        let file = host.file(
            ".claude.json",
            r#"{"s": {"server": {"command": "server"}}}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert!(!mcp.contains_key("server"), "{mcp:?}");
        let skipped = reasons(&servers);
        assert!(
            skipped
                .iter()
                .any(|(name, reason)| *name == "server" && reason.contains("its interpreter")),
            "{skipped:?}"
        );
    }

    #[test]
    fn an_addition_that_sets_a_command_keeps_its_detected_server() {
        let mut host = Host::new();
        host.program("bin/fetcher", "/bin/sh");
        host.set = vec![("PASSED", "host-value")];
        let document = serde_json::json!({"s": {
            "fetch": {"command": "fetcher", "env": {"KEY": "kept-key"}, "env_vars": ["PASSED"]},
            "twin": {"command": "fetcher", "env": {"KEY": "twin-key"}, "env_vars": ["PASSED"]}
        }});
        let file = host.file(".claude.json", &document.to_string());
        let mut source = with_roles(row(&file, &["s"]), &[("env_vars", "variable-names")]);
        source.target = Some(Target {
            path: host.home().join(".strands/box/storage/agent.json"),
            kind: Format::Json,
            key: vec!["s".into()],
        });
        let mut mcp: toml::Table =
            toml::from_str("[fetch]\ncommand = [\"fetcher\", \"--mine\"]").expect("TOML");
        let servers = host.detect(&[source], &mut mcp);
        assert_eq!(
            reasons(&servers),
            vec![(
                "twin",
                "has the same detected command as the server fetch; calls routed to fetch use \
                 its policy and environment"
            )]
        );
        assert_eq!(mcp["fetch"]["type"].as_str(), Some("stdio"));
        assert_eq!(mcp["fetch"]["command"][1].as_str(), Some("--mine"));
        assert_eq!(mcp["fetch"]["env"]["KEY"].as_str(), Some("kept-key"));
        assert_eq!(mcp["fetch"]["env"]["PASSED"].as_str(), Some("host-value"));
        assert_eq!(
            servers.configs[0].servers["fetch"],
            serde_json::json!({"command": "fetcher", "args": ["--mine"]})
        );
        assert_eq!(servers.configs[0].servers["twin"], document["s"]["twin"]);
    }

    #[test]
    fn an_addition_that_lists_destinations_keeps_the_servers_own_host() {
        for (added, joined) in [
            (
                vec!["cdn.example.com"],
                vec!["mcp.example.com", "cdn.example.com"],
            ),
            (
                vec!["cdn.example.com", "MCP.example.com"],
                vec!["mcp.example.com", "cdn.example.com"],
            ),
            (
                vec!["mcp.example.com:443", "mcp.example.com/static/"],
                vec!["mcp.example.com"],
            ),
            (
                vec!["mcp.example.com:80", "mcp.example.com:8443"],
                vec!["mcp.example.com", "mcp.example.com:8443"],
            ),
        ] {
            let host = Host::new();
            let file = host.file(
                ".claude.json",
                r#"{"s": {"docs": {"url": "https://mcp.example.com/mcp"}}}"#,
            );
            let mut addition = toml::Table::new();
            addition.insert("destinations".into(), toml::Value::from(added.clone()));
            let mut mcp = toml::Table::from_iter([("docs".to_string(), addition.into())]);
            let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
            assert_eq!(reasons(&servers), Vec::<(&str, &str)>::new());
            assert_eq!(
                mcp["docs"]["destinations"],
                toml::Value::from(joined),
                "{added:?} joins after the URL's host, and a host already there is not added twice"
            );
        }
    }

    #[test]
    fn an_addition_with_a_wildcard_over_the_servers_own_host_is_skipped() {
        for wildcard in ["*.example.com", "*.Example.com", "*.example.com:443", "*"] {
            let host = Host::new();
            let file = host.file(
                ".claude.json",
                r#"{"s": {"docs": {"url": "https://mcp.example.com/mcp"}}}"#,
            );
            let mut addition = toml::Table::new();
            addition.insert("destinations".into(), toml::Value::from(vec![wildcard]));
            let mut mcp = toml::Table::from_iter([("docs".to_string(), addition.into())]);
            let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
            let reason = format!(
                "`[mcp.docs]` adds {wildcard}, which covers its own host mcp.example.com; Box \
                 Core refuses two destinations of one server that overlap"
            );
            assert_eq!(reasons(&servers), vec![("docs", reason.as_str())]);
            assert!(mcp.get("docs").is_none(), "{mcp:?}");
        }
    }

    #[test]
    fn an_http_server_on_this_machine_is_imported() {
        let host = Host::new();
        let file = host.file(
            ".claude.json",
            r#"{"s": {"local": {"url": "http://localhost:3000/mcp"}}}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert_eq!(reasons(&servers), Vec::<(&str, &str)>::new());
        assert_eq!(
            mcp["local"]["destinations"],
            toml::Value::from(vec!["localhost:3000"]),
            "{mcp:?}"
        );
    }

    #[test]
    fn an_addition_on_another_port_than_a_plain_http_servers_host_joins() {
        for (added, joined) in [
            (
                vec!["mcp.example.com", "mcp.example.com/static/"],
                vec!["mcp.example.com:80"],
            ),
            (
                vec!["*.example.com:8443", "*.example.com:443"],
                vec![
                    "mcp.example.com:80",
                    "*.example.com:8443",
                    "*.example.com:443",
                ],
            ),
        ] {
            let host = Host::new();
            let file = host.file(
                ".claude.json",
                r#"{"s": {"docs": {"url": "http://mcp.example.com/mcp"}}}"#,
            );
            let mut addition = toml::Table::new();
            addition.insert("destinations".into(), toml::Value::from(added.clone()));
            let mut mcp = toml::Table::from_iter([("docs".to_string(), addition.into())]);
            let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
            assert_eq!(reasons(&servers), Vec::<(&str, &str)>::new(), "{added:?}");
            assert_eq!(
                mcp["docs"]["destinations"],
                toml::Value::from(joined),
                "{added:?}"
            );
        }
    }

    #[test]
    fn a_program_name_that_a_server_the_agent_or_a_tool_runs_is_skipped() {
        let mut host = Host::new();
        host.others = vec![
            ("the agent".into(), "/opt/agents/claude".into()),
            ("the tool git".into(), "/usr/bin/git".into()),
        ];
        for name in ["fetcher", "claude", "git"] {
            host.program(&format!("bin/{name}"), "/bin/sh");
        }
        let file = host.file(
            ".claude.json",
            r#"{"s": {"fetch": {"command": "fetcher"}, "agent": {"command": "claude"}, "vcs": {"command": "git"}}}"#,
        );
        let mut mcp: toml::Table =
            toml::from_str("[local]\ntype = \"stdio\"\ncommand = [\"/opt/x/bin/fetcher\"]")
                .expect("TOML");
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert!(
            !mcp.contains_key("fetch"),
            "the declared absolute command has the same filename and arguments"
        );
        assert_eq!(
            reasons(&servers),
            vec![
                (
                    "agent",
                    "runs claude, which the agent runs too; the box puts one program of each name on PATH"
                ),
                (
                    "fetch",
                    "has the same detected command as the server local; calls routed to local \
                     use its policy and environment"
                ),
                (
                    "vcs",
                    "runs git, which the tool git runs too; the box puts one program of each name on PATH"
                ),
            ]
        );
    }

    #[test]
    fn a_path_entry_that_is_not_a_full_path_skips_no_stdio_server() {
        for entry in [".", "", "~/.dotnet/tools"] {
            let mut host = Host::new();
            host.program("bin/tool", "/bin/sh");
            host.path.insert(0, PathBuf::from(entry));
            let file = host.file(".claude.json", r#"{"s": {"tool": {"command": "tool"}}}"#);
            let mut mcp = toml::Table::new();
            let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
            assert_eq!(reasons(&servers), Vec::<(&str, &str)>::new(), "{entry:?}");
            assert!(
                mcp["tool"].get("env").is_none(),
                "compile writes the PATH: {entry:?}"
            );
        }
    }

    #[test]
    fn a_route_that_holds_only_destinations_shares_its_host_with_a_server() {
        let mut host = Host::new();
        host.egress =
            toml::from_str("[login]\ndestinations = [\"mcp.example.com\"]").expect("TOML");
        let file = host.file(
            ".claude.json",
            r#"{"s": {"remote": {"url": "https://mcp.example.com"}}}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert!(reasons(&servers).is_empty(), "{:?}", reasons(&servers));
        assert!(mcp.contains_key("remote"), "{mcp:?}");
    }

    #[test]
    fn a_shared_host_a_runtime_or_a_forbidden_install_directory_is_skipped() {
        let mut host = Host::new();
        host.egress =
            toml::from_str("[api]\ndestinations = [\"*.example.com\"]\nsecret.ref = \"env://KEY\"")
                .expect("TOML");
        host.program("bin/node", "/bin/sh");
        let docker = host.program("home/.docker/bin/docker-mcp", "/bin/sh");
        host.link("docker-mcp", &docker);
        let file = host.file(
            ".claude.json",
            r#"{"s": {
                "a-copilot": {"url": "https://api.githubcopilot.com/mcp/"},
                "b-copilot": {"url": "https://api.githubcopilot.com:8443/mcp/readonly"},
                "routed": {"url": "https://mcp.example.com"},
                "script": {"command": "node", "args": ["server.js"]},
                "docker": {"command": "docker-mcp"},
                "flag": {"command": "node", "enabled": "no"},
                "listed": {"command": "node", "env": ["X"]}
            }}"#,
        );
        let mut mcp = toml::Table::new();
        let docker_reason = format!(
            "its program {} lies in a credential store, which box grants no server",
            docker.display()
        );
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert_eq!(
            reasons(&servers),
            vec![
                (
                    "b-copilot",
                    "reaches api.githubcopilot.com, which the server a-copilot reaches too; the box routes a remote server by its host alone"
                ),
                ("docker", docker_reason.as_str()),
                ("flag", "`enabled` is not true or false"),
                ("listed", "`env` is not a table"),
                (
                    "routed",
                    "reaches mcp.example.com, which the route api reaches too; the box routes a remote server by its host alone"
                ),
                (
                    "script",
                    "runs node, which runs a script or a package rather than an installed server program"
                ),
            ]
        );
        assert_eq!(mcp.keys().collect::<Vec<_>>(), ["a-copilot"]);
    }

    #[test]
    fn box_core_decides_each_install_directory_grant() {
        let host = Host::new();
        let keg = host.program("brew/Cellar/fetcher/1.2.0/bin/fetcher", "/bin/sh");
        std::fs::write(
            host.root
                .join("brew/Cellar/fetcher/1.2.0/INSTALL_RECEIPT.json"),
            r#"{"runtime_dependencies":[]}"#,
        )
        .expect("a receipt");
        std::fs::create_dir_all(host.root.join("brew/real-opt")).expect("opt");
        symlink(host.root.join("brew/real-opt"), host.root.join("brew/opt")).expect("a link");
        std::fs::create_dir_all(host.root.join("brew/etc")).expect("etc");
        host.link("fetcher", &keg);
        let locked = host.program("Library/Keychains/bin/locked", "/bin/sh");
        host.link("locked", &locked);
        let file = host.file(
            ".claude.json",
            r#"{"s": {"fetch": {"command": "fetcher"}, "locked": {"command": "locked"}}}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert_eq!(
            reasons(&servers),
            vec![(
                "locked",
                format!(
                    "its program {} is one the box refuses to grant: {} is refused beneath every \
                     grant",
                    locked.display(),
                    locked.display()
                )
                .as_str()
            )]
        );
        assert_eq!(
            strings(&mcp["fetch"]["filesystem"]["read"]),
            [
                host.workspace().display().to_string(),
                host.root
                    .join("brew/Cellar/fetcher/1.2.0")
                    .display()
                    .to_string(),
            ],
            "the keg alone: /bin and the linked opt are no grant Box Core takes"
        );
    }

    #[test]
    fn a_system_tree_classification_drops_the_own_directory_without_a_path_list() {
        let mut host = Host::new();
        host.program("bin/fetcher", "/bin/sh");
        host.read_grants.insert(
            host.root.join("bin"),
            (
                strands_box::GrantRefusal::Forbidden(strands_box::ForbiddenClass::SystemTree),
                "Core system tree".into(),
            ),
        );
        let file = host.file(".claude.json", r#"{"s":{"fetch":{"command":"fetcher"}}}"#);
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert!(servers.skipped.is_empty(), "{:?}", reasons(&servers));
        assert_eq!(
            strings(&mcp["fetch"]["filesystem"]["read"]),
            [host.workspace().display().to_string()]
        );
    }

    #[test]
    fn a_non_system_refusal_under_a_system_prefix_skips_the_server() {
        use strands_box::{ForbiddenClass, GrantRefusal};
        let directory = canonical(Path::new("/bin/sh"))
            .expect("the shell")
            .parent()
            .expect("its directory")
            .to_path_buf();
        for kind in [
            GrantRefusal::NotAbsolute,
            GrantRefusal::Absent,
            GrantRefusal::Link,
            GrantRefusal::NotCanonical,
            GrantRefusal::Other,
            GrantRefusal::Forbidden(ForbiddenClass::WholeFilesystem),
            GrantRefusal::Forbidden(ForbiddenClass::HomeNamespace),
            GrantRefusal::Forbidden(ForbiddenClass::LoaderDirectory),
            GrantRefusal::Forbidden(ForbiddenClass::CredentialStore),
            GrantRefusal::Forbidden(ForbiddenClass::PasswordDatabase),
            GrantRefusal::Forbidden(ForbiddenClass::MachineCredential),
            GrantRefusal::Forbidden(ForbiddenClass::PrivilegeConfiguration),
        ] {
            let mut host = Host::new();
            host.program("bin/fetcher", "/bin/sh");
            host.read_grants
                .insert(directory.clone(), (kind, "Core refusal detail".into()));
            let file = host.file(".claude.json", r#"{"s":{"fetch":{"command":"fetcher"}}}"#);
            let mut mcp = toml::Table::new();
            let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
            let reason = format!(
                "its install directory {} is one the box refuses to grant: Core refusal detail",
                directory.display()
            );
            assert_eq!(reasons(&servers), [("fetch", reason.as_str())], "{kind:?}");
            assert!(mcp.is_empty(), "{kind:?}: {mcp:?}");
        }
    }

    #[test]
    fn an_interpreter_that_box_core_refuses_to_grant_skips_its_server() {
        let host = Host::new();
        let interpreter = host.program("Library/Keychains/bin/interp", "/bin/sh");
        host.program("bin/scripted", &interpreter.display().to_string());
        let file = host.file(
            ".claude.json",
            r#"{"s": {"scripted": {"command": "scripted"}}}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        let reason = format!(
            "its interpreter {path} is one the box refuses to grant: {path} is refused beneath \
             every grant",
            path = interpreter.display()
        );
        assert_eq!(reasons(&servers), vec![("scripted", reason.as_str())]);
        assert!(mcp.is_empty(), "{mcp:?}");
    }

    #[test]
    fn an_interpreter_in_a_credential_store_skips_its_server() {
        let host = Host::new();
        let interpreter = host.program("home/.docker/bin/interp", "/bin/sh");
        host.program("bin/scripted", &interpreter.display().to_string());
        let file = host.file(
            ".claude.json",
            r#"{"s": {"scripted": {"command": "scripted"}}}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        let reason = format!(
            "its interpreter {} lies in a credential store, which box grants no server",
            interpreter.display()
        );
        assert_eq!(reasons(&servers), vec![("scripted", reason.as_str())]);
        assert!(mcp.is_empty(), "{mcp:?}");
    }

    #[test]
    fn a_refused_own_directory_in_the_home_skips_and_a_refused_extra_directory_drops() {
        let host = Host::new();
        let cfgtool = host.program("home/.config/cfgtool", "/bin/sh");
        std::fs::create_dir_all(host.home().join(".config/gcloud")).expect("a credential store");
        host.link("cfgtool", &cfgtool);
        let keg = host.program("home/brew/Cellar/fetcher/1.2.0/bin/fetcher", "/bin/sh");
        std::fs::write(
            host.root
                .join("home/brew/Cellar/fetcher/1.2.0/INSTALL_RECEIPT.json"),
            r#"{"runtime_dependencies":[]}"#,
        )
        .expect("a receipt");
        std::fs::create_dir_all(host.home().join("brew/opt/gcloud")).expect("a refused opt");
        host.link("fetcher", &keg);
        let file = host.file(
            ".claude.json",
            r#"{"s": {"cfg": {"command": "cfgtool"}, "fetch": {"command": "fetcher"}}}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        let config = host.home().join(".config");
        let reason = format!(
            "its install directory ~/.config is one the box refuses to grant: {} holds a \
             credential store",
            config.display()
        );
        assert_eq!(reasons(&servers), vec![("cfg", reason.as_str())]);
        assert_eq!(
            strings(&mcp["fetch"]["filesystem"]["read"]),
            [
                host.workspace().display().to_string(),
                host.home()
                    .join("brew/Cellar/fetcher/1.2.0")
                    .display()
                    .to_string(),
            ],
            "the keg alone, without /bin, the interpreter's own system directory"
        );
    }

    #[test]
    fn a_refused_own_directory_of_the_interpreter_or_outside_a_system_root_skips() {
        let host = Host::new();
        let interpreter = host.program("home/.config/interp", "/bin/sh");
        std::fs::create_dir_all(host.home().join(".config/gcloud")).expect("a credential store");
        host.program("bin/scripted", &interpreter.display().to_string());
        let tool = host.program("data/bin/tool", "/bin/sh");
        std::fs::create_dir_all(host.root.join("data/bin/gcloud")).expect("a credential store");
        host.link("tool", &tool);
        let file = host.file(
            ".claude.json",
            r#"{"s": {"scripted": {"command": "scripted"}, "tool": {"command": "tool"}}}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        let refused = |directory: PathBuf| {
            format!(
                "its install directory {} is one the box refuses to grant: {} holds a credential \
                 store",
                tilde(&host.home(), &directory),
                directory.display()
            )
        };
        let (config, data) = (
            refused(host.home().join(".config")),
            refused(host.root.join("data/bin")),
        );
        assert_eq!(
            reasons(&servers),
            vec![("scripted", config.as_str()), ("tool", data.as_str())]
        );
        assert!(mcp.is_empty(), "{mcp:?}");
    }

    fn strings(value: &toml::Value) -> Vec<String> {
        value
            .as_array()
            .expect("a list")
            .iter()
            .map(|item| item.as_str().expect("a string").to_string())
            .collect()
    }

    #[test]
    fn an_https_url_becomes_its_host_and_port() {
        for (url, expected) in [
            (
                "https://api.example.com/mcp",
                Ok("api.example.com".to_string()),
            ),
            (
                "https://api.example.com:443/",
                Ok("api.example.com".to_string()),
            ),
            (
                "https://api.example.com:8443?x=1",
                Ok("api.example.com:8443".to_string()),
            ),
            (
                "https://user@api.example.com",
                Err("its url holds a user name".to_string()),
            ),
            (
                "https://[::1]:443",
                Err("its url \"https://[::1]:443\" names no host name".to_string()),
            ),
            (
                "https://${HOST}/mcp",
                Err("passes a variable in its url, which box does not fill in".to_string()),
            ),
            (
                "ws://x",
                Err("its url \"ws://x\" is not an http:// or https:// URL".to_string()),
            ),
            (
                "http://mcp.example.com/x",
                Ok("mcp.example.com:80".to_string()),
            ),
            (
                "http://MCP.example.com:8080/x",
                Ok("mcp.example.com:8080".to_string()),
            ),
            (
                "http://localhost:3000/mcp",
                Ok("localhost:3000".to_string()),
            ),
            ("https://localhost:8443", Ok("localhost:8443".to_string())),
            ("http://127.0.0.1:9000", Ok("127.0.0.1:9000".to_string())),
        ] {
            assert_eq!(destination(url), expected, "{url}");
        }
    }

    #[test]
    fn a_server_name_holds_only_letters_digits_dots_underscores_and_dashes() {
        assert!(allowed_name("a.b_c-D9"));
        for name in ["my server", "team/notes", "x:y", "caf\u{e9}", ""] {
            assert!(!allowed_name(name), "{name:?}");
        }
    }

    #[test]
    fn a_header_that_is_one_variable_gives_its_remote_server_that_key() {
        let mut host = Host::new();
        host.set = vec![
            ("TOKEN", "a-key"),
            ("API_KEY", "a-key"),
            ("A", "a-key"),
            ("B", "a-key"),
            ("M", "a-key"),
            ("QK", "a-key"),
            ("C", "a-key"),
            ("DEFAULTED", "a-key"),
        ];
        host.program("bin/tool", "/bin/sh");
        host.program("bin/aws-tool", "/bin/sh");
        host.program("bin/plain-tool", "/bin/sh");
        let file = host.file(
            ".claude.json",
            r#"{"s": {
                "bearer": {"url": "https://bearer.example.com", "headers": {"Authorization": "Bearer ${TOKEN}"}},
                "keyed": {"url": "https://keyed.example.com", "headers": {"X-Api-Key": "${API_KEY}"}},
                "pasted": {"url": "https://pasted.example.com", "headers": {"Authorization": "Bearer ghp_x"}},
                "defaulted": {"url": "https://defaulted.example.com", "headers": {"X-Key": "${DEFAULTED:-b}"}},
                "prefixed": {"url": "https://prefixed.example.com", "headers": {"X-Key": "key-${M}"}},
                "suffixed": {"url": "https://suffixed.example.com", "headers": {"X-Key": "${A}-x"}},
                "query": {"url": "https://query.example.com/mcp?v=1&api_key=${QK}"},
                "query-mixed": {"url": "https://query-mixed.example.com/mcp?k=x${A}"},
                "query-host": {"url": "https://${A}.example.com/mcp"},
                "query-path": {"url": "https://path.example.com/${A}/mcp"},
                "query-fragment": {"url": "https://fragment.example.com/mcp?v=1#k=${A}"},
                "query-param": {"url": "https://param.example.com/mcp?a%5Fb=${A}"},
                "query-twice": {"url": "https://query-twice.example.com/mcp?k=${A}&j=${A}"},
                "query-header": {"url": "https://query-header.example.com/mcp?k=${A}", "headers": {"X-Key": "${A}"}},
                "query-header-two": {"url": "https://query-header-two.example.com/mcp?k=${A}", "headers": {"X-Key": "${B}"}},
                "braced": {"url": "https://braced.example.com", "headers": {"X-Key": "Token {v1} ${A}"}},
                "tabbed": {"url": "https://tabbed.example.com", "headers": {"Authorization": "Bearer\t${A}"}},
                "two-unset": {"url": "https://two-unset.example.com", "headers": {"X-One": "${A}", "X-Two": "${MISSING}"}},
                "client": {"url": "https://client.example.com", "headers": {"Authorization": "Bearer ${C}", "X-Client": "claude"}},
                "labelled": {"url": "https://labelled.example.com", "headers": {"X-Request-Source": "claude"}},
                "pasted-key": {"url": "https://pasted-key.example.com", "headers": {"X-Api-Key": "abc123"}},
                "cookie": {"url": "https://cookie.example.com", "headers": {"Cookie": "session=1"}},
                "two": {"url": "https://two.example.com", "headers": {"X-One": "${A}", "X-Two": "${B}"}},
                "unset": {"url": "https://unset.example.com", "headers": {"X-Key": "${MISSING}"}},
                "twice": {"url": "https://twice.example.com", "headers": {"Authorization": "Bearer ${A}", "X-Key": "${A}"}},
                "added": {"url": "https://added.example.com", "headers": {"Authorization": "Bearer ${B}"}},
                "local": {"command": "tool", "headers": {"X-Key": "${A}"}},
                "local-suffixed": {"command": "tool", "headers": {"X-Key": "${A}-x"}},
                "aws": {"command": "aws-tool", "headers": {}},
                "plain": {"command": "plain-tool", "headers": {"X-Client": "claude"}},
                "keyed-env": {"command": "tool", "env": {"A": "${A}"}}
            }}"#,
        );
        let mut mcp: toml::Table =
            toml::from_str("[added]\nsecret.ref = \"env://B\"").expect("TOML");
        let servers = host.detect(
            &[with_roles(
                row(&file, &["s"]),
                &[("headers", "header-references")],
            )],
            &mut mcp,
        );
        let unplain = |header: &str| {
            format!(
                "sets its headers header {header} to text before its variable that holds a \
                 character other than a letter, a digit, a space, `-`, `_`, `.`, or `:`"
            )
        };
        let other = |header: &str| {
            format!(
                "sets its headers header {header} to a value that does not end in one variable \
                 written `${{NAME}}`; box takes a key only from your variable"
            )
        };
        assert_eq!(
            servers
                .skipped
                .iter()
                .map(|skip| (skip.name.as_str(), skip.reason.clone()))
                .collect::<Vec<_>>(),
            vec![
                ("braced", unplain("X-Key")),
                ("local", "uses headers".to_string()),
                ("local-suffixed", "uses headers".to_string()),
                ("query-fragment", VARIABLE_IN_URL.to_string()),
                (
                    "query-header",
                    "sends A in more than one place, such as the header X-Key, and the box \
                     attaches one key to a remote server"
                        .to_string()
                ),
                (
                    "query-header-two",
                    "takes keys from B and A, and the box attaches one key to a remote server"
                        .to_string()
                ),
                ("query-host", VARIABLE_IN_URL.to_string()),
                ("query-mixed", VARIABLE_IN_URL.to_string()),
                ("query-param", VARIABLE_IN_URL.to_string()),
                ("query-path", VARIABLE_IN_URL.to_string()),
                (
                    "query-twice",
                    "sends A in more than one place, such as the url's k, and the box attaches \
                     one key to a remote server"
                        .to_string()
                ),
                ("suffixed", other("X-Key")),
                ("tabbed", unplain("Authorization")),
                (
                    "twice",
                    "sends A in more than one place, such as the header Authorization, and the \
                     box attaches one key to a remote server"
                        .to_string()
                ),
                (
                    "two",
                    "takes keys from A and B, and the box attaches one key to a remote server"
                        .to_string()
                ),
                (
                    "two-unset",
                    "takes keys from A and MISSING, and the box attaches one key to a remote \
                     server"
                        .to_string()
                ),
                (
                    "unset",
                    "needs MISSING, which is not set in your environment".to_string()
                ),
            ]
        );
        let workspace = host.workspace().display().to_string();
        let expected: toml::Table = toml::from_str(&format!(
            r#"
            [added]
            type = "http"
            destinations = ["added.example.com"]
            secret.ref = "env://B"
            secret.header = "Authorization"
            secret.prefix = "Bearer "

            [aws]
            type = "stdio"
            command = ["aws-tool"]
            filesystem.read = [{workspace:?}, {bin:?}]
            filesystem.read_file = [{shell:?}]
            filesystem.write = [{workspace:?}]

            [bearer]
            type = "http"
            destinations = ["bearer.example.com"]
            secret.ref = "env://TOKEN"
            secret.header = "Authorization"
            secret.prefix = "Bearer "

            [client]
            type = "http"
            destinations = ["client.example.com"]
            secret.ref = "env://C"
            secret.header = "Authorization"
            secret.prefix = "Bearer "

            [cookie]
            type = "http"
            destinations = ["cookie.example.com"]

            [defaulted]
            type = "http"
            destinations = ["defaulted.example.com"]
            secret.ref = "env://DEFAULTED"
            secret.header = "X-Key"
            secret.prefix = ""

            [keyed]
            type = "http"
            destinations = ["keyed.example.com"]
            secret.ref = "env://API_KEY"
            secret.header = "X-Api-Key"
            secret.prefix = ""

            [keyed-env]
            type = "stdio"
            command = ["tool"]
            env.A = "${{A}}"
            filesystem.read = [{workspace:?}, {bin:?}]
            filesystem.read_file = [{shell:?}]
            filesystem.write = [{workspace:?}]

            [labelled]
            type = "http"
            destinations = ["labelled.example.com"]

            [pasted]
            type = "http"
            destinations = ["pasted.example.com"]

            [pasted-key]
            type = "http"
            destinations = ["pasted-key.example.com"]

            [plain]
            type = "stdio"
            command = ["plain-tool"]
            filesystem.read = [{workspace:?}, {bin:?}]
            filesystem.read_file = [{shell:?}]
            filesystem.write = [{workspace:?}]

            [prefixed]
            type = "http"
            destinations = ["prefixed.example.com"]
            secret.ref = "env://M"
            secret.header = "X-Key"
            secret.prefix = "key-"

            [query]
            type = "http"
            destinations = ["query.example.com"]
            secret.ref = "env://QK"
            secret.placement = "query_param"
            secret.param = "api_key"
            "#,
            shell = crate::fixtures::shell(),
            bin = host.root.join("bin").display().to_string(),
        ))
        .expect("TOML");
        assert_eq!(mcp, expected);
        let line = |server: &str, variables: &[&str]| {
            (
                server.to_string(),
                "~/.claude.json".to_string(),
                if variables.is_empty() {
                    String::new()
                } else {
                    format!(", with the key in {}", variables.join(", "))
                },
            )
        };
        assert_eq!(
            servers.detected_lines(&host.home()),
            vec![
                line("added", &["B"]),
                line("aws", &[]),
                line("bearer", &["TOKEN"]),
                line("client", &["C"]),
                line("cookie", &[]),
                line("defaulted", &["DEFAULTED"]),
                line("keyed", &["API_KEY"]),
                (
                    "keyed-env".to_string(),
                    "~/.claude.json".to_string(),
                    ", with A".to_string()
                ),
                line("labelled", &[]),
                line("pasted", &[]),
                line("pasted-key", &[]),
                line("plain", &[]),
                line("prefixed", &["M"]),
                line("query", &["QK"]),
            ]
        );
    }

    #[test]
    fn plain_header_names_do_not_skip_local_or_remote_servers() {
        for header in ["X_Client", "X.Trace"] {
            let host = Host::new();
            host.program("bin/tool", "/bin/sh");
            let file = host.file(
                ".claude.json",
                &serde_json::json!({"s": {
                    "local": {"command": "tool", "headers": {header: "claude"}},
                    "remote": {"url": "https://remote.example.com", "headers": {header: "claude"}}
                }})
                .to_string(),
            );
            let mut mcp = toml::Table::new();
            let servers = host.detect(
                &[with_roles(
                    row(&file, &["s"]),
                    &[("headers", "header-references")],
                )],
                &mut mcp,
            );
            assert_eq!(reasons(&servers), Vec::<(&str, &str)>::new(), "{header}");
            let workspace = host.workspace().display().to_string();
            let expected: toml::Table = toml::from_str(&format!(
                r#"
                [local]
                type = "stdio"
                command = ["tool"]
                filesystem.read = [{workspace:?}, {bin:?}]
                filesystem.read_file = [{shell:?}]
                filesystem.write = [{workspace:?}]

                [remote]
                type = "http"
                destinations = ["remote.example.com"]
                "#,
                shell = crate::fixtures::shell(),
                bin = host.root.join("bin").display().to_string(),
            ))
            .expect("TOML");
            assert_eq!(mcp, expected, "{header}");
            assert_eq!(
                servers.detected_lines(&host.home()),
                vec![
                    (
                        "local".to_string(),
                        "~/.claude.json".to_string(),
                        String::new()
                    ),
                    (
                        "remote".to_string(),
                        "~/.claude.json".to_string(),
                        String::new()
                    ),
                ],
                "{header}",
            );
        }
    }

    #[test]
    fn a_variable_header_still_needs_a_name_box_core_accepts() {
        for (role, value) in [
            ("header-references", "${TOKEN}"),
            ("header-variables", "TOKEN"),
        ] {
            for header in ["X_Client", "X.Trace", "X Key", ""] {
                let mut host = Host::new();
                host.set = vec![("TOKEN", "a-key")];
                let file = host.file(
                    ".agent.json",
                    &serde_json::json!({"s": {
                        "remote": {"url": "https://remote.example.com", "headers": {header: value}}
                    }})
                    .to_string(),
                );
                let mut mcp = toml::Table::new();
                let servers = host.detect(
                    &[with_roles(row(&file, &["s"]), &[("headers", role)])],
                    &mut mcp,
                );
                let reason = format!("its headers header {header:?} is not a header name");
                assert_eq!(
                    reasons(&servers),
                    vec![("remote", reason.as_str())],
                    "{role} {header}"
                );
                assert_eq!(mcp, toml::Table::new());
                assert_eq!(servers.detected_lines(&host.home()), Vec::new());
            }
        }
    }

    #[test]
    fn a_row_with_two_forms_reads_each_once_and_skips_what_it_cannot_read() {
        let mut host = Host::new();
        host.program("bin/tool", "/bin/sh");
        host.set = vec![
            ("TOKEN", "a-key"),
            ("BARE", "c-key"),
            ("NESTED", "$TOKEN"),
            ("OTHER", "b"),
        ];
        let file = host.file(
            ".pi.json",
            r#"{"s": {
                "braced": {"url": "https://braced.example.com", "headers": {"Authorization": "Bearer ${TOKEN}"}},
                "bare": {"url": "https://bare.example.com", "headers": {"Authorization": "Bearer $BARE"}},
                "priced": {"url": "https://priced.example.com", "headers": {"X-Note": "costs $5"}},
                "local": {"command": "tool", "env": {"A": "$TOKEN-${OTHER}", "B": "${NESTED}", "C": "x$"}},
                "command": {"command": "tool", "env": {"A": "!gh auth token"}},
                "escaped": {"command": "tool", "env": {"A": "$$TOKEN"}},
                "defaulted": {"command": "tool", "env": {"A": "$MISSING:-fallback"}},
                "banged": {"url": "https://banged.example.com", "headers": {"X-Key": "a$!b"}},
                "odata": {"url": "https://odata.example.com/mcp?$filter=x"},
                "azure": {"url": "https://acct.example.com/$web/mcp"},
                "pinned": {"command": "tool", "args": ["--db", "$HOME/data.db"]}
            }}"#,
        );
        let mut source = with_roles(
            row(&file, &["s"]),
            &[("env", "references"), ("headers", "header-references")],
        );
        source.env_var_syntax = Some(
            Syntax::new(&["$NAME".into(), "${NAME}".into()], Some("!".into())).expect("a syntax"),
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[source], &mut mcp);
        assert_eq!(
            reasons(&servers),
            vec![
                (
                    "banged",
                    "has a value in its headers that writes `$!`, an escape that box does not read"
                ),
                (
                    "command",
                    "has a value in its env that starts with `!`, so the agent runs it as a \
                     command, which box does not do"
                ),
                (
                    "defaulted",
                    "it needs MISSING, which isn't set where you ran box"
                ),
                (
                    "escaped",
                    "has a value in its env that writes `$$`, an escape that box does not read"
                ),
            ]
        );
        for (server, variable) in [("braced", "env://TOKEN"), ("bare", "env://BARE")] {
            assert_eq!(
                mcp[server]["secret"]["ref"].as_str(),
                Some(variable),
                "{server}"
            );
            assert_eq!(mcp[server]["secret"]["prefix"].as_str(), Some("Bearer "));
        }
        assert!(mcp["priced"].get("secret").is_none(), "{:?}", mcp["priced"]);
        assert_eq!(
            mcp["pinned"]["command"],
            toml::Value::from(vec!["tool", "--db", "$HOME/data.db"]),
            "an argument without `references` keeps a bare `$` as text"
        );
        assert!(mcp["pinned"].get("argument_wildcards").is_none());
        for server in ["odata", "azure"] {
            assert!(
                mcp.get(server)
                    .is_some_and(|table| table.get("secret").is_none()),
                "a $ in a URL is text, because pi fills in no url: {server}"
            );
        }
        let env = &mcp["local"]["env"];
        assert_eq!(env["A"].as_str(), Some("a-key-b"));
        assert_eq!(
            env["B"].as_str(),
            Some("$TOKEN"),
            "a value is filled in once, not read again"
        );
        assert_eq!(env["C"].as_str(), Some("x$"));
    }

    #[test]
    fn the_form_with_the_longest_opening_is_read_first_whatever_the_row_lists() {
        let mut host = Host::new();
        host.program("bin/tool", "/bin/sh");
        host.set = vec![("TOKEN", "a-key")];
        let file = host.file(
            ".agent.json",
            r#"{"s": {"local": {"command": "tool", "env": {"A": "{env:TOKEN}"}}}}"#,
        );
        let mut source = with_roles(row(&file, &["s"]), &[("env", "references")]);
        source.env_var_syntax =
            Some(Syntax::new(&["{NAME".into(), "{env:NAME}".into()], None).expect("a syntax"));
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[source], &mut mcp);
        assert!(servers.skipped.is_empty(), "{:?}", reasons(&servers));
        assert_eq!(mcp["local"]["env"]["A"].as_str(), Some("a-key"));
    }

    #[test]
    fn a_header_follows_the_env_var_syntax_its_row_names() {
        let mut host = Host::new();
        host.set = vec![("TOKEN", "a-key")];
        let file = host.file(
            ".opencode.json",
            r#"{"s": {
                "braced": {"url": "https://braced.example.com", "headers": {"Authorization": "Bearer {env:TOKEN}"}},
                "dollar": {"url": "https://dollar.example.com", "headers": {"Authorization": "Bearer ${TOKEN}"}}
            }}"#,
        );
        let mut source = row(&file, &["s"]);
        source
            .env_var_locations
            .insert("headers".into(), Role::HeaderReferences);
        source.env_var_syntax = Some(Syntax::one("{env:NAME}"));
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[source], &mut mcp);
        assert_eq!(
            reasons(&servers),
            vec![(
                "dollar",
                "sets its headers header Authorization to a value that does not end in one \
                 variable written `{env:NAME}`; box takes a key only from your variable"
            )]
        );
        assert_eq!(mcp["braced"]["secret"]["ref"].as_str(), Some("env://TOKEN"));
    }

    #[test]
    fn a_remote_server_with_one_variable_gets_its_key() {
        let mut host = Host::new();
        host.set = vec![
            ("API_TOKEN", "a-key"),
            ("H_KEY", "a-key"),
            ("MODEL_KEY", "a-key"),
            ("A", "a-key"),
            ("B", "a-key"),
            ("BLANK", "  "),
            ("HOME", "/home/you"),
            ("PYTHONANYWHERE_TOKEN", "a-key"),
        ];
        host.egress = toml::from_str(
            "[model]\ndestinations = [\"model.example.com\"]\nsecret.ref = \"env://MODEL_KEY\"",
        )
        .expect("TOML");
        host.program("bin/tool", "/bin/sh");
        host.program("bin/unkeyed-tool", "/bin/sh");
        host.program("bin/literal-tool", "/bin/sh");
        let file = host.file(
            ".codex/config.toml",
            r#"
            [mcp_servers.bearer]
            url = "https://api.example.com/mcp"
            bearer_token_env_var = "API_TOKEN"

            [mcp_servers.header]
            url = "https://h.example.com"
            env_http_headers = { "X-Api-Key" = "H_KEY" }

            [mcp_servers.two]
            url = "https://two.example.com"
            bearer_token_env_var = "A"
            env_http_headers = { "X-Other" = "B" }

            [mcp_servers.model]
            url = "https://other.example.com"
            bearer_token_env_var = "MODEL_KEY"

            [mcp_servers.local]
            command = "tool"
            env_vars = ["H_KEY"]

            [mcp_servers.misplaced]
            command = "tool"
            bearer_token_env_var = "API_TOKEN"

            [mcp_servers.unkeyed]
            command = "unkeyed-tool"
            env_http_headers = {}

            [mcp_servers.literal]
            command = "literal-tool"
            env = { LOG_LEVEL = "debug" }

            [mcp_servers.badname]
            url = "https://bad.example.com"
            bearer_token_env_var = "not a name"

            [mcp_servers.blank]
            url = "https://blank.example.com"
            bearer_token_env_var = "BLANK"

            [mcp_servers.home]
            url = "https://home.example.com"
            bearer_token_env_var = "HOME"

            [mcp_servers.python]
            url = "https://python.example.com"
            bearer_token_env_var = "PYTHONANYWHERE_TOKEN"

            [mcp_servers.second]
            url = "https://second.example.com"
            bearer_token_env_var = "API_TOKEN"

            [mcp_servers.badheader]
            url = "https://badheader.example.com"
            env_http_headers = { "X Key" = "H_KEY" }
            "#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(
            &[with_roles(
                row(&file, &["mcp_servers"]),
                &[
                    ("bearer_token_env_var", "bearer-variable"),
                    ("env_http_headers", "header-variables"),
                ],
            )],
            &mut mcp,
        );
        assert_eq!(
            reasons(&servers),
            vec![
                (
                    "badheader",
                    "its env_http_headers header \"X Key\" is not a header name"
                ),
                (
                    "badname",
                    "its bearer_token_env_var \"not a name\" is not a variable name"
                ),
                ("blank", "needs BLANK, which is not set in your environment"),
                ("home", "takes a key from HOME, which the box sets itself"),
                ("misplaced", "uses bearer_token_env_var"),
                (
                    "model",
                    "takes its key from MODEL_KEY, which the route model sends to its own hosts"
                ),
                (
                    "python",
                    "takes a key from PYTHONANYWHERE_TOKEN, which the box sets itself"
                ),
                (
                    "second",
                    "takes its key from API_TOKEN, which the server bearer takes too; the box \
                     gives each key to one remote server"
                ),
                (
                    "two",
                    "takes keys from A and B, and the box attaches one key to a remote server"
                ),
            ]
        );
        let workspace = host.workspace().display().to_string();
        let expected: toml::Table = toml::from_str(&format!(
            r#"
            [bearer]
            type = "http"
            destinations = ["api.example.com"]
            secret.ref = "env://API_TOKEN"

            [header]
            type = "http"
            destinations = ["h.example.com"]
            secret.ref = "env://H_KEY"
            secret.header = "X-Api-Key"
            secret.prefix = ""

            [literal]
            type = "stdio"
            command = ["literal-tool"]
            env.LOG_LEVEL = "debug"
            filesystem.read = [{workspace:?}, {bin:?}]
            filesystem.read_file = [{shell:?}]
            filesystem.write = [{workspace:?}]

            [local]
            type = "stdio"
            command = ["tool"]
            filesystem.read = [{workspace:?}, {bin:?}]
            filesystem.read_file = [{shell:?}]
            filesystem.write = [{workspace:?}]

            [unkeyed]
            type = "stdio"
            command = ["unkeyed-tool"]
            filesystem.read = [{workspace:?}, {bin:?}]
            filesystem.read_file = [{shell:?}]
            filesystem.write = [{workspace:?}]
            "#,
            shell = crate::fixtures::shell(),
            bin = host.root.join("bin").display().to_string(),
        ))
        .expect("TOML");
        assert_eq!(
            mcp, expected,
            "a stdio server with env_vars comes in, and env_vars stays in the agent's own \
             configuration"
        );
    }

    #[test]
    fn a_key_the_agent_env_sets_or_a_profile_secret_on_a_detected_server_is_skipped() {
        let mut host = Host::new();
        host.set = vec![
            ("AGENT_KEY", "a-key"),
            ("DOCS_KEY", "a-key"),
            ("OWN", "a-key"),
        ];
        host.agent_env = BTreeMap::from([("AGENT_KEY".to_string(), "x".to_string())]);
        host.program("bin/tool", "/bin/sh");
        let file = host.file(
            ".claude.json",
            r#"{"s": {
                "agent": {"url": "https://agent.example.com", "headers": {"X-Key": "${AGENT_KEY}"}},
                "docs": {"url": "https://docs.example.com", "headers": {"X-Key": "${DOCS_KEY}"}},
                "plain": {"url": "https://plain.example.com"},
                "same": {"url": "https://same.example.com", "headers": {"X-Key": "${OWN}"}},
                "local": {"command": "tool"}
            }}"#,
        );
        let mut mcp: toml::Table = toml::from_str(
            "[docs]\nsecret.ref = \"env://OTHER\"\n[plain]\nsecret.ref = \"env://OWN\"\n\
             [same]\nsecret = { ref = \"env://OWN\", header = \"X-Key\", prefix = \"\" }\n\
             [local]\nsecret.ref = \"env://OWN\"",
        )
        .expect("TOML");
        let servers = host.detect(
            &[with_roles(
                row(&file, &["s"]),
                &[("headers", "header-references")],
            )],
            &mut mcp,
        );
        let untyped = |name: &str| {
            format!(
                "the profile's `[mcp.{name}]` sets `secret` without a `type`, and the box gives \
                 a key only to a server the profile declares; to give this server a key, \
                 declare it with a `type` and its own `destinations`"
            )
        };
        assert_eq!(
            servers
                .skipped
                .iter()
                .map(|skip| (skip.name.clone(), skip.reason.clone()))
                .collect::<Vec<_>>(),
            vec![
                (
                    "agent".to_string(),
                    "takes its key from AGENT_KEY, which your profile sets in `[agent.env]`, so \
                     the agent holds that value and not a stand-in"
                        .to_string()
                ),
                ("docs".to_string(), untyped("docs")),
                ("local".to_string(), untyped("local")),
                ("plain".to_string(), untyped("plain")),
            ]
        );
        assert_eq!(
            mcp.keys().map(String::as_str).collect::<Vec<_>>(),
            ["same"],
            "no profile key reaches a detected server, and one that restates its own key merges"
        );
        assert_eq!(mcp["same"]["secret"]["ref"].as_str(), Some("env://OWN"));
    }

    /// The credentials of a profile that lists `@box/1password`, and declares a source of its own
    /// that passes each `OP_SESSION_` variable, which only a source of the profile can.
    fn vault_credentials() -> Credentials {
        Credentials::of(
            &toml::from_str(
                "[secret-source.op]\ncommand = [\"/usr/local/bin/op\", \"read\", \"op://{ref}\"]\n\
                 pass-env = [\"OP_ACCOUNT\"]\n\
                 pass-secret-env = [\"OP_SERVICE_ACCOUNT_TOKEN\", \"OP_CONNECT_TOKEN\"]\n\
                 [secret-source.session]\ncommand = [\"/usr/local/bin/op\", \"read\", \"op://{ref}\"]\n\
                 pass-secret-env = [\"OP_SESSION_*\"]",
            )
            .expect("TOML"),
            &BTreeMap::from([("op".to_string(), "@box/1password".to_string())]),
        )
    }

    /// How a message names the source of `vault_credentials` that passes `variable`.
    fn vault_source(variable: &str) -> &'static str {
        if variable.starts_with("OP_SESSION_") {
            "`[secret-source.session]` of the profile"
        } else {
            "the plugin @box/1password"
        }
    }

    #[test]
    fn a_server_that_reads_a_variable_that_a_secret_source_passes_is_skipped() {
        let mut host = Host::new();
        host.set = vec![
            ("OP_SERVICE_ACCOUNT_TOKEN", "ops_real"),
            ("OP_SESSION_my", "session_real"),
            ("OP_ACCOUNT", "my.1password.com"),
            ("MY_OP", "ops_real"),
            ("OP_CONNECT_TOKEN", ""),
        ];
        host.credentials = vault_credentials();
        host.program("bin/tool", "/bin/sh");
        let claude = host.file(
            ".claude.json",
            r#"{"s": {
                "env": {"command": "tool", "env": {"T": "${OP_SERVICE_ACCOUNT_TOKEN}"}},
                "args": {"command": "tool", "args": ["--session", "${OP_SESSION_my}"]},
                "command": {"command": "${OP_SESSION_my:-/usr/local}/bin/tool"},
                "account": {"command": "tool", "env": {"A": "${OP_ACCOUNT}"}},
                "pasted": {"command": "tool", "args": ["--pasted"], "env": {"OP_SERVICE_ACCOUNT_TOKEN": "Bearer ops_real"}},
                "alias": {"command": "tool", "args": ["--alias"], "env": {"T": "${MY_OP}"}},
                "session": {"command": "tool", "args": ["--session"], "env": {"S": "session_real"}},
                "named-session": {"command": "tool", "args": ["--named-session"], "env": {"OP_SESSION_my": "session_pasted"}},
                "named-token": {"command": "tool", "args": ["--named-token"], "env": {"OP_CONNECT_TOKEN": "connect_pasted"}},
                "off": {"command": "tool", "args": ["--off"], "enabled": false, "env": {"T": "ops_real"}},
                "arg-pasted": {"command": "tool", "args": ["--token", "ops_real"]},
                "arg-session": {"command": "tool", "args": ["--session=session_real", "--arg-session"]},
                "arg-mixed": {"command": "tool", "args": ["--arg-mixed", "--as", "ops_real:${OP_ACCOUNT}"], "env": {"LEVEL": "info"}},
                "arg-off": {"command": "tool", "args": ["--arg-off", "Bearer ops_real"], "enabled": false},
                "arg-plain": {"command": "tool", "args": ["--arg-plain", "", "ops_other"]},
                "remote": {"url": "https://vault.example.com", "headers": {"X-Key": "${OP_SERVICE_ACCOUNT_TOKEN}"}}
            }}"#,
        );
        let codex = host.file(
            ".codex/config.toml",
            r#"
            [mcp_servers.passed]
            command = "tool"
            env_vars = [{ name = "OP_SESSION_my", source = "local" }]

            [mcp_servers.literal]
            command = "tool"
            args = ["--literal"]
            env = { T = "${OP_SERVICE_ACCOUNT_TOKEN}" }

            [mcp_servers.bearer]
            url = "https://bearer.example.com"
            bearer_token_env_var = "OP_SERVICE_ACCOUNT_TOKEN"
            "#,
        );
        let mut codex_row = with_roles(
            row(&codex, &["mcp_servers"]),
            &[
                ("bearer_token_env_var", "bearer-variable"),
                ("env_vars", "variable-names"),
            ],
        );
        codex_row.env_var_syntax = None;
        let mut claude_row = with_roles(
            row(&claude, &["s"]),
            &[
                ("command", "references"),
                ("args", "references"),
                ("env", "references"),
                ("headers", "header-references"),
            ],
        );
        claude_row.target = Some(Target {
            path: host.home().join(".strands/box/storage/claude.json"),
            kind: Format::Json,
            key: vec!["s".into()],
        });
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[claude_row, codex_row], &mut mcp);
        let stdio = |variable: &str| {
            format!(
                "reads {variable}, which {} passes to its program as a credential, so no server \
                 in the box gets its value",
                vault_source(variable)
            )
        };
        let remote = "takes its key from OP_SERVICE_ACCOUNT_TOKEN, which the plugin \
                      @box/1password passes to its program as a credential, so the box sends its \
                      value to no host";
        let session = stdio("OP_SESSION_my");
        let token = stdio("OP_SERVICE_ACCOUNT_TOKEN");
        let held = |name: &str, variable: &str| {
            format!(
                "its env {name} holds the value of {variable}, which {} passes to its program \
                 as a credential, so no server in the box gets its value",
                vault_source(variable)
            )
        };
        let (alias, pasted) = (
            held("T", "OP_SERVICE_ACCOUNT_TOKEN"),
            held("OP_SERVICE_ACCOUNT_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN"),
        );
        let session_value = held("S", "OP_SESSION_my");
        let sets = |name: &str| {
            format!(
                "its env sets {name}, which {} passes to its program as a credential, so no \
                 server in the box gets its value",
                vault_source(name)
            )
        };
        let (named_session, named_token) = (sets("OP_SESSION_my"), sets("OP_CONNECT_TOKEN"));
        let argument = |place: usize, variable: &str| {
            format!(
                "its argument {place} holds the value of {variable}, which {} passes to its \
                 program as a credential, so no server in the box gets its value",
                vault_source(variable)
            )
        };
        let (arg_mixed, arg_pasted, arg_session) = (
            argument(3, "OP_SERVICE_ACCOUNT_TOKEN"),
            argument(2, "OP_SERVICE_ACCOUNT_TOKEN"),
            argument(1, "OP_SESSION_my"),
        );
        // A row that another rule skips keeps the words of that rule, and names no credential.
        let other = |name: &str| {
            let (_, reason) = reasons(&servers)
                .into_iter()
                .find(|(row, _)| *row == name)
                .expect("a skipped row");
            assert!(!reason.contains("credential"), "{name}: {reason}");
            reason
        };
        assert_eq!(
            reasons(&servers),
            vec![
                ("alias", alias.as_str()),
                ("arg-mixed", arg_mixed.as_str()),
                ("arg-off", other("arg-off")),
                ("arg-pasted", arg_pasted.as_str()),
                ("arg-session", arg_session.as_str()),
                ("args", session.as_str()),
                ("bearer", remote),
                ("command", session.as_str()),
                ("env", token.as_str()),
                ("named-session", named_session.as_str()),
                ("named-token", named_token.as_str()),
                ("off", other("off")),
                ("passed", session.as_str()),
                ("pasted", pasted.as_str()),
                ("remote", remote),
                ("session", session_value.as_str()),
            ]
        );
        assert_eq!(
            (mcp["account"]["env"].clone(), mcp["literal"]["env"].clone(),),
            (
                toml::from_str::<toml::Value>("A = \"my.1password.com\"").expect("TOML"),
                toml::from_str::<toml::Value>("T = \"${OP_SERVICE_ACCOUNT_TOKEN}\"").expect("TOML"),
            ),
            "a `pass-env` name is a plain setting, a field that the harness does not expand reads \
             no variable, and a blank value matches nothing"
        );
        assert_eq!(
            mcp["arg-plain"]["command"]
                .as_array()
                .map(|command| command[1..].to_vec()),
            Some(vec![
                toml::Value::from("--arg-plain"),
                toml::Value::from(""),
                toml::Value::from("ops_other"),
            ]),
            "the blank value of `OP_CONNECT_TOKEN` matches no argument, and another key in an \
             argument comes in as written"
        );
        let imported = &servers.configs[0].servers;
        assert_eq!(
            [
                "pasted",
                "off",
                "alias",
                "named-session",
                "named-token",
                "session",
                "arg-pasted",
                "arg-session",
                "arg-mixed",
                "arg-off",
                "arg-plain"
            ]
            .map(|name| imported[name].clone()),
            [
                serde_json::json!({"command": "tool", "args": ["--pasted"]}),
                serde_json::json!({"command": "tool", "args": ["--off"], "enabled": false}),
                serde_json::json!({"command": "tool", "args": ["--alias"], "env": {"T": "${MY_OP}"}}),
                serde_json::json!({"command": "tool", "args": ["--named-session"]}),
                serde_json::json!({"command": "tool", "args": ["--named-token"]}),
                serde_json::json!({"command": "tool", "args": ["--session"]}),
                serde_json::json!({"command": "tool"}),
                serde_json::json!({"command": "tool"}),
                serde_json::json!({"command": "tool", "env": {"LEVEL": "info"}}),
                serde_json::json!({"command": "tool", "enabled": false}),
                serde_json::json!({"command": "tool", "args": ["--arg-plain", "", "ops_other"]}),
            ],
            "the agent's copy of a server that writes the value of a credential keeps no `env`, \
             and of one that writes it in an argument no `args`, whatever skips it, and a \
             reference to another variable stays"
        );
    }

    #[test]
    fn a_local_server_that_reads_the_stand_in_of_a_key_from_a_secret_source_is_skipped() {
        let mut host = Host::new();
        host.set = vec![("GH_TOKEN", "stale_host_token"), ("MODEL_KEY", "model-key")];
        host.egress = toml::from_str(
            "[github]\ndestinations = [\"api.github.com\"]\n\
             secret.ref = \"op://Private/GitHub/token\"\nsecret.env = \"GH_TOKEN\"\n\
             [model]\ndestinations = [\"model.example.com\"]\n\
             secret.ref = \"env://MODEL_KEY\"\nsecret.env = \"MODEL_KEY\"",
        )
        .expect("TOML");
        host.program("bin/tool", "/bin/sh");
        let file = host.file(
            ".claude.json",
            r#"{"s": {
                "github": {"command": "tool", "args": ["--github"], "env": {"T": "${GH_TOKEN}"}},
                "github-args": {"command": "tool", "args": ["--token", "${GH_TOKEN}"]},
                "docs-local": {"command": "tool", "args": ["--docs"], "env": {"T": "${DOCS_KEY}"}},
                "model-local": {"command": "tool", "args": ["--model"], "env": {"T": "${MODEL_KEY}"}}
            }}"#,
        );
        let mut mcp: toml::Table = toml::from_str(
            "[docs]\ntype = \"http\"\ndestinations = [\"docs.example.com\"]\n\
             secret.ref = \"aws-secretsmanager://docs#KEY\"\nsecret.env = \"DOCS_KEY\"",
        )
        .expect("TOML");
        let servers = host.detect(
            &[with_roles(
                row(&file, &["s"]),
                &[("args", "references"), ("env", "references")],
            )],
            &mut mcp,
        );
        assert_eq!(
            reasons(&servers),
            vec![
                (
                    "docs-local",
                    "reads DOCS_KEY, which the server docs names in `secret.env` for its \
                     aws-secretsmanager:// key, and the host's value of DOCS_KEY is not that key"
                ),
                (
                    "github",
                    "reads GH_TOKEN, which the route github names in `secret.env` for its op:// \
                     key, and the host's value of GH_TOKEN is not that key"
                ),
            ]
        );
        assert_eq!(
            (
                mcp["model-local"]["env"].clone(),
                mcp["github-args"]["command"].clone()
            ),
            (
                toml::from_str::<toml::Value>("T = \"model-key\"").expect("TOML"),
                toml::Value::from(vec!["tool", "--token", "*"]),
            ),
            "a local server that reads a route's own `env://` variable gets its key, as before, \
             and a stand-in variable in `args` stays for the harness to fill in"
        );
    }

    /// **A declared server's entry that holds a vault credential keeps no `env`**, whether the
    /// profile's declaration matches it or not. A match also gets the bare filename, and the note
    /// that the environment stays goes only on an entry that keeps its environment.
    #[test]
    fn a_declared_entry_that_holds_a_vault_credential_keeps_no_environment() {
        let mut host = Host::new();
        host.set = vec![("OP_SERVICE_ACCOUNT_TOKEN", "ops_real")];
        host.credentials = vault_credentials();
        host.program("bin/tool", "/bin/sh");
        let file = host.file(
            ".claude.json",
            r#"{"s": {
                "named": {"command": "/opt/tool/bin/tool", "args": ["--named"], "env": {"OP_SERVICE_ACCOUNT_TOKEN": "ops_pasted"}},
                "pasted": {"command": "/opt/tool/bin/tool", "args": ["--pasted"], "env": {"T": "ops_real"}},
                "unmatched": {"command": "/opt/tool/bin/tool", "args": ["--other"], "env": {"T": "ops_real"}},
                "plain": {"command": "/opt/tool/bin/tool", "args": ["--other"], "env": {"T": "plain-key"}}
            }}"#,
        );
        let mut source = with_roles(row(&file, &["s"]), &[("env", "references")]);
        source.target = Some(Target {
            path: host.home().join(".strands/box/storage/claude.json"),
            kind: Format::Json,
            key: vec!["s".into()],
        });
        let mut mcp: toml::Table = toml::from_str(
            "[named]\ntype = \"stdio\"\ncommand = [\"/opt/tool/bin/tool\", \"--named\"]\n\
             [pasted]\ntype = \"stdio\"\ncommand = [\"tool\", \"--pasted\"]\n\
             [unmatched]\ntype = \"stdio\"\ncommand = [\"tool\", \"--unmatched\"]\n\
             [plain]\ntype = \"stdio\"\ncommand = [\"tool\", \"--plain\"]",
        )
        .expect("TOML");
        let declared = mcp.clone();
        let servers = host.detect(&[source], &mut mcp);
        let vault = |how: &str| {
            format!(
                "its env {how}, which the plugin @box/1password passes to its \
                 program as a credential, so no server in the box gets its value"
            )
        };
        let named = vault("sets OP_SERVICE_ACCOUNT_TOKEN");
        let held = vault("T holds the value of OP_SERVICE_ACCOUNT_TOKEN");
        let plain = reasons(&servers)
            .into_iter()
            .find(|(row, _)| *row == "plain")
            .expect("the plain row")
            .1
            .to_string();
        assert!(
            plain.ends_with(&env_stays("plain")) && !plain.contains("credential"),
            "an entry with another key keeps it, and its skip line says so: {plain}"
        );
        assert_eq!(
            reasons(&servers),
            vec![
                ("named", named.as_str()),
                ("pasted", held.as_str()),
                ("plain", plain.as_str()),
                ("unmatched", held.as_str()),
            ]
        );
        assert_eq!(
            serde_json::Value::Object(servers.configs[0].servers.clone()),
            serde_json::json!({
                "named": {"command": "tool", "args": ["--named"]},
                "pasted": {"command": "tool", "args": ["--pasted"]},
                "unmatched": {"command": "/opt/tool/bin/tool", "args": ["--other"]},
                "plain": {"command": "/opt/tool/bin/tool", "args": ["--other"], "env": {"T": "plain-key"}}
            }),
            "a match gets the bare filename and no env; an entry that holds a vault credential \
             keeps no env whether a declaration matches it or not; an entry with another key keeps \
             it, and its skip line says so"
        );
        assert_eq!(
            mcp, declared,
            "box.toml holds only the profile's own declarations"
        );
    }

    /// **An untyped profile table gives a detected server with no key no vault key either**: the
    /// server is skipped, as for an `env://` key, and its table leaves the profile's servers.
    #[test]
    fn an_untyped_table_with_a_vault_key_on_a_detected_server_with_none_is_skipped() {
        let mut host = Host::new();
        host.credentials = vault_credentials();
        host.egress = toml::from_str(
            "[github]\ndestinations = [\"api.github.com\"]\n\
             secret.ref = \"op://Private/GitHub/token\"\nsecret.env = \"GH_TOKEN\"",
        )
        .expect("TOML");
        let file = host.file(
            ".claude.json",
            r#"{"s": {
                "docs": {"url": "https://docs.example.com/mcp"},
                "notes": {"url": "https://notes.example.com/mcp"}
            }}"#,
        );
        let mut mcp: toml::Table = toml::from_str(
            "[docs]\nsecret.ref = \"op://Private/Docs/key\"\n\
             [notes]\nsecret = { ref = \"op://Private/Notes/key\", env = \"GH_TOKEN\" }",
        )
        .expect("TOML");
        let servers = host.detect(
            &[with_roles(
                row(&file, &["s"]),
                &[("headers", "header-references")],
            )],
            &mut mcp,
        );
        let untyped = |name: &str| {
            format!(
                "the profile's `[mcp.{name}]` sets `secret` without a `type`, and the box gives \
                 a key only to a server the profile declares; to give this server a key, \
                 declare it with a `type` and its own `destinations`"
            )
        };
        let (docs, notes) = (untyped("docs"), untyped("notes"));
        assert_eq!(
            reasons(&servers),
            vec![("docs", docs.as_str()), ("notes", notes.as_str())]
        );
        assert_eq!(
            (servers.detected.len(), mcp.len()),
            (0, 0),
            "no vault key reaches a host from the agent's settings"
        );
    }

    #[test]
    fn a_remote_key_that_a_secret_env_names_is_skipped_as_an_env_reference_is() {
        for set in [vec![], vec![("GH_TOKEN", "a-key"), ("DOCS_KEY", "a-key")]] {
            let mut host = Host::new();
            host.set = set.clone();
            host.egress = toml::from_str(
                "[github]\ndestinations = [\"api.github.com\"]\n\
                 secret.ref = \"op://Private/GitHub/token\"\nsecret.env = \"GH_TOKEN\"",
            )
            .expect("TOML");
            let file = host.file(
                ".claude.json",
                r#"{"s": {
                    "github": {"url": "https://mcp.github.example.com", "headers": {"Authorization": "Bearer ${GH_TOKEN}"}},
                    "github-fallback": {"url": "https://fallback.github.example.com", "headers": {"Authorization": "Bearer ${GH_TOKEN:-}"}},
                    "docs-copy": {"url": "https://copy.example.com", "headers": {"X-Key": "${DOCS_KEY}"}}
                }}"#,
            );
            let mut mcp: toml::Table = toml::from_str(
                "[docs]\ntype = \"http\"\ndestinations = [\"docs.example.com\"]\n\
                 secret.ref = \"op://Private/Docs/key\"\nsecret.env = \"DOCS_KEY\"",
            )
            .expect("TOML");
            let servers = host.detect(
                &[with_roles(
                    row(&file, &["s"]),
                    &[("headers", "header-references")],
                )],
                &mut mcp,
            );
            assert_eq!(
                reasons(&servers),
                vec![
                    (
                        "docs-copy",
                        "takes its key from DOCS_KEY, which the server docs takes too; the box \
                         gives each key to one remote server"
                    ),
                    (
                        "github",
                        "takes its key from GH_TOKEN, which the route github sends to its own \
                         hosts"
                    ),
                    (
                        "github-fallback",
                        "takes its key from GH_TOKEN, which the route github sends to its own \
                         hosts"
                    ),
                ],
                "the shell sets {set:?}"
            );
        }
    }

    #[test]
    fn a_server_that_a_launcher_starts_gets_its_cache_its_runtime_and_its_registry() {
        let mut host = Host::new();
        let node = host.program("nvm/v22/bin/node", "/bin/sh");
        host.link("node", &node);
        let npx = host.program(
            "nvm/v22/lib/node_modules/npm/bin/npx-cli.js",
            "/usr/bin/env node",
        );
        host.link("npx", &npx);
        host.others.push((
            "the tool npx".into(),
            host.root.join("bin/npx").display().to_string(),
        ));
        host.program("bin/docker", "/bin/sh");
        let cache = host.home().join(".strands/box/storage/p/w/mcp-cache/npx");
        let runtime = host.home().join(".local/share/uv/python");
        std::fs::create_dir_all(&runtime).expect("an installed runtime");
        let missing = host.home().join("missing-runtime");
        let helper = host.program("helpers/bin/helper", "/bin/sh");
        let listing = host.root.join("runtime-links");
        std::fs::create_dir_all(&listing).expect("a listing directory");
        host.launchers.insert(
            "npx".into(),
            Ok(Launcher {
                pack: "@box/npx".into(),
                hosts: vec!["registry.npmjs.org".into()],
                env: BTreeMap::from([(
                    "npm_config_cache".to_string(),
                    cache.display().to_string(),
                )]),
                read: vec![
                    runtime.clone(),
                    missing.clone(),
                    helper.parent().expect("helper folder").to_path_buf(),
                ],
                list: vec![listing.clone(), listing.clone()],
                deny: vec!["/private/forbidden".into()],
                cache: cache.clone(),
            }),
        );
        let file = host.file(
            ".claude.json",
            r#"{"s": {
                "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
                "memory": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]},
                "memory-copy": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]},
                "contained": {"command": "docker", "args": ["run", "-i", "mcp/fetch"]}
            }}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert_eq!(
            reasons(&servers),
            vec![
                (
                    "contained",
                    "runs docker, a launcher that fetches the server when it starts, and box \
                     ships no pack that runs it in the box"
                ),
                (
                    "memory-copy",
                    "has the same detected command as the server memory; calls routed to \
                     memory use its policy and environment"
                ),
            ]
        );
        let github = mcp["github"].as_table().expect("a table");
        assert_eq!(
            github["command"],
            toml::Value::Array(
                ["npx", "-y", "@modelcontextprotocol/server-github"]
                    .map(toml::Value::from)
                    .to_vec()
            ),
            "the full command, as the agent runs it"
        );
        assert_eq!(
            github["env"]["npm_config_cache"].as_str(),
            Some(cache.display().to_string().as_str())
        );
        let list = |key: &str| -> Vec<String> {
            github["filesystem"][key]
                .as_array()
                .expect("a list")
                .iter()
                .map(|item| item.as_str().expect("a path").to_string())
                .collect()
        };
        assert!(list("write").contains(&cache.display().to_string()));
        let mut listed = vec![shown(&listing)];
        if cfg!(target_os = "macos") {
            listed.push(shown(&host.root.join("bin")));
        }
        assert_eq!(list("list"), listed);
        let read = list("read");
        assert!(read.contains(&runtime.display().to_string()));
        assert!(!read.contains(&missing.display().to_string()));
        assert!(
            read.contains(
                &helper
                    .parent()
                    .expect("helper folder")
                    .display()
                    .to_string()
            )
        );
        assert!(
            read.contains(
                &host
                    .root
                    .join("nvm/v22/lib/node_modules")
                    .display()
                    .to_string()
            ),
            "{read:?}"
        );
        assert!(
            read.contains(&host.root.join("nvm/v22/bin").display().to_string()),
            "{read:?}"
        );
        assert!(mcp.contains_key("memory"), "two servers may share npx");
        assert_eq!(
            mcp["memory"]["filesystem"]["deny"].as_array(),
            Some(&vec![toml::Value::from("/private/forbidden")])
        );
        assert_eq!(servers.caches(), vec![cache]);
        assert_eq!(
            servers
                .launcher("github")
                .map(|launcher| launcher.hosts.clone()),
            Some(vec!["registry.npmjs.org".to_string()])
        );
    }

    #[test]
    fn a_launcher_helper_reached_by_a_link_is_granted_by_the_link() {
        let mut host = Host::new();
        let node = host.program("nvm/v22/bin/node", "/bin/sh");
        host.link("node", &node);
        let npx = host.program(
            "nvm/v22/lib/node_modules/npm/bin/npx-cli.js",
            "/usr/bin/env node",
        );
        host.link("npx", &npx);
        let shell = host.program("shells/bash", "/bin/sh");
        let named = host.root.join("shells/sh");
        symlink(&shell, &named).expect("a link");
        let cache = host.home().join(".strands/box/storage/p/w/mcp-cache/npx");
        host.launchers.insert(
            "npx".into(),
            Ok(Launcher {
                pack: "@box/npx".into(),
                hosts: Vec::new(),
                env: BTreeMap::new(),
                read: vec![named.clone()],
                list: Vec::new(),
                deny: Vec::new(),
                cache,
            }),
        );
        let file = host.file(
            ".claude.json",
            r#"{"s": {"github": {"command": "npx", "args": ["-y", "server"]}}}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert!(reasons(&servers).is_empty(), "{:?}", reasons(&servers));
        let read_file: Vec<&str> = mcp["github"]["filesystem"]["read_file"]
            .as_array()
            .expect("a list")
            .iter()
            .map(|item| item.as_str().expect("a path"))
            .collect();
        let named = named.display().to_string();
        let shell = canonical(&shell).expect("a file").display().to_string();
        assert!(read_file.contains(&named.as_str()), "{read_file:?}");
        assert!(
            !read_file.contains(&shell.as_str()),
            "Box Core refuses a link and its target granted together: {read_file:?}"
        );
    }

    #[test]
    fn a_launcher_refuses_runtime_directories_that_are_forbidden_or_writable() {
        for (target, reason) in [
            (".ssh", "lies in a credential store"),
            ("project", "workspace"),
            ("shared", "write grant"),
            ("", "holds the workspace"),
        ] {
            let mut host = Host::new();
            host.program("bin/uvx", "/bin/sh");
            let target = host.home().join(target);
            std::fs::create_dir_all(&target).expect("target");
            let runtime = host.home().join(".local/share/uv/python");
            std::fs::create_dir_all(runtime.parent().expect("parent")).expect("parent");
            symlink(&target, &runtime).expect("runtime link");
            host.launchers.insert(
                "uvx".into(),
                Ok(Launcher {
                    pack: "@box/uvx".into(),
                    hosts: Vec::new(),
                    env: BTreeMap::new(),
                    read: vec![runtime],
                    list: Vec::new(),
                    deny: Vec::new(),
                    cache: host.home().join(".strands/box/storage/p/w/mcp-cache/uvx"),
                }),
            );
            let file = host.file(
                ".agent.json",
                r#"{"s":{"time":{"command":"uvx","args":["mcp-server-time"]}}}"#,
            );
            let mut mcp = toml::Table::new();
            let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
            assert!(mcp.is_empty(), "{target:?} must be refused");
            let skipped = reasons(&servers);
            assert_eq!(skipped.len(), 1);
            assert!(skipped[0].1.contains(reason), "{target:?}: {skipped:?}");
        }
    }

    #[test]
    fn a_role_names_one_of_the_five_kinds_of_field() {
        for role in [
            "bearer-variable",
            "header-variables",
            "header-references",
            "references",
            "variable-names",
        ] {
            assert!(Role::named(role).is_some(), "{role}");
        }
        assert_eq!(Role::named("token"), None);
    }

    #[test]
    fn a_relative_home_or_tmpdir_skips_the_server_and_a_full_path_is_copied() {
        let host = Host::new();
        for name in [
            "inside", "tilde", "linked", "box", "outside", "other", "tool",
        ] {
            host.program(&format!("bin/{name}"), "/bin/sh");
        }
        let workspace = host.workspace().display().to_string();
        let outside = host.root.join("server-home").display().to_string();
        std::fs::create_dir_all(host.home().join("shared/x")).expect("a write grant");
        let linked = host.root.join("linked-home");
        symlink(host.home().join("shared/x"), &linked).expect("a link");
        let file = host.file(
            ".claude.json",
            &format!(
                r#"{{"s": {{
                "relative-home": {{"command": "tool", "env": {{"HOME": "mcp-home"}}}},
                "relative-tmpdir": {{"command": "tool", "env": {{"TMPDIR": "tmp"}}}},
                "inside-home": {{"command": "inside", "env": {{"HOME": "{workspace}/.cache"}}}},
                "tilde-tmpdir": {{"command": "tilde", "env": {{"TMPDIR": "~/project/tmp"}}}},
                "linked-home": {{"command": "linked", "env": {{"HOME": "{linked}"}}}},
                "box-home": {{"command": "box", "env": {{"HOME": "~/.strands/box/x"}}}},
                "outside": {{"command": "outside", "env": {{"HOME": "{outside}", "TMPDIR": "~/tmp"}}}},
                "own-home": {{"command": "other", "env": {{"HOME": "~"}}}}
            }}}}"#,
                linked = linked.display()
            ),
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[expanding(row(&file, &["s"]))], &mut mcp);
        let relative = |name: &str, value: &str| {
            format!("its {name} {value:?} is not a full path, which the box refuses")
        };
        let found: Vec<(&str, String)> = servers
            .skipped
            .iter()
            .map(|skip| (skip.name.as_str(), skip.reason.clone()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("relative-home", relative("HOME", "mcp-home")),
                ("relative-tmpdir", relative("TMPDIR", "tmp")),
            ]
        );
        let home = |server: &str, name: &str| mcp[server]["env"][name].as_str().map(str::to_string);
        assert_eq!(
            home("inside-home", "HOME"),
            Some(format!("{workspace}/.cache"))
        );
        assert_eq!(
            home("tilde-tmpdir", "TMPDIR"),
            Some(host.workspace().join("tmp").display().to_string())
        );
        assert_eq!(
            home("linked-home", "HOME"),
            Some(linked.display().to_string())
        );
        assert_eq!(
            home("box-home", "HOME"),
            Some(host.home().join(".strands/box/x").display().to_string()),
            "a home a box can write is the operator's choice, and is copied"
        );
        let expected: toml::Table = toml::from_str(&format!(
            "HOME = {outside:?}\nTMPDIR = {:?}",
            host.home().join("tmp").display().to_string()
        ))
        .expect("TOML");
        assert_eq!(mcp["outside"]["env"], toml::Value::Table(expected));
        assert_eq!(
            mcp["own-home"]["env"]["HOME"].as_str(),
            Some(host.home().display().to_string().as_str()),
            "a home that holds the project, and not one inside it, is copied"
        );
    }

    #[test]
    fn a_remote_server_with_a_stdio_role_field_is_skipped() {
        let mut host = Host::new();
        host.set = vec![("TOKEN", "x")];
        let file = host.file(
            ".codex/config.toml",
            "[mcp_servers.docs]\nurl = \"https://docs.example.com\"\nenv_vars = [\"TOKEN\"]\n",
        );
        let mut codex = row(&file, &["mcp_servers"]);
        codex.env_var_locations = BTreeMap::from([("env_vars".to_string(), Role::VariableNames)]);
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[codex], &mut mcp);
        assert_eq!(reasons(&servers), vec![("docs", "uses env_vars")]);
        assert!(mcp.is_empty(), "{mcp:?}");
    }

    /// A Claude Code row: `command`, `args`, and `env` expand `${NAME}`.
    fn expanding(source: Source) -> Source {
        with_roles(
            source,
            &[
                ("command", "references"),
                ("args", "references"),
                ("env", "references"),
                ("headers", "header-references"),
            ],
        )
    }

    #[test]
    fn a_local_server_that_reads_a_routes_variable_gets_its_value() {
        let mut host = Host::new();
        host.program("bin/model-tool", "/bin/sh");
        host.set = vec![("MODEL_KEY", "real-model-key")];
        host.egress = toml::from_str(
            "[model]\ndestinations = [\"model.example.com\"]\nsecret.ref = \"env://MODEL_KEY\"",
        )
        .expect("TOML");
        let file = host.file(
            ".claude.json",
            r#"{"s": {"tool": {"command": "model-tool", "env": {"MODEL_KEY": "${MODEL_KEY}"}}}}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[expanding(row(&file, &["s"]))], &mut mcp);
        assert_eq!(reasons(&servers), Vec::<(&str, &str)>::new());
        assert_eq!(
            mcp["tool"]["env"]["MODEL_KEY"].as_str(),
            Some("real-model-key"),
            "the server's own env wins over the route's placeholder, so nothing breaks"
        );
    }

    #[test]
    fn literal_star_and_wildcard_servers_remain_distinct_in_either_order() {
        let host = Host::new();
        host.program("bin/tool", "/bin/sh");
        for (first, second) in [("*", "${TOKEN}"), ("${TOKEN}", "*")] {
            let file = host.file(
                ".agent.json",
                &serde_json::json!({"s": {
                    "first": {"command": "tool", "args": [first]},
                    "second": {"command": "tool", "args": [second]}
                }})
                .to_string(),
            );
            let mut mcp = toml::Table::new();
            let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
            assert!(servers.skipped.is_empty(), "{:?}", servers.skipped);
            assert_eq!(mcp.len(), 2);
            for (name, argument) in [("first", first), ("second", second)] {
                assert_eq!(mcp[name]["command"], toml::Value::from(vec!["tool", "*"]));
                assert_eq!(
                    mcp[name]
                        .get("argument_wildcards")
                        .and_then(toml::Value::as_bool),
                    (argument != "*").then_some(true)
                );
            }
        }
    }

    #[test]
    fn shared_programs_keep_exact_commands_and_skip_overlapping_wildcards() {
        let host = Host::new();
        host.program("bin/tool", "/bin/sh");
        let file = host.file(
            ".agent.json",
            r#"{"s":{
                "a-pattern":{"command":"tool","args":["--token","${TOKEN}"]},
                "b-overlap":{"command":"tool","args":["${FLAG}","abc"]},
                "c-exact":{"command":"tool","args":["--token","abc"]},
                "d-separate":{"command":"tool","args":["--other","${OTHER}"]},
                "e-longer":{"command":"tool","args":["--token","${TOKEN}","extra"]}
            }}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert_eq!(
            mcp.keys().map(String::as_str).collect::<Vec<_>>(),
            ["a-pattern", "c-exact", "d-separate", "e-longer"]
        );
        assert_eq!(servers.skipped.len(), 1);
        assert_eq!(servers.skipped[0].name, "b-overlap");
        assert_eq!(
            servers.skipped[0].reason,
            "its argument wildcards overlap with the server a-pattern; calls routed to \
             a-pattern use its policy and environment"
        );
    }

    #[test]
    fn copied_configuration_keeps_caller_arguments_for_wildcard_slots() {
        let mut host = Host::new();
        host.program("bin/tool", "/bin/sh");
        host.set = vec![("TOKEN", "host-secret")];
        let file = host.file(
            ".agent.json",
            r#"{"s":{"tool":{"command":"tool","args":["--token","${TOKEN}","--level=${UNSET:-info}"],"env":{"TOKEN":"${TOKEN}"}}}}"#,
        );
        let mut source = expanding(row(&file, &["s"]));
        source.target = Some(Target {
            path: host.home().join(".strands/box/storage/agent.json"),
            kind: Format::Json,
            key: vec!["s".into()],
        });
        for overridden in [false, true] {
            let mut mcp = toml::Table::new();
            if overridden {
                mcp = toml::from_str(
                    r#"[tool]
                    command = ["tool", "--other", "*", "fixed"]
                    "#,
                )
                .expect("profile extension");
            }
            let servers = host.detect(&[source.clone()], &mut mcp);
            assert!(servers.skipped.is_empty(), "{:?}", servers.skipped);
            let copied = &servers.configs[0].servers["tool"];
            assert_eq!(
                copied["args"],
                if overridden {
                    serde_json::json!(["--other", "${TOKEN}", "fixed"])
                } else {
                    serde_json::json!(["--token", "${TOKEN}", "--level=${UNSET:-info}"])
                }
            );
            assert!(copied.get("env").is_none());
            assert!(!copied.to_string().contains("host-secret"));
            assert_eq!(mcp["tool"]["command"][2].as_str(), Some("*"));
            assert_eq!(mcp["tool"]["argument_wildcards"].as_bool(), Some(true));
        }
    }

    #[test]
    fn detected_argument_variables_use_caller_values_without_reading_the_host() {
        let mut host = Host::new();
        host.program("bin/tool", "/bin/sh");
        host.set = vec![("TOKEN", "host-secret")];
        let file = host.file(
            ".agent.json",
            r#"{"s": {"tool": {"command": "tool", "args": ["--token", "${TOKEN}",
                "--level=${MISSING:-info}", "${UNSET}", "${A}:${B}", "{env:KEY}",
                "cost-${", "--fixed", "", "--glob=*"]}}}"#,
        );
        for source in [row(&file, &["s"]), expanding(row(&file, &["s"]))] {
            let mut mcp = toml::Table::new();
            let servers = host.detect(&[source], &mut mcp);
            assert!(servers.skipped.is_empty(), "{:?}", servers.skipped);
            assert_eq!(
                mcp["tool"]["command"],
                toml::Value::from(vec![
                    "tool", "--token", "*", "*", "*", "*", "*", "*", "--fixed", "", "--glob=*"
                ])
            );
            assert_eq!(mcp["tool"]["argument_wildcards"].as_bool(), Some(true));
            assert!(
                servers.detected[0].env.is_empty(),
                "argument variables are not read"
            );
            assert!(!toml::to_string(&mcp).expect("TOML").contains("host-secret"));
        }
        let mut custom = row(&file, &["s"]);
        custom.env_var_syntax = Some(Syntax::one("%NAME%"));
        host.file(
            ".agent.json",
            r#"{"s":{"tool":{"command":"tool","args":["%KEY%"]}}}"#,
        );
        let mut mcp = toml::Table::new();
        assert!(host.detect(&[custom], &mut mcp).skipped.is_empty());
        assert_eq!(mcp["tool"]["command"], toml::Value::from(vec!["tool", "*"]));
        assert_eq!(mcp["tool"]["argument_wildcards"].as_bool(), Some(true));
    }

    #[test]
    fn detected_wildcards_do_not_change_literal_star_arguments() {
        let host = Host::new();
        host.program("bin/tool", "/bin/sh");
        for args in [vec!["*", "--fixed"], vec!["--fixed"], vec![]] {
            let file = host.file(
                ".agent.json",
                &serde_json::json!({"s": {
                    "tool": {"command": "tool", "args": args}
                }})
                .to_string(),
            );
            let mut mcp = toml::Table::new();
            assert!(
                host.detect(&[row(&file, &["s"])], &mut mcp)
                    .skipped
                    .is_empty()
            );
            assert!(mcp["tool"].get("argument_wildcards").is_none());
            assert_eq!(
                mcp["tool"]["command"],
                toml::Value::from(std::iter::once("tool").chain(args).collect::<Vec<_>>())
            );
        }
        let file = host.file(
            ".agent.json",
            r#"{"s":{"tool":{"command":"tool","args":["*","${TOKEN}"]}}}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[row(&file, &["s"])], &mut mcp);
        assert!(mcp.is_empty());
        assert_eq!(
            reasons(&servers),
            vec![(
                "tool",
                "mixes a literal `*` argument with a variable argument; Box Core would treat both as wildcards"
            )]
        );
    }

    #[test]
    fn a_local_server_expands_program_and_environment_but_accepts_caller_arguments() {
        let mut host = Host::new();
        let program = host.program("bin/github", "/bin/sh");
        host.program("bin/tool", "/bin/sh");
        host.set = vec![
            ("GITHUB_TOKEN", "ghp_real"),
            ("LOG", "debug"),
            ("EMPTY", ""),
        ];
        let file = host.file(
            ".claude.json",
            r#"{"s": {
                "github": {"command": "github",
                    "args": ["--token", "${GITHUB_TOKEN}", "--level=${LOG_LEVEL:-info}", "x-${UNSET_A:-d}-${LOG}"],
                    "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}", "LOG_LEVEL": "${LOG:-warn}",
                        "PASTED": "sk-pasted", "MIXED": "Bearer ${GITHUB_TOKEN}!",
                        "BLANK": "${EMPTY:-fallback}", "CACHE": "~/cache",
                        "TMPDIR": "~/tmp", "ALONE": "~", "LATER": "a/~/b"}},
                "named": {"command": "${TOOL_PROGRAM:-tool}"}
            }}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[expanding(row(&file, &["s"]))], &mut mcp);
        assert_eq!(reasons(&servers), Vec::<(&str, &str)>::new());
        let home = host.home().display().to_string();
        let github = mcp["github"].as_table().expect("a table");
        assert_eq!(
            github["command"],
            toml::Value::Array(
                ["github", "--token", "*", "*", "*"]
                    .map(toml::Value::from)
                    .to_vec()
            )
        );
        let expected: toml::Table = toml::from_str(&format!(
            r#"
            GITHUB_TOKEN = "ghp_real"
            LOG_LEVEL = "debug"
            PASTED = "sk-pasted"
            MIXED = "Bearer ghp_real!"
            BLANK = ""
            CACHE = "{home}/cache"
            TMPDIR = "{home}/tmp"
            ALONE = "{home}"
            LATER = "a/~/b"
            "#
        ))
        .expect("TOML");
        assert_eq!(github["env"], toml::Value::Table(expected));
        assert_eq!(
            servers.program_path("github"),
            Some(program.as_path()),
            "the expanded program is the one box checked"
        );
        assert_eq!(
            mcp["named"]["command"],
            toml::Value::Array(vec![toml::Value::from("tool")])
        );
        assert!(
            mcp["named"].get("env").is_none(),
            "a server with no env gets none"
        );
    }

    #[test]
    fn a_variable_with_no_value_or_a_name_the_box_refuses_skips_the_server() {
        let mut host = Host::new();
        host.program("bin/tool", "/bin/sh");
        host.set = vec![("SET", "x")];
        let file = host.file(
            ".claude.json",
            r#"{"s": {
                "unset-env": {"command": "tool", "env": {"K": "${NOT_SET}"}},
                "unset-command": {"command": "${NO_PROGRAM}"},
                "node": {"command": "tool", "env": {"NODE_OPTIONS": "--require ./x.js"}},
                "python": {"command": "tool", "env": {"PYTHONPATH": "/x"}},
                "dyld": {"command": "tool", "env": {"DYLD_INSERT_LIBRARIES": "${SET}"}},
                "path": {"command": "tool", "env": {"PATH": "/usr/bin"}},
                "badname": {"command": "tool", "env": {"1X": "y"}},
                "number": {"command": "tool", "env": {"N": 1}}
            }}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[expanding(row(&file, &["s"]))], &mut mcp);
        assert!(mcp.is_empty(), "{mcp:?}");
        assert_eq!(
            reasons(&servers),
            vec![
                (
                    "badname",
                    "its env name \"1X\" is not a variable name, which Box Core refuses"
                ),
                (
                    "dyld",
                    "sets DYLD_INSERT_LIBRARIES, a variable that makes a program load code, \
                     so box does not declare this server automatically"
                ),
                (
                    "node",
                    "sets NODE_OPTIONS, a variable that makes a program load code, so box \
                     does not declare this server automatically"
                ),
                ("number", "`env` is not a table of strings"),
                (
                    "path",
                    "sets PATH, which can change the programs a server starts; box uses your \
                     PATH"
                ),
                (
                    "python",
                    "sets PYTHONPATH, a variable that makes a program load code, so box \
                     does not declare this server automatically"
                ),
                (
                    "unset-command",
                    "it needs NO_PROGRAM, which isn't set where you ran box"
                ),
                (
                    "unset-env",
                    "it needs NOT_SET, which isn't set where you ran box"
                ),
            ]
        );
    }

    #[test]
    fn a_name_the_box_sets_itself_is_dropped_and_the_server_kept() {
        let host = Host::new();
        host.program("bin/tool", "/bin/sh");
        let file = host.file(
            ".claude.json",
            r#"{"s": {"proxied": {"command": "tool", "env": {
                "HTTPS_PROXY": "http://proxy.example.com", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://x",
                "USER": "me", "KEEP": "1"}}}}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[expanding(row(&file, &["s"]))], &mut mcp);
        assert_eq!(reasons(&servers), Vec::<(&str, &str)>::new());
        assert_eq!(
            mcp["proxied"]["env"],
            toml::Value::Table(toml::Table::from_iter([(
                "KEEP".to_string(),
                toml::Value::from("1")
            )]))
        );
        assert_eq!(
            servers.detected_lines(&host.home()),
            vec![(
                "proxied".to_string(),
                "~/.claude.json".to_string(),
                ", with KEEP".to_string()
            )]
        );
        assert_eq!(
            servers.dropped_lines(&host.home()),
            ["HTTPS_PROXY", "OTEL_EXPORTER_OTLP_ENDPOINT", "USER"]
                .map(|variable| (
                    variable.to_string(),
                    "proxied".to_string(),
                    "~/.claude.json".to_string(),
                    "the box sets it itself".to_string()
                ))
                .to_vec()
        );
    }

    #[test]
    fn an_unset_proxy_skips_a_server_with_direct_network_access_and_only_drops_for_others() {
        let host = Host::new();
        host.program("bin/tool", "/bin/sh");
        let file = host.file(
            ".claude.json",
            r#"{"s": {"proxied": {"command": "tool", "env": {"HTTPS_PROXY": "${CORP_PROXY}"}}}}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[expanding(row(&file, &["s"]))], &mut mcp);
        assert_eq!(reasons(&servers), Vec::<(&str, &str)>::new());
        assert_eq!(
            servers.dropped_lines(&host.home())[0].3,
            "the box sets it itself"
        );
        let mut mcp: toml::Table =
            toml::from_str("[proxied.network]\ncontain_egress = false").expect("an addition");
        let servers = host.detect(&[expanding(row(&file, &["s"]))], &mut mcp);
        assert!(servers.detected.is_empty(), "{servers:?}");
        assert_eq!(servers.skipped.len(), 1, "{servers:?}");
        assert!(
            servers.skipped[0].reason.contains("CORP_PROXY"),
            "{}",
            servers.skipped[0].reason
        );
    }

    #[test]
    fn a_codex_server_passes_its_env_vars_and_copies_its_env_as_written() {
        let mut host = Host::new();
        host.program("bin/tool", "/bin/sh");
        host.program("bin/literal-tool", "/bin/sh");
        host.program("bin/other", "/bin/sh");
        host.program("bin/optional", "/bin/sh");
        host.set = vec![
            ("GITHUB_TOKEN", "ghp_real"),
            ("LEVEL", "debug"),
            ("PASSED_DIR", "~/passed"),
            ("LD_PRELOAD", "/library.so"),
            ("HTTP_PROXY", "http://proxy.example.com"),
        ];
        let file = host.file(
            ".codex/config.toml",
            r#"
            [mcp_servers.github]
            command = "tool"
            env_vars = ["GITHUB_TOKEN", "LEVEL", "PASSED_DIR"]
            env = { LEVEL = "${LEVEL}", PASTED = "sk-pasted", WRITTEN_DIR = "~/written" }

            [mcp_servers.missing]
            command = "optional"
            env_vars = ["NOPE"]

            [mcp_servers.loader]
            command = "tool"
            env_vars = ["LD_PRELOAD"]

            [mcp_servers.proxied]
            command = "other"
            env_vars = ["HTTP_PROXY"]

            [mcp_servers.literal]
            command = "literal-tool"
            args = ["${GITHUB_TOKEN}"]

            [mcp_servers.tilde-home]
            command = "tool"
            env = { HOME = "~/x" }

            [mcp_servers.remote]
            url = "https://remote.example.com/mcp"
            env_vars = ["GITHUB_TOKEN"]
            "#,
        );
        let mut codex = row(&file, &["mcp_servers"]);
        codex.env_var_locations = BTreeMap::from([
            ("bearer_token_env_var".to_string(), Role::BearerVariable),
            ("env_http_headers".to_string(), Role::HeaderVariables),
            ("env_vars".to_string(), Role::VariableNames),
        ]);
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[codex], &mut mcp);
        assert_eq!(
            reasons(&servers),
            vec![
                (
                    "loader",
                    "sets LD_PRELOAD, a variable that makes a program load code, so box \
                     does not declare this server automatically"
                ),
                ("remote", "uses env_vars"),
                (
                    "tilde-home",
                    "its HOME \"~/x\" is not a full path, which the box refuses"
                ),
            ]
        );
        let expected: toml::Table = toml::from_str(
            "GITHUB_TOKEN = \"ghp_real\"\nLEVEL = \"${LEVEL}\"\nPASTED = \"sk-pasted\"\n\
             PASSED_DIR = \"~/passed\"\nWRITTEN_DIR = \"~/written\"",
        )
        .expect("TOML");
        assert_eq!(
            mcp["github"]["env"],
            toml::Value::Table(expected),
            "a passed or a written value keeps its ~, as on the host"
        );
        assert!(mcp["proxied"].get("env").is_none(), "{:?}", mcp["proxied"]);
        assert!(mcp["missing"].get("env").is_none(), "{:?}", mcp["missing"]);
        assert_eq!(
            servers.dropped_lines(&host.home()),
            vec![(
                "HTTP_PROXY".to_string(),
                "proxied".to_string(),
                "~/.codex/config.toml".to_string(),
                "the box sets it itself".to_string()
            )]
        );
    }

    #[test]
    fn a_form_with_no_closing_text_takes_no_default_in_a_header_and_is_text_in_a_url() {
        let mut host = Host::new();
        host.set = vec![("TOKEN", "a-key")];
        let file = host.file(
            ".agent.json",
            r#"{"s": {
                "header": {"url": "https://header.example.com/mcp", "headers": {"Authorization": "Bearer $TOKEN:-public"}},
                "query": {"url": "https://query.example.com/mcp?key=$TOKEN:-public"}
            }}"#,
        );
        let mut source = with_roles(row(&file, &["s"]), &[("headers", "header-references")]);
        source.env_var_syntax = Some(Syntax::one("$NAME"));
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[source], &mut mcp);
        assert_eq!(
            reasons(&servers),
            vec![(
                "header",
                "sets its headers header Authorization to a value that does not end in one \
                     variable written `$NAME`; box takes a key only from your variable"
            ),]
        );
        assert!(mcp["query"].get("secret").is_none(), "{:?}", mcp["query"]);
    }

    #[test]
    fn remote_fallbacks_use_a_set_key_and_leave_an_unset_default_to_the_harness() {
        for (syntax, reference) in [
            ("${NAME}", "${TOKEN:-literal-default}"),
            ("{env:NAME}", "{env:TOKEN:-literal-default}"),
        ] {
            for value in [Some("private-value"), None, Some(""), Some(" ")] {
                for query in [false, true] {
                    let mut host = Host::new();
                    if let Some(value) = value {
                        host.set = vec![("TOKEN", value)];
                    }
                    let server = if query {
                        serde_json::json!({"url": format!("https://remote.example.com/mcp?key={reference}")})
                    } else {
                        serde_json::json!({"url": "https://remote.example.com/mcp",
                        "headers": {"Authorization": format!("Bearer {reference}")}})
                    };
                    let text = serde_json::json!({"s": {"remote": server}}).to_string();
                    let file = host.file(".agent.json", &text);
                    let mut mcp = toml::Table::new();
                    let mut source =
                        with_roles(row(&file, &["s"]), &[("headers", "header-references")]);
                    source.env_var_syntax = Some(Syntax::one(syntax));
                    let servers = host.detect(&[source], &mut mcp);
                    if value.is_some_and(|value| value.trim().is_empty()) {
                        assert_eq!(
                            reasons(&servers),
                            vec![(
                                "remote",
                                "needs TOKEN, which is not set in your environment"
                            )]
                        );
                        assert!(mcp.is_empty());
                        continue;
                    }
                    assert!(servers.skipped.is_empty(), "{:?}", reasons(&servers));
                    assert_eq!(
                        mcp["remote"]["destinations"][0].as_str(),
                        Some("remote.example.com")
                    );
                    if value.is_some() {
                        assert_eq!(mcp["remote"]["secret"]["ref"].as_str(), Some("env://TOKEN"));
                        if query {
                            assert_eq!(mcp["remote"]["secret"]["param"].as_str(), Some("key"));
                        } else {
                            assert_eq!(mcp["remote"]["secret"]["prefix"].as_str(), Some("Bearer "));
                        }
                        assert_eq!(servers.detected[0].variables, ["TOKEN"]);
                    } else {
                        assert!(mcp["remote"].get("secret").is_none());
                        assert!(servers.detected[0].variables.is_empty());
                    }
                    assert_eq!(std::fs::read_to_string(&file).expect("source"), text);
                    let report = format!("{servers:?}{mcp:?}");
                    assert!(!report.contains("literal-default"));
                    assert!(!report.contains("private-value"));
                }
            }
        }
    }

    #[test]
    fn remote_fallbacks_keep_reference_and_environment_checks() {
        for (value, variable, configured) in [
            ("${TOKEN:-${OTHER}}", "TOKEN", false),
            ("${TOKEN:-default}-suffix", "TOKEN", false),
            ("${TOKEN:-default}${OTHER}", "TOKEN", false),
            ("${1TOKEN:-default}", "TOKEN", false),
            ("${HOME:-default}", "HOME", false),
            ("${TOKEN:-default}", "TOKEN", true),
        ] {
            let mut host = Host::new();
            if configured {
                host.agent_env
                    .insert(variable.to_string(), "override".to_string());
            }
            let file = host.file(
                ".agent.json",
                &serde_json::json!({
                    "s": {"remote": {"url": "https://remote.example.com",
                        "headers": {"X-Key": value}}}
                })
                .to_string(),
            );
            let mut mcp = toml::Table::new();
            let servers = host.detect(
                &[with_roles(
                    row(&file, &["s"]),
                    &[("headers", "header-references")],
                )],
                &mut mcp,
            );
            assert_eq!(servers.skipped.len(), 1, "{value}");
            assert!(mcp.is_empty(), "{value}");
            assert!(!servers.skipped[0].reason.contains("default"), "{value}");
        }
    }

    #[test]
    fn remote_gateway_keys_require_https() {
        for port in ["", ":443", ":8080"] {
            for (field, role, value) in [
                ("token", "bearer-variable", serde_json::json!("TOKEN")),
                (
                    "headers",
                    "header-variables",
                    serde_json::json!({"X-Key": "TOKEN"}),
                ),
                (
                    "headers",
                    "header-references",
                    serde_json::json!({"Authorization": "Bearer ${TOKEN}"}),
                ),
                ("headers", "header-references", serde_json::json!({})),
            ] {
                let mut host = Host::new();
                host.set = vec![("TOKEN", "private-value")];
                let query = if value == serde_json::json!({}) {
                    "?key=${TOKEN}"
                } else {
                    ""
                };
                let file = host.file(
                    ".agent.json",
                    &serde_json::json!({"s": {"remote": {
                        "url": format!("http://remote.example.com{port}/mcp{query}"),
                        field: value
                    }}})
                    .to_string(),
                );
                let mut mcp = toml::Table::new();
                let servers = host.detect(
                    &[with_roles(row(&file, &["s"]), &[(field, role)])],
                    &mut mcp,
                );
                assert_eq!(
                    reasons(&servers),
                    vec![(
                        "remote",
                        "takes a key over http://; Box Core sends keys only over https://; change the server URL to https://"
                    )]
                );
                assert!(mcp.is_empty());
                assert!(servers.detected.is_empty());
            }
        }
    }

    #[test]
    fn codex_env_vars_omit_absent_names_and_preserve_written_values() {
        let mut host = Host::new();
        host.program("bin/tool", "/bin/sh");
        host.set = vec![("TOKEN", "private-value"), ("EMPTY", ""), ("LEVEL", "host")];
        let file = host.file(
            ".codex/config.toml",
            r#"
            [mcp_servers.tool]
            command = "tool"
            env_vars = ["TOKEN", "OPTIONAL", "EMPTY", "LEVEL", "LD_PRELOAD", "PATH", "HTTP_PROXY"]
            env = { LEVEL = "configured" }
            "#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(
            &[with_roles(
                row(&file, &["mcp_servers"]),
                &[("env_vars", "variable-names")],
            )],
            &mut mcp,
        );
        assert!(servers.skipped.is_empty(), "{:?}", reasons(&servers));
        assert_eq!(
            mcp["tool"]["env"],
            toml::Value::Table(
                toml::from_str("TOKEN = \"private-value\"\nEMPTY = \"\"\nLEVEL = \"configured\"")
                    .expect("TOML")
            )
        );
        assert!(servers.dropped_lines(&host.home()).is_empty());
        assert_eq!(servers.detected[0].env, ["EMPTY", "LEVEL", "TOKEN"]);
    }

    #[test]
    fn codex_env_vars_accept_local_objects_and_refuse_other_shapes() {
        for names in [
            serde_json::json!(["TOKEN"]),
            serde_json::json!([{"name": "TOKEN"}]),
            serde_json::json!([{"name": "TOKEN", "source": "local"}]),
            serde_json::json!([{"name": "TOKEN", "source": null}]),
        ] {
            let mut host = Host::new();
            host.program("bin/tool", "/bin/sh");
            host.set = vec![("TOKEN", "private-value")];
            let file = host.file(
                ".agent.json",
                &serde_json::json!({
                    "s": {"tool": {"command": "tool", "env_vars": names}}
                })
                .to_string(),
            );
            let mut mcp = toml::Table::new();
            let servers = host.detect(
                &[with_roles(
                    row(&file, &["s"]),
                    &[("env_vars", "variable-names")],
                )],
                &mut mcp,
            );
            assert!(
                servers.skipped.is_empty(),
                "{names}: {:?}",
                reasons(&servers)
            );
            assert_eq!(mcp["tool"]["env"]["TOKEN"].as_str(), Some("private-value"));
        }
        for names in [
            serde_json::json!([{"name": "TOKEN", "source": "remote"}]),
            serde_json::json!([{"name": "TOKEN", "source": "other"}]),
            serde_json::json!([{"name": "TOKEN", "source": false}]),
            serde_json::json!([{"name": "TOKEN", "extra": "private-value"}]),
            serde_json::json!([{"name": 1}]),
            serde_json::json!([{}]),
            serde_json::json!([false]),
        ] {
            let host = Host::new();
            host.program("bin/tool", "/bin/sh");
            let file = host.file(
                ".agent.json",
                &serde_json::json!({
                    "s": {"tool": {"command": "tool", "env_vars": names}}
                })
                .to_string(),
            );
            let mut mcp = toml::Table::new();
            let servers = host.detect(
                &[with_roles(
                    row(&file, &["s"]),
                    &[("env_vars", "variable-names")],
                )],
                &mut mcp,
            );
            assert_eq!(servers.skipped.len(), 1, "{names}");
            assert!(mcp.is_empty(), "{names}");
            assert!(!servers.skipped[0].reason.contains("private-value"));
        }
    }

    #[test]
    fn the_report_names_the_variables_a_server_gets_and_never_their_values() {
        let mut host = Host::new();
        host.program("bin/tool", "/bin/sh");
        host.program("bin/other", "/bin/sh");
        host.set = vec![("GITHUB_TOKEN", "ghp_real"), ("DOCS_KEY", "a-key")];
        let file = host.file(
            ".claude.json",
            r#"{"s": {
                "github": {"command": "tool", "env": {"LOG_LEVEL": "info", "GITHUB_TOKEN": "${GITHUB_TOKEN}"}},
                "argued": {"command": "other", "args": ["--token", "${GITHUB_TOKEN}", "--level=${UNSET_LEVEL:-info}"]},
                "docs": {"url": "https://docs.example.com", "headers": {"X-Key": "${DOCS_KEY}"}},
                "plain": {"url": "https://plain.example.com"}
            }}"#,
        );
        let mut mcp = toml::Table::new();
        let servers = host.detect(&[expanding(row(&file, &["s"]))], &mut mcp);
        assert_eq!(
            servers.detected_lines(&host.home()),
            vec![
                (
                    "argued".to_string(),
                    "~/.claude.json".to_string(),
                    String::new()
                ),
                (
                    "docs".to_string(),
                    "~/.claude.json".to_string(),
                    ", with the key in DOCS_KEY".to_string()
                ),
                (
                    "github".to_string(),
                    "~/.claude.json".to_string(),
                    ", with GITHUB_TOKEN, LOG_LEVEL".to_string()
                ),
                (
                    "plain".to_string(),
                    "~/.claude.json".to_string(),
                    String::new()
                ),
            ]
        );
        assert!(servers.dropped_lines(&host.home()).is_empty());
    }
}
